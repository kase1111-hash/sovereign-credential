// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {ICredentialLifecycleManager} from "./interfaces/ICredentialLifecycleManager.sol";
import {IClaimToken} from "./interfaces/IClaimToken.sol";
import {IIssuerRegistry} from "./interfaces/IIssuerRegistry.sol";
import {CredentialTypes} from "./libraries/CredentialTypes.sol";
import {ClaimTypes} from "./libraries/ClaimTypes.sol";
import {Errors} from "./libraries/Errors.sol";

/**
 * @title CredentialLifecycleManager
 * @notice Manages credential renewal, inheritance, and batch operations
 * @dev Implements SPEC.md Section 4.4
 *
 * Features:
 * - Renewal workflow with request/approve/deny pattern
 * - 90-day grace period for expired credential renewal
 * - Inheritance directive management
 * - Credential splitting for partial inheritance
 * - Batch transfer operations
 */
contract CredentialLifecycleManager is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    ICredentialLifecycleManager
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using EnumerableSet for EnumerableSet.UintSet;

    // ============================================
    // Roles
    // ============================================

    /// @notice Role for upgrading the contract
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice Role for FIE bridge to execute inheritance
    bytes32 public constant FIE_BRIDGE_ROLE = keccak256("FIE_BRIDGE_ROLE");

    // ============================================
    // Storage
    // ============================================

    /// @notice Reference to the ClaimToken contract
    IClaimToken public claimToken;

    /// @notice Reference to the IssuerRegistry contract
    IIssuerRegistry public issuerRegistry;

    /// @notice Address of the FIE Bridge contract
    address public fieBridge;

    /// @notice Mapping of token ID to renewal request
    mapping(uint256 => CredentialTypes.RenewalRequest) private _renewalRequests;

    /// @notice Mapping of token ID to inheritance directive
    mapping(uint256 => CredentialTypes.InheritanceDirective) private _inheritanceDirectives;

    /// @notice Set of token IDs with pending renewal requests
    EnumerableSet.UintSet private _pendingRenewals;

    /// @notice Mapping of holder to token IDs with inheritance directives
    mapping(address => EnumerableSet.UintSet) private _credentialsWithInheritance;

    /// @notice Mapping of claim type to whether it's splittable
    mapping(bytes32 => bool) private _splittableTypes;

    /// @notice Mapping of signature hash to used status (replay prevention)
    mapping(bytes32 => bool) private _usedSignatures;

    /// @notice Mapping of token ID to executor access
    mapping(uint256 => CredentialTypes.ExecutorAccess) private _executorAccess;

    /// @notice Mapping of token ID to inheritance conditions
    mapping(uint256 => CredentialTypes.InheritanceCondition[]) private _inheritanceConditions;

    /// @notice Mapping of dispute ID to dispute record
    mapping(uint256 => CredentialTypes.InheritanceDispute) private _disputes;

    /// @notice Mapping of token ID to active dispute ID (0 = no dispute)
    mapping(uint256 => uint256) private _activeDisputes;

    /// @notice Mapping of token ID to FIE trigger timestamp (for dispute window)
    mapping(uint256 => uint64) private _triggerTimestamps;

    /// @notice Counter for dispute IDs
    uint256 private _disputeIdCounter;

    // ============================================
    // Events (Advanced Inheritance)
    // ============================================

    /// @notice Emitted when executor access is granted
    event ExecutorAccessGranted(
        uint256 indexed tokenId,
        address indexed executor,
        uint64 expiresAt,
        uint8 permissions
    );

    /// @notice Emitted when executor access is revoked
    event ExecutorAccessRevoked(uint256 indexed tokenId, address indexed executor);

    /// @notice Emitted when inheritance conditions are set
    event InheritanceConditionsSet(uint256 indexed tokenId, uint256 conditionCount);

    /// @notice Emitted when a dispute is filed
    event DisputeFiled(
        uint256 indexed disputeId,
        uint256 indexed tokenId,
        address indexed disputant
    );

    /// @notice Emitted when a dispute is resolved
    event DisputeResolved(uint256 indexed disputeId, uint8 resolution);

    // ============================================
    // Constructor & Initializer
    // ============================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the contract
     * @param _claimToken Address of the ClaimToken contract
     * @param _issuerRegistry Address of the IssuerRegistry contract
     */
    function initialize(
        address _claimToken,
        address _issuerRegistry
    ) public initializer {
        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        if (_claimToken == address(0) || _issuerRegistry == address(0)) {
            revert Errors.ZeroAddress();
        }

        claimToken = IClaimToken(_claimToken);
        issuerRegistry = IIssuerRegistry(_issuerRegistry);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);

        // Initialize default splittable types (property-related)
        _splittableTypes[ClaimTypes.PROPERTY_DEED] = true;
        _splittableTypes[ClaimTypes.PROPERTY_TITLE] = true;
        _splittableTypes[ClaimTypes.PROPERTY_LIEN] = true;
    }

    // ============================================
    // Renewal Functions
    // ============================================

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function requestRenewal(uint256 tokenId) external override nonReentrant {
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);

        // Only the holder can request renewal
        address holder = _getCredentialHolder(tokenId);
        if (msg.sender != holder) {
            revert Errors.NotHolder(msg.sender, holder);
        }

        // Check if credential can be renewed
        _validateRenewalEligibility(cred);

        // Check if renewal already requested
        if (_pendingRenewals.contains(tokenId)) {
            revert Errors.RenewalAlreadyRequested(tokenId);
        }

        // Create renewal request
        _renewalRequests[tokenId] = CredentialTypes.RenewalRequest({
            tokenId: tokenId,
            requester: msg.sender,
            requestedAt: uint64(block.timestamp),
            newExpiry: 0 // Set by issuer on approval
        });

        _pendingRenewals.add(tokenId);

        emit RenewalRequested(tokenId, msg.sender);
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function approveRenewal(
        uint256 tokenId,
        uint64 newExpiry,
        bytes calldata signature
    ) external override nonReentrant {
        // Check renewal request exists
        if (!_pendingRenewals.contains(tokenId)) {
            revert Errors.NoRenewalRequest(tokenId);
        }

        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);

        // Verify caller is authorized issuer
        (bool authorized, ) = issuerRegistry.isAuthorizedSigner(msg.sender, cred.claimType);
        if (!authorized) {
            revert Errors.UnauthorizedIssuer(msg.sender, cred.claimType);
        }

        // Check within grace period if expired
        CredentialTypes.CredentialStatus status = claimToken.getStatus(tokenId);
        if (status == CredentialTypes.CredentialStatus.EXPIRED) {
            _validateWithinGracePeriod(cred.expiresAt);
        }

        // Verify signature
        _verifyRenewalSignature(tokenId, newExpiry, cred.issuer, cred.claimType, signature);

        // New expiry must be in the future
        if (newExpiry <= block.timestamp) {
            revert Errors.OutOfRange(newExpiry, block.timestamp + 1, type(uint64).max);
        }

        // Update credential expiry via ClaimToken
        claimToken.updateExpiry(tokenId, newExpiry);

        // Clean up renewal request
        _renewalRequests[tokenId].newExpiry = newExpiry;
        _pendingRenewals.remove(tokenId);

        emit RenewalApproved(tokenId, newExpiry);
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function denyRenewal(uint256 tokenId, string calldata reason) external override {
        // Check renewal request exists
        if (!_pendingRenewals.contains(tokenId)) {
            revert Errors.NoRenewalRequest(tokenId);
        }

        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);

        // Verify caller is authorized issuer
        (bool authorized, ) = issuerRegistry.isAuthorizedSigner(msg.sender, cred.claimType);
        if (!authorized) {
            revert Errors.UnauthorizedIssuer(msg.sender, cred.claimType);
        }

        // Remove renewal request
        delete _renewalRequests[tokenId];
        _pendingRenewals.remove(tokenId);

        emit RenewalDenied(tokenId, reason);
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function cancelRenewalRequest(uint256 tokenId) external override {
        // Check renewal request exists
        if (!_pendingRenewals.contains(tokenId)) {
            revert Errors.NoRenewalRequest(tokenId);
        }

        // Only requester can cancel
        CredentialTypes.RenewalRequest memory request = _renewalRequests[tokenId];
        if (msg.sender != request.requester) {
            revert Errors.NotHolder(msg.sender, request.requester);
        }

        // Remove renewal request
        delete _renewalRequests[tokenId];
        _pendingRenewals.remove(tokenId);
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function getRenewalRequest(
        uint256 tokenId
    ) external view override returns (CredentialTypes.RenewalRequest memory request) {
        return _renewalRequests[tokenId];
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function hasRenewalRequest(uint256 tokenId) external view override returns (bool pending) {
        return _pendingRenewals.contains(tokenId);
    }

    // ============================================
    // Inheritance Functions
    // ============================================

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function setInheritanceDirective(
        uint256 tokenId,
        CredentialTypes.InheritanceDirective calldata directive
    ) external override nonReentrant {
        // Verify caller is the holder
        address holder = _getCredentialHolder(tokenId);
        if (msg.sender != holder) {
            revert Errors.NotHolder(msg.sender, holder);
        }

        // Validate beneficiaries
        if (directive.beneficiaries.length == 0) {
            revert Errors.EmptyArray();
        }

        for (uint256 i = 0; i < directive.beneficiaries.length; i++) {
            if (directive.beneficiaries[i] == address(0)) {
                revert Errors.BeneficiaryInvalid(address(0));
            }
        }

        // Validate shares if provided (for splittable credentials)
        if (directive.shares.length > 0) {
            if (directive.shares.length != directive.beneficiaries.length) {
                revert Errors.BeneficiarySharesMismatch(
                    directive.beneficiaries.length,
                    directive.shares.length
                );
            }

            uint256 totalShares = 0;
            for (uint256 i = 0; i < directive.shares.length; i++) {
                totalShares += directive.shares[i];
            }
            if (totalShares != 100) {
                revert Errors.InvalidShares(totalShares);
            }
        }

        // Store directive
        _inheritanceDirectives[tokenId] = directive;
        _inheritanceDirectives[tokenId].credentialId = tokenId;

        // Track in holder's set
        _credentialsWithInheritance[holder].add(tokenId);

        emit InheritanceDirectiveSet(tokenId, directive.beneficiaries);
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function removeInheritanceDirective(uint256 tokenId) external override {
        // Verify caller is the holder
        address holder = _getCredentialHolder(tokenId);
        if (msg.sender != holder) {
            revert Errors.NotHolder(msg.sender, holder);
        }

        // Check directive exists
        if (_inheritanceDirectives[tokenId].beneficiaries.length == 0) {
            revert Errors.InheritanceNotSet(tokenId);
        }

        // Remove from holder's set
        _credentialsWithInheritance[holder].remove(tokenId);

        // Delete directive
        delete _inheritanceDirectives[tokenId];

        emit InheritanceDirectiveRemoved(tokenId);
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function getInheritanceDirective(
        uint256 tokenId
    ) external view override returns (CredentialTypes.InheritanceDirective memory directive) {
        return _inheritanceDirectives[tokenId];
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function hasInheritanceDirective(
        uint256 tokenId
    ) external view override returns (bool hasDirective) {
        return _inheritanceDirectives[tokenId].beneficiaries.length > 0;
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function executeInheritance(
        uint256 tokenId,
        bytes calldata fieProof
    ) external override nonReentrant onlyRole(FIE_BRIDGE_ROLE) {
        CredentialTypes.InheritanceDirective memory directive = _inheritanceDirectives[tokenId];

        // Check directive exists
        if (directive.beneficiaries.length == 0) {
            revert Errors.InheritanceNotSet(tokenId);
        }

        // Verify FIE proof if required
        if (directive.requiresFIETrigger) {
            _verifyFIEProof(directive.fieIntentHash, fieProof);
        }

        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        address currentHolder = _getCredentialHolder(tokenId);

        // Check if credential is splittable and has shares
        if (directive.shares.length > 0 && _splittableTypes[cred.claimType]) {
            // Split credential among beneficiaries
            _executeSplitInheritance(tokenId, directive);
        } else {
            // Transfer to primary beneficiary
            address beneficiary = directive.beneficiaries[0];

            // Mark credential as inherited
            claimToken.markInherited(tokenId);

            // Note: Actual transfer would happen via ClaimToken
            // This requires ClaimToken to have a transferFrom that LifecycleManager can call
            // For now, we emit the event and mark status

            emit InheritanceExecuted(tokenId, beneficiary);
        }

        // Clean up
        _credentialsWithInheritance[currentHolder].remove(tokenId);
        delete _inheritanceDirectives[tokenId];
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function splitCredential(
        uint256 tokenId,
        address[] calldata beneficiaries,
        uint8[] calldata shares
    ) external override nonReentrant returns (uint256[] memory newTokenIds) {
        // Only FIE bridge or admin can split
        if (!hasRole(FIE_BRIDGE_ROLE, msg.sender) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert Errors.OperationNotAllowed();
        }

        // Check for pending disputes
        if (_activeDisputes[tokenId] != 0) {
            revert Errors.InheritanceFrozen(tokenId, _activeDisputes[tokenId]);
        }

        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);

        // Check if splittable
        if (!_splittableTypes[cred.claimType]) {
            revert Errors.NotSplittable(cred.claimType);
        }

        // Check if already a split credential
        if (claimToken.isSplitCredential(tokenId)) {
            revert Errors.CannotSplitCredential(tokenId, "Already split");
        }

        // Validate inputs
        if (beneficiaries.length != shares.length) {
            revert Errors.BeneficiarySharesMismatch(beneficiaries.length, shares.length);
        }
        if (beneficiaries.length == 0) {
            revert Errors.EmptyArray();
        }

        uint256 totalShares = 0;
        for (uint256 i = 0; i < shares.length; i++) {
            if (beneficiaries[i] == address(0)) {
                revert Errors.BeneficiaryInvalid(address(0));
            }
            totalShares += shares[i];
        }
        if (totalShares != 100) {
            revert Errors.InvalidShares(totalShares);
        }

        // Burn original credential
        claimToken.burn(tokenId);

        // Mint new credentials for each beneficiary
        newTokenIds = new uint256[](beneficiaries.length);
        uint8 totalSplits = uint8(beneficiaries.length);

        for (uint256 i = 0; i < beneficiaries.length; i++) {
            newTokenIds[i] = claimToken.mintSplit(
                cred,
                beneficiaries[i],
                shares[i],
                uint8(i),
                totalSplits
            );
        }

        emit CredentialSplit(tokenId, newTokenIds, beneficiaries, shares);

        return newTokenIds;
    }

    // ============================================
    // Conditional Inheritance Functions
    // ============================================

    /**
     * @notice Set inheritance conditions for a credential
     * @param tokenId The credential to set conditions for
     * @param conditions Array of inheritance conditions
     */
    function setInheritanceConditions(
        uint256 tokenId,
        CredentialTypes.InheritanceCondition[] calldata conditions
    ) external nonReentrant {
        // Verify caller is the holder
        address holder = _getCredentialHolder(tokenId);
        if (msg.sender != holder) {
            revert Errors.NotHolder(msg.sender, holder);
        }

        // Validate conditions
        for (uint256 i = 0; i < conditions.length; i++) {
            _validateCondition(conditions[i]);
        }

        // Clear existing conditions
        delete _inheritanceConditions[tokenId];

        // Store new conditions
        for (uint256 i = 0; i < conditions.length; i++) {
            _inheritanceConditions[tokenId].push(conditions[i]);
        }

        emit InheritanceConditionsSet(tokenId, conditions.length);
    }

    /**
     * @notice Get inheritance conditions for a credential
     * @param tokenId The credential to query
     * @return conditions Array of inheritance conditions
     */
    function getInheritanceConditions(
        uint256 tokenId
    ) external view returns (CredentialTypes.InheritanceCondition[] memory conditions) {
        return _inheritanceConditions[tokenId];
    }

    /**
     * @notice Evaluate if all inheritance conditions are met for a beneficiary
     * @param tokenId The credential
     * @param beneficiary The beneficiary to check
     * @return met True if all conditions are met
     */
    function evaluateConditions(
        uint256 tokenId,
        address beneficiary
    ) external view returns (bool met) {
        CredentialTypes.InheritanceCondition[] storage conditions = _inheritanceConditions[tokenId];

        for (uint256 i = 0; i < conditions.length; i++) {
            if (!_evaluateCondition(conditions[i], beneficiary)) {
                return false;
            }
        }

        return true;
    }

    // ============================================
    // Executor Access Functions (Time-bounded)
    // ============================================

    /**
     * @notice Grant executor access for estate settlement
     * @param tokenId The credential to grant access to
     * @param executor Address of the executor
     * @param duration Duration of access in seconds
     * @param permissions Permission bitmap
     */
    function grantExecutorAccess(
        uint256 tokenId,
        address executor,
        uint64 duration,
        uint8 permissions
    ) external nonReentrant {
        // Only FIE bridge or admin can grant executor access
        if (!hasRole(FIE_BRIDGE_ROLE, msg.sender) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert Errors.OperationNotAllowed();
        }

        // Validate executor
        if (executor == address(0)) {
            revert Errors.ZeroAddress();
        }

        // Check if access already granted
        if (_executorAccess[tokenId].executor != address(0) &&
            _executorAccess[tokenId].expiresAt > block.timestamp) {
            revert Errors.ExecutorAccessAlreadyGranted(executor, tokenId);
        }

        // Validate duration
        if (duration > CredentialTypes.MAX_EXECUTOR_PERIOD) {
            revert Errors.ExecutorPeriodExceedsMax(duration, CredentialTypes.MAX_EXECUTOR_PERIOD);
        }
        if (duration == 0) {
            duration = CredentialTypes.DEFAULT_EXECUTOR_PERIOD;
        }

        uint64 expiresAt = uint64(block.timestamp) + duration;

        _executorAccess[tokenId] = CredentialTypes.ExecutorAccess({
            executor: executor,
            grantedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            permissions: permissions
        });

        emit ExecutorAccessGranted(tokenId, executor, expiresAt, permissions);
    }

    /**
     * @notice Revoke executor access
     * @param tokenId The credential to revoke access from
     */
    function revokeExecutorAccess(uint256 tokenId) external {
        // Only admin can revoke
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert Errors.OperationNotAllowed();
        }

        address executor = _executorAccess[tokenId].executor;
        delete _executorAccess[tokenId];

        emit ExecutorAccessRevoked(tokenId, executor);
    }

    /**
     * @notice Get executor access details
     * @param tokenId The credential to query
     * @return access The executor access struct
     */
    function getExecutorAccess(
        uint256 tokenId
    ) external view returns (CredentialTypes.ExecutorAccess memory access) {
        return _executorAccess[tokenId];
    }

    /**
     * @notice Check if an address has valid executor access
     * @param tokenId The credential
     * @param executor The address to check
     * @param permission The required permission flag
     * @return hasAccess True if access is valid
     */
    function hasExecutorAccess(
        uint256 tokenId,
        address executor,
        uint8 permission
    ) external view returns (bool hasAccess) {
        CredentialTypes.ExecutorAccess storage access = _executorAccess[tokenId];

        if (access.executor != executor) {
            return false;
        }
        if (block.timestamp > access.expiresAt) {
            return false;
        }
        if ((access.permissions & permission) == 0) {
            return false;
        }

        return true;
    }

    // ============================================
    // Dispute Handling Functions
    // ============================================

    /**
     * @notice File a dispute against inheritance
     * @param tokenId The credential being disputed
     * @param reason Encoded reason for the dispute
     * @return disputeId The ID of the filed dispute
     */
    function fileDispute(
        uint256 tokenId,
        bytes calldata reason
    ) external nonReentrant returns (uint256 disputeId) {
        // Check dispute window
        uint64 triggerTime = _triggerTimestamps[tokenId];
        if (triggerTime == 0) {
            // No trigger yet, allow dispute filing anyway
        } else {
            uint64 windowEnd = triggerTime + CredentialTypes.DISPUTE_FILING_WINDOW;
            if (block.timestamp > windowEnd) {
                revert Errors.DisputeWindowExpired(tokenId, windowEnd);
            }
        }

        // Check no active dispute
        if (_activeDisputes[tokenId] != 0) {
            revert Errors.DisputeAlreadyFiled(tokenId);
        }

        // Create dispute
        _disputeIdCounter++;
        disputeId = _disputeIdCounter;

        _disputes[disputeId] = CredentialTypes.InheritanceDispute({
            disputeId: disputeId,
            tokenId: tokenId,
            disputant: msg.sender,
            reason: reason,
            filedAt: uint64(block.timestamp),
            resolvedAt: 0,
            resolution: CredentialTypes.DISPUTE_PENDING
        });

        _activeDisputes[tokenId] = disputeId;

        emit DisputeFiled(disputeId, tokenId, msg.sender);

        return disputeId;
    }

    /**
     * @notice Resolve a dispute (admin only)
     * @param disputeId The dispute to resolve
     * @param resolution Resolution outcome (1=upheld, 2=rejected)
     */
    function resolveDispute(
        uint256 disputeId,
        uint8 resolution
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        CredentialTypes.InheritanceDispute storage dispute = _disputes[disputeId];

        if (dispute.disputeId == 0) {
            revert Errors.DisputeNotFound(disputeId);
        }
        if (dispute.resolution != CredentialTypes.DISPUTE_PENDING) {
            revert Errors.DisputeAlreadyResolved(disputeId);
        }
        if (resolution != CredentialTypes.DISPUTE_UPHELD &&
            resolution != CredentialTypes.DISPUTE_REJECTED) {
            revert Errors.InvalidConditionParams(bytes32(0));
        }

        dispute.resolvedAt = uint64(block.timestamp);
        dispute.resolution = resolution;

        // Clear active dispute
        _activeDisputes[dispute.tokenId] = 0;

        emit DisputeResolved(disputeId, resolution);
    }

    /**
     * @notice Get dispute details
     * @param disputeId The dispute to query
     * @return dispute The dispute struct
     */
    function getDispute(
        uint256 disputeId
    ) external view returns (CredentialTypes.InheritanceDispute memory dispute) {
        return _disputes[disputeId];
    }

    /**
     * @notice Check if a credential has an active dispute
     * @param tokenId The credential to check
     * @return hasDispute True if there's an active dispute
     * @return disputeId The active dispute ID (0 if none)
     */
    function hasActiveDispute(
        uint256 tokenId
    ) external view returns (bool hasDispute, uint256 disputeId) {
        disputeId = _activeDisputes[tokenId];
        return (disputeId != 0, disputeId);
    }

    /**
     * @notice Record FIE trigger timestamp for dispute window calculation
     * @param tokenId The credential that was triggered
     */
    function recordTrigger(uint256 tokenId) external onlyRole(FIE_BRIDGE_ROLE) {
        _triggerTimestamps[tokenId] = uint64(block.timestamp);
    }

    // ============================================
    // Batch Operations
    // ============================================

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function batchTransfer(
        uint256[] calldata tokenIds,
        address to
    ) external override nonReentrant {
        if (tokenIds.length == 0) {
            revert Errors.EmptyArray();
        }
        if (to == address(0)) {
            revert Errors.ZeroAddress();
        }

        address from = msg.sender;

        for (uint256 i = 0; i < tokenIds.length; i++) {
            // Verify ownership and transferability
            address holder = _getCredentialHolder(tokenIds[i]);
            if (holder != from) {
                revert Errors.NotHolder(from, holder);
            }

            // Execute the transfer via ClaimToken
            // This requires the caller to have approved this contract
            claimToken.safeTransferFrom(from, to, tokenIds[i]);
        }

        emit BatchTransferred(tokenIds, from, to);
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function batchSetInheritance(
        uint256[] calldata tokenIds,
        CredentialTypes.InheritanceDirective[] calldata directives
    ) external override nonReentrant {
        if (tokenIds.length != directives.length) {
            revert Errors.ArrayLengthMismatch(tokenIds.length, directives.length);
        }
        if (tokenIds.length == 0) {
            revert Errors.EmptyArray();
        }

        for (uint256 i = 0; i < tokenIds.length; i++) {
            // Verify ownership
            address holder = _getCredentialHolder(tokenIds[i]);
            if (msg.sender != holder) {
                revert Errors.NotHolder(msg.sender, holder);
            }

            // Validate and store directive
            CredentialTypes.InheritanceDirective calldata directive = directives[i];

            if (directive.beneficiaries.length == 0) {
                revert Errors.EmptyArray();
            }

            for (uint256 j = 0; j < directive.beneficiaries.length; j++) {
                if (directive.beneficiaries[j] == address(0)) {
                    revert Errors.BeneficiaryInvalid(address(0));
                }
            }

            _inheritanceDirectives[tokenIds[i]] = directive;
            _inheritanceDirectives[tokenIds[i]].credentialId = tokenIds[i];
            _credentialsWithInheritance[holder].add(tokenIds[i]);

            emit InheritanceDirectiveSet(tokenIds[i], directive.beneficiaries);
        }
    }

    // ============================================
    // Query Functions
    // ============================================

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function getPendingRenewals() external view override returns (uint256[] memory tokenIds) {
        uint256 count = _pendingRenewals.length();
        tokenIds = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            tokenIds[i] = _pendingRenewals.at(i);
        }
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function getCredentialsWithInheritance(
        address holder
    ) external view override returns (uint256[] memory tokenIds) {
        uint256 count = _credentialsWithInheritance[holder].length();
        tokenIds = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            tokenIds[i] = _credentialsWithInheritance[holder].at(i);
        }
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function isSplittable(bytes32 claimType) external view override returns (bool splittable) {
        return _splittableTypes[claimType];
    }

    // ============================================
    // Administrative Functions
    // ============================================

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function setClaimToken(address _claimToken) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_claimToken == address(0)) {
            revert Errors.ZeroAddress();
        }
        claimToken = IClaimToken(_claimToken);
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function setIssuerRegistry(address _issuerRegistry) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_issuerRegistry == address(0)) {
            revert Errors.ZeroAddress();
        }
        issuerRegistry = IIssuerRegistry(_issuerRegistry);
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function setFIEBridge(address _fieBridge) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_fieBridge != address(0)) {
            _grantRole(FIE_BRIDGE_ROLE, _fieBridge);
        }
        if (fieBridge != address(0)) {
            _revokeRole(FIE_BRIDGE_ROLE, fieBridge);
        }
        fieBridge = _fieBridge;
    }

    /**
     * @inheritdoc ICredentialLifecycleManager
     */
    function setSplittable(
        bytes32 claimType,
        bool splittable
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        _splittableTypes[claimType] = splittable;
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @dev Get the current holder of a credential
     */
    function _getCredentialHolder(uint256 tokenId) internal view returns (address) {
        // ClaimToken is ERC721, so we can cast and call ownerOf
        // This assumes ClaimToken exposes ownerOf via IERC721
        return address(claimToken) != address(0)
            ? _ownerOfToken(tokenId)
            : address(0);
    }

    /**
     * @dev External call to get token owner (ERC721 ownerOf)
     */
    function _ownerOfToken(uint256 tokenId) internal view returns (address) {
        // Static call to ClaimToken's ownerOf function
        (bool success, bytes memory data) = address(claimToken).staticcall(
            abi.encodeWithSignature("ownerOf(uint256)", tokenId)
        );
        if (!success || data.length < 32) {
            revert Errors.CredentialNotFound(tokenId);
        }
        return abi.decode(data, (address));
    }

    /**
     * @dev Validate credential is eligible for renewal
     */
    function _validateRenewalEligibility(CredentialTypes.Credential memory cred) internal view {
        CredentialTypes.CredentialStatus status = CredentialTypes.CredentialStatus(cred.status);

        // Can only renew ACTIVE or EXPIRED credentials
        if (status != CredentialTypes.CredentialStatus.ACTIVE &&
            status != CredentialTypes.CredentialStatus.EXPIRED) {
            revert Errors.InvalidCredentialStatus(cred.tokenId, cred.status);
        }

        // If expired, must be within grace period
        if (status == CredentialTypes.CredentialStatus.EXPIRED ||
            (cred.expiresAt != 0 && block.timestamp > cred.expiresAt)) {
            _validateWithinGracePeriod(cred.expiresAt);
        }
    }

    /**
     * @dev Validate credential is within renewal grace period
     */
    function _validateWithinGracePeriod(uint64 expiresAt) internal view {
        if (expiresAt == 0) {
            // Never expires, no grace period needed
            return;
        }

        uint64 gracePeriodEnd = expiresAt + CredentialTypes.RENEWAL_GRACE_PERIOD;
        if (block.timestamp > gracePeriodEnd) {
            revert Errors.GracePeriodExpired(0, expiresAt, gracePeriodEnd);
        }
    }

    /**
     * @dev Verify renewal approval signature
     */
    function _verifyRenewalSignature(
        uint256 tokenId,
        uint64 newExpiry,
        address expectedIssuer,
        bytes32 claimType,
        bytes calldata signature
    ) internal {
        // Create message hash
        bytes32 messageHash = keccak256(
            abi.encode(
                "RENEWAL_APPROVAL",
                tokenId,
                newExpiry,
                block.chainid,
                address(this)
            )
        );

        // Check for replay
        bytes32 sigHash = keccak256(signature);
        if (_usedSignatures[sigHash]) {
            revert Errors.ProofReplayed(sigHash);
        }
        _usedSignatures[sigHash] = true;

        // Recover signer
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedHash.recover(signature);

        // Verify signer is authorized for the issuer and claim type
        (bool authorized, address principal) = issuerRegistry.isAuthorizedSigner(signer, claimType);
        if (!authorized || (principal != expectedIssuer && signer != expectedIssuer)) {
            revert Errors.InvalidSignature();
        }
    }

    /**
     * @dev Verify FIE proof for inheritance execution
     */
    function _verifyFIEProof(bytes32 intentHash, bytes calldata fieProof) internal view {
        // Decode and verify FIE proof
        // For now, we check that proof contains the expected intent hash
        if (fieProof.length < 32) {
            revert Errors.FIETriggerInvalid(intentHash);
        }

        bytes32 proofIntentHash = abi.decode(fieProof, (bytes32));
        if (proofIntentHash != intentHash) {
            revert Errors.FIETriggerInvalid(intentHash);
        }
    }

    /**
     * @dev Execute split inheritance for credentials with shares
     */
    function _executeSplitInheritance(
        uint256 tokenId,
        CredentialTypes.InheritanceDirective memory directive
    ) internal {
        // Get original credential data
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);

        // Burn the original credential
        claimToken.burn(tokenId);

        // Mint new credentials for each beneficiary
        uint256[] memory newTokenIds = new uint256[](directive.beneficiaries.length);
        uint8 totalSplits = uint8(directive.beneficiaries.length);

        for (uint256 i = 0; i < directive.beneficiaries.length; i++) {
            newTokenIds[i] = claimToken.mintSplit(
                cred,
                directive.beneficiaries[i],
                directive.shares[i],
                uint8(i),
                totalSplits
            );
        }

        emit CredentialSplit(
            tokenId,
            newTokenIds,
            directive.beneficiaries,
            directive.shares
        );

        // Emit individual inheritance events
        for (uint256 i = 0; i < directive.beneficiaries.length; i++) {
            emit InheritanceExecuted(tokenId, directive.beneficiaries[i]);
        }
    }

    /**
     * @dev Validate an inheritance condition
     */
    function _validateCondition(
        CredentialTypes.InheritanceCondition calldata condition
    ) internal pure {
        // Validate condition type
        if (condition.conditionType == CredentialTypes.CONDITION_AGE_THRESHOLD) {
            // Params should encode: uint8 minAge
            if (condition.params.length < 1) {
                revert Errors.InvalidConditionParams(condition.conditionType);
            }
        } else if (condition.conditionType == CredentialTypes.CONDITION_DATE_AFTER) {
            // Params should encode: uint64 timestamp
            if (condition.params.length < 8) {
                revert Errors.InvalidConditionParams(condition.conditionType);
            }
        } else if (condition.conditionType == CredentialTypes.CONDITION_CUSTOM) {
            // Custom conditions require an oracle
            if (condition.oracleAddress == address(0)) {
                revert Errors.InvalidConditionParams(condition.conditionType);
            }
        } else {
            revert Errors.InvalidConditionParams(condition.conditionType);
        }
    }

    /**
     * @dev Evaluate a single inheritance condition
     */
    function _evaluateCondition(
        CredentialTypes.InheritanceCondition storage condition,
        address beneficiary
    ) internal view returns (bool) {
        if (condition.conditionType == CredentialTypes.CONDITION_AGE_THRESHOLD) {
            // For age threshold, we would need beneficiary's age from an oracle
            // For now, we check if there's an oracle to query
            if (condition.oracleAddress != address(0)) {
                // Try to call oracle - simplified for this implementation
                (bool success, bytes memory result) = condition.oracleAddress.staticcall(
                    abi.encodeWithSignature("verifyAge(address,uint8)", beneficiary, abi.decode(condition.params, (uint8)))
                );
                if (success && result.length >= 32) {
                    return abi.decode(result, (bool));
                }
            }
            // If no oracle or call failed, condition cannot be evaluated
            return false;
        } else if (condition.conditionType == CredentialTypes.CONDITION_DATE_AFTER) {
            // Decode the target timestamp
            uint64 targetDate = abi.decode(condition.params, (uint64));
            return block.timestamp >= targetDate;
        } else if (condition.conditionType == CredentialTypes.CONDITION_CUSTOM) {
            // Custom conditions must call the oracle
            if (condition.oracleAddress == address(0)) {
                return false;
            }
            (bool success, bytes memory result) = condition.oracleAddress.staticcall(
                abi.encodeWithSignature("evaluate(address)", beneficiary)
            );
            if (success && result.length >= 32) {
                return abi.decode(result, (bool));
            }
            return false;
        }

        return false;
    }

    // ============================================
    // Required Overrides
    // ============================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
