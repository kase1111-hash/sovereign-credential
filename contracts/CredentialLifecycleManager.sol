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
        _verifyRenewalSignature(tokenId, newExpiry, cred.issuer, signature);

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

        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);

        // Check if splittable
        if (!_splittableTypes[cred.claimType]) {
            revert Errors.NotSplittable(cred.claimType);
        }

        // Validate inputs
        if (beneficiaries.length != shares.length) {
            revert Errors.BeneficiarySharesMismatch(beneficiaries.length, shares.length);
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

        // Note: Actual splitting implementation would require ClaimToken support
        // for burning the original and minting new credentials with share metadata
        // This is a placeholder that emits the event

        newTokenIds = new uint256[](beneficiaries.length);
        // In a full implementation, newTokenIds would be populated with actual minted tokens

        emit CredentialSplit(tokenId, newTokenIds, beneficiaries, shares);

        return newTokenIds;
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

            // Note: Actual transfer would call claimToken.transferFrom
            // This requires the caller to have approved this contract
            // or for this contract to have special transfer rights
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

        // Verify signer is authorized for the issuer
        (bool authorized, address principal) = issuerRegistry.isAuthorizedSigner(signer, bytes32(0));
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
        // This would mint new credentials for each beneficiary with their share
        // The original credential would be burned

        uint256[] memory newTokenIds = new uint256[](directive.beneficiaries.length);

        // In a full implementation:
        // 1. Burn original credential
        // 2. Mint new credentials with share metadata for each beneficiary
        // 3. Track lineage from original to new credentials

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

    // ============================================
    // Required Overrides
    // ============================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
