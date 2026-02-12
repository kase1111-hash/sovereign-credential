// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IInheritanceManager} from "./interfaces/IInheritanceManager.sol";
import {IClaimToken} from "./interfaces/IClaimToken.sol";
import {CredentialTypes} from "./libraries/CredentialTypes.sol";
import {ClaimTypes} from "./libraries/ClaimTypes.sol";
import {Errors} from "./libraries/Errors.sol";

/**
 * @title InheritanceManager
 * @notice Manages credential inheritance, splitting, executor access, and disputes
 * @dev Optional module extracted from CredentialLifecycleManager.
 *      Depends on FIE (Finite Intent Executor) for death trigger notifications.
 *      Can be deployed independently of the core credential system.
 *
 * Features:
 * - Inheritance directive management with beneficiary designations
 * - Credential splitting for partial inheritance
 * - Executor access control with time-bounded permissions
 * - Inheritance conditions and dispute handling
 */
contract InheritanceManager is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    IInheritanceManager
{
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

    /// @notice Address of the FIE Bridge contract
    address public fieBridge;

    /// @notice Mapping of token ID to inheritance directive
    mapping(uint256 => CredentialTypes.InheritanceDirective) private _inheritanceDirectives;

    /// @notice Mapping of holder to token IDs with inheritance directives
    mapping(address => EnumerableSet.UintSet) private _credentialsWithInheritance;

    /// @notice Mapping of claim type to whether it's splittable
    mapping(bytes32 => bool) private _splittableTypes;

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
    // Constructor & Initializer
    // ============================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the contract
     * @param _claimToken Address of the ClaimToken contract
     */
    function initialize(address _claimToken) public initializer {
        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        if (_claimToken == address(0)) {
            revert Errors.ZeroAddress();
        }

        claimToken = IClaimToken(_claimToken);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);

        // Initialize default splittable types (property-related)
        _splittableTypes[ClaimTypes.PROPERTY_DEED] = true;
        _splittableTypes[ClaimTypes.PROPERTY_TITLE] = true;
        _splittableTypes[ClaimTypes.PROPERTY_LIEN] = true;
    }

    // ============================================
    // Inheritance Directive Functions
    // ============================================

    /// @inheritdoc IInheritanceManager
    function setInheritanceDirective(
        uint256 tokenId,
        CredentialTypes.InheritanceDirective calldata directive
    ) external override nonReentrant {
        address holder = _getCredentialHolder(tokenId);
        if (msg.sender != holder) {
            revert Errors.NotHolder(msg.sender, holder);
        }

        if (directive.beneficiaries.length == 0) {
            revert Errors.EmptyArray();
        }

        for (uint256 i = 0; i < directive.beneficiaries.length; i++) {
            if (directive.beneficiaries[i] == address(0)) {
                revert Errors.BeneficiaryInvalid(address(0));
            }
        }

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

        _inheritanceDirectives[tokenId] = directive;
        _inheritanceDirectives[tokenId].credentialId = tokenId;
        _credentialsWithInheritance[holder].add(tokenId);

        emit InheritanceDirectiveSet(tokenId, directive.beneficiaries);
    }

    /// @inheritdoc IInheritanceManager
    function removeInheritanceDirective(uint256 tokenId) external override {
        address holder = _getCredentialHolder(tokenId);
        if (msg.sender != holder) {
            revert Errors.NotHolder(msg.sender, holder);
        }

        if (_inheritanceDirectives[tokenId].beneficiaries.length == 0) {
            revert Errors.InheritanceNotSet(tokenId);
        }

        _credentialsWithInheritance[holder].remove(tokenId);
        delete _inheritanceDirectives[tokenId];

        emit InheritanceDirectiveRemoved(tokenId);
    }

    /// @inheritdoc IInheritanceManager
    function getInheritanceDirective(
        uint256 tokenId
    ) external view override returns (CredentialTypes.InheritanceDirective memory directive) {
        return _inheritanceDirectives[tokenId];
    }

    /// @inheritdoc IInheritanceManager
    function hasInheritanceDirective(
        uint256 tokenId
    ) external view override returns (bool hasDirective) {
        return _inheritanceDirectives[tokenId].beneficiaries.length > 0;
    }

    // ============================================
    // Inheritance Execution Functions
    // ============================================

    /// @inheritdoc IInheritanceManager
    function executeInheritance(
        uint256 tokenId,
        bytes calldata fieProof
    ) external override nonReentrant onlyRole(FIE_BRIDGE_ROLE) {
        CredentialTypes.InheritanceDirective memory directive = _inheritanceDirectives[tokenId];

        if (directive.beneficiaries.length == 0) {
            revert Errors.InheritanceNotSet(tokenId);
        }

        if (directive.requiresFIETrigger) {
            _verifyFIEProof(directive.fieIntentHash, fieProof);
        }

        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        address currentHolder = _getCredentialHolder(tokenId);

        if (directive.shares.length > 0 && _splittableTypes[cred.claimType]) {
            _executeSplitInheritance(tokenId, directive);
        } else {
            address beneficiary = directive.beneficiaries[0];
            claimToken.markInherited(tokenId);
            emit InheritanceExecuted(tokenId, beneficiary);
        }

        _credentialsWithInheritance[currentHolder].remove(tokenId);
        delete _inheritanceDirectives[tokenId];
    }

    /// @inheritdoc IInheritanceManager
    function splitCredential(
        uint256 tokenId,
        address[] calldata beneficiaries,
        uint8[] calldata shares
    ) external override nonReentrant returns (uint256[] memory newTokenIds) {
        if (!hasRole(FIE_BRIDGE_ROLE, msg.sender) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert Errors.OperationNotAllowed();
        }

        if (_activeDisputes[tokenId] != 0) {
            revert Errors.InheritanceFrozen(tokenId, _activeDisputes[tokenId]);
        }

        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);

        if (!_splittableTypes[cred.claimType]) {
            revert Errors.NotSplittable(cred.claimType);
        }

        if (claimToken.isSplitCredential(tokenId)) {
            revert Errors.CannotSplitCredential(tokenId, "Already split");
        }

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

        claimToken.burn(tokenId);

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

    /// @inheritdoc IInheritanceManager
    function setInheritanceConditions(
        uint256 tokenId,
        CredentialTypes.InheritanceCondition[] calldata conditions
    ) external nonReentrant {
        address holder = _getCredentialHolder(tokenId);
        if (msg.sender != holder) {
            revert Errors.NotHolder(msg.sender, holder);
        }

        for (uint256 i = 0; i < conditions.length; i++) {
            _validateCondition(conditions[i]);
        }

        delete _inheritanceConditions[tokenId];

        for (uint256 i = 0; i < conditions.length; i++) {
            _inheritanceConditions[tokenId].push(conditions[i]);
        }

        emit InheritanceConditionsSet(tokenId, conditions.length);
    }

    /// @inheritdoc IInheritanceManager
    function getInheritanceConditions(
        uint256 tokenId
    ) external view returns (CredentialTypes.InheritanceCondition[] memory conditions) {
        return _inheritanceConditions[tokenId];
    }

    /// @inheritdoc IInheritanceManager
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
    // Executor Access Functions
    // ============================================

    /// @inheritdoc IInheritanceManager
    function grantExecutorAccess(
        uint256 tokenId,
        address executor,
        uint64 duration,
        uint8 permissions
    ) external nonReentrant {
        if (!hasRole(FIE_BRIDGE_ROLE, msg.sender) && !hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert Errors.OperationNotAllowed();
        }

        if (executor == address(0)) {
            revert Errors.ZeroAddress();
        }

        if (_executorAccess[tokenId].executor != address(0) &&
            _executorAccess[tokenId].expiresAt > block.timestamp) {
            revert Errors.ExecutorAccessAlreadyGranted(executor, tokenId);
        }

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

    /// @inheritdoc IInheritanceManager
    function revokeExecutorAccess(uint256 tokenId) external {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert Errors.OperationNotAllowed();
        }

        address executor = _executorAccess[tokenId].executor;
        delete _executorAccess[tokenId];

        emit ExecutorAccessRevoked(tokenId, executor);
    }

    /// @inheritdoc IInheritanceManager
    function getExecutorAccess(
        uint256 tokenId
    ) external view returns (CredentialTypes.ExecutorAccess memory access) {
        return _executorAccess[tokenId];
    }

    /// @inheritdoc IInheritanceManager
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

    /// @inheritdoc IInheritanceManager
    function fileDispute(
        uint256 tokenId,
        bytes calldata reason
    ) external nonReentrant returns (uint256 disputeId) {
        uint64 triggerTime = _triggerTimestamps[tokenId];
        if (triggerTime != 0) {
            uint64 windowEnd = triggerTime + CredentialTypes.DISPUTE_FILING_WINDOW;
            if (block.timestamp > windowEnd) {
                revert Errors.DisputeWindowExpired(tokenId, windowEnd);
            }
        }

        if (_activeDisputes[tokenId] != 0) {
            revert Errors.DisputeAlreadyFiled(tokenId);
        }

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

    /// @inheritdoc IInheritanceManager
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
        _activeDisputes[dispute.tokenId] = 0;

        emit DisputeResolved(disputeId, resolution);
    }

    /// @inheritdoc IInheritanceManager
    function getDispute(
        uint256 disputeId
    ) external view returns (CredentialTypes.InheritanceDispute memory dispute) {
        return _disputes[disputeId];
    }

    /// @inheritdoc IInheritanceManager
    function hasActiveDispute(
        uint256 tokenId
    ) external view returns (bool hasDispute, uint256 disputeId) {
        disputeId = _activeDisputes[tokenId];
        return (disputeId != 0, disputeId);
    }

    /// @inheritdoc IInheritanceManager
    function recordTrigger(uint256 tokenId) external onlyRole(FIE_BRIDGE_ROLE) {
        _triggerTimestamps[tokenId] = uint64(block.timestamp);
    }

    // ============================================
    // Batch & Query Functions
    // ============================================

    /// @inheritdoc IInheritanceManager
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
            address holder = _getCredentialHolder(tokenIds[i]);
            if (msg.sender != holder) {
                revert Errors.NotHolder(msg.sender, holder);
            }

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

    /// @inheritdoc IInheritanceManager
    function getCredentialsWithInheritance(
        address holder
    ) external view override returns (uint256[] memory tokenIds) {
        uint256 count = _credentialsWithInheritance[holder].length();
        tokenIds = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            tokenIds[i] = _credentialsWithInheritance[holder].at(i);
        }
    }

    /// @inheritdoc IInheritanceManager
    function isSplittable(bytes32 claimType) external view override returns (bool splittable) {
        return _splittableTypes[claimType];
    }

    // ============================================
    // Administrative Functions
    // ============================================

    /// @inheritdoc IInheritanceManager
    function setClaimToken(address _claimToken) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_claimToken == address(0)) {
            revert Errors.ZeroAddress();
        }
        claimToken = IClaimToken(_claimToken);
    }

    /// @inheritdoc IInheritanceManager
    function setFIEBridge(address _fieBridge) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_fieBridge != address(0)) {
            _grantRole(FIE_BRIDGE_ROLE, _fieBridge);
        }
        if (fieBridge != address(0)) {
            _revokeRole(FIE_BRIDGE_ROLE, fieBridge);
        }
        fieBridge = _fieBridge;
    }

    /// @inheritdoc IInheritanceManager
    function setSplittable(
        bytes32 claimType,
        bool splittable
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        _splittableTypes[claimType] = splittable;
    }

    // ============================================
    // Internal Functions
    // ============================================

    function _getCredentialHolder(uint256 tokenId) internal view returns (address) {
        return address(claimToken) != address(0)
            ? _ownerOfToken(tokenId)
            : address(0);
    }

    function _ownerOfToken(uint256 tokenId) internal view returns (address) {
        (bool success, bytes memory data) = address(claimToken).staticcall(
            abi.encodeWithSignature("ownerOf(uint256)", tokenId)
        );
        if (!success || data.length < 32) {
            revert Errors.CredentialNotFound(tokenId);
        }
        return abi.decode(data, (address));
    }

    function _verifyFIEProof(bytes32 intentHash, bytes calldata fieProof) internal pure {
        if (fieProof.length < 32) {
            revert Errors.FIETriggerInvalid(intentHash);
        }

        bytes32 proofIntentHash = abi.decode(fieProof, (bytes32));
        if (proofIntentHash != intentHash) {
            revert Errors.FIETriggerInvalid(intentHash);
        }
    }

    function _executeSplitInheritance(
        uint256 tokenId,
        CredentialTypes.InheritanceDirective memory directive
    ) internal {
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);

        claimToken.burn(tokenId);

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

        for (uint256 i = 0; i < directive.beneficiaries.length; i++) {
            emit InheritanceExecuted(tokenId, directive.beneficiaries[i]);
        }
    }

    function _validateCondition(
        CredentialTypes.InheritanceCondition calldata condition
    ) internal pure {
        if (condition.conditionType == CredentialTypes.CONDITION_AGE_THRESHOLD) {
            if (condition.params.length < 1) {
                revert Errors.InvalidConditionParams(condition.conditionType);
            }
        } else if (condition.conditionType == CredentialTypes.CONDITION_DATE_AFTER) {
            if (condition.params.length < 8) {
                revert Errors.InvalidConditionParams(condition.conditionType);
            }
        } else if (condition.conditionType == CredentialTypes.CONDITION_CUSTOM) {
            if (condition.oracleAddress == address(0)) {
                revert Errors.InvalidConditionParams(condition.conditionType);
            }
        } else {
            revert Errors.InvalidConditionParams(condition.conditionType);
        }
    }

    function _evaluateCondition(
        CredentialTypes.InheritanceCondition storage condition,
        address beneficiary
    ) internal view returns (bool) {
        if (condition.conditionType == CredentialTypes.CONDITION_AGE_THRESHOLD) {
            if (condition.oracleAddress != address(0)) {
                (bool success, bytes memory result) = condition.oracleAddress.staticcall(
                    abi.encodeWithSignature("verifyAge(address,uint8)", beneficiary, abi.decode(condition.params, (uint8)))
                );
                if (success && result.length >= 32) {
                    return abi.decode(result, (bool));
                }
            }
            return false;
        } else if (condition.conditionType == CredentialTypes.CONDITION_DATE_AFTER) {
            uint64 targetDate = abi.decode(condition.params, (uint64));
            return block.timestamp >= targetDate;
        } else if (condition.conditionType == CredentialTypes.CONDITION_CUSTOM) {
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
