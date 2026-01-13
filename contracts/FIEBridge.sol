// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {IFIEBridge} from "./interfaces/IFIEBridge.sol";
import {ICredentialLifecycleManager} from "./interfaces/ICredentialLifecycleManager.sol";
import {CredentialTypes} from "./libraries/CredentialTypes.sol";
import {Errors} from "./libraries/Errors.sol";

/**
 * @title FIEBridge
 * @notice Bridge connecting Sovereign Credential to Finite Intent Executor (FIE)
 * @dev Implements SPEC.md Section 4.5 and 8 (FIE Bridge Protocol)
 *
 * The FIE Bridge handles:
 * - Death trigger notifications from FIE
 * - Credential inheritance execution
 * - Double-execution prevention via processed trigger tracking
 * - FIE proof verification
 */
contract FIEBridge is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    IFIEBridge
{
    // ============================================
    // Roles
    // ============================================

    /// @notice Role for upgrading the contract
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // ============================================
    // Storage
    // ============================================

    /// @notice Reference to the CredentialLifecycleManager contract
    ICredentialLifecycleManager public lifecycleManager;

    /// @notice Authorized FIE execution agent address
    address public fieExecutionAgent;

    /// @notice Mapping of intent hash to processed status (prevents double execution)
    mapping(bytes32 => bool) public processedTriggers;

    /// @notice Mapping of token ID to linked FIE intent hash
    mapping(uint256 => bytes32) private _linkedIntentHashes;

    /// @notice Mapping of subject to their FIE-linked credentials
    mapping(address => uint256[]) private _subjectCredentials;

    // ============================================
    // Constructor & Initializer
    // ============================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the contract
     * @param _lifecycleManager Address of the CredentialLifecycleManager contract
     */
    function initialize(address _lifecycleManager) public initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        if (_lifecycleManager == address(0)) {
            revert Errors.ZeroAddress();
        }

        lifecycleManager = ICredentialLifecycleManager(_lifecycleManager);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);
    }

    // ============================================
    // Modifiers
    // ============================================

    /**
     * @dev Ensures caller is the authorized FIE execution agent
     */
    modifier onlyFIE() {
        if (msg.sender != fieExecutionAgent) {
            revert Errors.NotFIEAgent(msg.sender);
        }
        _;
    }

    // ============================================
    // FIE Agent Management
    // ============================================

    /**
     * @inheritdoc IFIEBridge
     */
    function setFIEExecutionAgent(address agent) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (agent == address(0)) {
            revert Errors.ZeroAddress();
        }
        fieExecutionAgent = agent;
        emit FIEAgentUpdated(agent);
    }

    /**
     * @inheritdoc IFIEBridge
     */
    function getFIEExecutionAgent() external view override returns (address agent) {
        return fieExecutionAgent;
    }

    // ============================================
    // Trigger Handling
    // ============================================

    /**
     * @inheritdoc IFIEBridge
     */
    function notifyTrigger(
        bytes32 intentHash,
        address subject
    ) external override onlyFIE whenNotPaused nonReentrant {
        // Validate inputs
        if (intentHash == bytes32(0)) {
            revert Errors.FIETriggerInvalid(intentHash);
        }
        if (subject == address(0)) {
            revert Errors.ZeroAddress();
        }

        // Check not already processed
        if (processedTriggers[intentHash]) {
            revert Errors.InheritanceAlreadyExecuted(intentHash);
        }

        emit FIETriggerReceived(intentHash, subject);

        // Query credentials with inheritance directives for this subject
        // and auto-execute if they match the intent hash
        uint256[] memory credentialIds = _subjectCredentials[subject];

        for (uint256 i = 0; i < credentialIds.length; i++) {
            uint256 tokenId = credentialIds[i];
            bytes32 linkedHash = _linkedIntentHashes[tokenId];

            if (linkedHash == intentHash) {
                _executeInheritanceInternal(tokenId, intentHash);
            }
        }
    }

    /**
     * @inheritdoc IFIEBridge
     */
    function executeCredentialInheritance(
        uint256 tokenId,
        bytes32 intentHash
    ) external override onlyFIE whenNotPaused nonReentrant {
        _executeInheritanceInternal(tokenId, intentHash);
    }

    /**
     * @inheritdoc IFIEBridge
     */
    function batchExecuteInheritance(
        uint256[] calldata tokenIds,
        bytes32 intentHash
    ) external override onlyFIE whenNotPaused nonReentrant {
        if (tokenIds.length == 0) {
            revert Errors.EmptyArray();
        }

        // Validate intent hash
        if (intentHash == bytes32(0)) {
            revert Errors.FIETriggerInvalid(intentHash);
        }

        // Check not already processed
        if (processedTriggers[intentHash]) {
            revert Errors.InheritanceAlreadyExecuted(intentHash);
        }

        // Execute inheritance for each token
        for (uint256 i = 0; i < tokenIds.length; i++) {
            _executeInheritanceForBatch(tokenIds[i], intentHash);
        }

        // Mark trigger as processed after all executions
        processedTriggers[intentHash] = true;
        emit TriggerProcessed(intentHash);
    }

    // ============================================
    // Verification Functions
    // ============================================

    /**
     * @inheritdoc IFIEBridge
     */
    function verifyFIEProof(bytes calldata proof) external view override returns (bool valid) {
        // Validate proof format
        if (proof.length < 96) {
            return false;
        }

        // Decode proof components
        // Expected format: intentHash (32) + subject (32) + timestamp (32) + signature (variable)
        (bytes32 intentHash, address subject, uint256 timestamp) = abi.decode(
            proof[:96],
            (bytes32, address, uint256)
        );

        // Verify intent hash is not zero
        if (intentHash == bytes32(0)) {
            return false;
        }

        // Verify subject is not zero
        if (subject == address(0)) {
            return false;
        }

        // Verify timestamp is reasonable (not in future, not too old)
        if (timestamp > block.timestamp) {
            return false;
        }
        // Allow proofs up to 1 day old
        if (block.timestamp - timestamp > 1 days) {
            return false;
        }

        return true;
    }

    /**
     * @inheritdoc IFIEBridge
     */
    function isTriggerProcessed(bytes32 intentHash) external view override returns (bool processed) {
        return processedTriggers[intentHash];
    }

    // ============================================
    // Query Functions
    // ============================================

    /**
     * @inheritdoc IFIEBridge
     */
    function getCredentialsWithFIEInheritance(
        address subject
    ) external view override returns (uint256[] memory tokenIds) {
        return _subjectCredentials[subject];
    }

    /**
     * @inheritdoc IFIEBridge
     */
    function getLinkedIntentHash(uint256 tokenId) external view override returns (bytes32 intentHash) {
        return _linkedIntentHashes[tokenId];
    }

    // ============================================
    // Registration Functions
    // ============================================

    /**
     * @notice Register a credential with FIE-linked inheritance
     * @param tokenId The credential token ID
     * @param subject The subject (owner) address
     * @param intentHash The FIE intent hash to link
     * @dev Called when inheritance directive is set with FIE trigger requirement
     */
    function registerCredentialForFIE(
        uint256 tokenId,
        address subject,
        bytes32 intentHash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (subject == address(0)) {
            revert Errors.ZeroAddress();
        }
        if (intentHash == bytes32(0)) {
            revert Errors.FIETriggerInvalid(intentHash);
        }

        _linkedIntentHashes[tokenId] = intentHash;
        _subjectCredentials[subject].push(tokenId);
    }

    /**
     * @notice Unregister a credential from FIE inheritance tracking
     * @param tokenId The credential token ID
     * @param subject The subject (owner) address
     */
    function unregisterCredentialForFIE(
        uint256 tokenId,
        address subject
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        delete _linkedIntentHashes[tokenId];

        // Remove from subject's credentials array
        uint256[] storage credentials = _subjectCredentials[subject];
        for (uint256 i = 0; i < credentials.length; i++) {
            if (credentials[i] == tokenId) {
                credentials[i] = credentials[credentials.length - 1];
                credentials.pop();
                break;
            }
        }
    }

    // ============================================
    // Administrative Functions
    // ============================================

    /**
     * @inheritdoc IFIEBridge
     */
    function setLifecycleManager(address _lifecycleManager) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_lifecycleManager == address(0)) {
            revert Errors.ZeroAddress();
        }
        lifecycleManager = ICredentialLifecycleManager(_lifecycleManager);
    }

    /**
     * @inheritdoc IFIEBridge
     */
    function getLifecycleManager() external view override returns (address) {
        return address(lifecycleManager);
    }

    /**
     * @inheritdoc IFIEBridge
     */
    function setPaused(bool paused) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (paused) {
            _pause();
        } else {
            _unpause();
        }
    }

    /**
     * @inheritdoc IFIEBridge
     */
    function isPaused() external view override returns (bool) {
        return paused();
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @dev Internal function to execute inheritance for a single credential
     * @param tokenId The credential to transfer
     * @param intentHash The FIE intent hash
     */
    function _executeInheritanceInternal(uint256 tokenId, bytes32 intentHash) internal {
        // Validate intent hash
        if (intentHash == bytes32(0)) {
            revert Errors.FIETriggerInvalid(intentHash);
        }

        // Check not already processed
        if (processedTriggers[intentHash]) {
            revert Errors.InheritanceAlreadyExecuted(intentHash);
        }

        // Get inheritance directive from lifecycle manager
        CredentialTypes.InheritanceDirective memory directive = lifecycleManager.getInheritanceDirective(tokenId);

        // Verify directive exists and requires FIE trigger
        if (directive.beneficiaries.length == 0) {
            revert Errors.InheritanceNotSet(tokenId);
        }
        if (!directive.requiresFIETrigger) {
            revert Errors.OperationNotAllowed();
        }

        // Verify intent hash matches
        if (directive.fieIntentHash != intentHash) {
            revert Errors.FIETriggerInvalid(intentHash);
        }

        // Execute inheritance via lifecycle manager
        // Encode the intent hash as the FIE proof
        bytes memory fieProof = abi.encode(intentHash);
        lifecycleManager.executeInheritance(tokenId, fieProof);

        // Mark as processed
        processedTriggers[intentHash] = true;
        emit TriggerProcessed(intentHash);

        // Emit inheritance executed event
        emit CredentialInheritanceExecuted(tokenId, intentHash, directive.beneficiaries[0]);
    }

    /**
     * @dev Internal function for batch execution (doesn't mark processed, caller does)
     * @param tokenId The credential to transfer
     * @param intentHash The FIE intent hash
     */
    function _executeInheritanceForBatch(uint256 tokenId, bytes32 intentHash) internal {
        // Get inheritance directive from lifecycle manager
        CredentialTypes.InheritanceDirective memory directive = lifecycleManager.getInheritanceDirective(tokenId);

        // Verify directive exists and requires FIE trigger
        if (directive.beneficiaries.length == 0) {
            revert Errors.InheritanceNotSet(tokenId);
        }
        if (!directive.requiresFIETrigger) {
            revert Errors.OperationNotAllowed();
        }

        // Verify intent hash matches
        if (directive.fieIntentHash != intentHash) {
            revert Errors.FIETriggerInvalid(intentHash);
        }

        // Execute inheritance via lifecycle manager
        bytes memory fieProof = abi.encode(intentHash);
        lifecycleManager.executeInheritance(tokenId, fieProof);

        // Emit inheritance executed event
        emit CredentialInheritanceExecuted(tokenId, intentHash, directive.beneficiaries[0]);
    }

    // ============================================
    // Required Overrides
    // ============================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
