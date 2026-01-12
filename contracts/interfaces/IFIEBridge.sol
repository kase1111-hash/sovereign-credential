// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

/**
 * @title IFIEBridge
 * @notice Interface for bridging to the Finite Intent Executor (FIE) system
 * @dev Implements functionality defined in SPEC.md Section 4.5 and 8
 */
interface IFIEBridge {
    // ============================================
    // Events (Spec 4.5)
    // ============================================

    /// @notice Emitted when a death trigger is received from FIE
    event FIETriggerReceived(
        bytes32 indexed intentHash,
        address indexed subject
    );

    /// @notice Emitted when credential inheritance is executed via FIE
    event CredentialInheritanceExecuted(
        uint256 indexed tokenId,
        bytes32 indexed intentHash,
        address indexed beneficiary
    );

    /// @notice Emitted when the FIE execution agent is updated
    event FIEAgentUpdated(address indexed newAgent);

    /// @notice Emitted when a trigger is marked as processed
    event TriggerProcessed(bytes32 indexed intentHash);

    // ============================================
    // FIE Agent Management
    // ============================================

    /**
     * @notice Set the authorized FIE execution agent contract
     * @param agent Address of the FIE contract/agent
     */
    function setFIEExecutionAgent(address agent) external;

    /**
     * @notice Get the current FIE execution agent address
     * @return agent Address of the FIE agent
     */
    function getFIEExecutionAgent() external view returns (address agent);

    // ============================================
    // Trigger Handling
    // ============================================

    /**
     * @notice Receive notification of a death trigger from FIE
     * @param intentHash Hash of the FIE intent that triggered
     * @param subject Address of the deceased subject
     * @dev Only callable by the FIE execution agent
     */
    function notifyTrigger(
        bytes32 intentHash,
        address subject
    ) external;

    /**
     * @notice Execute credential inheritance based on FIE trigger
     * @param tokenId The credential to transfer
     * @param intentHash Hash of the triggering FIE intent
     * @dev Only callable by the FIE execution agent
     */
    function executeCredentialInheritance(
        uint256 tokenId,
        bytes32 intentHash
    ) external;

    /**
     * @notice Execute batch credential inheritance
     * @param tokenIds Array of credentials to transfer
     * @param intentHash Hash of the triggering FIE intent
     */
    function batchExecuteInheritance(
        uint256[] calldata tokenIds,
        bytes32 intentHash
    ) external;

    // ============================================
    // Verification Functions
    // ============================================

    /**
     * @notice Verify a FIE execution proof
     * @param proof The proof bytes from FIE
     * @return valid True if proof is valid
     */
    function verifyFIEProof(bytes calldata proof) external view returns (bool valid);

    /**
     * @notice Check if a trigger has already been processed
     * @param intentHash The FIE intent hash to check
     * @return processed True if trigger has been processed
     */
    function isTriggerProcessed(
        bytes32 intentHash
    ) external view returns (bool processed);

    // ============================================
    // Query Functions
    // ============================================

    /**
     * @notice Get all credentials with FIE-linked inheritance for a subject
     * @param subject The subject address
     * @return tokenIds Array of credential token IDs
     */
    function getCredentialsWithFIEInheritance(
        address subject
    ) external view returns (uint256[] memory tokenIds);

    /**
     * @notice Get the intent hash linked to a credential's inheritance
     * @param tokenId The credential to query
     * @return intentHash The linked FIE intent hash
     */
    function getLinkedIntentHash(
        uint256 tokenId
    ) external view returns (bytes32 intentHash);

    // ============================================
    // Administrative Functions
    // ============================================

    /**
     * @notice Set the CredentialLifecycleManager contract address
     * @param lifecycleManager Address of the LifecycleManager
     */
    function setLifecycleManager(address lifecycleManager) external;

    /**
     * @notice Get the CredentialLifecycleManager contract address
     * @return lifecycleManager Address of the LifecycleManager
     */
    function getLifecycleManager() external view returns (address lifecycleManager);

    /**
     * @notice Emergency pause for FIE integration
     * @param paused True to pause, false to unpause
     */
    function setPaused(bool paused) external;

    /**
     * @notice Check if FIE integration is paused
     * @return paused True if paused
     */
    function isPaused() external view returns (bool paused);
}
