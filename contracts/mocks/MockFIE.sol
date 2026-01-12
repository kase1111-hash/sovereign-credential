// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {IFIEBridge} from "../interfaces/IFIEBridge.sol";

/**
 * @title MockFIE
 * @notice Mock Finite Intent Executor for testing FIE Bridge integration
 * @dev Simulates death triggers and inheritance execution
 */
contract MockFIE {
    // ============================================
    // State
    // ============================================

    /// @notice The FIEBridge contract to notify
    IFIEBridge public fieBridge;

    /// @notice Mapping of intent hash to trigger status
    mapping(bytes32 => bool) public triggeredIntents;

    /// @notice Mapping of intent hash to subject address
    mapping(bytes32 => address) public intentSubjects;

    /// @notice Counter for generating unique intent hashes
    uint256 private _intentCounter;

    // ============================================
    // Events
    // ============================================

    event IntentCreated(bytes32 indexed intentHash, address indexed subject);
    event DeathTriggerFired(bytes32 indexed intentHash, address indexed subject);
    event InheritanceRequested(bytes32 indexed intentHash, uint256 indexed tokenId);

    // ============================================
    // Constructor
    // ============================================

    constructor() {}

    // ============================================
    // Configuration
    // ============================================

    /**
     * @notice Set the FIEBridge contract address
     * @param _fieBridge Address of the FIEBridge
     */
    function setFIEBridge(address _fieBridge) external {
        fieBridge = IFIEBridge(_fieBridge);
    }

    // ============================================
    // Intent Management
    // ============================================

    /**
     * @notice Create a new intent for a subject
     * @param subject The subject address (person who may die)
     * @return intentHash The unique intent hash
     */
    function createIntent(address subject) external returns (bytes32 intentHash) {
        _intentCounter++;
        intentHash = keccak256(
            abi.encodePacked(subject, _intentCounter, block.timestamp)
        );
        intentSubjects[intentHash] = subject;
        emit IntentCreated(intentHash, subject);
    }

    /**
     * @notice Create a deterministic intent hash for testing
     * @param subject The subject address
     * @param salt Additional entropy
     * @return intentHash The intent hash
     */
    function createDeterministicIntent(
        address subject,
        bytes32 salt
    ) external returns (bytes32 intentHash) {
        intentHash = keccak256(abi.encodePacked(subject, salt));
        intentSubjects[intentHash] = subject;
        emit IntentCreated(intentHash, subject);
    }

    // ============================================
    // Trigger Simulation
    // ============================================

    /**
     * @notice Simulate a death trigger (called by test)
     * @param intentHash The intent to trigger
     */
    function simulateDeathTrigger(bytes32 intentHash) external {
        address subject = intentSubjects[intentHash];
        require(subject != address(0), "Intent not found");
        require(!triggeredIntents[intentHash], "Already triggered");

        triggeredIntents[intentHash] = true;
        emit DeathTriggerFired(intentHash, subject);

        // Notify the bridge
        if (address(fieBridge) != address(0)) {
            fieBridge.notifyTrigger(intentHash, subject);
        }
    }

    /**
     * @notice Simulate death trigger and execute specific credential inheritance
     * @param intentHash The intent hash
     * @param tokenId The credential to inherit
     */
    function simulateDeathTriggerWithCredential(
        bytes32 intentHash,
        uint256 tokenId
    ) external {
        address subject = intentSubjects[intentHash];
        require(subject != address(0), "Intent not found");
        require(!triggeredIntents[intentHash], "Already triggered");

        triggeredIntents[intentHash] = true;
        emit DeathTriggerFired(intentHash, subject);
        emit InheritanceRequested(intentHash, tokenId);

        // Execute inheritance directly
        if (address(fieBridge) != address(0)) {
            fieBridge.executeCredentialInheritance(tokenId, intentHash);
        }
    }

    /**
     * @notice Batch trigger multiple credentials
     * @param intentHash The intent hash
     * @param tokenIds Array of credentials to inherit
     */
    function simulateBatchInheritance(
        bytes32 intentHash,
        uint256[] calldata tokenIds
    ) external {
        address subject = intentSubjects[intentHash];
        require(subject != address(0), "Intent not found");
        require(!triggeredIntents[intentHash], "Already triggered");

        triggeredIntents[intentHash] = true;
        emit DeathTriggerFired(intentHash, subject);

        if (address(fieBridge) != address(0)) {
            fieBridge.batchExecuteInheritance(tokenIds, intentHash);
        }
    }

    // ============================================
    // Proof Generation (Mock)
    // ============================================

    /**
     * @notice Generate a mock FIE proof for testing
     * @param intentHash The intent hash
     * @return proof Mock proof bytes
     */
    function generateMockProof(bytes32 intentHash) external view returns (bytes memory proof) {
        require(triggeredIntents[intentHash], "Intent not triggered");

        // Mock proof format: intentHash + subject + timestamp + signature placeholder
        address subject = intentSubjects[intentHash];
        proof = abi.encode(intentHash, subject, block.timestamp, bytes32(0));
    }

    /**
     * @notice Verify a mock proof (always returns true for valid format)
     * @param proof The proof to verify
     * @return valid True if proof format is valid
     */
    function verifyMockProof(bytes calldata proof) external pure returns (bool valid) {
        // Just check it can be decoded
        if (proof.length >= 128) {
            (bytes32 intentHash, address subject, , ) = abi.decode(
                proof,
                (bytes32, address, uint256, bytes32)
            );
            return intentHash != bytes32(0) && subject != address(0);
        }
        return false;
    }

    // ============================================
    // Query Functions
    // ============================================

    /**
     * @notice Check if an intent has been triggered
     * @param intentHash The intent to check
     * @return triggered True if triggered
     */
    function isTriggered(bytes32 intentHash) external view returns (bool triggered) {
        return triggeredIntents[intentHash];
    }

    /**
     * @notice Get the subject for an intent
     * @param intentHash The intent to query
     * @return subject The subject address
     */
    function getSubject(bytes32 intentHash) external view returns (address subject) {
        return intentSubjects[intentHash];
    }

    // ============================================
    // Test Helpers
    // ============================================

    /**
     * @notice Reset a trigger for re-testing
     * @param intentHash The intent to reset
     */
    function resetTrigger(bytes32 intentHash) external {
        triggeredIntents[intentHash] = false;
    }

    /**
     * @notice Delete an intent entirely
     * @param intentHash The intent to delete
     */
    function deleteIntent(bytes32 intentHash) external {
        delete intentSubjects[intentHash];
        delete triggeredIntents[intentHash];
    }
}
