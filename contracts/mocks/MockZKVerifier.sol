// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

/**
 * @title MockZKVerifier
 * @notice Mock ZK proof verifier for testing
 * @dev Simulates Groth16/PLONK verification without actual cryptography
 */
contract MockZKVerifier {
    // ============================================
    // State
    // ============================================

    /// @notice Whether to accept all proofs (for positive path testing)
    bool public acceptAll;

    /// @notice Mapping of proof hashes to their validity
    mapping(bytes32 => bool) public validProofs;

    /// @notice Mapping of proof hashes to custom responses
    mapping(bytes32 => bool) public proofResponses;
    mapping(bytes32 => bool) public hasCustomResponse;

    /// @notice Counter for verification calls (for testing)
    uint256 public verificationCount;

    // ============================================
    // Events
    // ============================================

    event ProofVerified(bytes32 indexed proofHash, bool result);
    event ProofRegistered(bytes32 indexed proofHash, bool valid);

    // ============================================
    // Constructor
    // ============================================

    constructor() {
        acceptAll = true; // Default to accepting all proofs for testing
    }

    // ============================================
    // Configuration
    // ============================================

    /**
     * @notice Set whether to accept all proofs
     * @param _acceptAll True to accept all proofs
     */
    function setAcceptAll(bool _acceptAll) external {
        acceptAll = _acceptAll;
    }

    /**
     * @notice Register a specific proof as valid or invalid
     * @param proofHash Hash of the proof
     * @param valid Whether the proof is valid
     */
    function registerProof(bytes32 proofHash, bool valid) external {
        validProofs[proofHash] = valid;
        hasCustomResponse[proofHash] = true;
        proofResponses[proofHash] = valid;
        emit ProofRegistered(proofHash, valid);
    }

    /**
     * @notice Register a proof by its raw bytes
     * @param proof The proof bytes
     * @param valid Whether the proof is valid
     */
    function registerProofBytes(bytes calldata proof, bool valid) external {
        bytes32 proofHash = keccak256(proof);
        validProofs[proofHash] = valid;
        hasCustomResponse[proofHash] = true;
        proofResponses[proofHash] = valid;
        emit ProofRegistered(proofHash, valid);
    }

    // ============================================
    // Verification Interface (Groth16 style)
    // ============================================

    /**
     * @notice Verify a Groth16-style proof
     * @param _pA Point A of the proof
     * @param _pB Point B of the proof (2x2 array)
     * @param _pC Point C of the proof
     * @param _pubSignals Public signals/inputs
     * @return valid True if proof is valid
     */
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[] calldata _pubSignals
    ) external returns (bool valid) {
        verificationCount++;

        // Calculate proof hash
        bytes32 proofHash = keccak256(
            abi.encode(_pA, _pB, _pC, _pubSignals)
        );

        // Check if we have a custom response for this proof
        if (hasCustomResponse[proofHash]) {
            valid = proofResponses[proofHash];
        } else {
            valid = acceptAll;
        }

        emit ProofVerified(proofHash, valid);
    }

    /**
     * @notice Verify raw proof bytes
     * @param proof The proof bytes
     * @return valid True if proof is valid
     */
    function verifyProofBytes(bytes calldata proof) external returns (bool valid) {
        verificationCount++;

        bytes32 proofHash = keccak256(proof);

        if (hasCustomResponse[proofHash]) {
            valid = proofResponses[proofHash];
        } else {
            valid = acceptAll;
        }

        emit ProofVerified(proofHash, valid);
    }

    // ============================================
    // Age Threshold Verification (Mock)
    // ============================================

    /**
     * @notice Mock age threshold proof verification
     * @param credentialCommitment The credential commitment
     * @param threshold Age threshold
     * @param comparisonType 0 = greater than, 1 = less than
     * @param currentTimestamp Current time
     * @param proof The proof bytes
     * @return valid True if proof is valid
     */
    function verifyAgeThreshold(
        bytes32 credentialCommitment,
        uint256 threshold,
        uint256 comparisonType,
        uint256 currentTimestamp,
        bytes calldata proof
    ) external returns (bool valid) {
        verificationCount++;

        bytes32 proofHash = keccak256(
            abi.encode(credentialCommitment, threshold, comparisonType, currentTimestamp, proof)
        );

        if (hasCustomResponse[proofHash]) {
            valid = proofResponses[proofHash];
        } else {
            valid = acceptAll;
        }

        emit ProofVerified(proofHash, valid);
    }

    // ============================================
    // Date Range Verification (Mock)
    // ============================================

    /**
     * @notice Mock date range proof verification
     * @param credentialCommitment The credential commitment
     * @param rangeStart Start of range
     * @param rangeEnd End of range
     * @param proof The proof bytes
     * @return valid True if proof is valid
     */
    function verifyDateRange(
        bytes32 credentialCommitment,
        uint256 rangeStart,
        uint256 rangeEnd,
        bytes calldata proof
    ) external returns (bool valid) {
        verificationCount++;

        bytes32 proofHash = keccak256(
            abi.encode(credentialCommitment, rangeStart, rangeEnd, proof)
        );

        if (hasCustomResponse[proofHash]) {
            valid = proofResponses[proofHash];
        } else {
            valid = acceptAll;
        }

        emit ProofVerified(proofHash, valid);
    }

    // ============================================
    // Set Membership Verification (Mock)
    // ============================================

    /**
     * @notice Mock set membership proof verification
     * @param credentialCommitment The credential commitment
     * @param setRoot Merkle root of allowed set
     * @param proof The proof bytes
     * @return valid True if proof is valid
     */
    function verifySetMembership(
        bytes32 credentialCommitment,
        bytes32 setRoot,
        bytes calldata proof
    ) external returns (bool valid) {
        verificationCount++;

        bytes32 proofHash = keccak256(
            abi.encode(credentialCommitment, setRoot, proof)
        );

        if (hasCustomResponse[proofHash]) {
            valid = proofResponses[proofHash];
        } else {
            valid = acceptAll;
        }

        emit ProofVerified(proofHash, valid);
    }

    // ============================================
    // Test Helpers
    // ============================================

    /**
     * @notice Reset verification counter
     */
    function resetCounter() external {
        verificationCount = 0;
    }

    /**
     * @notice Clear all registered proofs
     */
    function clearProofs() external {
        // Note: This doesn't actually clear mappings, just resets behavior
        acceptAll = true;
    }

    /**
     * @notice Get the hash of a proof for registration
     * @param proof The proof bytes
     * @return proofHash The hash
     */
    function getProofHash(bytes calldata proof) external pure returns (bytes32 proofHash) {
        return keccak256(proof);
    }
}
