// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {CredentialTypes} from "../libraries/CredentialTypes.sol";

/**
 * @title IZKDisclosureEngine
 * @notice Interface for zero-knowledge proof verification engine
 * @dev Implements functionality defined in SPEC.md Section 4.3
 */
interface IZKDisclosureEngine {
    // ============================================
    // Events (Spec 4.3)
    // ============================================

    /// @notice Emitted when a verifier contract is registered
    event VerifierRegistered(
        bytes32 indexed disclosureType,
        address indexed verifier
    );

    /// @notice Emitted when a proof is successfully verified
    event ProofVerified(
        uint256 indexed credentialId,
        bytes32 indexed disclosureType,
        address indexed verifier
    );

    /// @notice Emitted when a proof verification fails
    event ProofRejected(
        uint256 indexed credentialId,
        bytes32 indexed disclosureType,
        string reason
    );

    // ============================================
    // Verifier Management
    // ============================================

    /**
     * @notice Register a ZK verifier contract for a disclosure type
     * @param disclosureType The type of disclosure this verifier handles
     * @param verifier Address of the verifier contract
     */
    function registerVerifier(
        bytes32 disclosureType,
        address verifier
    ) external;

    /**
     * @notice Remove a verifier registration
     * @param disclosureType The disclosure type to remove verifier for
     */
    function removeVerifier(bytes32 disclosureType) external;

    /**
     * @notice Get the verifier address for a disclosure type
     * @param disclosureType The disclosure type to query
     * @return verifier Address of the registered verifier
     */
    function getVerifier(
        bytes32 disclosureType
    ) external view returns (address verifier);

    // ============================================
    // Age Threshold Verification
    // ============================================

    /**
     * @notice Verify an age threshold proof
     * @param tokenId The credential token ID
     * @param threshold The age threshold in years
     * @param greaterThan True if proving age > threshold, false for age < threshold
     * @param proof The ZK proof bytes
     * @return valid True if proof is valid
     */
    function verifyAgeThreshold(
        uint256 tokenId,
        uint256 threshold,
        bool greaterThan,
        bytes calldata proof
    ) external returns (bool valid);

    // ============================================
    // Date Range Verification
    // ============================================

    /**
     * @notice Verify a date range proof
     * @param tokenId The credential token ID
     * @param start Start of valid range (Unix timestamp)
     * @param end End of valid range (Unix timestamp)
     * @param proof The ZK proof bytes
     * @return valid True if proof is valid
     */
    function verifyDateRange(
        uint256 tokenId,
        uint64 start,
        uint64 end,
        bytes calldata proof
    ) external returns (bool valid);

    // ============================================
    // Value Range Verification
    // ============================================

    /**
     * @notice Verify a value range proof
     * @param tokenId The credential token ID
     * @param field The field identifier being checked
     * @param min Minimum acceptable value
     * @param max Maximum acceptable value
     * @param proof The ZK proof bytes
     * @return valid True if proof is valid
     */
    function verifyValueRange(
        uint256 tokenId,
        bytes32 field,
        uint256 min,
        uint256 max,
        bytes calldata proof
    ) external returns (bool valid);

    // ============================================
    // Set Membership Verification
    // ============================================

    /**
     * @notice Verify a set membership proof
     * @param tokenId The credential token ID
     * @param field The field identifier being checked
     * @param setRoot Merkle root of the allowed value set
     * @param proof The ZK proof bytes
     * @return valid True if proof is valid
     */
    function verifySetMembership(
        uint256 tokenId,
        bytes32 field,
        bytes32 setRoot,
        bytes calldata proof
    ) external returns (bool valid);

    // ============================================
    // Existence Verification
    // ============================================

    /**
     * @notice Verify a credential existence proof
     * @param tokenId The credential token ID
     * @param proof The ZK proof bytes
     * @return valid True if proof is valid
     */
    function verifyExistence(
        uint256 tokenId,
        bytes calldata proof
    ) external returns (bool valid);

    // ============================================
    // Compound Proof Verification
    // ============================================

    /**
     * @notice Verify a compound proof with multiple disclosures
     * @param tokenId The credential token ID
     * @param disclosureTypes Array of disclosure types in the proof
     * @param publicInputs Encoded public inputs for all disclosures
     * @param proof The ZK proof bytes
     * @return valid True if proof is valid
     */
    function verifyCompound(
        uint256 tokenId,
        bytes32[] calldata disclosureTypes,
        bytes calldata publicInputs,
        bytes calldata proof
    ) external returns (bool valid);

    // ============================================
    // Generic Proof Verification
    // ============================================

    /**
     * @notice Verify a generic disclosure request
     * @param request The disclosure request struct
     * @return valid True if proof is valid
     */
    function verifyProof(
        CredentialTypes.DisclosureRequest calldata request
    ) external returns (bool valid);

    // ============================================
    // Proof Status
    // ============================================

    /**
     * @notice Check if a proof has been used (for replay prevention)
     * @param proofHash Hash of the proof
     * @return used True if proof has been used
     */
    function isProofUsed(bytes32 proofHash) external view returns (bool used);

    /**
     * @notice Get the ClaimToken contract address
     * @return claimToken Address of the ClaimToken contract
     */
    function getClaimToken() external view returns (address claimToken);

    /**
     * @notice Set the ClaimToken contract address
     * @param claimToken Address of the ClaimToken contract
     */
    function setClaimToken(address claimToken) external;
}
