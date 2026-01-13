// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {IZKDisclosureEngine} from "./interfaces/IZKDisclosureEngine.sol";
import {IClaimToken} from "./interfaces/IClaimToken.sol";
import {CredentialTypes} from "./libraries/CredentialTypes.sol";
import {Errors} from "./libraries/Errors.sol";
import {IAgeThresholdVerifier, IDateRangeVerifier, IValueRangeVerifier} from "./verifiers/IGroth16Verifier.sol";

/**
 * @title ZKDisclosureEngine
 * @notice On-chain engine for managing ZK verifiers and validating proofs
 * @dev Implements functionality defined in SPEC.md Section 4.3
 *
 * This contract serves as the central hub for zero-knowledge proof verification,
 * enabling credential holders to make selective disclosures without revealing
 * the underlying private data.
 *
 * Key features:
 * - Verifier registration for different disclosure types
 * - Proof replay prevention (INV-04)
 * - Credential status validation before proof verification
 * - Support for multiple disclosure types (age, date range, value range, etc.)
 */
contract ZKDisclosureEngine is IZKDisclosureEngine, AccessControl, ReentrancyGuard {
    // ============================================
    // Constants
    // ============================================

    /// @notice Role required to register/remove verifiers
    bytes32 public constant VERIFIER_ADMIN_ROLE = keccak256("VERIFIER_ADMIN_ROLE");

    /// @notice Disclosure type identifier for age threshold proofs
    bytes32 public constant DISCLOSURE_AGE_THRESHOLD = keccak256("AGE_THRESHOLD");

    /// @notice Disclosure type identifier for date range proofs
    bytes32 public constant DISCLOSURE_DATE_RANGE = keccak256("DATE_RANGE");

    /// @notice Disclosure type identifier for value range proofs
    bytes32 public constant DISCLOSURE_VALUE_RANGE = keccak256("VALUE_RANGE");

    /// @notice Disclosure type identifier for set membership proofs
    bytes32 public constant DISCLOSURE_SET_MEMBERSHIP = keccak256("SET_MEMBERSHIP");

    /// @notice Disclosure type identifier for existence proofs
    bytes32 public constant DISCLOSURE_EXISTENCE = keccak256("EXISTENCE");

    /// @notice Disclosure type identifier for compound proofs
    bytes32 public constant DISCLOSURE_COMPOUND = keccak256("COMPOUND");

    // ============================================
    // State Variables
    // ============================================

    /// @notice Mapping from disclosure type to verifier contract address
    mapping(bytes32 => address) public verifiers;

    /// @notice Mapping of proof hashes that have been used (replay prevention)
    mapping(bytes32 => bool) public usedProofs;

    /// @notice Reference to the ClaimToken contract
    IClaimToken public claimToken;

    // ============================================
    // Constructor
    // ============================================

    /**
     * @notice Initialize the ZKDisclosureEngine
     * @param admin Address to receive admin role
     * @param _claimToken Address of the ClaimToken contract
     */
    constructor(address admin, address _claimToken) {
        if (admin == address(0)) revert Errors.ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(VERIFIER_ADMIN_ROLE, admin);

        if (_claimToken != address(0)) {
            claimToken = IClaimToken(_claimToken);
        }
    }

    // ============================================
    // Verifier Management
    // ============================================

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function registerVerifier(
        bytes32 disclosureType,
        address verifier
    ) external override onlyRole(VERIFIER_ADMIN_ROLE) {
        if (verifier == address(0)) revert Errors.ZeroAddress();

        verifiers[disclosureType] = verifier;
        emit VerifierRegistered(disclosureType, verifier);
    }

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function removeVerifier(bytes32 disclosureType) external override onlyRole(VERIFIER_ADMIN_ROLE) {
        if (verifiers[disclosureType] == address(0)) {
            revert Errors.VerifierNotRegistered(disclosureType);
        }

        delete verifiers[disclosureType];
        emit VerifierRegistered(disclosureType, address(0));
    }

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function getVerifier(bytes32 disclosureType) external view override returns (address verifier) {
        return verifiers[disclosureType];
    }

    // ============================================
    // Age Threshold Verification
    // ============================================

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function verifyAgeThreshold(
        uint256 tokenId,
        uint256 threshold,
        bool greaterThan,
        bytes calldata proof
    ) external override nonReentrant returns (bool valid) {
        // 1. Verify credential exists and is active
        _validateCredential(tokenId);

        // 2. Verify verifier is registered
        address verifier = verifiers[DISCLOSURE_AGE_THRESHOLD];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(DISCLOSURE_AGE_THRESHOLD);
        }

        // 3. Calculate proof hash and check for replay
        bytes32 proofHash = keccak256(proof);
        _checkProofReplay(proofHash);

        // 4. Get credential commitment
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        bytes32 commitment = cred.commitments.length > 0 ? cred.commitments[0] : bytes32(0);

        // 5. Decode proof and call verifier
        // Proof format: abi.encode(pA, pB, pC)
        (
            uint256[2] memory pA,
            uint256[2][2] memory pB,
            uint256[2] memory pC
        ) = _decodeGroth16Proof(proof);

        // 6. Build public signals: [credentialCommitment, threshold, currentTimestamp, comparisonType]
        uint256[4] memory pubSignals = [
            uint256(commitment),
            threshold,
            block.timestamp,
            greaterThan ? 0 : 1 // 0 = greater than, 1 = less than
        ];

        // 7. Verify the proof
        valid = IAgeThresholdVerifier(verifier).verifyProof(pA, pB, pC, pubSignals);

        // 8. Mark proof as used if valid
        if (valid) {
            usedProofs[proofHash] = true;
            emit ProofVerified(tokenId, DISCLOSURE_AGE_THRESHOLD, msg.sender);
        } else {
            emit ProofRejected(tokenId, DISCLOSURE_AGE_THRESHOLD, "Proof verification failed");
        }

        return valid;
    }

    // ============================================
    // Date Range Verification
    // ============================================

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function verifyDateRange(
        uint256 tokenId,
        uint64 start,
        uint64 end,
        bytes calldata proof
    ) external override nonReentrant returns (bool valid) {
        // 1. Verify credential exists and is active
        _validateCredential(tokenId);

        // 2. Verify verifier is registered
        address verifier = verifiers[DISCLOSURE_DATE_RANGE];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(DISCLOSURE_DATE_RANGE);
        }

        // 3. Check for proof replay
        bytes32 proofHash = keccak256(proof);
        _checkProofReplay(proofHash);

        // 4. Get credential commitment
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        bytes32 commitment = cred.commitments.length > 0 ? cred.commitments[0] : bytes32(0);

        // 5. Decode proof
        (
            uint256[2] memory pA,
            uint256[2][2] memory pB,
            uint256[2] memory pC
        ) = _decodeGroth16Proof(proof);

        // 6. Build public signals: [credentialCommitment, rangeStart, rangeEnd, fieldIndex]
        // fieldIndex is encoded in the proof but we use a default of 0 here
        uint256[4] memory pubSignals = [
            uint256(commitment),
            uint256(start),
            uint256(end),
            0 // fieldIndex - should be provided in proof or as parameter
        ];

        // 7. Verify the proof
        valid = IDateRangeVerifier(verifier).verifyProof(pA, pB, pC, pubSignals);

        // 8. Handle result
        if (valid) {
            usedProofs[proofHash] = true;
            emit ProofVerified(tokenId, DISCLOSURE_DATE_RANGE, msg.sender);
        } else {
            emit ProofRejected(tokenId, DISCLOSURE_DATE_RANGE, "Proof verification failed");
        }

        return valid;
    }

    // ============================================
    // Value Range Verification
    // ============================================

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function verifyValueRange(
        uint256 tokenId,
        bytes32 field,
        uint256 min,
        uint256 max,
        bytes calldata proof
    ) external override nonReentrant returns (bool valid) {
        // 1. Verify credential exists and is active
        _validateCredential(tokenId);

        // 2. Verify verifier is registered
        address verifier = verifiers[DISCLOSURE_VALUE_RANGE];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(DISCLOSURE_VALUE_RANGE);
        }

        // 3. Check for proof replay
        bytes32 proofHash = keccak256(proof);
        _checkProofReplay(proofHash);

        // 4. Get credential commitment
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        bytes32 commitment = cred.commitments.length > 0 ? cred.commitments[0] : bytes32(0);

        // 5. Decode proof
        (
            uint256[2] memory pA,
            uint256[2][2] memory pB,
            uint256[2] memory pC
        ) = _decodeGroth16Proof(proof);

        // 6. Build public signals: [credentialCommitment, minValue, maxValue, fieldIndex]
        // We convert field hash to a field index (simplified - in practice this would be more complex)
        uint256 fieldIndex = uint256(field) % 16; // Map to 0-15 range
        uint256[4] memory pubSignals = [
            uint256(commitment),
            min,
            max,
            fieldIndex
        ];

        // 7. Verify the proof
        valid = IValueRangeVerifier(verifier).verifyProof(pA, pB, pC, pubSignals);

        // 8. Handle result
        if (valid) {
            usedProofs[proofHash] = true;
            emit ProofVerified(tokenId, DISCLOSURE_VALUE_RANGE, msg.sender);
        } else {
            emit ProofRejected(tokenId, DISCLOSURE_VALUE_RANGE, "Proof verification failed");
        }

        return valid;
    }

    // ============================================
    // Set Membership Verification
    // ============================================

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function verifySetMembership(
        uint256 tokenId,
        bytes32 field,
        bytes32 setRoot,
        bytes calldata proof
    ) external override nonReentrant returns (bool valid) {
        // 1. Verify credential exists and is active
        _validateCredential(tokenId);

        // 2. Verify verifier is registered
        address verifier = verifiers[DISCLOSURE_SET_MEMBERSHIP];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(DISCLOSURE_SET_MEMBERSHIP);
        }

        // 3. Check for proof replay
        bytes32 proofHash = keccak256(proof);
        _checkProofReplay(proofHash);

        // 4. Get credential commitment
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        bytes32 commitment = cred.commitments.length > 0 ? cred.commitments[0] : bytes32(0);

        // 5. Decode proof - Set membership uses a different number of public signals
        (
            uint256[2] memory pA,
            uint256[2][2] memory pB,
            uint256[2] memory pC
        ) = _decodeGroth16Proof(proof);

        // 6. Build public signals array for generic verifier
        uint256[] memory pubSignals = new uint256[](3);
        pubSignals[0] = uint256(commitment);
        pubSignals[1] = uint256(setRoot);
        pubSignals[2] = uint256(field) % 16; // fieldIndex

        // 7. Verify using generic interface (set membership may have variable signals)
        // We use a low-level call since the verifier signature may vary
        bytes memory callData = abi.encodeWithSignature(
            "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[])",
            pA, pB, pC, pubSignals
        );

        (bool success, bytes memory result) = verifier.staticcall(callData);

        if (success && result.length >= 32) {
            valid = abi.decode(result, (bool));
        } else {
            valid = false;
        }

        // 8. Handle result
        if (valid) {
            usedProofs[proofHash] = true;
            emit ProofVerified(tokenId, DISCLOSURE_SET_MEMBERSHIP, msg.sender);
        } else {
            emit ProofRejected(tokenId, DISCLOSURE_SET_MEMBERSHIP, "Proof verification failed");
        }

        return valid;
    }

    // ============================================
    // Existence Verification
    // ============================================

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function verifyExistence(
        uint256 tokenId,
        bytes calldata proof
    ) external override nonReentrant returns (bool valid) {
        // 1. Verify credential exists and is active
        _validateCredential(tokenId);

        // 2. Verify verifier is registered
        address verifier = verifiers[DISCLOSURE_EXISTENCE];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(DISCLOSURE_EXISTENCE);
        }

        // 3. Check for proof replay
        bytes32 proofHash = keccak256(proof);
        _checkProofReplay(proofHash);

        // 4. Get credential commitment
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        bytes32 commitment = cred.commitments.length > 0 ? cred.commitments[0] : bytes32(0);

        // 5. Decode proof
        (
            uint256[2] memory pA,
            uint256[2][2] memory pB,
            uint256[2] memory pC
        ) = _decodeGroth16Proof(proof);

        // 6. Build public signals - just the commitment for existence proof
        uint256[] memory pubSignals = new uint256[](1);
        pubSignals[0] = uint256(commitment);

        // 7. Verify using generic interface
        bytes memory callData = abi.encodeWithSignature(
            "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[])",
            pA, pB, pC, pubSignals
        );

        (bool success, bytes memory result) = verifier.staticcall(callData);

        if (success && result.length >= 32) {
            valid = abi.decode(result, (bool));
        } else {
            valid = false;
        }

        // 8. Handle result
        if (valid) {
            usedProofs[proofHash] = true;
            emit ProofVerified(tokenId, DISCLOSURE_EXISTENCE, msg.sender);
        } else {
            emit ProofRejected(tokenId, DISCLOSURE_EXISTENCE, "Proof verification failed");
        }

        return valid;
    }

    // ============================================
    // Compound Proof Verification
    // ============================================

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function verifyCompound(
        uint256 tokenId,
        bytes32[] calldata disclosureTypes,
        bytes calldata publicInputs,
        bytes calldata proof
    ) external override nonReentrant returns (bool valid) {
        // 1. Validate inputs
        if (disclosureTypes.length == 0) revert Errors.EmptyArray();

        // 2. Verify credential exists and is active
        _validateCredential(tokenId);

        // 3. Verify compound verifier is registered
        address verifier = verifiers[DISCLOSURE_COMPOUND];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(DISCLOSURE_COMPOUND);
        }

        // 4. Check for proof replay
        bytes32 proofHash = keccak256(proof);
        _checkProofReplay(proofHash);

        // 5. Get credential commitment
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        bytes32 commitment = cred.commitments.length > 0 ? cred.commitments[0] : bytes32(0);

        // 6. Decode proof
        (
            uint256[2] memory pA,
            uint256[2][2] memory pB,
            uint256[2] memory pC
        ) = _decodeGroth16Proof(proof);

        // 7. Build public signals from commitment and provided inputs
        // Decode public inputs (format depends on implementation)
        uint256[] memory decodedInputs;
        if (publicInputs.length > 0) {
            decodedInputs = abi.decode(publicInputs, (uint256[]));
        } else {
            decodedInputs = new uint256[](0);
        }

        // Prepend commitment to public signals
        uint256[] memory pubSignals = new uint256[](1 + decodedInputs.length);
        pubSignals[0] = uint256(commitment);
        for (uint256 i = 0; i < decodedInputs.length; i++) {
            pubSignals[i + 1] = decodedInputs[i];
        }

        // 8. Verify using generic interface
        bytes memory callData = abi.encodeWithSignature(
            "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[])",
            pA, pB, pC, pubSignals
        );

        (bool success, bytes memory result) = verifier.staticcall(callData);

        if (success && result.length >= 32) {
            valid = abi.decode(result, (bool));
        } else {
            valid = false;
        }

        // 9. Handle result
        if (valid) {
            usedProofs[proofHash] = true;
            emit ProofVerified(tokenId, DISCLOSURE_COMPOUND, msg.sender);
        } else {
            emit ProofRejected(tokenId, DISCLOSURE_COMPOUND, "Proof verification failed");
        }

        return valid;
    }

    // ============================================
    // Generic Proof Verification
    // ============================================

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function verifyProof(
        CredentialTypes.DisclosureRequest calldata request
    ) external override nonReentrant returns (bool valid) {
        // 1. Validate request
        if (request.verifier != address(0) && request.verifier != msg.sender) {
            revert Errors.WrongVerifier(request.verifier, msg.sender);
        }

        // 2. Check proof expiration
        if (request.validUntil > 0 && block.timestamp > request.validUntil) {
            revert Errors.ProofExpired(request.validUntil, uint64(block.timestamp));
        }

        // 3. Verify credential exists and is active
        _validateCredential(request.credentialId);

        // 4. Get verifier for disclosure type
        address verifier = verifiers[request.disclosureType];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(request.disclosureType);
        }

        // 5. Check for proof replay
        bytes32 proofHash = keccak256(request.proof);
        _checkProofReplay(proofHash);

        // 6. Get credential commitment
        CredentialTypes.Credential memory cred = claimToken.getCredential(request.credentialId);
        bytes32 commitment = cred.commitments.length > 0 ? cred.commitments[0] : bytes32(0);

        // 7. Decode proof
        (
            uint256[2] memory pA,
            uint256[2][2] memory pB,
            uint256[2] memory pC
        ) = _decodeGroth16Proof(request.proof);

        // 8. Build minimal public signals with commitment
        uint256[] memory pubSignals = new uint256[](1);
        pubSignals[0] = uint256(commitment);

        // 9. Verify using generic interface
        bytes memory callData = abi.encodeWithSignature(
            "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[])",
            pA, pB, pC, pubSignals
        );

        (bool success, bytes memory result) = verifier.staticcall(callData);

        if (success && result.length >= 32) {
            valid = abi.decode(result, (bool));
        } else {
            valid = false;
        }

        // 10. Handle result
        if (valid) {
            usedProofs[proofHash] = true;
            emit ProofVerified(request.credentialId, request.disclosureType, msg.sender);
        } else {
            emit ProofRejected(request.credentialId, request.disclosureType, "Proof verification failed");
        }

        return valid;
    }

    // ============================================
    // Proof Status
    // ============================================

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function isProofUsed(bytes32 proofHash) external view override returns (bool used) {
        return usedProofs[proofHash];
    }

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function getClaimToken() external view override returns (address) {
        return address(claimToken);
    }

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function setClaimToken(address _claimToken) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_claimToken == address(0)) revert Errors.ZeroAddress();
        claimToken = IClaimToken(_claimToken);
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @notice Validate that a credential exists and is valid for disclosure
     * @param tokenId The credential token ID
     */
    function _validateCredential(uint256 tokenId) internal view {
        // Check credential exists and is valid
        if (!claimToken.verify(tokenId)) {
            // Get status for more specific error
            CredentialTypes.CredentialStatus status = claimToken.getStatus(tokenId);

            if (status == CredentialTypes.CredentialStatus.REVOKED) {
                revert Errors.CredentialRevoked(tokenId);
            } else if (status == CredentialTypes.CredentialStatus.EXPIRED) {
                revert Errors.CredentialExpired(tokenId);
            } else if (status == CredentialTypes.CredentialStatus.SUSPENDED) {
                revert Errors.CredentialSuspended(tokenId);
            } else {
                revert Errors.InvalidCredentialStatus(tokenId, uint8(status));
            }
        }
    }

    /**
     * @notice Check if a proof has been used and revert if so
     * @param proofHash Hash of the proof
     */
    function _checkProofReplay(bytes32 proofHash) internal view {
        if (usedProofs[proofHash]) {
            revert Errors.ProofReplayed(proofHash);
        }
    }

    /**
     * @notice Decode a Groth16 proof from bytes
     * @param proof Encoded proof bytes (abi.encode(pA, pB, pC))
     * @return pA First G1 point
     * @return pB G2 point
     * @return pC Second G1 point
     */
    function _decodeGroth16Proof(bytes calldata proof)
        internal
        pure
        returns (
            uint256[2] memory pA,
            uint256[2][2] memory pB,
            uint256[2] memory pC
        )
    {
        // Proof should be encoded as abi.encode(pA, pB, pC)
        // pA: 2 * 32 = 64 bytes
        // pB: 2 * 2 * 32 = 128 bytes
        // pC: 2 * 32 = 64 bytes
        // Total: 256 bytes minimum

        if (proof.length < 256) {
            // For testing with mock verifiers, we may have shorter proofs
            // Return zeros which will fail verification with real verifiers
            return (pA, pB, pC);
        }

        (pA, pB, pC) = abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));
    }

    // ============================================
    // View Helpers
    // ============================================

    /**
     * @notice Get the disclosure type constant for age threshold
     * @return The bytes32 disclosure type identifier
     */
    function getAgeThresholdType() external pure returns (bytes32) {
        return DISCLOSURE_AGE_THRESHOLD;
    }

    /**
     * @notice Get the disclosure type constant for date range
     * @return The bytes32 disclosure type identifier
     */
    function getDateRangeType() external pure returns (bytes32) {
        return DISCLOSURE_DATE_RANGE;
    }

    /**
     * @notice Get the disclosure type constant for value range
     * @return The bytes32 disclosure type identifier
     */
    function getValueRangeType() external pure returns (bytes32) {
        return DISCLOSURE_VALUE_RANGE;
    }

    /**
     * @notice Get the disclosure type constant for set membership
     * @return The bytes32 disclosure type identifier
     */
    function getSetMembershipType() external pure returns (bytes32) {
        return DISCLOSURE_SET_MEMBERSHIP;
    }

    /**
     * @notice Get the disclosure type constant for existence
     * @return The bytes32 disclosure type identifier
     */
    function getExistenceType() external pure returns (bytes32) {
        return DISCLOSURE_EXISTENCE;
    }

    /**
     * @notice Get the disclosure type constant for compound proofs
     * @return The bytes32 disclosure type identifier
     */
    function getCompoundType() external pure returns (bytes32) {
        return DISCLOSURE_COMPOUND;
    }
}
