// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {IZKDisclosureEngine} from "./interfaces/IZKDisclosureEngine.sol";
import {IClaimToken} from "./interfaces/IClaimToken.sol";
import {CredentialTypes} from "./libraries/CredentialTypes.sol";
import {Errors} from "./libraries/Errors.sol";

import {
    IGroth16Verifier,
    IAgeThresholdVerifier,
    IDateRangeVerifier,
    IValueRangeVerifier,
    ICompoundProofVerifier,
    ICompoundProof3Verifier,
    ICompoundProof4Verifier
} from "./verifiers/IGroth16Verifier.sol";

/**
 * @title ZKDisclosureEngine
 * @notice On-chain engine for verifying zero-knowledge disclosure proofs
 * @dev Implements SPEC.md Section 4.3
 *
 * Features:
 * - Verifier registration for each disclosure type
 * - Age threshold, date range, value range, set membership verification
 * - Compound proof verification (multiple disclosures in one proof)
 * - Proof replay prevention
 * - Integration with ClaimToken for credential validation
 */
contract ZKDisclosureEngine is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    IZKDisclosureEngine
{
    // ============================================
    // Constants
    // ============================================

    /// @notice Role for upgrading the contract
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice Disclosure type identifiers
    bytes32 public constant DISCLOSURE_AGE_THRESHOLD = keccak256("AGE_THRESHOLD");
    bytes32 public constant DISCLOSURE_DATE_RANGE = keccak256("DATE_RANGE");
    bytes32 public constant DISCLOSURE_VALUE_RANGE = keccak256("VALUE_RANGE");
    bytes32 public constant DISCLOSURE_SET_MEMBERSHIP = keccak256("SET_MEMBERSHIP");
    bytes32 public constant DISCLOSURE_EXISTENCE = keccak256("EXISTENCE");
    bytes32 public constant DISCLOSURE_COMPOUND = keccak256("COMPOUND");
    bytes32 public constant DISCLOSURE_COMPOUND_3 = keccak256("COMPOUND_3");
    bytes32 public constant DISCLOSURE_COMPOUND_4 = keccak256("COMPOUND_4");

    // ============================================
    // Storage
    // ============================================

    /// @notice Mapping of disclosure type to verifier contract address
    mapping(bytes32 => address) public verifiers;

    /// @notice Mapping of proof hash to used status (replay prevention)
    /// @dev Private to prevent enumeration of used proofs - use isProofUsed() for queries
    mapping(bytes32 => bool) private __usedProofs;

    /// @notice Reference to the ClaimToken contract
    IClaimToken public claimToken;

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
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (verifier == address(0)) {
            revert Errors.ZeroAddress();
        }

        verifiers[disclosureType] = verifier;
        emit VerifierRegistered(disclosureType, verifier);
    }

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function removeVerifier(
        bytes32 disclosureType
    ) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        delete verifiers[disclosureType];
        emit VerifierRegistered(disclosureType, address(0));
    }

    /**
     * @inheritdoc IZKDisclosureEngine
     */
    function getVerifier(
        bytes32 disclosureType
    ) external view override returns (address verifier) {
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
        // 1. Verify credential exists and is valid
        if (!claimToken.verify(tokenId)) {
            emit ProofRejected(tokenId, DISCLOSURE_AGE_THRESHOLD, "Credential not valid");
            return false;
        }

        // 2. Check replay prevention
        bytes32 proofHash = keccak256(proof);
        if (_usedProofs[proofHash]) {
            revert Errors.ProofReplayed(proofHash);
        }

        // 3. Get verifier
        address verifier = verifiers[DISCLOSURE_AGE_THRESHOLD];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(DISCLOSURE_AGE_THRESHOLD);
        }

        // 4. Get credential commitment
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        if (cred.commitments.length == 0) {
            emit ProofRejected(tokenId, DISCLOSURE_AGE_THRESHOLD, "No commitment");
            return false;
        }

        // 5. Decode and verify proof
        (
            uint[2] memory pA,
            uint[2][2] memory pB,
            uint[2] memory pC,
            uint[4] memory pubSignals
        ) = _decodeAgeProof(proof);

        // Verify public signals match expected values
        // pubSignals[0] = commitment, pubSignals[1] = threshold,
        // pubSignals[2] = currentTimestamp, pubSignals[3] = comparisonType
        if (pubSignals[0] != uint256(cred.commitments[0])) {
            emit ProofRejected(tokenId, DISCLOSURE_AGE_THRESHOLD, "Commitment mismatch");
            return false;
        }
        if (pubSignals[1] != threshold) {
            emit ProofRejected(tokenId, DISCLOSURE_AGE_THRESHOLD, "Threshold mismatch");
            return false;
        }
        // comparisonType: 0 = greaterThan, 1 = lessThan
        if (pubSignals[3] != (greaterThan ? 0 : 1)) {
            emit ProofRejected(tokenId, DISCLOSURE_AGE_THRESHOLD, "ComparisonType mismatch");
            return false;
        }

        // Validate timestamp is within acceptable range (5 minutes tolerance)
        // This prevents proofs with manipulated timestamps
        uint256 proofTimestamp = pubSignals[2];
        if (proofTimestamp > block.timestamp + 300) {
            emit ProofRejected(tokenId, DISCLOSURE_AGE_THRESHOLD, "Timestamp in future");
            return false;
        }
        if (proofTimestamp < block.timestamp - 300) {
            emit ProofRejected(tokenId, DISCLOSURE_AGE_THRESHOLD, "Timestamp too old");
            return false;
        }

        // 6. Call verifier
        valid = IAgeThresholdVerifier(verifier).verifyProof(pA, pB, pC, pubSignals);

        // 7. Mark proof as used if valid
        if (valid) {
            _usedProofs[proofHash] = true;
            emit ProofVerified(tokenId, DISCLOSURE_AGE_THRESHOLD, msg.sender);
        } else {
            emit ProofRejected(tokenId, DISCLOSURE_AGE_THRESHOLD, "Proof invalid");
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
        // 1. Verify credential exists and is valid
        if (!claimToken.verify(tokenId)) {
            emit ProofRejected(tokenId, DISCLOSURE_DATE_RANGE, "Credential not valid");
            return false;
        }

        // 2. Check replay prevention
        bytes32 proofHash = keccak256(proof);
        if (_usedProofs[proofHash]) {
            revert Errors.ProofReplayed(proofHash);
        }

        // 3. Get verifier
        address verifier = verifiers[DISCLOSURE_DATE_RANGE];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(DISCLOSURE_DATE_RANGE);
        }

        // 4. Get credential commitment
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        if (cred.commitments.length == 0) {
            emit ProofRejected(tokenId, DISCLOSURE_DATE_RANGE, "No commitment");
            return false;
        }

        // 5. Decode and verify proof
        (
            uint[2] memory pA,
            uint[2][2] memory pB,
            uint[2] memory pC,
            uint[4] memory pubSignals
        ) = _decodeDateRangeProof(proof);

        // Verify public signals
        if (pubSignals[0] != uint256(cred.commitments[0])) {
            emit ProofRejected(tokenId, DISCLOSURE_DATE_RANGE, "Commitment mismatch");
            return false;
        }
        if (pubSignals[1] != uint256(start)) {
            emit ProofRejected(tokenId, DISCLOSURE_DATE_RANGE, "RangeStart mismatch");
            return false;
        }
        if (pubSignals[2] != uint256(end)) {
            emit ProofRejected(tokenId, DISCLOSURE_DATE_RANGE, "RangeEnd mismatch");
            return false;
        }

        // 6. Call verifier
        valid = IDateRangeVerifier(verifier).verifyProof(pA, pB, pC, pubSignals);

        // 7. Mark proof as used if valid
        if (valid) {
            _usedProofs[proofHash] = true;
            emit ProofVerified(tokenId, DISCLOSURE_DATE_RANGE, msg.sender);
        } else {
            emit ProofRejected(tokenId, DISCLOSURE_DATE_RANGE, "Proof invalid");
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
        // 1. Verify credential exists and is valid
        if (!claimToken.verify(tokenId)) {
            emit ProofRejected(tokenId, DISCLOSURE_VALUE_RANGE, "Credential not valid");
            return false;
        }

        // 2. Check replay prevention
        bytes32 proofHash = keccak256(proof);
        if (_usedProofs[proofHash]) {
            revert Errors.ProofReplayed(proofHash);
        }

        // 3. Get verifier
        address verifier = verifiers[DISCLOSURE_VALUE_RANGE];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(DISCLOSURE_VALUE_RANGE);
        }

        // 4. Get credential commitment
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        if (cred.commitments.length == 0) {
            emit ProofRejected(tokenId, DISCLOSURE_VALUE_RANGE, "No commitment");
            return false;
        }

        // 5. Decode and verify proof
        (
            uint[2] memory pA,
            uint[2][2] memory pB,
            uint[2] memory pC,
            uint[4] memory pubSignals
        ) = _decodeValueRangeProof(proof);

        // Verify public signals
        if (pubSignals[0] != uint256(cred.commitments[0])) {
            emit ProofRejected(tokenId, DISCLOSURE_VALUE_RANGE, "Commitment mismatch");
            return false;
        }
        if (pubSignals[1] != min) {
            emit ProofRejected(tokenId, DISCLOSURE_VALUE_RANGE, "Min mismatch");
            return false;
        }
        if (pubSignals[2] != max) {
            emit ProofRejected(tokenId, DISCLOSURE_VALUE_RANGE, "Max mismatch");
            return false;
        }

        // 6. Call verifier
        valid = IValueRangeVerifier(verifier).verifyProof(pA, pB, pC, pubSignals);

        // 7. Mark proof as used if valid
        if (valid) {
            _usedProofs[proofHash] = true;
            emit ProofVerified(tokenId, DISCLOSURE_VALUE_RANGE, msg.sender);
        } else {
            emit ProofRejected(tokenId, DISCLOSURE_VALUE_RANGE, "Proof invalid");
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
        // 1. Verify credential exists and is valid
        if (!claimToken.verify(tokenId)) {
            emit ProofRejected(tokenId, DISCLOSURE_SET_MEMBERSHIP, "Credential not valid");
            return false;
        }

        // 2. Check replay prevention
        bytes32 proofHash = keccak256(proof);
        if (_usedProofs[proofHash]) {
            revert Errors.ProofReplayed(proofHash);
        }

        // 3. Get verifier
        address verifier = verifiers[DISCLOSURE_SET_MEMBERSHIP];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(DISCLOSURE_SET_MEMBERSHIP);
        }

        // 4. Get credential commitment
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        if (cred.commitments.length == 0) {
            emit ProofRejected(tokenId, DISCLOSURE_SET_MEMBERSHIP, "No commitment");
            return false;
        }

        // 5. Decode proof (generic format for set membership)
        (
            uint[2] memory pA,
            uint[2][2] memory pB,
            uint[2] memory pC,
            uint[] memory pubSignals
        ) = _decodeGenericProof(proof);

        // Verify commitment matches
        if (pubSignals[0] != uint256(cred.commitments[0])) {
            emit ProofRejected(tokenId, DISCLOSURE_SET_MEMBERSHIP, "Commitment mismatch");
            return false;
        }
        // Verify set root matches
        if (pubSignals[1] != uint256(setRoot)) {
            emit ProofRejected(tokenId, DISCLOSURE_SET_MEMBERSHIP, "SetRoot mismatch");
            return false;
        }

        // 6. Call verifier
        valid = IGroth16Verifier(verifier).verifyProof(pA, pB, pC, pubSignals);

        // 7. Mark proof as used if valid
        if (valid) {
            _usedProofs[proofHash] = true;
            emit ProofVerified(tokenId, DISCLOSURE_SET_MEMBERSHIP, msg.sender);
        } else {
            emit ProofRejected(tokenId, DISCLOSURE_SET_MEMBERSHIP, "Proof invalid");
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
        // 1. Verify credential exists and is valid
        if (!claimToken.verify(tokenId)) {
            emit ProofRejected(tokenId, DISCLOSURE_EXISTENCE, "Credential not valid");
            return false;
        }

        // 2. Check replay prevention
        bytes32 proofHash = keccak256(proof);
        if (_usedProofs[proofHash]) {
            revert Errors.ProofReplayed(proofHash);
        }

        // 3. Get verifier
        address verifier = verifiers[DISCLOSURE_EXISTENCE];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(DISCLOSURE_EXISTENCE);
        }

        // 4. Get credential commitment
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        if (cred.commitments.length == 0) {
            emit ProofRejected(tokenId, DISCLOSURE_EXISTENCE, "No commitment");
            return false;
        }

        // 5. Decode proof
        (
            uint[2] memory pA,
            uint[2][2] memory pB,
            uint[2] memory pC,
            uint[] memory pubSignals
        ) = _decodeGenericProof(proof);

        // Verify commitment matches
        if (pubSignals[0] != uint256(cred.commitments[0])) {
            emit ProofRejected(tokenId, DISCLOSURE_EXISTENCE, "Commitment mismatch");
            return false;
        }

        // 6. Call verifier
        valid = IGroth16Verifier(verifier).verifyProof(pA, pB, pC, pubSignals);

        // 7. Mark proof as used if valid
        if (valid) {
            _usedProofs[proofHash] = true;
            emit ProofVerified(tokenId, DISCLOSURE_EXISTENCE, msg.sender);
        } else {
            emit ProofRejected(tokenId, DISCLOSURE_EXISTENCE, "Proof invalid");
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
        // 1. Verify credential exists and is valid
        if (!claimToken.verify(tokenId)) {
            emit ProofRejected(tokenId, DISCLOSURE_COMPOUND, "Credential not valid");
            return false;
        }

        // 2. Check replay prevention
        bytes32 proofHash = keccak256(proof);
        if (_usedProofs[proofHash]) {
            revert Errors.ProofReplayed(proofHash);
        }

        // 3. Determine which verifier to use based on number of disclosures
        bytes32 verifierType;
        if (disclosureTypes.length == 2) {
            verifierType = DISCLOSURE_COMPOUND;
        } else if (disclosureTypes.length == 3) {
            verifierType = DISCLOSURE_COMPOUND_3;
        } else if (disclosureTypes.length == 4) {
            verifierType = DISCLOSURE_COMPOUND_4;
        } else {
            revert Errors.InvalidDisclosureCount(disclosureTypes.length);
        }

        address verifier = verifiers[verifierType];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(verifierType);
        }

        // 4. Get credential commitment
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);
        if (cred.commitments.length == 0) {
            emit ProofRejected(tokenId, verifierType, "No commitment");
            return false;
        }

        // 5. Decode proof and public inputs
        (
            uint[2] memory pA,
            uint[2][2] memory pB,
            uint[2] memory pC
        ) = _decodeProofPoints(proof);

        // 6. Verify based on disclosure count
        if (disclosureTypes.length == 2) {
            valid = _verifyCompound2(
                verifier,
                cred.commitments[0],
                disclosureTypes,
                publicInputs,
                pA,
                pB,
                pC
            );
        } else if (disclosureTypes.length == 3) {
            valid = _verifyCompound3(
                verifier,
                cred.commitments[0],
                disclosureTypes,
                publicInputs,
                pA,
                pB,
                pC
            );
        } else {
            valid = _verifyCompound4(
                verifier,
                cred.commitments[0],
                disclosureTypes,
                publicInputs,
                pA,
                pB,
                pC
            );
        }

        // 7. Mark proof as used if valid
        if (valid) {
            _usedProofs[proofHash] = true;
            emit ProofVerified(tokenId, verifierType, msg.sender);
        } else {
            emit ProofRejected(tokenId, verifierType, "Proof invalid");
        }

        return valid;
    }

    /**
     * @dev Verify compound proof with 2 disclosures
     */
    function _verifyCompound2(
        address verifier,
        bytes32 commitment,
        bytes32[] calldata disclosureTypes,
        bytes calldata publicInputs,
        uint[2] memory pA,
        uint[2][2] memory pB,
        uint[2] memory pC
    ) internal view returns (bool) {
        // Decode public inputs: types[2] + params[2][4] = 10 values
        // Total public signals: 1 (commitment) + 2 (types) + 8 (params) = 11
        uint[11] memory pubSignals;

        pubSignals[0] = uint256(commitment);

        // Decode types
        (uint256 type0, uint256 type1) = abi.decode(publicInputs[:64], (uint256, uint256));
        pubSignals[1] = type0;
        pubSignals[2] = type1;

        // Decode params (8 uint256 values)
        uint256[8] memory params = abi.decode(publicInputs[64:], (uint256[8]));
        for (uint256 i = 0; i < 8; i++) {
            pubSignals[3 + i] = params[i];
        }

        // Verify disclosure types match
        if (pubSignals[1] != _disclosureTypeToUint(disclosureTypes[0])) {
            return false;
        }
        if (pubSignals[2] != _disclosureTypeToUint(disclosureTypes[1])) {
            return false;
        }

        return ICompoundProofVerifier(verifier).verifyProof(pA, pB, pC, pubSignals);
    }

    /**
     * @dev Verify compound proof with 3 disclosures
     */
    function _verifyCompound3(
        address verifier,
        bytes32 commitment,
        bytes32[] calldata disclosureTypes,
        bytes calldata publicInputs,
        uint[2] memory pA,
        uint[2][2] memory pB,
        uint[2] memory pC
    ) internal view returns (bool) {
        // Total public signals: 1 (commitment) + 3 (types) + 12 (params) = 16
        uint[16] memory pubSignals;

        pubSignals[0] = uint256(commitment);

        // Decode types
        (uint256 type0, uint256 type1, uint256 type2) = abi.decode(
            publicInputs[:96],
            (uint256, uint256, uint256)
        );
        pubSignals[1] = type0;
        pubSignals[2] = type1;
        pubSignals[3] = type2;

        // Decode params (12 uint256 values)
        uint256[12] memory params = abi.decode(publicInputs[96:], (uint256[12]));
        for (uint256 i = 0; i < 12; i++) {
            pubSignals[4 + i] = params[i];
        }

        // Verify disclosure types match
        for (uint256 i = 0; i < 3; i++) {
            if (pubSignals[1 + i] != _disclosureTypeToUint(disclosureTypes[i])) {
                return false;
            }
        }

        return ICompoundProof3Verifier(verifier).verifyProof(pA, pB, pC, pubSignals);
    }

    /**
     * @dev Verify compound proof with 4 disclosures
     */
    function _verifyCompound4(
        address verifier,
        bytes32 commitment,
        bytes32[] calldata disclosureTypes,
        bytes calldata publicInputs,
        uint[2] memory pA,
        uint[2][2] memory pB,
        uint[2] memory pC
    ) internal view returns (bool) {
        // Total public signals: 1 (commitment) + 4 (types) + 16 (params) = 21
        uint[21] memory pubSignals;

        pubSignals[0] = uint256(commitment);

        // Decode types
        (uint256 type0, uint256 type1, uint256 type2, uint256 type3) = abi.decode(
            publicInputs[:128],
            (uint256, uint256, uint256, uint256)
        );
        pubSignals[1] = type0;
        pubSignals[2] = type1;
        pubSignals[3] = type2;
        pubSignals[4] = type3;

        // Decode params (16 uint256 values)
        uint256[16] memory params = abi.decode(publicInputs[128:], (uint256[16]));
        for (uint256 i = 0; i < 16; i++) {
            pubSignals[5 + i] = params[i];
        }

        // Verify disclosure types match
        for (uint256 i = 0; i < 4; i++) {
            if (pubSignals[1 + i] != _disclosureTypeToUint(disclosureTypes[i])) {
                return false;
            }
        }

        return ICompoundProof4Verifier(verifier).verifyProof(pA, pB, pC, pubSignals);
    }

    /**
     * @dev Convert disclosure type bytes32 to uint256
     */
    function _disclosureTypeToUint(bytes32 disclosureType) internal pure returns (uint256) {
        if (disclosureType == DISCLOSURE_AGE_THRESHOLD) return 0;
        if (disclosureType == DISCLOSURE_DATE_RANGE) return 1;
        if (disclosureType == DISCLOSURE_VALUE_RANGE) return 2;
        if (disclosureType == DISCLOSURE_SET_MEMBERSHIP) return 3;
        if (disclosureType == DISCLOSURE_EXISTENCE) return 4;
        revert Errors.InvalidDisclosureType(disclosureType);
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
        // Check replay prevention
        bytes32 proofHash = keccak256(request.proof);
        if (_usedProofs[proofHash]) {
            revert Errors.ProofReplayed(proofHash);
        }

        // Verify credential
        if (!claimToken.verify(request.credentialId)) {
            return false;
        }

        // Check proof validity period
        if (request.validUntil != 0 && block.timestamp > request.validUntil) {
            return false;
        }

        // Check verifier restriction
        if (request.verifier != address(0) && request.verifier != msg.sender) {
            return false;
        }

        // Get verifier
        address verifier = verifiers[request.disclosureType];
        if (verifier == address(0)) {
            revert Errors.VerifierNotRegistered(request.disclosureType);
        }

        // Decode and verify
        (
            uint[2] memory pA,
            uint[2][2] memory pB,
            uint[2] memory pC,
            uint[] memory pubSignals
        ) = _decodeGenericProof(request.proof);

        valid = IGroth16Verifier(verifier).verifyProof(pA, pB, pC, pubSignals);

        if (valid) {
            _usedProofs[proofHash] = true;
            emit ProofVerified(request.credentialId, request.disclosureType, msg.sender);
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
        return _usedProofs[proofHash];
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
        if (_claimToken == address(0)) {
            revert Errors.ZeroAddress();
        }
        claimToken = IClaimToken(_claimToken);
    }

    // ============================================
    // Proof Decoding Helpers
    // ============================================

    /**
     * @dev Decode age threshold proof
     */
    function _decodeAgeProof(
        bytes calldata proof
    ) internal pure returns (
        uint[2] memory pA,
        uint[2][2] memory pB,
        uint[2] memory pC,
        uint[4] memory pubSignals
    ) {
        (pA, pB, pC, pubSignals) = abi.decode(
            proof,
            (uint[2], uint[2][2], uint[2], uint[4])
        );
    }

    /**
     * @dev Decode date range proof
     */
    function _decodeDateRangeProof(
        bytes calldata proof
    ) internal pure returns (
        uint[2] memory pA,
        uint[2][2] memory pB,
        uint[2] memory pC,
        uint[4] memory pubSignals
    ) {
        (pA, pB, pC, pubSignals) = abi.decode(
            proof,
            (uint[2], uint[2][2], uint[2], uint[4])
        );
    }

    /**
     * @dev Decode value range proof
     */
    function _decodeValueRangeProof(
        bytes calldata proof
    ) internal pure returns (
        uint[2] memory pA,
        uint[2][2] memory pB,
        uint[2] memory pC,
        uint[4] memory pubSignals
    ) {
        (pA, pB, pC, pubSignals) = abi.decode(
            proof,
            (uint[2], uint[2][2], uint[2], uint[4])
        );
    }

    /**
     * @dev Decode generic proof with variable-length public signals
     */
    function _decodeGenericProof(
        bytes calldata proof
    ) internal pure returns (
        uint[2] memory pA,
        uint[2][2] memory pB,
        uint[2] memory pC,
        uint[] memory pubSignals
    ) {
        (pA, pB, pC, pubSignals) = abi.decode(
            proof,
            (uint[2], uint[2][2], uint[2], uint[])
        );
    }

    /**
     * @dev Decode just the proof points (without public signals)
     */
    function _decodeProofPoints(
        bytes calldata proof
    ) internal pure returns (
        uint[2] memory pA,
        uint[2][2] memory pB,
        uint[2] memory pC
    ) {
        (pA, pB, pC) = abi.decode(
            proof,
            (uint[2], uint[2][2], uint[2])
        );
    }

    // ============================================
    // UUPS Upgrade Authorization
    // ============================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
