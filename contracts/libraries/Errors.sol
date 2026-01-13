// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

/**
 * @title Errors
 * @notice Custom error definitions for the Sovereign Credential system
 * @dev Error codes match Appendix A of SPEC.md
 */
library Errors {
    // ============================================
    // Issuer Errors (SC001-SC002, SC015)
    // ============================================

    /// @notice SC001: Issuer not authorized for the specified claim type
    error UnauthorizedIssuer(address issuer, bytes32 claimType);

    /// @notice SC002: Issuer signature verification failed
    error InvalidSignature();

    /// @notice SC015: Issuer reputation below required threshold
    error ReputationInsufficient(address issuer, uint256 current, uint256 required);

    /// @notice Issuer is not active
    error IssuerNotActive(address issuer);

    /// @notice Issuer already registered
    error IssuerAlreadyRegistered(address issuer);

    /// @notice Issuer not found
    error IssuerNotFound(address issuer);

    /// @notice Delegate already added
    error DelegateAlreadyExists(address issuer, address delegate);

    /// @notice Delegate not found
    error DelegateNotFound(address issuer, address delegate);

    // ============================================
    // Credential Errors (SC003-SC006, SC010)
    // ============================================

    /// @notice SC003: Token ID does not exist
    error CredentialNotFound(uint256 tokenId);

    /// @notice SC004: Credential has been permanently revoked
    error CredentialRevoked(uint256 tokenId);

    /// @notice SC005: Credential is past expiration
    error CredentialExpired(uint256 tokenId);

    /// @notice Credential has not yet expired (cannot mark as expired)
    error CredentialNotExpired(uint256 tokenId);

    /// @notice SC006: Credential is currently suspended
    error CredentialSuspended(uint256 tokenId);

    /// @notice SC010: Caller cannot transfer this credential
    error TransferUnauthorized(address caller, uint256 tokenId);

    /// @notice Invalid status transition attempted
    error InvalidStatusTransition(uint8 currentStatus, uint8 targetStatus);

    /// @notice Credential is not in a valid state for this operation
    error InvalidCredentialStatus(uint256 tokenId, uint8 status);

    /// @notice Payload size exceeds maximum allowed (32KB)
    error PayloadTooLarge(uint256 size, uint256 maxSize);

    /// @notice Payload hash mismatch
    error PayloadHashMismatch(bytes32 expected, bytes32 actual);

    /// @notice Subject address cannot be zero
    error InvalidSubject();

    /// @notice Claim type not supported
    error UnsupportedClaimType(bytes32 claimType);

    // ============================================
    // Proof Errors (SC007-SC009)
    // ============================================

    /// @notice SC007: Zero-knowledge proof verification failed
    error InvalidProof();

    /// @notice SC008: ZK proof is past its validity window
    error ProofExpired(uint64 validUntil, uint64 currentTime);

    /// @notice SC009: ZK proof has already been used (replay prevention)
    error ProofReplayed(bytes32 proofHash);

    /// @notice Verifier not registered for disclosure type
    error VerifierNotRegistered(bytes32 disclosureType);

    /// @notice Invalid disclosure type provided
    error InvalidDisclosureType(bytes32 disclosureType);

    /// @notice Invalid number of disclosures for compound proof
    error InvalidDisclosureCount(uint256 count);

    /// @notice Proof does not match credential commitment
    error CommitmentMismatch(bytes32 expected, bytes32 actual);

    /// @notice Intended verifier does not match caller
    error WrongVerifier(address expected, address actual);

    // ============================================
    // Inheritance Errors (SC011-SC013)
    // ============================================

    /// @notice SC011: No inheritance directive set for credential
    error InheritanceNotSet(uint256 tokenId);

    /// @notice SC012: FIE trigger verification failed
    error FIETriggerInvalid(bytes32 intentHash);

    /// @notice SC013: Beneficiary address is invalid
    error BeneficiaryInvalid(address beneficiary);

    /// @notice Inheritance already executed for this trigger
    error InheritanceAlreadyExecuted(bytes32 intentHash);

    /// @notice Shares must sum to 100
    error InvalidShares(uint256 total);

    /// @notice Credential type is not splittable
    error NotSplittable(bytes32 claimType);

    /// @notice Beneficiaries and shares length mismatch
    error BeneficiarySharesMismatch(uint256 beneficiaries, uint256 shares);

    // ============================================
    // Renewal Errors (SC014)
    // ============================================

    /// @notice SC014: Issuer denied the renewal request
    error RenewalDenied(uint256 tokenId, string reason);

    /// @notice No renewal request pending for this credential
    error NoRenewalRequest(uint256 tokenId);

    /// @notice Renewal grace period has expired
    error GracePeriodExpired(uint256 tokenId, uint64 expiredAt, uint64 gracePeriodEnd);

    /// @notice Only holder can request renewal
    error NotHolder(address caller, address holder);

    /// @notice Renewal already requested
    error RenewalAlreadyRequested(uint256 tokenId);

    // ============================================
    // Access Control Errors
    // ============================================

    /// @notice Caller is not the FIE execution agent
    error NotFIEAgent(address caller);

    /// @notice Caller does not have required role
    error MissingRole(bytes32 role, address account);

    /// @notice Operation not allowed in current state
    error OperationNotAllowed();

    // ============================================
    // General Errors
    // ============================================

    /// @notice Array length mismatch in batch operation
    error ArrayLengthMismatch(uint256 length1, uint256 length2);

    /// @notice Zero address not allowed
    error ZeroAddress();

    /// @notice Empty array not allowed
    error EmptyArray();

    /// @notice Value out of allowed range
    error OutOfRange(uint256 value, uint256 min, uint256 max);

    /// @notice Duplicate entry
    error DuplicateEntry();

    /// @notice Operation would exceed maximum limit
    error LimitExceeded(uint256 current, uint256 max);

    // ============================================
    // Advanced Inheritance Errors
    // ============================================

    /// @notice Inheritance condition not met
    error ConditionNotMet(bytes32 conditionType, address beneficiary);

    /// @notice Executor access not granted or expired
    error ExecutorAccessDenied(address executor, uint256 tokenId);

    /// @notice Executor access already granted
    error ExecutorAccessAlreadyGranted(address executor, uint256 tokenId);

    /// @notice Executor access period exceeds maximum
    error ExecutorPeriodExceedsMax(uint64 requested, uint64 max);

    /// @notice Dispute already filed for this credential
    error DisputeAlreadyFiled(uint256 tokenId);

    /// @notice Dispute not found
    error DisputeNotFound(uint256 disputeId);

    /// @notice Dispute filing window has passed
    error DisputeWindowExpired(uint256 tokenId, uint64 windowEnd);

    /// @notice Dispute already resolved
    error DisputeAlreadyResolved(uint256 disputeId);

    /// @notice Inheritance frozen due to pending dispute
    error InheritanceFrozen(uint256 tokenId, uint256 disputeId);

    /// @notice Credential cannot be split (not splittable type or already split)
    error CannotSplitCredential(uint256 tokenId, string reason);

    /// @notice Invalid condition parameters
    error InvalidConditionParams(bytes32 conditionType);

    /// @notice Oracle verification failed
    error OracleVerificationFailed(address oracle, bytes32 conditionType);
}
