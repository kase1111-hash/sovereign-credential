// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

/**
 * @title CredentialTypes
 * @notice Core data structures for the Sovereign Credential system
 * @dev All structs match the specification in SPEC.md Section 3
 */
library CredentialTypes {
    // ============================================
    // Credential States (Spec 1.2)
    // ============================================

    /**
     * @notice Possible states of a credential throughout its lifecycle
     * @dev State transitions are defined in Spec 5.1
     */
    enum CredentialStatus {
        PENDING,    // Credential minted but awaiting issuer confirmation
        ACTIVE,     // Credential is valid and can be used for verification/disclosure
        SUSPENDED,  // Temporarily invalid; can be reactivated by issuer
        REVOKED,    // Permanently invalid; cannot be reactivated
        EXPIRED,    // Past expiration timestamp; may be renewable
        INHERITED   // Transferred via FIE inheritance mechanism
    }

    // ============================================
    // Disclosure Types (Spec 3.4)
    // ============================================

    /**
     * @notice Types of zero-knowledge disclosures supported
     */
    enum DisclosureType {
        AGE_THRESHOLD,    // Prove age > or < threshold
        DATE_RANGE,       // Prove date within range
        VALUE_RANGE,      // Prove numeric value within range
        SET_MEMBERSHIP,   // Prove value is in allowed set
        EQUALITY,         // Prove value equals public value
        EXISTENCE,        // Prove credential exists and is valid
        COMPOUND          // Multiple disclosures in one proof
    }

    // ============================================
    // Core Structures (Spec 3.1 - 3.5)
    // ============================================

    /**
     * @notice A verifiable claim minted as an NFT (Spec 3.1)
     * @param tokenId ERC721 token ID
     * @param claimType Claim type identifier (see ClaimTypes.sol)
     * @param subject Entity the claim describes
     * @param issuer Issuing authority address
     * @param encryptedPayload ECIES-encrypted claim data
     * @param payloadHash Keccak256 of plaintext payload for verification
     * @param commitments ZK-compatible Poseidon commitments for disclosure
     * @param issuedAt Issuance timestamp (Unix epoch seconds)
     * @param expiresAt Expiration timestamp (0 = never expires)
     * @param status Current credential status
     * @param metadataURI IPFS URI for schema and display metadata
     */
    struct Credential {
        uint256 tokenId;
        bytes32 claimType;
        address subject;
        address issuer;
        bytes encryptedPayload;
        bytes32 payloadHash;
        bytes32[] commitments;
        uint64 issuedAt;
        uint64 expiresAt;
        uint8 status;
        string metadataURI;
    }

    /**
     * @notice Registered credential issuer (Spec 3.2)
     * @param issuerAddress Primary signing address
     * @param authorizedTypes Claim types this issuer can create
     * @param jurisdiction Geographic/legal jurisdiction code
     * @param reputationScore Aggregate reputation (0-10000 basis points)
     * @param totalIssued Total credentials issued by this issuer
     * @param totalRevoked Total credentials revoked by this issuer
     * @param totalDisputed Total credentials disputed
     * @param isActive Whether issuer can issue new credentials
     * @param delegates Authorized delegate signing addresses
     */
    struct Issuer {
        address issuerAddress;
        bytes32[] authorizedTypes;
        string jurisdiction;
        uint256 reputationScore;
        uint256 totalIssued;
        uint256 totalRevoked;
        uint256 totalDisputed;
        bool isActive;
        address[] delegates;
    }

    /**
     * @notice Request for zero-knowledge disclosure (Spec 3.3)
     * @param credentialId Token ID of credential being disclosed
     * @param disclosureType Type of disclosure being requested
     * @param predicateHash Hash of the predicate being proven
     * @param proof ZK proof bytes
     * @param generatedAt Proof generation timestamp
     * @param validUntil Proof expiration timestamp
     * @param verifier Intended verifier address (address(0) = anyone)
     */
    struct DisclosureRequest {
        uint256 credentialId;
        bytes32 disclosureType;
        bytes32 predicateHash;
        bytes proof;
        uint64 generatedAt;
        uint64 validUntil;
        address verifier;
    }

    /**
     * @notice Inheritance directive for FIE integration (Spec 3.5)
     * @param credentialId Credential to transfer on death trigger
     * @param beneficiaries Ordered list of beneficiary addresses
     * @param shares Share percentages for splittable credentials (must sum to 100)
     * @param requiresFIETrigger Whether transfer must be triggered by FIE
     * @param fieIntentHash Hash of linked FIE intent record
     * @param conditions Encoded additional conditions for inheritance
     */
    struct InheritanceDirective {
        uint256 credentialId;
        address[] beneficiaries;
        uint8[] shares;
        bool requiresFIETrigger;
        bytes32 fieIntentHash;
        bytes conditions;
    }

    /**
     * @notice Cross-reference to other NatLangChain records (Spec 7.3)
     * @param recordHash Hash of referenced NatLangChain record
     * @param relationship Type of relationship (SUPERSEDES, AMENDS, SUPPORTS, etc.)
     * @param prose Natural language description of relationship
     */
    struct CrossReference {
        bytes32 recordHash;
        string relationship;
        string prose;
    }

    /**
     * @notice Mint request parameters for credential creation
     * @param claimType Type of claim being issued
     * @param subject Address of the claim subject
     * @param encryptedPayload ECIES-encrypted claim data
     * @param payloadHash Hash of plaintext payload
     * @param commitments ZK commitments for selective disclosure
     * @param expiresAt Expiration timestamp (0 = never)
     * @param metadataURI IPFS URI for metadata
     */
    struct MintRequest {
        bytes32 claimType;
        address subject;
        bytes encryptedPayload;
        bytes32 payloadHash;
        bytes32[] commitments;
        uint64 expiresAt;
        string metadataURI;
    }

    /**
     * @notice Renewal request data
     * @param tokenId Credential being renewed
     * @param requester Address that requested renewal
     * @param requestedAt Timestamp of request
     * @param newExpiry Proposed new expiration (set by issuer on approval)
     */
    struct RenewalRequest {
        uint256 tokenId;
        address requester;
        uint64 requestedAt;
        uint64 newExpiry;
    }

    /**
     * @notice Inheritance condition for conditional transfers (Spec 8.3)
     * @param conditionType Type of condition (AGE_THRESHOLD, DATE_AFTER, CUSTOM)
     * @param params Encoded condition parameters
     * @param oracleAddress Address of oracle for condition verification (if needed)
     */
    struct InheritanceCondition {
        bytes32 conditionType;
        bytes params;
        address oracleAddress;
    }

    /**
     * @notice Executor access for estate settlement (Spec 8.4)
     * @param executor Address of the designated executor
     * @param grantedAt Timestamp when access was granted
     * @param expiresAt Timestamp when access expires
     * @param permissions Bitmap of allowed operations
     */
    struct ExecutorAccess {
        address executor;
        uint64 grantedAt;
        uint64 expiresAt;
        uint8 permissions;
    }

    /**
     * @notice Inheritance dispute record (Spec 8.5)
     * @param disputeId Unique identifier for the dispute
     * @param tokenId Credential being disputed
     * @param disputant Address filing the dispute
     * @param reason Encoded reason for dispute
     * @param filedAt Timestamp when dispute was filed
     * @param resolvedAt Timestamp when dispute was resolved (0 if pending)
     * @param resolution Resolution outcome (0=pending, 1=upheld, 2=rejected)
     */
    struct InheritanceDispute {
        uint256 disputeId;
        uint256 tokenId;
        address disputant;
        bytes reason;
        uint64 filedAt;
        uint64 resolvedAt;
        uint8 resolution;
    }

    /**
     * @notice Split credential metadata for partial inheritance
     * @param originalTokenId Token ID of the original credential that was split
     * @param sharePercentage Percentage share (0-100) this split represents
     * @param splitIndex Index of this split among siblings
     * @param totalSplits Total number of splits created
     */
    struct SplitMetadata {
        uint256 originalTokenId;
        uint8 sharePercentage;
        uint8 splitIndex;
        uint8 totalSplits;
    }

    // ============================================
    // Condition Type Constants
    // ============================================

    /// @notice Condition: beneficiary must be above age threshold
    bytes32 internal constant CONDITION_AGE_THRESHOLD = keccak256("AGE_THRESHOLD");

    /// @notice Condition: current date must be after specified date
    bytes32 internal constant CONDITION_DATE_AFTER = keccak256("DATE_AFTER");

    /// @notice Condition: custom condition verified by oracle
    bytes32 internal constant CONDITION_CUSTOM = keccak256("CUSTOM");

    // ============================================
    // Executor Permission Flags
    // ============================================

    /// @notice Permission to view credential details
    uint8 internal constant PERMISSION_VIEW = 1;

    /// @notice Permission to transfer credentials
    uint8 internal constant PERMISSION_TRANSFER = 2;

    /// @notice Permission to manage inheritance directives
    uint8 internal constant PERMISSION_MANAGE_INHERITANCE = 4;

    /// @notice Full permissions (all flags set)
    uint8 internal constant PERMISSION_FULL = 7;

    // ============================================
    // Dispute Resolution Outcomes
    // ============================================

    /// @notice Dispute is still pending
    uint8 internal constant DISPUTE_PENDING = 0;

    /// @notice Dispute was upheld (inheritance blocked/modified)
    uint8 internal constant DISPUTE_UPHELD = 1;

    /// @notice Dispute was rejected (inheritance proceeds)
    uint8 internal constant DISPUTE_REJECTED = 2;

    // ============================================
    // Constants
    // ============================================

    /// @notice Minimum reputation score to issue credentials
    /// @dev v1.0: Set to 0 (disabled). Authorization gated by isActive only.
    ///      v1.1: Re-enable with calibrated threshold once real issuer data exists.
    uint256 internal constant MIN_REPUTATION = 0;

    /// @notice Maximum reputation score (100% = 10000 basis points)
    uint256 internal constant MAX_REPUTATION = 10000;

    /// @notice Initial reputation score for new issuers (50%)
    uint256 internal constant INITIAL_REPUTATION = 5000;

    /// @notice Grace period for renewal after expiration (90 days)
    uint64 internal constant RENEWAL_GRACE_PERIOD = 90 days;

    /// @notice Auto-revoke period for suspended credentials (365 days)
    uint64 internal constant SUSPENSION_AUTO_REVOKE_PERIOD = 365 days;

    /// @notice Maximum encrypted payload size (32KB as per Spec C-05)
    uint256 internal constant MAX_PAYLOAD_SIZE = 32 * 1024;

    /// @notice Maximum batch size for batch operations (prevent DoS via gas exhaustion)
    uint256 internal constant MAX_BATCH_SIZE = 50;

    /// @notice Default executor access period (90 days)
    uint64 internal constant DEFAULT_EXECUTOR_PERIOD = 90 days;

    /// @notice Maximum executor access period (365 days)
    uint64 internal constant MAX_EXECUTOR_PERIOD = 365 days;

    /// @notice Dispute filing window after trigger (30 days)
    uint64 internal constant DISPUTE_FILING_WINDOW = 30 days;
}
