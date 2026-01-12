// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {CredentialTypes} from "../libraries/CredentialTypes.sol";

/**
 * @title IClaimToken
 * @notice Interface for the ClaimToken ERC721 credential NFT contract
 * @dev Implements functionality defined in SPEC.md Section 4.1
 */
interface IClaimToken {
    // ============================================
    // Events (Spec 4.1)
    // ============================================

    /// @notice Emitted when a new credential is minted
    event CredentialMinted(
        uint256 indexed tokenId,
        address indexed subject,
        address indexed issuer,
        bytes32 claimType
    );

    /// @notice Emitted when a credential is revoked
    event CredentialRevoked(
        uint256 indexed tokenId,
        address indexed revoker,
        string reason
    );

    /// @notice Emitted when a credential is suspended
    event CredentialSuspended(
        uint256 indexed tokenId,
        address indexed suspender,
        string reason
    );

    /// @notice Emitted when a suspended credential is reinstated
    event CredentialReinstated(
        uint256 indexed tokenId,
        address indexed reinstater
    );

    /// @notice Emitted when a credential expiration is extended
    event CredentialRenewed(
        uint256 indexed tokenId,
        uint64 oldExpiry,
        uint64 newExpiry
    );

    /// @notice Emitted when a credential is transferred
    event CredentialTransferred(
        uint256 indexed tokenId,
        address indexed from,
        address indexed to
    );

    /// @notice Emitted when a credential status is updated to EXPIRED
    event CredentialExpired(
        uint256 indexed tokenId,
        uint64 expiredAt
    );

    /// @notice Emitted when a pending credential is confirmed
    event CredentialConfirmed(
        uint256 indexed tokenId,
        address indexed confirmer
    );

    // ============================================
    // Minting Functions
    // ============================================

    /**
     * @notice Mint a new credential NFT
     * @param request The mint request containing credential data
     * @param signature Issuer's signature over the credential data
     * @return tokenId The ID of the newly minted credential
     */
    function mint(
        CredentialTypes.MintRequest calldata request,
        bytes calldata signature
    ) external returns (uint256 tokenId);

    /**
     * @notice Mint multiple credentials in a single transaction
     * @param requests Array of mint requests
     * @param signatures Array of corresponding issuer signatures
     * @return tokenIds Array of minted token IDs
     */
    function batchMint(
        CredentialTypes.MintRequest[] calldata requests,
        bytes[] calldata signatures
    ) external returns (uint256[] memory tokenIds);

    // ============================================
    // Status Management Functions
    // ============================================

    /**
     * @notice Permanently revoke a credential
     * @param tokenId The credential to revoke
     * @param reason Human-readable reason for revocation
     */
    function revoke(uint256 tokenId, string calldata reason) external;

    /**
     * @notice Temporarily suspend a credential
     * @param tokenId The credential to suspend
     * @param reason Human-readable reason for suspension
     */
    function suspend(uint256 tokenId, string calldata reason) external;

    /**
     * @notice Reinstate a suspended credential
     * @param tokenId The credential to reinstate
     */
    function reinstate(uint256 tokenId) external;

    /**
     * @notice Explicitly mark an expired credential as EXPIRED
     * @dev Can be called by anyone to update status for gas efficiency in queries
     * @param tokenId The credential to mark as expired
     */
    function markExpired(uint256 tokenId) external;

    /**
     * @notice Mint a credential in PENDING status (multi-step flow)
     * @param request The mint request containing credential data
     * @param signature Issuer's signature over the credential data
     * @return tokenId The ID of the newly minted credential
     */
    function mintPending(
        CredentialTypes.MintRequest calldata request,
        bytes calldata signature
    ) external returns (uint256 tokenId);

    /**
     * @notice Confirm a pending credential, transitioning it to ACTIVE
     * @param tokenId The pending credential to confirm
     */
    function confirm(uint256 tokenId) external;

    /**
     * @notice Extend credential expiration (called by LifecycleManager)
     * @param tokenId The credential to renew
     * @param newExpiry New expiration timestamp
     */
    function updateExpiry(uint256 tokenId, uint64 newExpiry) external;

    /**
     * @notice Update credential status to INHERITED (called by FIEBridge)
     * @param tokenId The credential being inherited
     */
    function markInherited(uint256 tokenId) external;

    // ============================================
    // Verification Functions
    // ============================================

    /**
     * @notice Check if a credential is currently valid
     * @param tokenId The credential to verify
     * @return valid True if credential is ACTIVE and not expired
     */
    function verify(uint256 tokenId) external view returns (bool valid);

    /**
     * @notice Check if a credential has expired
     * @param tokenId The credential to check
     * @return expired True if past expiration timestamp
     */
    function isExpired(uint256 tokenId) external view returns (bool expired);

    /**
     * @notice Check if a credential has been revoked
     * @param tokenId The credential to check
     * @return revoked True if status is REVOKED
     */
    function isRevoked(uint256 tokenId) external view returns (bool revoked);

    /**
     * @notice Check if a credential is suspended
     * @param tokenId The credential to check
     * @return suspended True if status is SUSPENDED
     */
    function isSuspended(uint256 tokenId) external view returns (bool suspended);

    // ============================================
    // Query Functions
    // ============================================

    /**
     * @notice Get full credential data
     * @param tokenId The credential to retrieve
     * @return credential The credential struct
     */
    function getCredential(
        uint256 tokenId
    ) external view returns (CredentialTypes.Credential memory credential);

    /**
     * @notice Get all credentials for a subject
     * @param subject The subject address
     * @return tokenIds Array of credential token IDs
     */
    function getCredentialsBySubject(
        address subject
    ) external view returns (uint256[] memory tokenIds);

    /**
     * @notice Get all credentials of a specific type
     * @param claimType The claim type to filter by
     * @return tokenIds Array of credential token IDs
     */
    function getCredentialsByType(
        bytes32 claimType
    ) external view returns (uint256[] memory tokenIds);

    /**
     * @notice Get all credentials issued by an issuer
     * @param issuer The issuer address
     * @return tokenIds Array of credential token IDs
     */
    function getCredentialsByIssuer(
        address issuer
    ) external view returns (uint256[] memory tokenIds);

    /**
     * @notice Get the current status of a credential
     * @param tokenId The credential to check
     * @return status The credential status enum value
     */
    function getStatus(
        uint256 tokenId
    ) external view returns (CredentialTypes.CredentialStatus status);

    /**
     * @notice Get the commitments for ZK disclosure
     * @param tokenId The credential
     * @return commitments Array of Poseidon hash commitments
     */
    function getCommitments(
        uint256 tokenId
    ) external view returns (bytes32[] memory commitments);

    // ============================================
    // Administrative Functions
    // ============================================

    /**
     * @notice Set the IssuerRegistry contract address
     * @param registry Address of the IssuerRegistry
     */
    function setIssuerRegistry(address registry) external;

    /**
     * @notice Set the ZKDisclosureEngine contract address
     * @param engine Address of the ZKDisclosureEngine
     */
    function setZKEngine(address engine) external;

    /**
     * @notice Set the CredentialLifecycleManager contract address
     * @param manager Address of the CredentialLifecycleManager
     */
    function setLifecycleManager(address manager) external;

    /**
     * @notice Get the total number of credentials minted
     * @return count Total credential count
     */
    function totalCredentials() external view returns (uint256 count);
}
