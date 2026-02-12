// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {CredentialTypes} from "../libraries/CredentialTypes.sol";

/**
 * @title ICredentialRenewalManager
 * @notice Interface for managing credential renewal and batch transfers
 * @dev Split from ICredentialLifecycleManager — contains only core lifecycle
 *      operations that do not depend on the FIE inheritance subsystem.
 */
interface ICredentialRenewalManager {
    // ============================================
    // Events
    // ============================================

    /// @notice Emitted when a renewal is requested
    event RenewalRequested(
        uint256 indexed tokenId,
        address indexed requester
    );

    /// @notice Emitted when a renewal is approved
    event RenewalApproved(
        uint256 indexed tokenId,
        uint64 newExpiry
    );

    /// @notice Emitted when a renewal is denied
    event RenewalDenied(
        uint256 indexed tokenId,
        string reason
    );

    /// @notice Emitted when credentials are batch transferred
    event BatchTransferred(
        uint256[] tokenIds,
        address indexed from,
        address indexed to
    );

    // ============================================
    // Renewal Functions
    // ============================================

    /**
     * @notice Request renewal of an expiring/expired credential
     * @param tokenId The credential to renew
     */
    function requestRenewal(uint256 tokenId) external;

    /**
     * @notice Approve a renewal request (called by issuer)
     * @param tokenId The credential to renew
     * @param newExpiry New expiration timestamp
     * @param signature Issuer's signature authorizing the renewal
     */
    function approveRenewal(
        uint256 tokenId,
        uint64 newExpiry,
        bytes calldata signature
    ) external;

    /**
     * @notice Deny a renewal request (called by issuer)
     * @param tokenId The credential renewal to deny
     * @param reason Reason for denial
     */
    function denyRenewal(uint256 tokenId, string calldata reason) external;

    /**
     * @notice Cancel a pending renewal request (called by holder)
     * @param tokenId The credential renewal to cancel
     */
    function cancelRenewalRequest(uint256 tokenId) external;

    /**
     * @notice Get the renewal request for a credential
     * @param tokenId The credential to query
     * @return request The renewal request struct
     */
    function getRenewalRequest(
        uint256 tokenId
    ) external view returns (CredentialTypes.RenewalRequest memory request);

    /**
     * @notice Check if a credential has a pending renewal request
     * @param tokenId The credential to check
     * @return pending True if renewal is pending
     */
    function hasRenewalRequest(uint256 tokenId) external view returns (bool pending);

    // ============================================
    // Batch Operations
    // ============================================

    /**
     * @notice Transfer multiple credentials to a single recipient
     * @param tokenIds Array of credential token IDs to transfer
     * @param to Recipient address
     */
    function batchTransfer(
        uint256[] calldata tokenIds,
        address to
    ) external;

    // ============================================
    // Query Functions
    // ============================================

    /**
     * @notice Get all credentials with pending renewal requests
     * @return tokenIds Array of credential token IDs
     */
    function getPendingRenewals() external view returns (uint256[] memory tokenIds);

    // ============================================
    // Administrative Functions
    // ============================================

    /**
     * @notice Set the ClaimToken contract address
     * @param claimToken Address of the ClaimToken contract
     */
    function setClaimToken(address claimToken) external;

    /**
     * @notice Set the IssuerRegistry contract address
     * @param issuerRegistry Address of the IssuerRegistry contract
     */
    function setIssuerRegistry(address issuerRegistry) external;
}
