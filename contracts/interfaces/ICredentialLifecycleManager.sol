// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {CredentialTypes} from "../libraries/CredentialTypes.sol";

/**
 * @title ICredentialLifecycleManager
 * @notice Interface for managing credential renewal and inheritance
 * @dev Implements functionality defined in SPEC.md Section 4.4
 */
interface ICredentialLifecycleManager {
    // ============================================
    // Events (Spec 4.4)
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

    /// @notice Emitted when an inheritance directive is set
    event InheritanceDirectiveSet(
        uint256 indexed tokenId,
        address[] beneficiaries
    );

    /// @notice Emitted when an inheritance directive is removed
    event InheritanceDirectiveRemoved(uint256 indexed tokenId);

    /// @notice Emitted when inheritance is executed
    event InheritanceExecuted(
        uint256 indexed tokenId,
        address indexed beneficiary
    );

    /// @notice Emitted when a credential is split for partial inheritance
    event CredentialSplit(
        uint256 indexed originalTokenId,
        uint256[] newTokenIds,
        address[] beneficiaries,
        uint8[] shares
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
    // Inheritance Functions
    // ============================================

    /**
     * @notice Set inheritance directive for a credential
     * @param tokenId The credential to set inheritance for
     * @param directive The inheritance directive
     */
    function setInheritanceDirective(
        uint256 tokenId,
        CredentialTypes.InheritanceDirective calldata directive
    ) external;

    /**
     * @notice Remove inheritance directive from a credential
     * @param tokenId The credential to remove inheritance from
     */
    function removeInheritanceDirective(uint256 tokenId) external;

    /**
     * @notice Get the inheritance directive for a credential
     * @param tokenId The credential to query
     * @return directive The inheritance directive
     */
    function getInheritanceDirective(
        uint256 tokenId
    ) external view returns (CredentialTypes.InheritanceDirective memory directive);

    /**
     * @notice Check if a credential has an inheritance directive
     * @param tokenId The credential to check
     * @return hasDirective True if directive exists
     */
    function hasInheritanceDirective(
        uint256 tokenId
    ) external view returns (bool hasDirective);

    /**
     * @notice Execute inheritance transfer (called by FIEBridge)
     * @param tokenId The credential to transfer
     * @param fieProof Proof from FIE trigger mechanism
     */
    function executeInheritance(
        uint256 tokenId,
        bytes calldata fieProof
    ) external;

    /**
     * @notice Split a credential for partial inheritance
     * @param tokenId The credential to split
     * @param beneficiaries Array of beneficiary addresses
     * @param shares Array of share percentages (must sum to 100)
     * @return newTokenIds Array of new credential token IDs
     */
    function splitCredential(
        uint256 tokenId,
        address[] calldata beneficiaries,
        uint8[] calldata shares
    ) external returns (uint256[] memory newTokenIds);

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

    /**
     * @notice Set inheritance directives for multiple credentials
     * @param tokenIds Array of credential token IDs
     * @param directives Array of inheritance directives
     */
    function batchSetInheritance(
        uint256[] calldata tokenIds,
        CredentialTypes.InheritanceDirective[] calldata directives
    ) external;

    // ============================================
    // Query Functions
    // ============================================

    /**
     * @notice Get all credentials with pending renewal requests
     * @return tokenIds Array of credential token IDs
     */
    function getPendingRenewals() external view returns (uint256[] memory tokenIds);

    /**
     * @notice Get all credentials with inheritance directives for a holder
     * @param holder The holder address
     * @return tokenIds Array of credential token IDs
     */
    function getCredentialsWithInheritance(
        address holder
    ) external view returns (uint256[] memory tokenIds);

    /**
     * @notice Check if a credential type supports splitting
     * @param claimType The claim type to check
     * @return splittable True if credentials of this type can be split
     */
    function isSplittable(bytes32 claimType) external view returns (bool splittable);

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

    /**
     * @notice Set the FIEBridge contract address
     * @param fieBridge Address of the FIEBridge contract
     */
    function setFIEBridge(address fieBridge) external;

    /**
     * @notice Register a claim type as splittable
     * @param claimType The claim type to register
     * @param splittable Whether the type is splittable
     */
    function setSplittable(bytes32 claimType, bool splittable) external;
}
