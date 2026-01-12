// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {CredentialTypes} from "../libraries/CredentialTypes.sol";

/**
 * @title IIssuerRegistry
 * @notice Interface for managing authorized credential issuers
 * @dev Implements functionality defined in SPEC.md Section 4.2
 */
interface IIssuerRegistry {
    // ============================================
    // Events (Spec 4.2)
    // ============================================

    /// @notice Emitted when a new issuer is registered
    event IssuerRegistered(
        address indexed issuer,
        string jurisdiction
    );

    /// @notice Emitted when an issuer is deactivated
    event IssuerDeactivated(
        address indexed issuer,
        string reason
    );

    /// @notice Emitted when an issuer is reactivated
    event IssuerReactivated(address indexed issuer);

    /// @notice Emitted when an issuer is authorized for a claim type
    event TypeAuthorized(
        address indexed issuer,
        bytes32 indexed claimType
    );

    /// @notice Emitted when an issuer's type authorization is revoked
    event TypeRevoked(
        address indexed issuer,
        bytes32 indexed claimType
    );

    /// @notice Emitted when a delegate is added to an issuer
    event DelegateAdded(
        address indexed issuer,
        address indexed delegate
    );

    /// @notice Emitted when a delegate is removed from an issuer
    event DelegateRemoved(
        address indexed issuer,
        address indexed delegate
    );

    /// @notice Emitted when an issuer's reputation is adjusted
    event ReputationAdjusted(
        address indexed issuer,
        int256 delta,
        uint256 newScore,
        string reason
    );

    /// @notice Emitted when issuer statistics are updated after credential action
    event IssuerStatsUpdated(
        address indexed issuer,
        uint256 totalIssued,
        uint256 totalRevoked,
        uint256 totalDisputed
    );

    // ============================================
    // Registration Functions
    // ============================================

    /**
     * @notice Register a new issuer
     * @param issuerAddress Address of the issuer
     * @param jurisdiction Geographic/legal jurisdiction code
     * @param initialTypes Initial claim types to authorize
     */
    function registerIssuer(
        address issuerAddress,
        string calldata jurisdiction,
        bytes32[] calldata initialTypes
    ) external;

    /**
     * @notice Deactivate an issuer (cannot issue new credentials)
     * @param issuerAddress Address of the issuer to deactivate
     * @param reason Reason for deactivation
     */
    function deactivateIssuer(
        address issuerAddress,
        string calldata reason
    ) external;

    /**
     * @notice Reactivate a previously deactivated issuer
     * @param issuerAddress Address of the issuer to reactivate
     */
    function reactivateIssuer(address issuerAddress) external;

    // ============================================
    // Type Authorization Functions
    // ============================================

    /**
     * @notice Authorize an issuer for a specific claim type
     * @param issuerAddress Address of the issuer
     * @param claimType The claim type to authorize
     */
    function authorizeType(
        address issuerAddress,
        bytes32 claimType
    ) external;

    /**
     * @notice Revoke an issuer's authorization for a claim type
     * @param issuerAddress Address of the issuer
     * @param claimType The claim type to revoke
     */
    function revokeType(
        address issuerAddress,
        bytes32 claimType
    ) external;

    /**
     * @notice Batch authorize multiple claim types for an issuer
     * @param issuerAddress Address of the issuer
     * @param claimTypes Array of claim types to authorize
     */
    function batchAuthorizeTypes(
        address issuerAddress,
        bytes32[] calldata claimTypes
    ) external;

    // ============================================
    // Delegate Management Functions
    // ============================================

    /**
     * @notice Add a delegate signer for an issuer (called by issuer)
     * @param delegate Address to add as delegate
     */
    function addDelegate(address delegate) external;

    /**
     * @notice Remove a delegate signer (called by issuer)
     * @param delegate Address to remove as delegate
     */
    function removeDelegate(address delegate) external;

    // ============================================
    // Reputation Functions
    // ============================================

    /**
     * @notice Adjust an issuer's reputation score
     * @param issuerAddress Address of the issuer
     * @param delta Amount to adjust (positive or negative)
     * @param reason Reason for adjustment
     */
    function adjustReputation(
        address issuerAddress,
        int256 delta,
        string calldata reason
    ) external;

    /**
     * @notice Record that an issuer minted a credential
     * @param issuerAddress Address of the issuer
     */
    function recordIssuance(address issuerAddress) external;

    /**
     * @notice Record that an issuer revoked a credential
     * @param issuerAddress Address of the issuer
     */
    function recordRevocation(address issuerAddress) external;

    /**
     * @notice Record that a credential was disputed
     * @param issuerAddress Address of the issuer
     */
    function recordDispute(address issuerAddress) external;

    // ============================================
    // Query Functions
    // ============================================

    /**
     * @notice Check if an issuer is authorized for a claim type
     * @param issuerAddress Address to check
     * @param claimType Claim type to check authorization for
     * @return authorized True if issuer can issue this claim type
     */
    function isAuthorized(
        address issuerAddress,
        bytes32 claimType
    ) external view returns (bool authorized);

    /**
     * @notice Check if an address is an issuer or delegate
     * @param signer Address to check
     * @param claimType Claim type to check authorization for
     * @return authorized True if signer can sign for this claim type
     * @return issuerAddress The issuer address (signer or their principal)
     */
    function isAuthorizedSigner(
        address signer,
        bytes32 claimType
    ) external view returns (bool authorized, address issuerAddress);

    /**
     * @notice Get full issuer data
     * @param issuerAddress Address of the issuer
     * @return issuer The issuer struct
     */
    function getIssuer(
        address issuerAddress
    ) external view returns (CredentialTypes.Issuer memory issuer);

    /**
     * @notice Check if issuer meets a reputation threshold
     * @param issuerAddress Address of the issuer
     * @param threshold Required reputation (basis points)
     * @return meets True if reputation >= threshold
     */
    function meetsReputationThreshold(
        address issuerAddress,
        uint256 threshold
    ) external view returns (bool meets);

    /**
     * @notice Get all issuers authorized for a claim type
     * @param claimType The claim type to query
     * @return issuers Array of issuer addresses
     */
    function getIssuersByType(
        bytes32 claimType
    ) external view returns (address[] memory issuers);

    /**
     * @notice Check if an issuer is active
     * @param issuerAddress Address to check
     * @return active True if issuer is active
     */
    function isActive(address issuerAddress) external view returns (bool active);

    /**
     * @notice Check if an address is a delegate for an issuer
     * @param issuerAddress The issuer
     * @param delegate The potential delegate
     * @return isDelegate True if delegate is authorized
     */
    function isDelegate(
        address issuerAddress,
        address delegate
    ) external view returns (bool isDelegate);

    /**
     * @notice Get the minimum reputation required to issue
     * @return minReputation Minimum reputation in basis points
     */
    function getMinReputation() external view returns (uint256 minReputation);

    /**
     * @notice Get the total number of registered issuers
     * @return count Total issuer count
     */
    function totalIssuers() external view returns (uint256 count);
}
