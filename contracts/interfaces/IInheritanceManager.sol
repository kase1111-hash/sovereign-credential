// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {CredentialTypes} from "../libraries/CredentialTypes.sol";

/**
 * @title IInheritanceManager
 * @notice Interface for managing credential inheritance, splitting, and disputes
 * @dev Split from ICredentialLifecycleManager — contains all FIE-dependent
 *      inheritance operations. This contract is an optional module that can be
 *      deployed independently of the core credential system.
 */
interface IInheritanceManager {
    // ============================================
    // Events
    // ============================================

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

    /// @notice Emitted when executor access is granted
    event ExecutorAccessGranted(
        uint256 indexed tokenId,
        address indexed executor,
        uint64 expiresAt,
        uint8 permissions
    );

    /// @notice Emitted when executor access is revoked
    event ExecutorAccessRevoked(uint256 indexed tokenId, address indexed executor);

    /// @notice Emitted when inheritance conditions are set
    event InheritanceConditionsSet(uint256 indexed tokenId, uint256 conditionCount);

    /// @notice Emitted when a dispute is filed
    event DisputeFiled(
        uint256 indexed disputeId,
        uint256 indexed tokenId,
        address indexed disputant
    );

    /// @notice Emitted when a dispute is resolved
    event DisputeResolved(uint256 indexed disputeId, uint8 resolution);

    // ============================================
    // Inheritance Directive Functions
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

    // ============================================
    // Inheritance Execution Functions
    // ============================================

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
    // Conditional Inheritance Functions
    // ============================================

    /**
     * @notice Set inheritance conditions for a credential
     * @param tokenId The credential to set conditions for
     * @param conditions Array of inheritance conditions
     */
    function setInheritanceConditions(
        uint256 tokenId,
        CredentialTypes.InheritanceCondition[] calldata conditions
    ) external;

    /**
     * @notice Get inheritance conditions for a credential
     * @param tokenId The credential to query
     * @return conditions Array of inheritance conditions
     */
    function getInheritanceConditions(
        uint256 tokenId
    ) external view returns (CredentialTypes.InheritanceCondition[] memory conditions);

    /**
     * @notice Evaluate if all inheritance conditions are met for a beneficiary
     * @param tokenId The credential
     * @param beneficiary The beneficiary to check
     * @return met True if all conditions are met
     */
    function evaluateConditions(
        uint256 tokenId,
        address beneficiary
    ) external view returns (bool met);

    // ============================================
    // Executor Access Functions
    // ============================================

    /**
     * @notice Grant executor access for estate settlement
     * @param tokenId The credential to grant access to
     * @param executor Address of the executor
     * @param duration Duration of access in seconds
     * @param permissions Permission bitmap
     */
    function grantExecutorAccess(
        uint256 tokenId,
        address executor,
        uint64 duration,
        uint8 permissions
    ) external;

    /**
     * @notice Revoke executor access
     * @param tokenId The credential to revoke access from
     */
    function revokeExecutorAccess(uint256 tokenId) external;

    /**
     * @notice Get executor access details
     * @param tokenId The credential to query
     * @return access The executor access struct
     */
    function getExecutorAccess(
        uint256 tokenId
    ) external view returns (CredentialTypes.ExecutorAccess memory access);

    /**
     * @notice Check if an address has valid executor access
     * @param tokenId The credential
     * @param executor The address to check
     * @param permission The required permission flag
     * @return hasAccess True if access is valid
     */
    function hasExecutorAccess(
        uint256 tokenId,
        address executor,
        uint8 permission
    ) external view returns (bool hasAccess);

    // ============================================
    // Dispute Functions
    // ============================================

    /**
     * @notice File a dispute against inheritance
     * @param tokenId The credential being disputed
     * @param reason Encoded reason for the dispute
     * @return disputeId The ID of the filed dispute
     */
    function fileDispute(
        uint256 tokenId,
        bytes calldata reason
    ) external returns (uint256 disputeId);

    /**
     * @notice Resolve a dispute (admin only)
     * @param disputeId The dispute to resolve
     * @param resolution Resolution outcome (1=upheld, 2=rejected)
     */
    function resolveDispute(uint256 disputeId, uint8 resolution) external;

    /**
     * @notice Get dispute details
     * @param disputeId The dispute to query
     * @return dispute The dispute struct
     */
    function getDispute(
        uint256 disputeId
    ) external view returns (CredentialTypes.InheritanceDispute memory dispute);

    /**
     * @notice Check if a credential has an active dispute
     * @param tokenId The credential to check
     * @return hasDispute True if there's an active dispute
     * @return disputeId The active dispute ID (0 if none)
     */
    function hasActiveDispute(
        uint256 tokenId
    ) external view returns (bool hasDispute, uint256 disputeId);

    /**
     * @notice Record FIE trigger timestamp for dispute window calculation
     * @param tokenId The credential that was triggered
     */
    function recordTrigger(uint256 tokenId) external;

    // ============================================
    // Batch & Query Functions
    // ============================================

    /**
     * @notice Set inheritance directives for multiple credentials
     * @param tokenIds Array of credential token IDs
     * @param directives Array of inheritance directives
     */
    function batchSetInheritance(
        uint256[] calldata tokenIds,
        CredentialTypes.InheritanceDirective[] calldata directives
    ) external;

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
