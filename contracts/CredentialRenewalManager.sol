// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {ICredentialRenewalManager} from "./interfaces/ICredentialRenewalManager.sol";
import {IClaimToken} from "./interfaces/IClaimToken.sol";
import {IIssuerRegistry} from "./interfaces/IIssuerRegistry.sol";
import {CredentialTypes} from "./libraries/CredentialTypes.sol";
import {Errors} from "./libraries/Errors.sol";

/**
 * @title CredentialRenewalManager
 * @notice Manages credential renewal and batch transfers
 * @dev Core lifecycle operations extracted from CredentialLifecycleManager.
 *      Does not depend on FIE or any inheritance subsystem.
 *
 * Features:
 * - Renewal workflow with request/approve/deny pattern
 * - 90-day grace period for expired credential renewal
 * - Batch transfer operations
 */
contract CredentialRenewalManager is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    ICredentialRenewalManager
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using EnumerableSet for EnumerableSet.UintSet;

    // ============================================
    // Roles
    // ============================================

    /// @notice Role for upgrading the contract
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // ============================================
    // Storage
    // ============================================

    /// @notice Reference to the ClaimToken contract
    IClaimToken public claimToken;

    /// @notice Reference to the IssuerRegistry contract
    IIssuerRegistry public issuerRegistry;

    /// @notice Mapping of token ID to renewal request
    mapping(uint256 => CredentialTypes.RenewalRequest) private _renewalRequests;

    /// @notice Set of token IDs with pending renewal requests
    EnumerableSet.UintSet private _pendingRenewals;

    /// @notice Mapping of signature hash to used status (replay prevention)
    mapping(bytes32 => bool) private _usedSignatures;

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
     * @param _issuerRegistry Address of the IssuerRegistry contract
     */
    function initialize(
        address _claimToken,
        address _issuerRegistry
    ) public initializer {
        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        if (_claimToken == address(0) || _issuerRegistry == address(0)) {
            revert Errors.ZeroAddress();
        }

        claimToken = IClaimToken(_claimToken);
        issuerRegistry = IIssuerRegistry(_issuerRegistry);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);
    }

    // ============================================
    // Renewal Functions
    // ============================================

    /// @inheritdoc ICredentialRenewalManager
    function requestRenewal(uint256 tokenId) external override nonReentrant {
        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);

        // Only the holder can request renewal
        address holder = _getCredentialHolder(tokenId);
        if (msg.sender != holder) {
            revert Errors.NotHolder(msg.sender, holder);
        }

        // Check if credential can be renewed
        _validateRenewalEligibility(cred);

        // Check if renewal already requested
        if (_pendingRenewals.contains(tokenId)) {
            revert Errors.RenewalAlreadyRequested(tokenId);
        }

        // Create renewal request
        _renewalRequests[tokenId] = CredentialTypes.RenewalRequest({
            tokenId: tokenId,
            requester: msg.sender,
            requestedAt: uint64(block.timestamp),
            newExpiry: 0 // Set by issuer on approval
        });

        _pendingRenewals.add(tokenId);

        emit RenewalRequested(tokenId, msg.sender);
    }

    /// @inheritdoc ICredentialRenewalManager
    function approveRenewal(
        uint256 tokenId,
        uint64 newExpiry,
        bytes calldata signature
    ) external override nonReentrant {
        // Check renewal request exists
        if (!_pendingRenewals.contains(tokenId)) {
            revert Errors.NoRenewalRequest(tokenId);
        }

        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);

        // Verify caller is authorized issuer
        (bool authorized, ) = issuerRegistry.isAuthorizedSigner(msg.sender, cred.claimType);
        if (!authorized) {
            revert Errors.UnauthorizedIssuer(msg.sender, cred.claimType);
        }

        // Check within grace period if expired
        CredentialTypes.CredentialStatus status = claimToken.getStatus(tokenId);
        if (status == CredentialTypes.CredentialStatus.EXPIRED) {
            _validateWithinGracePeriod(cred.expiresAt);
        }

        // Verify signature
        _verifyRenewalSignature(tokenId, newExpiry, cred.issuer, cred.claimType, signature);

        // New expiry must be in the future
        if (newExpiry <= block.timestamp) {
            revert Errors.OutOfRange(newExpiry, block.timestamp + 1, type(uint64).max);
        }

        // Update credential expiry via ClaimToken
        claimToken.updateExpiry(tokenId, newExpiry);

        // Clean up renewal request
        _renewalRequests[tokenId].newExpiry = newExpiry;
        _pendingRenewals.remove(tokenId);

        emit RenewalApproved(tokenId, newExpiry);
    }

    /// @inheritdoc ICredentialRenewalManager
    function denyRenewal(uint256 tokenId, string calldata reason) external override {
        // Check renewal request exists
        if (!_pendingRenewals.contains(tokenId)) {
            revert Errors.NoRenewalRequest(tokenId);
        }

        CredentialTypes.Credential memory cred = claimToken.getCredential(tokenId);

        // Verify caller is authorized issuer
        (bool authorized, ) = issuerRegistry.isAuthorizedSigner(msg.sender, cred.claimType);
        if (!authorized) {
            revert Errors.UnauthorizedIssuer(msg.sender, cred.claimType);
        }

        // Remove renewal request
        delete _renewalRequests[tokenId];
        _pendingRenewals.remove(tokenId);

        emit RenewalDenied(tokenId, reason);
    }

    /// @inheritdoc ICredentialRenewalManager
    function cancelRenewalRequest(uint256 tokenId) external override {
        // Check renewal request exists
        if (!_pendingRenewals.contains(tokenId)) {
            revert Errors.NoRenewalRequest(tokenId);
        }

        // Only requester can cancel
        CredentialTypes.RenewalRequest memory request = _renewalRequests[tokenId];
        if (msg.sender != request.requester) {
            revert Errors.NotHolder(msg.sender, request.requester);
        }

        // Remove renewal request
        delete _renewalRequests[tokenId];
        _pendingRenewals.remove(tokenId);
    }

    /// @inheritdoc ICredentialRenewalManager
    function getRenewalRequest(
        uint256 tokenId
    ) external view override returns (CredentialTypes.RenewalRequest memory request) {
        return _renewalRequests[tokenId];
    }

    /// @inheritdoc ICredentialRenewalManager
    function hasRenewalRequest(uint256 tokenId) external view override returns (bool pending) {
        return _pendingRenewals.contains(tokenId);
    }

    // ============================================
    // Batch Operations
    // ============================================

    /// @inheritdoc ICredentialRenewalManager
    function batchTransfer(
        uint256[] calldata tokenIds,
        address to
    ) external override nonReentrant {
        if (tokenIds.length == 0) {
            revert Errors.EmptyArray();
        }
        if (to == address(0)) {
            revert Errors.ZeroAddress();
        }

        address from = msg.sender;

        for (uint256 i = 0; i < tokenIds.length; i++) {
            // Verify ownership and transferability
            address holder = _getCredentialHolder(tokenIds[i]);
            if (holder != from) {
                revert Errors.NotHolder(from, holder);
            }

            // Execute the transfer via ClaimToken
            claimToken.safeTransferFrom(from, to, tokenIds[i]);
        }

        emit BatchTransferred(tokenIds, from, to);
    }

    // ============================================
    // Query Functions
    // ============================================

    /// @inheritdoc ICredentialRenewalManager
    function getPendingRenewals() external view override returns (uint256[] memory tokenIds) {
        uint256 count = _pendingRenewals.length();
        tokenIds = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            tokenIds[i] = _pendingRenewals.at(i);
        }
    }

    // ============================================
    // Administrative Functions
    // ============================================

    /// @inheritdoc ICredentialRenewalManager
    function setClaimToken(address _claimToken) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_claimToken == address(0)) {
            revert Errors.ZeroAddress();
        }
        claimToken = IClaimToken(_claimToken);
    }

    /// @inheritdoc ICredentialRenewalManager
    function setIssuerRegistry(address _issuerRegistry) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_issuerRegistry == address(0)) {
            revert Errors.ZeroAddress();
        }
        issuerRegistry = IIssuerRegistry(_issuerRegistry);
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @dev Get the current holder of a credential
     */
    function _getCredentialHolder(uint256 tokenId) internal view returns (address) {
        return address(claimToken) != address(0)
            ? _ownerOfToken(tokenId)
            : address(0);
    }

    /**
     * @dev External call to get token owner (ERC721 ownerOf)
     */
    function _ownerOfToken(uint256 tokenId) internal view returns (address) {
        (bool success, bytes memory data) = address(claimToken).staticcall(
            abi.encodeWithSignature("ownerOf(uint256)", tokenId)
        );
        if (!success || data.length < 32) {
            revert Errors.CredentialNotFound(tokenId);
        }
        return abi.decode(data, (address));
    }

    /**
     * @dev Validate credential is eligible for renewal
     */
    function _validateRenewalEligibility(CredentialTypes.Credential memory cred) internal view {
        CredentialTypes.CredentialStatus status = CredentialTypes.CredentialStatus(cred.status);

        // Can only renew ACTIVE or EXPIRED credentials
        if (status != CredentialTypes.CredentialStatus.ACTIVE &&
            status != CredentialTypes.CredentialStatus.EXPIRED) {
            revert Errors.InvalidCredentialStatus(cred.tokenId, cred.status);
        }

        // If expired, must be within grace period
        if (status == CredentialTypes.CredentialStatus.EXPIRED ||
            (cred.expiresAt != 0 && block.timestamp > cred.expiresAt)) {
            _validateWithinGracePeriod(cred.expiresAt);
        }
    }

    /**
     * @dev Validate credential is within renewal grace period
     */
    function _validateWithinGracePeriod(uint64 expiresAt) internal view {
        if (expiresAt == 0) {
            return;
        }

        uint64 gracePeriodEnd = expiresAt + CredentialTypes.RENEWAL_GRACE_PERIOD;
        if (block.timestamp > gracePeriodEnd) {
            revert Errors.GracePeriodExpired(0, expiresAt, gracePeriodEnd);
        }
    }

    /**
     * @dev Verify renewal approval signature
     */
    function _verifyRenewalSignature(
        uint256 tokenId,
        uint64 newExpiry,
        address expectedIssuer,
        bytes32 claimType,
        bytes calldata signature
    ) internal {
        bytes32 messageHash = keccak256(
            abi.encode(
                "RENEWAL_APPROVAL",
                tokenId,
                newExpiry,
                block.chainid,
                address(this)
            )
        );

        // Check for replay
        bytes32 sigHash = keccak256(signature);
        if (_usedSignatures[sigHash]) {
            revert Errors.ProofReplayed(sigHash);
        }
        _usedSignatures[sigHash] = true;

        // Recover signer
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedHash.recover(signature);

        // Verify signer is authorized for the issuer and claim type
        (bool authorized, address principal) = issuerRegistry.isAuthorizedSigner(signer, claimType);
        if (!authorized || (principal != expectedIssuer && signer != expectedIssuer)) {
            revert Errors.InvalidSignature();
        }
    }

    // ============================================
    // Required Overrides
    // ============================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
