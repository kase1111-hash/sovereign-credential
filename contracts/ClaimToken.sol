// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {ERC721Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {ERC721EnumerableUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IClaimToken} from "./interfaces/IClaimToken.sol";
import {IIssuerRegistry} from "./interfaces/IIssuerRegistry.sol";
import {CredentialTypes} from "./libraries/CredentialTypes.sol";
import {ClaimTypes} from "./libraries/ClaimTypes.sol";
import {Errors} from "./libraries/Errors.sol";

/**
 * @title ClaimToken
 * @notice ERC721 NFT representing verifiable credentials
 * @dev Implements SPEC.md Section 4.1
 *
 * Features:
 * - Credentials as transferable/non-transferable NFTs
 * - Issuer signature verification on minting
 * - Status management (active, suspended, revoked, expired)
 * - Indexed queries by subject, issuer, and claim type
 * - Integration with IssuerRegistry for authorization
 */
contract ClaimToken is
    Initializable,
    ERC721Upgradeable,
    ERC721EnumerableUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    IClaimToken
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using EnumerableSet for EnumerableSet.UintSet;

    // ============================================
    // Roles
    // ============================================

    /// @notice Role for upgrading the contract
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice Role for lifecycle manager contract
    bytes32 public constant LIFECYCLE_MANAGER_ROLE = keccak256("LIFECYCLE_MANAGER_ROLE");

    /// @notice Role for FIE bridge contract
    bytes32 public constant FIE_BRIDGE_ROLE = keccak256("FIE_BRIDGE_ROLE");

    // ============================================
    // Storage
    // ============================================

    /// @notice Reference to the IssuerRegistry contract
    IIssuerRegistry public issuerRegistry;

    /// @notice Address of the ZK Disclosure Engine
    address public zkEngine;

    /// @notice Address of the Lifecycle Manager
    address public lifecycleManager;

    /// @notice Address of the FIE Bridge
    address public fieBridge;

    /// @notice Mapping of token ID to credential data
    mapping(uint256 => CredentialData) private _credentials;

    /// @notice Mapping of claim type to token IDs
    mapping(bytes32 => EnumerableSet.UintSet) private _credentialsByType;

    /// @notice Mapping of subject to token IDs
    mapping(address => EnumerableSet.UintSet) private _credentialsBySubject;

    /// @notice Mapping of issuer to token IDs
    mapping(address => EnumerableSet.UintSet) private _credentialsByIssuer;

    /// @notice Counter for token IDs
    uint256 private _tokenIdCounter;

    /// @notice Mapping of signature hash to used status (replay prevention)
    mapping(bytes32 => bool) private _usedSignatures;

    /// @notice Mapping of issuer to nonce for signature validation
    mapping(address => uint256) private _issuerNonces;

    /// @notice Mapping of token ID to split metadata (for split credentials)
    mapping(uint256 => CredentialTypes.SplitMetadata) private _splitMetadata;

    // ============================================
    // Internal Structs
    // ============================================

    /// @dev Internal storage struct for credential data
    struct CredentialData {
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
        bool exists;
    }

    // ============================================
    // Constructor & Initializer
    // ============================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the contract
     * @param _issuerRegistry Address of the IssuerRegistry contract
     */
    function initialize(address _issuerRegistry) public initializer {
        __ERC721_init("SovereignCredential", "SCRED");
        __ERC721Enumerable_init();
        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        if (_issuerRegistry == address(0)) {
            revert Errors.ZeroAddress();
        }

        issuerRegistry = IIssuerRegistry(_issuerRegistry);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);
    }

    // ============================================
    // Minting Functions
    // ============================================

    /**
     * @inheritdoc IClaimToken
     */
    function mint(
        CredentialTypes.MintRequest calldata request,
        bytes calldata signature
    ) external override nonReentrant returns (uint256 tokenId) {
        // Validate request
        _validateMintRequest(request);

        // Verify signature and get issuer
        address issuer = _verifyMintSignature(request, signature);

        // Check issuer authorization
        (bool authorized, address principal) = issuerRegistry.isAuthorizedSigner(
            issuer,
            request.claimType
        );
        if (!authorized) {
            revert Errors.UnauthorizedIssuer(issuer, request.claimType);
        }

        // Use principal as the issuer (in case signer was a delegate)
        address actualIssuer = principal;

        // Mint the token
        tokenId = _mintCredential(request, actualIssuer);

        // Record issuance in registry
        issuerRegistry.recordIssuance(actualIssuer);

        return tokenId;
    }

    /**
     * @inheritdoc IClaimToken
     */
    function batchMint(
        CredentialTypes.MintRequest[] calldata requests,
        bytes[] calldata signatures
    ) external override nonReentrant returns (uint256[] memory tokenIds) {
        if (requests.length != signatures.length) {
            revert Errors.ArrayLengthMismatch(requests.length, signatures.length);
        }
        if (requests.length == 0) {
            revert Errors.EmptyArray();
        }
        if (requests.length > CredentialTypes.MAX_BATCH_SIZE) {
            revert Errors.BatchSizeTooLarge(requests.length, CredentialTypes.MAX_BATCH_SIZE);
        }

        tokenIds = new uint256[](requests.length);

        for (uint256 i = 0; i < requests.length; i++) {
            _validateMintRequest(requests[i]);

            address issuer = _verifyMintSignature(requests[i], signatures[i]);

            (bool authorized, address principal) = issuerRegistry.isAuthorizedSigner(
                issuer,
                requests[i].claimType
            );
            if (!authorized) {
                revert Errors.UnauthorizedIssuer(issuer, requests[i].claimType);
            }

            tokenIds[i] = _mintCredential(requests[i], principal);
            issuerRegistry.recordIssuance(principal);
        }

        return tokenIds;
    }

    /**
     * @dev Internal function to mint a credential
     */
    function _mintCredential(
        CredentialTypes.MintRequest calldata request,
        address issuer
    ) internal returns (uint256 tokenId) {
        _tokenIdCounter++;
        tokenId = _tokenIdCounter;

        // Store credential data
        _credentials[tokenId] = CredentialData({
            claimType: request.claimType,
            subject: request.subject,
            issuer: issuer,
            encryptedPayload: request.encryptedPayload,
            payloadHash: request.payloadHash,
            commitments: request.commitments,
            issuedAt: uint64(block.timestamp),
            expiresAt: request.expiresAt,
            status: uint8(CredentialTypes.CredentialStatus.ACTIVE),
            metadataURI: request.metadataURI,
            exists: true
        });

        // Add to indexes
        _credentialsByType[request.claimType].add(tokenId);
        _credentialsBySubject[request.subject].add(tokenId);
        _credentialsByIssuer[issuer].add(tokenId);

        // Mint the NFT to the subject
        _safeMint(request.subject, tokenId);

        emit CredentialMinted(tokenId, request.subject, issuer, request.claimType);

        return tokenId;
    }

    /**
     * @dev Internal function to mint a credential in PENDING status
     */
    function _mintCredentialPending(
        CredentialTypes.MintRequest calldata request,
        address issuer
    ) internal returns (uint256 tokenId) {
        _tokenIdCounter++;
        tokenId = _tokenIdCounter;

        // Store credential data with PENDING status
        _credentials[tokenId] = CredentialData({
            claimType: request.claimType,
            subject: request.subject,
            issuer: issuer,
            encryptedPayload: request.encryptedPayload,
            payloadHash: request.payloadHash,
            commitments: request.commitments,
            issuedAt: uint64(block.timestamp),
            expiresAt: request.expiresAt,
            status: uint8(CredentialTypes.CredentialStatus.PENDING),
            metadataURI: request.metadataURI,
            exists: true
        });

        // Add to indexes
        _credentialsByType[request.claimType].add(tokenId);
        _credentialsBySubject[request.subject].add(tokenId);
        _credentialsByIssuer[issuer].add(tokenId);

        // Mint the NFT to the subject
        _safeMint(request.subject, tokenId);

        emit CredentialMinted(tokenId, request.subject, issuer, request.claimType);

        return tokenId;
    }

    /**
     * @dev Validate a mint request
     */
    function _validateMintRequest(CredentialTypes.MintRequest calldata request) internal view {
        if (request.subject == address(0)) {
            revert Errors.InvalidSubject();
        }

        if (request.encryptedPayload.length > CredentialTypes.MAX_PAYLOAD_SIZE) {
            revert Errors.PayloadTooLarge(
                request.encryptedPayload.length,
                CredentialTypes.MAX_PAYLOAD_SIZE
            );
        }

        if (!ClaimTypes.isValidClaimType(request.claimType)) {
            revert Errors.UnsupportedClaimType(request.claimType);
        }
    }

    /**
     * @dev Verify the issuer's signature on a mint request
     */
    function _verifyMintSignature(
        CredentialTypes.MintRequest calldata request,
        bytes calldata signature
    ) internal returns (address issuer) {
        // Create message hash
        bytes32 messageHash = keccak256(
            abi.encode(
                request.claimType,
                request.subject,
                request.payloadHash,
                request.expiresAt,
                request.metadataURI,
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
        issuer = ethSignedHash.recover(signature);

        if (issuer == address(0)) {
            revert Errors.InvalidSignature();
        }

        return issuer;
    }

    // ============================================
    // Status Management Functions
    // ============================================

    /**
     * @inheritdoc IClaimToken
     */
    function revoke(uint256 tokenId, string calldata reason) external override {
        _requireCredentialExists(tokenId);

        CredentialData storage cred = _credentials[tokenId];

        // Check caller is the issuer or a delegate of the credential's issuer
        (bool authorized, address principal) = issuerRegistry.isAuthorizedSigner(msg.sender, cred.claimType);
        if (!authorized) {
            revert Errors.UnauthorizedIssuer(msg.sender, cred.claimType);
        }
        // Verify the principal matches the credential's issuer
        // This ensures only the original issuer or their delegates can revoke
        if (principal != cred.issuer && msg.sender != cred.issuer) {
            revert Errors.UnauthorizedIssuer(msg.sender, cred.claimType);
        }

        // Check current status allows revocation
        CredentialTypes.CredentialStatus currentStatus = CredentialTypes.CredentialStatus(
            cred.status
        );
        if (
            currentStatus != CredentialTypes.CredentialStatus.ACTIVE &&
            currentStatus != CredentialTypes.CredentialStatus.SUSPENDED
        ) {
            revert Errors.InvalidStatusTransition(cred.status, uint8(CredentialTypes.CredentialStatus.REVOKED));
        }

        cred.status = uint8(CredentialTypes.CredentialStatus.REVOKED);

        // Record revocation in registry
        issuerRegistry.recordRevocation(cred.issuer);

        emit CredentialRevoked(tokenId, msg.sender, reason);
    }

    /**
     * @inheritdoc IClaimToken
     */
    function suspend(uint256 tokenId, string calldata reason) external override {
        _requireCredentialExists(tokenId);

        CredentialData storage cred = _credentials[tokenId];

        // Check caller is the issuer or a delegate of the credential's issuer
        (bool authorized, address principal) = issuerRegistry.isAuthorizedSigner(msg.sender, cred.claimType);
        if (!authorized) {
            revert Errors.UnauthorizedIssuer(msg.sender, cred.claimType);
        }
        // Verify the principal matches the credential's issuer
        if (principal != cred.issuer && msg.sender != cred.issuer) {
            revert Errors.UnauthorizedIssuer(msg.sender, cred.claimType);
        }

        // Check current status allows suspension
        if (cred.status != uint8(CredentialTypes.CredentialStatus.ACTIVE)) {
            revert Errors.InvalidStatusTransition(cred.status, uint8(CredentialTypes.CredentialStatus.SUSPENDED));
        }

        cred.status = uint8(CredentialTypes.CredentialStatus.SUSPENDED);

        emit CredentialSuspended(tokenId, msg.sender, reason);
    }

    /**
     * @inheritdoc IClaimToken
     */
    function reinstate(uint256 tokenId) external override {
        _requireCredentialExists(tokenId);

        CredentialData storage cred = _credentials[tokenId];

        // Check caller is the issuer or a delegate of the credential's issuer
        (bool authorized, address principal) = issuerRegistry.isAuthorizedSigner(msg.sender, cred.claimType);
        if (!authorized) {
            revert Errors.UnauthorizedIssuer(msg.sender, cred.claimType);
        }
        // Verify the principal matches the credential's issuer
        if (principal != cred.issuer && msg.sender != cred.issuer) {
            revert Errors.UnauthorizedIssuer(msg.sender, cred.claimType);
        }

        // Check current status allows reinstatement
        if (cred.status != uint8(CredentialTypes.CredentialStatus.SUSPENDED)) {
            revert Errors.InvalidStatusTransition(cred.status, uint8(CredentialTypes.CredentialStatus.ACTIVE));
        }

        cred.status = uint8(CredentialTypes.CredentialStatus.ACTIVE);

        emit CredentialReinstated(tokenId, msg.sender);
    }

    /**
     * @inheritdoc IClaimToken
     */
    function markExpired(uint256 tokenId) external override {
        _requireCredentialExists(tokenId);

        CredentialData storage cred = _credentials[tokenId];

        // Must have an expiration set and be past it
        if (cred.expiresAt == 0) {
            revert Errors.CredentialNotExpired(tokenId);
        }
        if (block.timestamp <= cred.expiresAt) {
            revert Errors.CredentialNotExpired(tokenId);
        }

        // Only ACTIVE credentials can be marked expired
        if (cred.status != uint8(CredentialTypes.CredentialStatus.ACTIVE)) {
            revert Errors.InvalidStatusTransition(cred.status, uint8(CredentialTypes.CredentialStatus.EXPIRED));
        }

        cred.status = uint8(CredentialTypes.CredentialStatus.EXPIRED);

        emit CredentialExpired(tokenId, cred.expiresAt);
    }

    /**
     * @inheritdoc IClaimToken
     */
    function mintPending(
        CredentialTypes.MintRequest calldata request,
        bytes calldata signature
    ) external override nonReentrant returns (uint256 tokenId) {
        // Validate request
        _validateMintRequest(request);

        // Verify signature and get issuer
        address issuer = _verifyMintSignature(request, signature);

        // Check issuer authorization
        (bool authorized, address principal) = issuerRegistry.isAuthorizedSigner(
            issuer,
            request.claimType
        );
        if (!authorized) {
            revert Errors.UnauthorizedIssuer(issuer, request.claimType);
        }

        // Use principal as the issuer (in case signer was a delegate)
        address actualIssuer = principal;

        // Mint the credential in PENDING status
        tokenId = _mintCredentialPending(request, actualIssuer);

        return tokenId;
    }

    /**
     * @inheritdoc IClaimToken
     */
    function confirm(uint256 tokenId) external override {
        _requireCredentialExists(tokenId);

        CredentialData storage cred = _credentials[tokenId];

        // Check caller is the issuer or a delegate
        (bool authorized, ) = issuerRegistry.isAuthorizedSigner(msg.sender, cred.claimType);
        if (!authorized) {
            revert Errors.UnauthorizedIssuer(msg.sender, cred.claimType);
        }

        // Check current status is PENDING
        if (cred.status != uint8(CredentialTypes.CredentialStatus.PENDING)) {
            revert Errors.InvalidStatusTransition(cred.status, uint8(CredentialTypes.CredentialStatus.ACTIVE));
        }

        cred.status = uint8(CredentialTypes.CredentialStatus.ACTIVE);

        // Record issuance in registry
        issuerRegistry.recordIssuance(cred.issuer);

        emit CredentialConfirmed(tokenId, msg.sender);
    }

    /**
     * @inheritdoc IClaimToken
     */
    function updateExpiry(
        uint256 tokenId,
        uint64 newExpiry
    ) external override onlyRole(LIFECYCLE_MANAGER_ROLE) {
        _requireCredentialExists(tokenId);

        CredentialData storage cred = _credentials[tokenId];
        uint64 oldExpiry = cred.expiresAt;

        cred.expiresAt = newExpiry;

        // If credential was expired, set back to active
        if (cred.status == uint8(CredentialTypes.CredentialStatus.EXPIRED)) {
            cred.status = uint8(CredentialTypes.CredentialStatus.ACTIVE);
        }

        emit CredentialRenewed(tokenId, oldExpiry, newExpiry);
    }

    /**
     * @inheritdoc IClaimToken
     */
    function markInherited(uint256 tokenId) external override onlyRole(FIE_BRIDGE_ROLE) {
        _requireCredentialExists(tokenId);

        CredentialData storage cred = _credentials[tokenId];
        cred.status = uint8(CredentialTypes.CredentialStatus.INHERITED);
    }

    /**
     * @inheritdoc IClaimToken
     */
    function burn(uint256 tokenId) external override onlyRole(LIFECYCLE_MANAGER_ROLE) {
        _requireCredentialExists(tokenId);

        CredentialData storage cred = _credentials[tokenId];

        // Remove from indexes
        _credentialsByType[cred.claimType].remove(tokenId);
        _credentialsBySubject[cred.subject].remove(tokenId);
        _credentialsByIssuer[cred.issuer].remove(tokenId);

        // Mark as not existing (keep data for audit trail)
        cred.exists = false;

        // Burn the NFT
        _burn(tokenId);
    }

    /**
     * @inheritdoc IClaimToken
     */
    function mintSplit(
        CredentialTypes.Credential calldata original,
        address beneficiary,
        uint8 sharePercentage,
        uint8 splitIndex,
        uint8 totalSplits
    ) external override onlyRole(LIFECYCLE_MANAGER_ROLE) returns (uint256 tokenId) {
        _tokenIdCounter++;
        tokenId = _tokenIdCounter;

        // Store credential data with modified metadata to indicate split
        string memory splitMetadataURI = string(
            abi.encodePacked(
                original.metadataURI,
                "?split=",
                _uint8ToString(splitIndex),
                "&share=",
                _uint8ToString(sharePercentage)
            )
        );

        _credentials[tokenId] = CredentialData({
            claimType: original.claimType,
            subject: beneficiary,
            issuer: original.issuer,
            encryptedPayload: original.encryptedPayload,
            payloadHash: original.payloadHash,
            commitments: original.commitments,
            issuedAt: uint64(block.timestamp),
            expiresAt: original.expiresAt,
            status: uint8(CredentialTypes.CredentialStatus.INHERITED),
            metadataURI: splitMetadataURI,
            exists: true
        });

        // Store split metadata
        _splitMetadata[tokenId] = CredentialTypes.SplitMetadata({
            originalTokenId: original.tokenId,
            sharePercentage: sharePercentage,
            splitIndex: splitIndex,
            totalSplits: totalSplits
        });

        // Add to indexes
        _credentialsByType[original.claimType].add(tokenId);
        _credentialsBySubject[beneficiary].add(tokenId);
        _credentialsByIssuer[original.issuer].add(tokenId);

        // Mint the NFT to the beneficiary
        _safeMint(beneficiary, tokenId);

        emit CredentialMinted(tokenId, beneficiary, original.issuer, original.claimType);

        return tokenId;
    }

    /**
     * @dev Convert uint8 to string for metadata URI
     */
    function _uint8ToString(uint8 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint8 temp = value;
        uint8 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint8(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    // ============================================
    // Verification Functions
    // ============================================

    /**
     * @inheritdoc IClaimToken
     */
    function verify(uint256 tokenId) external view override returns (bool valid) {
        if (!_credentials[tokenId].exists) {
            return false;
        }

        CredentialData storage cred = _credentials[tokenId];

        // Check status
        CredentialTypes.CredentialStatus status = CredentialTypes.CredentialStatus(cred.status);
        if (status != CredentialTypes.CredentialStatus.ACTIVE &&
            status != CredentialTypes.CredentialStatus.INHERITED) {
            return false;
        }

        // Check expiration
        if (cred.expiresAt != 0 && block.timestamp > cred.expiresAt) {
            return false;
        }

        // Check issuer is still authorized
        return issuerRegistry.isAuthorized(cred.issuer, cred.claimType);
    }

    /**
     * @inheritdoc IClaimToken
     */
    function isExpired(uint256 tokenId) external view override returns (bool expired) {
        _requireCredentialExists(tokenId);

        CredentialData storage cred = _credentials[tokenId];
        if (cred.expiresAt == 0) {
            return false; // Never expires
        }
        return block.timestamp > cred.expiresAt;
    }

    /**
     * @inheritdoc IClaimToken
     */
    function isRevoked(uint256 tokenId) external view override returns (bool revoked) {
        _requireCredentialExists(tokenId);
        return _credentials[tokenId].status == uint8(CredentialTypes.CredentialStatus.REVOKED);
    }

    /**
     * @inheritdoc IClaimToken
     */
    function isSuspended(uint256 tokenId) external view override returns (bool suspended) {
        _requireCredentialExists(tokenId);
        return _credentials[tokenId].status == uint8(CredentialTypes.CredentialStatus.SUSPENDED);
    }

    // ============================================
    // Query Functions
    // ============================================

    /**
     * @inheritdoc IClaimToken
     */
    function getCredential(
        uint256 tokenId
    ) external view override returns (CredentialTypes.Credential memory credential) {
        _requireCredentialExists(tokenId);

        CredentialData storage cred = _credentials[tokenId];

        credential = CredentialTypes.Credential({
            tokenId: tokenId,
            claimType: cred.claimType,
            subject: cred.subject,
            issuer: cred.issuer,
            encryptedPayload: cred.encryptedPayload,
            payloadHash: cred.payloadHash,
            commitments: cred.commitments,
            issuedAt: cred.issuedAt,
            expiresAt: cred.expiresAt,
            status: cred.status,
            metadataURI: cred.metadataURI
        });
    }

    /**
     * @inheritdoc IClaimToken
     */
    function getCredentialsBySubject(
        address subject
    ) external view override returns (uint256[] memory tokenIds) {
        uint256 count = _credentialsBySubject[subject].length();
        tokenIds = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            tokenIds[i] = _credentialsBySubject[subject].at(i);
        }
    }

    /**
     * @inheritdoc IClaimToken
     */
    function getCredentialsByType(
        bytes32 claimType
    ) external view override returns (uint256[] memory tokenIds) {
        uint256 count = _credentialsByType[claimType].length();
        tokenIds = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            tokenIds[i] = _credentialsByType[claimType].at(i);
        }
    }

    /**
     * @inheritdoc IClaimToken
     */
    function getCredentialsByIssuer(
        address issuer
    ) external view override returns (uint256[] memory tokenIds) {
        uint256 count = _credentialsByIssuer[issuer].length();
        tokenIds = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            tokenIds[i] = _credentialsByIssuer[issuer].at(i);
        }
    }

    /**
     * @inheritdoc IClaimToken
     */
    function getStatus(
        uint256 tokenId
    ) external view override returns (CredentialTypes.CredentialStatus status) {
        _requireCredentialExists(tokenId);

        CredentialData storage cred = _credentials[tokenId];

        // Check if expired but status not updated
        if (cred.status == uint8(CredentialTypes.CredentialStatus.ACTIVE) &&
            cred.expiresAt != 0 &&
            block.timestamp > cred.expiresAt) {
            return CredentialTypes.CredentialStatus.EXPIRED;
        }

        return CredentialTypes.CredentialStatus(cred.status);
    }

    /**
     * @inheritdoc IClaimToken
     */
    function getCommitments(
        uint256 tokenId
    ) external view override returns (bytes32[] memory commitments) {
        _requireCredentialExists(tokenId);
        return _credentials[tokenId].commitments;
    }

    /**
     * @inheritdoc IClaimToken
     */
    function getSplitMetadata(
        uint256 tokenId
    ) external view override returns (CredentialTypes.SplitMetadata memory metadata) {
        _requireCredentialExists(tokenId);
        return _splitMetadata[tokenId];
    }

    /**
     * @inheritdoc IClaimToken
     */
    function isSplitCredential(uint256 tokenId) external view override returns (bool isSplit) {
        _requireCredentialExists(tokenId);
        return _splitMetadata[tokenId].originalTokenId != 0;
    }

    /**
     * @inheritdoc IClaimToken
     */
    function totalCredentials() external view override returns (uint256 count) {
        return _tokenIdCounter;
    }

    // ============================================
    // Administrative Functions
    // ============================================

    /**
     * @inheritdoc IClaimToken
     */
    function setIssuerRegistry(address registry) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (registry == address(0)) {
            revert Errors.ZeroAddress();
        }
        issuerRegistry = IIssuerRegistry(registry);
    }

    /**
     * @inheritdoc IClaimToken
     */
    function setZKEngine(address engine) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        zkEngine = engine;
    }

    /**
     * @inheritdoc IClaimToken
     */
    function setLifecycleManager(address manager) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (manager != address(0)) {
            _grantRole(LIFECYCLE_MANAGER_ROLE, manager);
        }
        if (lifecycleManager != address(0)) {
            _revokeRole(LIFECYCLE_MANAGER_ROLE, lifecycleManager);
        }
        lifecycleManager = manager;
    }

    /**
     * @notice Set the FIE Bridge address
     * @param bridge Address of the FIE Bridge contract
     */
    function setFIEBridge(address bridge) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (bridge != address(0)) {
            _grantRole(FIE_BRIDGE_ROLE, bridge);
        }
        if (fieBridge != address(0)) {
            _revokeRole(FIE_BRIDGE_ROLE, fieBridge);
        }
        fieBridge = bridge;
    }

    // ============================================
    // Transfer Hooks
    // ============================================

    /**
     * @dev Hook that is called before any token transfer
     * Implements transfer restrictions for non-transferable credentials
     */
    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal virtual override(ERC721Upgradeable, ERC721EnumerableUpgradeable) returns (address) {
        address from = _ownerOf(tokenId);

        // If this is a mint (from == address(0)), allow it
        if (from != address(0)) {
            // Check if credential type is non-transferable
            CredentialData storage cred = _credentials[tokenId];
            if (cred.exists && ClaimTypes.isNonTransferable(cred.claimType)) {
                // Only allow transfers to the original subject (return to owner)
                // or if the credential is inherited
                if (to != cred.subject &&
                    cred.status != uint8(CredentialTypes.CredentialStatus.INHERITED)) {
                    revert Errors.TransferUnauthorized(auth, tokenId);
                }
            }

            // Emit transfer event if not a mint/burn
            if (to != address(0)) {
                emit CredentialTransferred(tokenId, from, to);
            }
        }

        return super._update(to, tokenId, auth);
    }

    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireCredentialExists(tokenId);
        return _credentials[tokenId].metadataURI;
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @dev Require that a credential exists
     */
    function _requireCredentialExists(uint256 tokenId) internal view {
        if (!_credentials[tokenId].exists) {
            revert Errors.CredentialNotFound(tokenId);
        }
    }

    // ============================================
    // Required Overrides
    // ============================================

    function _increaseBalance(
        address account,
        uint128 value
    ) internal virtual override(ERC721Upgradeable, ERC721EnumerableUpgradeable) {
        super._increaseBalance(account, value);
    }

    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        virtual
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
