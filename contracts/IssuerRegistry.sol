// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IIssuerRegistry} from "./interfaces/IIssuerRegistry.sol";
import {CredentialTypes} from "./libraries/CredentialTypes.sol";
import {Errors} from "./libraries/Errors.sol";

/**
 * @title IssuerRegistry
 * @notice Manages authorized credential issuers, their permissions, and reputation
 * @dev Implements SPEC.md Section 4.2
 *
 * Roles:
 * - DEFAULT_ADMIN_ROLE: Can grant/revoke other roles, upgrade contract
 * - REGISTRAR_ROLE: Can register/deactivate issuers, authorize claim types
 * - ARBITER_ROLE: Can resolve disputes and adjust reputation
 * - UPGRADER_ROLE: Can upgrade the contract implementation
 */
contract IssuerRegistry is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    IIssuerRegistry
{
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // ============================================
    // Roles
    // ============================================

    /// @notice Role for registering and managing issuers
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    /// @notice Role for dispute resolution and reputation adjustments
    bytes32 public constant ARBITER_ROLE = keccak256("ARBITER_ROLE");

    /// @notice Role for upgrading the contract
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /// @notice Role for ClaimToken contract to record issuances/revocations
    bytes32 public constant CREDENTIAL_CONTRACT_ROLE = keccak256("CREDENTIAL_CONTRACT_ROLE");

    // ============================================
    // Constants
    // ============================================

    /// @notice Minimum reputation score to issue credentials (10%)
    uint256 public constant MIN_REPUTATION = CredentialTypes.MIN_REPUTATION;

    /// @notice Maximum reputation score (100%)
    uint256 public constant MAX_REPUTATION = CredentialTypes.MAX_REPUTATION;

    /// @notice Initial reputation for new issuers (50%)
    uint256 public constant INITIAL_REPUTATION = CredentialTypes.INITIAL_REPUTATION;

    // ============================================
    // Storage
    // ============================================

    /// @notice Mapping of issuer address to issuer data
    mapping(address => IssuerData) private _issuers;

    /// @notice Mapping of claim type to authorized issuer addresses
    mapping(bytes32 => EnumerableSet.AddressSet) private _issuersByType;

    /// @notice Mapping of issuer to their authorized claim types
    mapping(address => EnumerableSet.Bytes32Set) private _issuerTypes;

    /// @notice Mapping of issuer to their delegate addresses
    mapping(address => EnumerableSet.AddressSet) private _issuerDelegates;

    /// @notice Mapping of delegate to their principal issuer
    mapping(address => address) private _delegateToPrincipal;

    /// @notice Set of all registered issuer addresses
    EnumerableSet.AddressSet private _allIssuers;

    /// @notice Total number of issuers ever registered
    uint256 private _totalRegistered;

    // ============================================
    // Internal Structs
    // ============================================

    /// @dev Internal storage struct for issuer data
    struct IssuerData {
        string jurisdiction;
        uint256 reputationScore;
        uint256 totalIssued;
        uint256 totalRevoked;
        uint256 totalDisputed;
        bool isActive;
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
     * @dev Sets up roles and initial state
     */
    function initialize() public initializer {
        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        // Grant admin role to deployer
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRAR_ROLE, msg.sender);
        _grantRole(ARBITER_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);
    }

    // ============================================
    // Registration Functions
    // ============================================

    /**
     * @inheritdoc IIssuerRegistry
     */
    function registerIssuer(
        address issuerAddress,
        string calldata jurisdiction,
        bytes32[] calldata initialTypes
    ) external override onlyRole(REGISTRAR_ROLE) {
        if (issuerAddress == address(0)) {
            revert Errors.ZeroAddress();
        }
        if (_issuers[issuerAddress].exists) {
            revert Errors.IssuerAlreadyRegistered(issuerAddress);
        }

        // Create issuer record
        _issuers[issuerAddress] = IssuerData({
            jurisdiction: jurisdiction,
            reputationScore: INITIAL_REPUTATION,
            totalIssued: 0,
            totalRevoked: 0,
            totalDisputed: 0,
            isActive: true,
            exists: true
        });

        // Add to global set
        _allIssuers.add(issuerAddress);
        _totalRegistered++;

        // Authorize initial claim types
        for (uint256 i = 0; i < initialTypes.length; i++) {
            _authorizeType(issuerAddress, initialTypes[i]);
        }

        emit IssuerRegistered(issuerAddress, jurisdiction);
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function deactivateIssuer(
        address issuerAddress,
        string calldata reason
    ) external override onlyRole(REGISTRAR_ROLE) {
        _requireIssuerExists(issuerAddress);

        if (!_issuers[issuerAddress].isActive) {
            revert Errors.IssuerNotActive(issuerAddress);
        }

        _issuers[issuerAddress].isActive = false;

        emit IssuerDeactivated(issuerAddress, reason);
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function reactivateIssuer(address issuerAddress) external override onlyRole(REGISTRAR_ROLE) {
        _requireIssuerExists(issuerAddress);

        if (_issuers[issuerAddress].isActive) {
            revert Errors.OperationNotAllowed();
        }

        _issuers[issuerAddress].isActive = true;

        emit IssuerReactivated(issuerAddress);
    }

    // ============================================
    // Type Authorization Functions
    // ============================================

    /**
     * @inheritdoc IIssuerRegistry
     */
    function authorizeType(
        address issuerAddress,
        bytes32 claimType
    ) external override onlyRole(REGISTRAR_ROLE) {
        _requireIssuerExists(issuerAddress);
        _authorizeType(issuerAddress, claimType);
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function revokeType(
        address issuerAddress,
        bytes32 claimType
    ) external override onlyRole(REGISTRAR_ROLE) {
        _requireIssuerExists(issuerAddress);

        bool removed = _issuerTypes[issuerAddress].remove(claimType);
        if (!removed) {
            revert Errors.OperationNotAllowed();
        }

        _issuersByType[claimType].remove(issuerAddress);

        emit TypeRevoked(issuerAddress, claimType);
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function batchAuthorizeTypes(
        address issuerAddress,
        bytes32[] calldata claimTypes
    ) external override onlyRole(REGISTRAR_ROLE) {
        _requireIssuerExists(issuerAddress);

        for (uint256 i = 0; i < claimTypes.length; i++) {
            _authorizeType(issuerAddress, claimTypes[i]);
        }
    }

    /**
     * @dev Internal function to authorize a claim type
     */
    function _authorizeType(address issuerAddress, bytes32 claimType) internal {
        bool added = _issuerTypes[issuerAddress].add(claimType);
        if (added) {
            _issuersByType[claimType].add(issuerAddress);
            emit TypeAuthorized(issuerAddress, claimType);
        }
    }

    // ============================================
    // Delegate Management Functions
    // ============================================

    /**
     * @inheritdoc IIssuerRegistry
     */
    function addDelegate(address delegate) external override {
        address issuerAddress = msg.sender;
        _requireIssuerExists(issuerAddress);
        _requireIssuerActive(issuerAddress);

        if (delegate == address(0)) {
            revert Errors.ZeroAddress();
        }
        if (delegate == issuerAddress) {
            revert Errors.OperationNotAllowed();
        }
        if (_delegateToPrincipal[delegate] != address(0)) {
            revert Errors.DelegateAlreadyExists(_delegateToPrincipal[delegate], delegate);
        }

        _issuerDelegates[issuerAddress].add(delegate);
        _delegateToPrincipal[delegate] = issuerAddress;

        emit DelegateAdded(issuerAddress, delegate);
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function removeDelegate(address delegate) external override {
        address issuerAddress = msg.sender;
        _requireIssuerExists(issuerAddress);

        if (_delegateToPrincipal[delegate] != issuerAddress) {
            revert Errors.DelegateNotFound(issuerAddress, delegate);
        }

        _issuerDelegates[issuerAddress].remove(delegate);
        delete _delegateToPrincipal[delegate];

        emit DelegateRemoved(issuerAddress, delegate);
    }

    // ============================================
    // Reputation Functions
    // ============================================

    /**
     * @inheritdoc IIssuerRegistry
     */
    function adjustReputation(
        address issuerAddress,
        int256 delta,
        string calldata reason
    ) external override onlyRole(ARBITER_ROLE) {
        _requireIssuerExists(issuerAddress);

        uint256 currentScore = _issuers[issuerAddress].reputationScore;
        uint256 newScore;

        if (delta >= 0) {
            newScore = currentScore + uint256(delta);
            if (newScore > MAX_REPUTATION) {
                newScore = MAX_REPUTATION;
            }
        } else {
            // Handle negative delta safely
            // Note: delta == type(int256).min would overflow when negated,
            // but since MAX_REPUTATION is 10000, such extreme values would
            // always result in newScore = 0 anyway
            uint256 absDelta;
            if (delta == type(int256).min) {
                // Special case: can't safely negate type(int256).min
                // This value is so large it will always zero out the score
                absDelta = type(uint256).max;
            } else {
                absDelta = uint256(-delta);
            }

            if (absDelta >= currentScore) {
                newScore = 0;
            } else {
                newScore = currentScore - absDelta;
            }
        }

        _issuers[issuerAddress].reputationScore = newScore;

        emit ReputationAdjusted(issuerAddress, delta, newScore, reason);
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function recordIssuance(address issuerAddress) external override onlyRole(CREDENTIAL_CONTRACT_ROLE) {
        if (_issuers[issuerAddress].exists) {
            _issuers[issuerAddress].totalIssued++;

            emit IssuerStatsUpdated(
                issuerAddress,
                _issuers[issuerAddress].totalIssued,
                _issuers[issuerAddress].totalRevoked,
                _issuers[issuerAddress].totalDisputed
            );
        }
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function recordRevocation(address issuerAddress) external override onlyRole(CREDENTIAL_CONTRACT_ROLE) {
        if (_issuers[issuerAddress].exists) {
            _issuers[issuerAddress].totalRevoked++;

            emit IssuerStatsUpdated(
                issuerAddress,
                _issuers[issuerAddress].totalIssued,
                _issuers[issuerAddress].totalRevoked,
                _issuers[issuerAddress].totalDisputed
            );
        }
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function recordDispute(address issuerAddress) external override onlyRole(ARBITER_ROLE) {
        if (_issuers[issuerAddress].exists) {
            _issuers[issuerAddress].totalDisputed++;

            emit IssuerStatsUpdated(
                issuerAddress,
                _issuers[issuerAddress].totalIssued,
                _issuers[issuerAddress].totalRevoked,
                _issuers[issuerAddress].totalDisputed
            );
        }
    }

    // ============================================
    // Query Functions
    // ============================================

    /**
     * @inheritdoc IIssuerRegistry
     */
    function isAuthorized(
        address issuerAddress,
        bytes32 claimType
    ) external view override returns (bool authorized) {
        if (!_issuers[issuerAddress].exists) {
            return false;
        }
        if (!_issuers[issuerAddress].isActive) {
            return false;
        }
        if (_issuers[issuerAddress].reputationScore < MIN_REPUTATION) {
            return false;
        }
        return _issuerTypes[issuerAddress].contains(claimType);
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function isAuthorizedSigner(
        address signer,
        bytes32 claimType
    ) external view override returns (bool authorized, address issuerAddress) {
        // Check if signer is a direct issuer
        if (_issuers[signer].exists) {
            issuerAddress = signer;
        } else {
            // Check if signer is a delegate
            issuerAddress = _delegateToPrincipal[signer];
        }

        if (issuerAddress == address(0)) {
            return (false, address(0));
        }

        // Check authorization
        if (!_issuers[issuerAddress].isActive) {
            return (false, issuerAddress);
        }
        if (_issuers[issuerAddress].reputationScore < MIN_REPUTATION) {
            return (false, issuerAddress);
        }
        if (!_issuerTypes[issuerAddress].contains(claimType)) {
            return (false, issuerAddress);
        }

        return (true, issuerAddress);
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function getIssuer(
        address issuerAddress
    ) external view override returns (CredentialTypes.Issuer memory issuer) {
        _requireIssuerExists(issuerAddress);

        IssuerData storage data = _issuers[issuerAddress];

        // Build authorized types array
        uint256 typeCount = _issuerTypes[issuerAddress].length();
        bytes32[] memory authorizedTypes = new bytes32[](typeCount);
        for (uint256 i = 0; i < typeCount; i++) {
            authorizedTypes[i] = _issuerTypes[issuerAddress].at(i);
        }

        // Build delegates array
        uint256 delegateCount = _issuerDelegates[issuerAddress].length();
        address[] memory delegates = new address[](delegateCount);
        for (uint256 i = 0; i < delegateCount; i++) {
            delegates[i] = _issuerDelegates[issuerAddress].at(i);
        }

        issuer = CredentialTypes.Issuer({
            issuerAddress: issuerAddress,
            authorizedTypes: authorizedTypes,
            jurisdiction: data.jurisdiction,
            reputationScore: data.reputationScore,
            totalIssued: data.totalIssued,
            totalRevoked: data.totalRevoked,
            totalDisputed: data.totalDisputed,
            isActive: data.isActive,
            delegates: delegates
        });
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function meetsReputationThreshold(
        address issuerAddress,
        uint256 threshold
    ) external view override returns (bool meets) {
        if (!_issuers[issuerAddress].exists) {
            return false;
        }
        return _issuers[issuerAddress].reputationScore >= threshold;
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function getIssuersByType(
        bytes32 claimType
    ) external view override returns (address[] memory issuers) {
        uint256 count = _issuersByType[claimType].length();
        issuers = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            issuers[i] = _issuersByType[claimType].at(i);
        }
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function isActive(address issuerAddress) external view override returns (bool active) {
        if (!_issuers[issuerAddress].exists) {
            return false;
        }
        return _issuers[issuerAddress].isActive;
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function isDelegate(
        address issuerAddress,
        address delegate
    ) external view override returns (bool) {
        return _delegateToPrincipal[delegate] == issuerAddress;
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function getMinReputation() external pure override returns (uint256 minReputation) {
        return MIN_REPUTATION;
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function totalIssuers() external view override returns (uint256 count) {
        return _allIssuers.length();
    }

    // ============================================
    // Additional Query Functions
    // ============================================

    /**
     * @notice Get all registered issuer addresses
     * @return issuers Array of issuer addresses
     */
    function getAllIssuers() external view returns (address[] memory issuers) {
        uint256 count = _allIssuers.length();
        issuers = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            issuers[i] = _allIssuers.at(i);
        }
    }

    /**
     * @notice Get the claim types an issuer is authorized for
     * @param issuerAddress The issuer to query
     * @return types Array of claim type bytes32 values
     */
    function getAuthorizedTypes(address issuerAddress) external view returns (bytes32[] memory types) {
        uint256 count = _issuerTypes[issuerAddress].length();
        types = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            types[i] = _issuerTypes[issuerAddress].at(i);
        }
    }

    /**
     * @notice Get all delegates for an issuer
     * @param issuerAddress The issuer to query
     * @return delegates Array of delegate addresses
     */
    function getDelegates(address issuerAddress) external view returns (address[] memory delegates) {
        uint256 count = _issuerDelegates[issuerAddress].length();
        delegates = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            delegates[i] = _issuerDelegates[issuerAddress].at(i);
        }
    }

    /**
     * @notice Get the principal issuer for a delegate
     * @param delegate The delegate address
     * @return principal The issuer address (or zero if not a delegate)
     */
    function getPrincipal(address delegate) external view returns (address principal) {
        return _delegateToPrincipal[delegate];
    }

    /**
     * @notice Check if an address is a registered issuer
     * @param issuerAddress The address to check
     * @return registered True if registered
     */
    function isRegistered(address issuerAddress) external view returns (bool registered) {
        return _issuers[issuerAddress].exists;
    }

    /**
     * @notice Get issuer reputation score
     * @param issuerAddress The issuer to query
     * @return score The reputation score (0-10000)
     */
    function getReputation(address issuerAddress) external view returns (uint256 score) {
        return _issuers[issuerAddress].reputationScore;
    }

    /**
     * @notice Get issuer statistics
     * @param issuerAddress The issuer to query
     * @return issued Total credentials issued
     * @return revoked Total credentials revoked
     * @return disputed Total credentials disputed
     */
    function getStats(address issuerAddress) external view returns (
        uint256 issued,
        uint256 revoked,
        uint256 disputed
    ) {
        IssuerData storage data = _issuers[issuerAddress];
        return (data.totalIssued, data.totalRevoked, data.totalDisputed);
    }

    // ============================================
    // Internal Functions
    // ============================================

    /**
     * @dev Require that an issuer exists
     */
    function _requireIssuerExists(address issuerAddress) internal view {
        if (!_issuers[issuerAddress].exists) {
            revert Errors.IssuerNotFound(issuerAddress);
        }
    }

    /**
     * @dev Require that an issuer is active
     */
    function _requireIssuerActive(address issuerAddress) internal view {
        if (!_issuers[issuerAddress].isActive) {
            revert Errors.IssuerNotActive(issuerAddress);
        }
    }

    // ============================================
    // Upgrade Authorization
    // ============================================

    /**
     * @dev Authorize contract upgrades
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}
}
