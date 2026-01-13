# Sovereign Credential API Reference

This document provides a comprehensive API reference for the Sovereign Credential smart contracts.

## Contract Addresses

Contract addresses are network-specific. After deployment, addresses can be found in:
- `deployments/<network>-latest.json`

## Core Contracts

### IssuerRegistry

Manages authorized credential issuers and their permissions.

#### Functions

##### `registerIssuer`
```solidity
function registerIssuer(
    address issuerAddress,
    string memory jurisdiction,
    bytes32[] memory authorizedClaimTypes
) external
```
Registers a new credential issuer.
- **Access**: `REGISTRAR_ROLE` or `DEFAULT_ADMIN_ROLE`
- **Parameters**:
  - `issuerAddress`: Address of the issuer
  - `jurisdiction`: Jurisdiction code (e.g., "US-CA", "EU", "GLOBAL")
  - `authorizedClaimTypes`: Array of claim type hashes the issuer can issue

##### `authorizeType`
```solidity
function authorizeType(address issuer, bytes32 claimType) external
```
Authorizes an issuer for a specific claim type.
- **Access**: `REGISTRAR_ROLE` or `DEFAULT_ADMIN_ROLE`

##### `revokeType`
```solidity
function revokeType(address issuer, bytes32 claimType) external
```
Revokes an issuer's authorization for a claim type.
- **Access**: `REGISTRAR_ROLE` or `DEFAULT_ADMIN_ROLE`

##### `suspendIssuer`
```solidity
function suspendIssuer(address issuer) external
```
Suspends an issuer, preventing them from issuing new credentials.
- **Access**: `DEFAULT_ADMIN_ROLE`

##### `reinstateIssuer`
```solidity
function reinstateIssuer(address issuer) external
```
Reinstates a suspended issuer.
- **Access**: `DEFAULT_ADMIN_ROLE`

##### `isAuthorized`
```solidity
function isAuthorized(address issuer, bytes32 claimType) external view returns (bool)
```
Checks if an issuer is authorized for a claim type.

##### `getIssuer`
```solidity
function getIssuer(address issuer) external view returns (IssuerInfo memory)
```
Returns issuer information.

#### Events

```solidity
event IssuerRegistered(address indexed issuer, string jurisdiction);
event IssuerSuspended(address indexed issuer);
event IssuerReinstated(address indexed issuer);
event TypeAuthorized(address indexed issuer, bytes32 indexed claimType);
event TypeRevoked(address indexed issuer, bytes32 indexed claimType);
event ReputationUpdated(address indexed issuer, uint256 newScore);
```

---

### ClaimToken

ERC-721 token representing verifiable credentials.

#### Functions

##### `mint`
```solidity
function mint(
    address subject,
    bytes32 claimType,
    bytes memory encryptedPayload,
    bytes32[] memory commitments,
    uint64 expiresAt
) external returns (uint256 tokenId)
```
Mints a new credential NFT.
- **Access**: Authorized issuer for the claim type
- **Parameters**:
  - `subject`: Address receiving the credential
  - `claimType`: Type of credential (keccak256 hash)
  - `encryptedPayload`: Encrypted credential data
  - `commitments`: Array of Poseidon hash commitments for ZK proofs
  - `expiresAt`: Unix timestamp when credential expires
- **Returns**: The minted token ID

##### `revoke`
```solidity
function revoke(uint256 tokenId, string memory reason) external
```
Revokes a credential (permanent).
- **Access**: Original issuer only

##### `verify`
```solidity
function verify(uint256 tokenId) external view returns (bool)
```
Verifies a credential is valid (active, not expired, issuer active).

##### `getCredential`
```solidity
function getCredential(uint256 tokenId) external view returns (Credential memory)
```
Returns full credential details.

##### `setLifecycleManager`
```solidity
function setLifecycleManager(address manager) external
```
Sets the lifecycle manager contract address.
- **Access**: `DEFAULT_ADMIN_ROLE`

#### Credential Struct

```solidity
struct Credential {
    uint256 tokenId;
    bytes32 claimType;
    address subject;
    address issuer;
    bytes encryptedPayload;
    bytes32[] commitments;
    uint64 issuedAt;
    uint64 expiresAt;
    CredentialStatus status;
}

enum CredentialStatus {
    ACTIVE,
    REVOKED,
    EXPIRED,
    SUSPENDED,
    INHERITED
}
```

#### Events

```solidity
event CredentialMinted(
    uint256 indexed tokenId,
    address indexed subject,
    address indexed issuer,
    bytes32 claimType
);
event CredentialRevoked(uint256 indexed tokenId, string reason);
event CredentialSuspended(uint256 indexed tokenId);
event CredentialReinstated(uint256 indexed tokenId);
event CredentialInherited(uint256 indexed tokenId, address indexed beneficiary);
```

---

### CredentialLifecycleManager

Handles credential renewal, inheritance, and disputes.

#### Functions

##### `requestRenewal`
```solidity
function requestRenewal(uint256 tokenId) external
```
Requests renewal of an expiring credential.
- **Access**: Credential subject

##### `approveRenewal`
```solidity
function approveRenewal(uint256 tokenId, uint64 newExpiresAt) external
```
Approves a renewal request.
- **Access**: Original issuer

##### `setInheritanceDirective`
```solidity
function setInheritanceDirective(
    uint256 tokenId,
    address[] memory beneficiaries,
    uint256[] memory shares,
    bool requiresFIETrigger,
    bytes32 fieIntentHash
) external
```
Sets inheritance instructions for a credential.
- **Access**: Credential subject

##### `executeInheritance`
```solidity
function executeInheritance(uint256 tokenId, bytes memory fieProof) external
```
Executes inheritance transfer.
- **Access**: FIEBridge (if FIE trigger required) or beneficiary

##### `getInheritanceDirective`
```solidity
function getInheritanceDirective(uint256 tokenId)
    external view returns (InheritanceDirective memory)
```
Returns inheritance directive for a credential.

##### `fileDispute`
```solidity
function fileDispute(uint256 tokenId, string memory reason) external
```
Files a dispute against a credential.

##### `resolveDispute`
```solidity
function resolveDispute(uint256 disputeId, bool upheld) external
```
Resolves a pending dispute.
- **Access**: `DISPUTE_RESOLVER_ROLE`

#### Events

```solidity
event RenewalRequested(uint256 indexed tokenId, address indexed subject);
event RenewalApproved(uint256 indexed tokenId, uint64 newExpiresAt);
event InheritanceDirectiveSet(uint256 indexed tokenId, address[] beneficiaries);
event InheritanceExecuted(uint256 indexed tokenId, address indexed beneficiary);
event DisputeFiled(uint256 indexed disputeId, uint256 indexed tokenId, address filer);
event DisputeResolved(uint256 indexed disputeId, bool upheld);
```

---

### ZKDisclosureEngine

Verifies zero-knowledge proofs for selective disclosure.

#### Functions

##### `registerVerifier`
```solidity
function registerVerifier(bytes32 disclosureType, address verifier) external
```
Registers a ZK verifier for a disclosure type.
- **Access**: `DEFAULT_ADMIN_ROLE`

##### `verifyAgeThreshold`
```solidity
function verifyAgeThreshold(
    uint256 tokenId,
    uint256 threshold,
    bool greaterThan,
    bytes calldata proof
) external returns (bool valid)
```
Verifies age threshold proof (e.g., "over 18").
- **Parameters**:
  - `tokenId`: Credential to verify against
  - `threshold`: Age threshold in years
  - `greaterThan`: True for >, false for <
  - `proof`: ZK proof bytes

##### `verifyDateRange`
```solidity
function verifyDateRange(
    uint256 tokenId,
    uint64 start,
    uint64 end,
    bytes calldata proof
) external returns (bool valid)
```
Verifies a date falls within a range.

##### `verifyValueRange`
```solidity
function verifyValueRange(
    uint256 tokenId,
    bytes32 field,
    uint256 min,
    uint256 max,
    bytes calldata proof
) external returns (bool valid)
```
Verifies a numeric value is within bounds.

##### `verifySetMembership`
```solidity
function verifySetMembership(
    uint256 tokenId,
    bytes32 field,
    bytes32 setRoot,
    bytes calldata proof
) external returns (bool valid)
```
Verifies a value is in an allowed set (Merkle proof).

##### `verifyCompound`
```solidity
function verifyCompound(
    uint256 tokenId,
    bytes32[] calldata disclosureTypes,
    bytes calldata publicInputs,
    bytes calldata proof
) external returns (bool valid)
```
Verifies multiple disclosures in a single proof.

##### `isProofUsed`
```solidity
function isProofUsed(bytes32 proofHash) external view returns (bool)
```
Checks if a proof has been used (replay prevention).

#### Disclosure Types

```solidity
bytes32 constant DISCLOSURE_AGE_THRESHOLD = keccak256("AGE_THRESHOLD");
bytes32 constant DISCLOSURE_DATE_RANGE = keccak256("DATE_RANGE");
bytes32 constant DISCLOSURE_VALUE_RANGE = keccak256("VALUE_RANGE");
bytes32 constant DISCLOSURE_SET_MEMBERSHIP = keccak256("SET_MEMBERSHIP");
bytes32 constant DISCLOSURE_EXISTENCE = keccak256("EXISTENCE");
bytes32 constant DISCLOSURE_COMPOUND = keccak256("COMPOUND");
```

#### Events

```solidity
event VerifierRegistered(bytes32 indexed disclosureType, address verifier);
event ProofVerified(uint256 indexed tokenId, bytes32 indexed disclosureType, address verifier);
event ProofRejected(uint256 indexed tokenId, bytes32 indexed disclosureType, string reason);
```

---

### FIEBridge

Bridge to Finite Intent Executor for posthumous credential transfer.

#### Functions

##### `setFIEExecutionAgent`
```solidity
function setFIEExecutionAgent(address agent) external
```
Sets the authorized FIE execution agent.
- **Access**: `DEFAULT_ADMIN_ROLE`

##### `notifyTrigger`
```solidity
function notifyTrigger(bytes32 intentHash, address subject) external
```
Notifies of a FIE trigger event (death notification).
- **Access**: FIE Execution Agent only

##### `executeCredentialInheritance`
```solidity
function executeCredentialInheritance(uint256 tokenId, bytes32 intentHash) external
```
Executes inheritance for a single credential.
- **Access**: FIE Execution Agent only

##### `batchExecuteInheritance`
```solidity
function batchExecuteInheritance(uint256[] calldata tokenIds, bytes32 intentHash) external
```
Executes inheritance for multiple credentials.
- **Access**: FIE Execution Agent only

##### `isTriggerProcessed`
```solidity
function isTriggerProcessed(bytes32 intentHash) external view returns (bool)
```
Checks if a trigger has been processed.

##### `getCredentialsWithFIEInheritance`
```solidity
function getCredentialsWithFIEInheritance(address subject)
    external view returns (uint256[] memory)
```
Returns credentials with FIE-linked inheritance for a subject.

#### Events

```solidity
event FIEAgentUpdated(address indexed agent);
event FIETriggerReceived(bytes32 indexed intentHash, address indexed subject);
event TriggerProcessed(bytes32 indexed intentHash);
event CredentialInheritanceExecuted(
    uint256 indexed tokenId,
    bytes32 indexed intentHash,
    address indexed beneficiary
);
```

---

## Claim Types

Standard claim type identifiers (use `keccak256` of these strings):

| Claim Type | String | Hash |
|------------|--------|------|
| Birth Certificate | `IDENTITY.BIRTH` | `0x7c9a...` |
| Professional License | `LICENSE.PROFESSIONAL` | `0x3b2e...` |
| Driver's License | `LICENSE.OPERATOR` | `0x9f1c...` |
| Degree | `EDUCATION.DEGREE` | `0x4d8a...` |
| Certification | `EDUCATION.CERTIFICATION` | `0x2e7b...` |
| Organization Membership | `MEMBERSHIP.ORGANIZATION` | `0x8c3d...` |

---

## Error Codes

All contracts use custom errors for gas efficiency:

```solidity
error ZeroAddress();
error NotAuthorized();
error CredentialNotActive(uint256 tokenId);
error CredentialExpired(uint256 tokenId);
error IssuerNotActive(address issuer);
error IssuerNotAuthorized(address issuer, bytes32 claimType);
error ProofReplayed(bytes32 proofHash);
error VerifierNotRegistered(bytes32 disclosureType);
error InvalidDisclosureType(bytes32 disclosureType);
error InvalidDisclosureCount(uint256 count);
error InheritanceNotSet(uint256 tokenId);
error InheritanceAlreadyExecuted(bytes32 intentHash);
error FIETriggerInvalid(bytes32 intentHash);
error NotFIEAgent(address caller);
error RenewalNotRequested(uint256 tokenId);
error NotSubject(address caller, uint256 tokenId);
error NotIssuer(address caller, uint256 tokenId);
error EmptyArray();
error OperationNotAllowed();
```

---

## Access Control Roles

All contracts use OpenZeppelin's AccessControl:

```solidity
bytes32 constant DEFAULT_ADMIN_ROLE = 0x00;
bytes32 constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
bytes32 constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");
bytes32 constant CREDENTIAL_CONTRACT_ROLE = keccak256("CREDENTIAL_CONTRACT_ROLE");
bytes32 constant LIFECYCLE_MANAGER_ROLE = keccak256("LIFECYCLE_MANAGER_ROLE");
bytes32 constant DISPUTE_RESOLVER_ROLE = keccak256("DISPUTE_RESOLVER_ROLE");
```

---

## Gas Estimates

| Operation | Estimated Gas |
|-----------|--------------|
| Mint Credential | ~350,000 |
| Revoke Credential | ~50,000 |
| Verify Credential | ~25,000 |
| ZK Proof Verification | ~200,000 |
| Set Inheritance | ~75,000 |
| Execute Inheritance | ~100,000 |
| Register Issuer | ~150,000 |

---

## ABI Files

After compilation, ABI files are located at:
- `artifacts/contracts/<ContractName>.sol/<ContractName>.json`

To extract just the ABI:
```bash
jq '.abi' artifacts/contracts/ClaimToken.sol/ClaimToken.json > ClaimToken.abi.json
```
