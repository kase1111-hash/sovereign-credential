# Sovereign Credential Specification v1.0

> Technical specification for custodian-independent verifiable claims as sovereign NFTs

## Table of Contents

1. [Definitions](#1-definitions)
2. [System Requirements](#2-system-requirements)
3. [Data Structures](#3-data-structures)
4. [Smart Contract Specifications](#4-smart-contract-specifications)
5. [Credential Lifecycle](#5-credential-lifecycle)
6. [Zero-Knowledge Disclosure](#6-zero-knowledge-disclosure)
7. [NatLangChain Integration](#7-natlangchain-integration)
8. [FIE Bridge Protocol](#8-fie-bridge-protocol)
9. [Security Requirements](#9-security-requirements)
10. [Formal Invariants](#10-formal-invariants)
11. [Implementation Status](#11-implementation-status)

---

## 1. Definitions

### 1.1 Core Terms

| Term | Definition |
|------|------------|
| **Claim** | An assertion about a subject made by an issuer |
| **Credential** | A claim that has been cryptographically signed and minted as an NFT |
| **Subject** | The entity (person, organization, asset) that a claim describes |
| **Holder** | The current owner of a credential NFT (may differ from subject) |
| **Issuer** | An authorized entity that can create and sign claims |
| **Verifier** | Any party that checks the validity of a credential or disclosure |
| **Disclosure** | A proof derived from a credential that reveals limited information |
| **Commitment** | A cryptographic value that binds to hidden data without revealing it |

### 1.2 Credential States

| State | Description |
|-------|-------------|
| **PENDING** | Credential minted but awaiting issuer confirmation (multi-step issuance) |
| **ACTIVE** | Credential is valid and can be used for verification/disclosure |
| **SUSPENDED** | Temporarily invalid; can be reactivated by issuer |
| **REVOKED** | Permanently invalid; cannot be reactivated |
| **EXPIRED** | Past expiration timestamp; may be renewable |
| **INHERITED** | Transferred via FIE inheritance mechanism |

### 1.3 Claim Types

Claim types are extensible. Initial supported types:

| Type ID | Name | Description |
|---------|------|-------------|
| `0x01` | `IDENTITY_BIRTH` | Birth certificate / proof of birth |
| `0x02` | `IDENTITY_CITIZENSHIP` | Citizenship or nationality |
| `0x03` | `IDENTITY_RESIDENCE` | Proof of address or residence |
| `0x10` | `LICENSE_PROFESSIONAL` | Professional license (medical, legal, etc.) |
| `0x11` | `LICENSE_OPERATOR` | Operator license (driver, pilot, etc.) |
| `0x12` | `LICENSE_CONTRACTOR` | Contractor or trade license |
| `0x20` | `EDUCATION_DEGREE` | Academic degree |
| `0x21` | `EDUCATION_CERTIFICATION` | Professional certification |
| `0x22` | `EDUCATION_COURSE` | Course completion |
| `0x30` | `PROPERTY_DEED` | Real property ownership |
| `0x31` | `PROPERTY_TITLE` | Vehicle or asset title |
| `0x32` | `PROPERTY_LIEN` | Lien or encumbrance record |
| `0x40` | `HEALTH_IMMUNIZATION` | Vaccination record |
| `0x41` | `HEALTH_INSURANCE` | Insurance coverage credential |
| `0x42` | `HEALTH_PRESCRIPTION` | Prescription authorization |
| `0xFF` | `CUSTOM` | Custom claim type (schema in metadata) |

---

## 2. System Requirements

### 2.1 Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-01 | System SHALL mint credentials as ERC721 tokens | MUST |
| FR-02 | System SHALL encrypt credential payloads to holder's public key | MUST |
| FR-03 | System SHALL verify issuer authorization before minting | MUST |
| FR-04 | System SHALL support credential revocation by authorized issuers | MUST |
| FR-05 | System SHALL generate zero-knowledge proofs for selective disclosure | MUST |
| FR-06 | System SHALL verify ZK proofs on-chain | MUST |
| FR-07 | System SHALL track issuer reputation based on credential validity | SHOULD |
| FR-08 | System SHALL support credential renewal before expiration | SHOULD |
| FR-09 | System SHALL integrate with FIE for inheritance transfers | SHOULD |
| FR-10 | System SHALL support batch credential operations | MAY |
| FR-11 | System SHALL support credential delegation | MAY |

### 2.2 Non-Functional Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-01 | Credential minting gas cost | < 500,000 gas |
| NFR-02 | ZK proof verification gas cost | < 300,000 gas |
| NFR-03 | Credential verification latency | < 1 block confirmation |
| NFR-04 | System availability | 99.9% (inherited from chain) |
| NFR-05 | Issuer registry update propagation | < 10 blocks |
| NFR-06 | Maximum credentials per holder | Unlimited |
| NFR-07 | Maximum issuers per claim type | Unlimited |

### 2.3 Constraints

| ID | Constraint |
|----|------------|
| C-01 | All contracts MUST be upgradeable via transparent proxy pattern |
| C-02 | Encryption MUST use ECIES with secp256k1 (Ethereum-compatible) |
| C-03 | ZK circuits MUST be Groth16 or PLONK (verifiable on-chain) |
| C-04 | Metadata MUST be stored on IPFS with on-chain content hash |
| C-05 | Credential payload size MUST NOT exceed 32KB encrypted |
| C-06 | All timestamps MUST be Unix epoch seconds (uint64) |

---

## 3. Data Structures

### 3.1 Credential

```solidity
struct Credential {
    uint256 tokenId;              // ERC721 token ID
    bytes32 claimType;            // Claim type identifier
    address subject;              // Entity the claim describes
    address issuer;               // Issuing authority
    bytes encryptedPayload;       // ECIES-encrypted claim data
    bytes32 payloadHash;          // Keccak256 of plaintext payload
    bytes32[] commitments;        // ZK-compatible commitments for disclosure
    uint64 issuedAt;              // Issuance timestamp
    uint64 expiresAt;             // Expiration timestamp (0 = never)
    uint8 status;                 // CredentialStatus enum
    string metadataURI;           // IPFS URI for schema and display data
}
```

### 3.2 Issuer

```solidity
struct Issuer {
    address issuerAddress;        // Primary signing address
    bytes32[] authorizedTypes;    // Claim types this issuer can create
    string jurisdiction;          // Geographic/legal jurisdiction
    uint256 reputationScore;      // Aggregate reputation (0-10000 basis points)
    uint256 totalIssued;          // Total credentials issued
    uint256 totalRevoked;         // Total credentials revoked
    uint256 totalDisputed;        // Total credentials disputed
    bool isActive;                // Can issue new credentials
    address[] delegates;          // Authorized delegate signers
}
```

### 3.3 Disclosure Request

```solidity
struct DisclosureRequest {
    uint256 credentialId;         // Token ID of credential
    bytes32 disclosureType;       // Type of disclosure requested
    bytes32 predicateHash;        // Hash of predicate being proven
    bytes proof;                  // ZK proof bytes
    uint64 generatedAt;           // Proof generation timestamp
    uint64 validUntil;            // Proof expiration
    address verifier;             // Intended verifier (0x0 = anyone)
}
```

### 3.4 Disclosure Types

```solidity
enum DisclosureType {
    AGE_THRESHOLD,        // Prove age > or < threshold
    DATE_RANGE,           // Prove date within range
    VALUE_RANGE,          // Prove numeric value within range
    SET_MEMBERSHIP,       // Prove value is in allowed set
    EQUALITY,             // Prove value equals public value
    EXISTENCE,            // Prove credential exists and is valid
    COMPOUND              // Multiple disclosures in one proof
}
```

### 3.5 Inheritance Directive

```solidity
struct InheritanceDirective {
    uint256 credentialId;         // Credential to transfer
    address[] beneficiaries;      // Ordered list of beneficiaries
    uint8[] shares;               // Share percentages (for splittable credentials)
    bool requiresFIETrigger;      // Must be triggered by FIE
    bytes32 fieIntentHash;        // Hash of linked FIE intent (if any)
    bytes conditions;             // Encoded additional conditions
}
```

---

## 4. Smart Contract Specifications

### 4.1 ClaimToken

**Inherits:** ERC721, ERC721Enumerable, AccessControl, ReentrancyGuard

#### Roles

| Role | Description |
|------|-------------|
| `DEFAULT_ADMIN_ROLE` | Can grant/revoke other roles |
| `ISSUER_ROLE` | Can mint credentials (checked against IssuerRegistry) |
| `REVOKER_ROLE` | Can revoke credentials (usually same as issuer) |
| `UPGRADER_ROLE` | Can upgrade contract implementation |

#### State Variables

```solidity
mapping(uint256 => Credential) public credentials;
mapping(bytes32 => uint256[]) public credentialsByType;
mapping(address => uint256[]) public credentialsBySubject;
mapping(address => uint256[]) public credentialsByIssuer;
IssuerRegistry public issuerRegistry;
ZKDisclosureEngine public zkEngine;
uint256 private _tokenIdCounter;
```

#### Functions

| Function | Access | Description |
|----------|--------|-------------|
| `mint(Credential, bytes signature)` | ISSUER_ROLE | Mint new credential with issuer signature |
| `batchMint(Credential[], bytes[])` | ISSUER_ROLE | Mint multiple credentials |
| `revoke(uint256 tokenId, string reason)` | REVOKER_ROLE | Revoke credential |
| `suspend(uint256 tokenId, string reason)` | REVOKER_ROLE | Suspend credential |
| `reinstate(uint256 tokenId)` | REVOKER_ROLE | Reinstate suspended credential |
| `renew(uint256 tokenId, uint64 newExpiry, bytes sig)` | ISSUER_ROLE | Extend credential expiration |
| `verify(uint256 tokenId)` | Public | Check credential validity |
| `getCredential(uint256 tokenId)` | Public | Get credential data |
| `isExpired(uint256 tokenId)` | Public | Check expiration status |
| `isRevoked(uint256 tokenId)` | Public | Check revocation status |

#### Events

```solidity
event CredentialMinted(uint256 indexed tokenId, address indexed subject, address indexed issuer, bytes32 claimType);
event CredentialRevoked(uint256 indexed tokenId, address indexed revoker, string reason);
event CredentialSuspended(uint256 indexed tokenId, address indexed suspender, string reason);
event CredentialReinstated(uint256 indexed tokenId, address indexed reinstater);
event CredentialRenewed(uint256 indexed tokenId, uint64 oldExpiry, uint64 newExpiry);
event CredentialTransferred(uint256 indexed tokenId, address indexed from, address indexed to);
```

### 4.2 IssuerRegistry

**Inherits:** AccessControl, ReentrancyGuard

#### Roles

| Role | Description |
|------|-------------|
| `DEFAULT_ADMIN_ROLE` | Can grant/revoke other roles |
| `REGISTRAR_ROLE` | Can register/deactivate issuers |
| `ARBITER_ROLE` | Can resolve disputes and adjust reputation |

#### State Variables

```solidity
mapping(address => Issuer) public issuers;
mapping(bytes32 => address[]) public issuersByType;
mapping(address => mapping(bytes32 => bool)) public typeAuthorization;
uint256 public constant MIN_REPUTATION = 1000;  // 10% minimum to issue
uint256 public constant MAX_REPUTATION = 10000; // 100%
```

#### Functions

| Function | Access | Description |
|----------|--------|-------------|
| `registerIssuer(Issuer)` | REGISTRAR_ROLE | Register new issuer |
| `deactivateIssuer(address)` | REGISTRAR_ROLE | Deactivate issuer |
| `reactivateIssuer(address)` | REGISTRAR_ROLE | Reactivate issuer |
| `authorizeType(address, bytes32)` | REGISTRAR_ROLE | Authorize issuer for claim type |
| `revokeType(address, bytes32)` | REGISTRAR_ROLE | Revoke type authorization |
| `addDelegate(address issuer, address delegate)` | Issuer | Add signing delegate |
| `removeDelegate(address issuer, address delegate)` | Issuer | Remove signing delegate |
| `adjustReputation(address, int256 delta, string reason)` | ARBITER_ROLE | Adjust issuer reputation |
| `isAuthorized(address, bytes32)` | Public | Check issuer authorization |
| `getIssuer(address)` | Public | Get issuer data |
| `meetsReputationThreshold(address, uint256)` | Public | Check reputation level |

#### Events

```solidity
event IssuerRegistered(address indexed issuer, string jurisdiction);
event IssuerDeactivated(address indexed issuer, string reason);
event IssuerReactivated(address indexed issuer);
event TypeAuthorized(address indexed issuer, bytes32 indexed claimType);
event TypeRevoked(address indexed issuer, bytes32 indexed claimType);
event DelegateAdded(address indexed issuer, address indexed delegate);
event DelegateRemoved(address indexed issuer, address indexed delegate);
event ReputationAdjusted(address indexed issuer, int256 delta, uint256 newScore, string reason);
```

### 4.3 ZKDisclosureEngine

**Inherits:** AccessControl

#### State Variables

```solidity
mapping(bytes32 => address) public verifiers;  // disclosureType => verifier contract
mapping(bytes32 => bool) public usedProofs;    // proof hash => used (replay prevention)
ClaimToken public claimToken;
```

#### Functions

| Function | Access | Description |
|----------|--------|-------------|
| `registerVerifier(bytes32 type, address verifier)` | Admin | Register ZK verifier for disclosure type |
| `generateProof(DisclosureRequest) → bytes` | Public | Generate ZK proof (off-chain call) |
| `verifyProof(DisclosureRequest) → bool` | Public | Verify ZK proof on-chain |
| `verifyAgeThreshold(uint256 tokenId, uint256 threshold, bool greaterThan, bytes proof) → bool` | Public | Verify age threshold proof |
| `verifyDateRange(uint256 tokenId, uint64 start, uint64 end, bytes proof) → bool` | Public | Verify date range proof |
| `verifyValueRange(uint256 tokenId, bytes32 field, uint256 min, uint256 max, bytes proof) → bool` | Public | Verify value range proof |
| `verifySetMembership(uint256 tokenId, bytes32 field, bytes32[] set, bytes proof) → bool` | Public | Verify set membership proof |
| `verifyExistence(uint256 tokenId, bytes proof) → bool` | Public | Verify credential existence |
| `markProofUsed(bytes32 proofHash)` | Internal | Prevent proof replay |

#### Events

```solidity
event VerifierRegistered(bytes32 indexed disclosureType, address indexed verifier);
event ProofVerified(uint256 indexed credentialId, bytes32 indexed disclosureType, address indexed verifier);
event ProofRejected(uint256 indexed credentialId, bytes32 indexed disclosureType, string reason);
```

### 4.4 CredentialLifecycleManager

**Inherits:** AccessControl, ReentrancyGuard

#### State Variables

```solidity
ClaimToken public claimToken;
IssuerRegistry public issuerRegistry;
mapping(uint256 => InheritanceDirective) public inheritanceDirectives;
mapping(uint256 => address) public renewalRequests;  // tokenId => requester
```

#### Functions

| Function | Access | Description |
|----------|--------|-------------|
| `requestRenewal(uint256 tokenId)` | Holder | Request credential renewal |
| `approveRenewal(uint256 tokenId, uint64 newExpiry, bytes sig)` | Issuer | Approve renewal request |
| `denyRenewal(uint256 tokenId, string reason)` | Issuer | Deny renewal request |
| `setInheritanceDirective(uint256 tokenId, InheritanceDirective)` | Holder | Set inheritance rules |
| `getInheritanceDirective(uint256 tokenId)` | Public | Get inheritance rules |
| `executeInheritance(uint256 tokenId, bytes fieProof)` | FIEBridge | Execute inheritance transfer |
| `batchTransfer(uint256[] tokenIds, address to)` | Holder | Transfer multiple credentials |

#### Events

```solidity
event RenewalRequested(uint256 indexed tokenId, address indexed requester);
event RenewalApproved(uint256 indexed tokenId, uint64 newExpiry);
event RenewalDenied(uint256 indexed tokenId, string reason);
event InheritanceDirectiveSet(uint256 indexed tokenId, address[] beneficiaries);
event InheritanceExecuted(uint256 indexed tokenId, address indexed beneficiary);
```

### 4.5 FIEBridge

**Inherits:** AccessControl

#### State Variables

```solidity
CredentialLifecycleManager public lifecycleManager;
address public fieExecutionAgent;  // Authorized FIE contract
mapping(bytes32 => bool) public processedTriggers;  // Prevent double execution
```

#### Functions

| Function | Access | Description |
|----------|--------|-------------|
| `setFIEExecutionAgent(address)` | Admin | Set authorized FIE contract |
| `notifyTrigger(bytes32 intentHash, address subject)` | FIE | Notify of death trigger |
| `executeCredentialInheritance(uint256 tokenId, bytes32 intentHash)` | FIE | Execute inheritance |
| `verifyFIEProof(bytes proof) → bool` | Public | Verify FIE execution proof |

#### Events

```solidity
event FIETriggerReceived(bytes32 indexed intentHash, address indexed subject);
event CredentialInheritanceExecuted(uint256 indexed tokenId, bytes32 indexed intentHash, address indexed beneficiary);
```

---

## 5. Credential Lifecycle

### 5.1 State Machine

```
                    ┌─────────────────────────────────────────┐
                    │                                         │
                    ▼                                         │
┌─────────┐    ┌────────┐    ┌─────────┐    ┌─────────┐    ┌──┴──────┐
│ (none)  │───▶│PENDING │───▶│ ACTIVE  │───▶│ EXPIRED │───▶│ RENEWED │
└─────────┘    └────────┘    └────┬────┘    └─────────┘    └─────────┘
    mint()     confirm()          │              │
                                  │              │ renew()
                    ┌─────────────┼──────────────┘
                    │             │
                    ▼             ▼
              ┌───────────┐  ┌─────────┐
              │ SUSPENDED │  │ REVOKED │
              └─────┬─────┘  └─────────┘
                    │             ▲
                    │ reinstate() │
                    ▼             │
              ┌───────────┐       │
              │  ACTIVE   │───────┘
              └───────────┘  revoke()

                    │
                    │ FIE trigger
                    ▼
              ┌───────────┐
              │ INHERITED │
              └───────────┘
```

### 5.2 Transition Rules

| From | To | Trigger | Conditions |
|------|-----|---------|------------|
| (none) | PENDING | `mint()` | Valid issuer signature, multi-step flow |
| (none) | ACTIVE | `mint()` | Valid issuer signature, single-step flow |
| PENDING | ACTIVE | `confirm()` | Issuer confirmation received |
| ACTIVE | SUSPENDED | `suspend()` | Called by authorized revoker |
| ACTIVE | REVOKED | `revoke()` | Called by authorized revoker |
| ACTIVE | EXPIRED | (automatic) | `block.timestamp > expiresAt` |
| SUSPENDED | ACTIVE | `reinstate()` | Called by authorized revoker |
| SUSPENDED | REVOKED | `revoke()` | Called by authorized revoker |
| EXPIRED | ACTIVE | `renew()` | Valid issuer signature, within grace period |
| ACTIVE | INHERITED | FIE trigger | Valid FIE proof, beneficiary designated |

### 5.3 Grace Periods

| Transition | Grace Period | Behavior |
|------------|--------------|----------|
| ACTIVE → EXPIRED | 0 | Immediate on timestamp |
| EXPIRED → renewable | 90 days | Can renew within grace |
| EXPIRED → permanent | After grace | Cannot renew |
| SUSPENDED → auto-revoke | 365 days | Auto-revoke if not resolved |

---

## 6. Zero-Knowledge Disclosure

### 6.1 Circuit Specifications

#### 6.1.1 Age Threshold Circuit

**Public Inputs:**
- `credentialCommitment`: Poseidon hash of credential
- `threshold`: Age threshold (in years)
- `currentTimestamp`: Verifier-provided current time
- `comparisonType`: 0 = greater than, 1 = less than

**Private Inputs:**
- `birthdate`: Unix timestamp of birth
- `credentialData`: Full credential payload
- `salt`: Randomness for commitment

**Constraints:**
1. `credentialCommitment == Poseidon(credentialData, salt)`
2. `age = (currentTimestamp - birthdate) / SECONDS_PER_YEAR`
3. If `comparisonType == 0`: `age > threshold`
4. If `comparisonType == 1`: `age < threshold`

#### 6.1.2 Date Range Circuit

**Public Inputs:**
- `credentialCommitment`
- `rangeStart`: Start of valid range (Unix timestamp)
- `rangeEnd`: End of valid range (Unix timestamp)
- `fieldIndex`: Which date field to check

**Private Inputs:**
- `dateValue`: The actual date value
- `credentialData`
- `salt`

**Constraints:**
1. `credentialCommitment == Poseidon(credentialData, salt)`
2. `dateValue == credentialData[fieldIndex]`
3. `dateValue >= rangeStart`
4. `dateValue <= rangeEnd`

#### 6.1.3 Value Range Circuit

**Public Inputs:**
- `credentialCommitment`
- `minValue`: Minimum acceptable value
- `maxValue`: Maximum acceptable value
- `fieldIndex`: Which numeric field to check

**Private Inputs:**
- `actualValue`
- `credentialData`
- `salt`

**Constraints:**
1. `credentialCommitment == Poseidon(credentialData, salt)`
2. `actualValue == credentialData[fieldIndex]`
3. `actualValue >= minValue`
4. `actualValue <= maxValue`

#### 6.1.4 Set Membership Circuit

**Public Inputs:**
- `credentialCommitment`
- `setRoot`: Merkle root of allowed values
- `fieldIndex`: Which field to check

**Private Inputs:**
- `actualValue`
- `merkleProof`: Path from value to root
- `credentialData`
- `salt`

**Constraints:**
1. `credentialCommitment == Poseidon(credentialData, salt)`
2. `actualValue == credentialData[fieldIndex]`
3. `MerkleVerify(actualValue, merkleProof, setRoot) == true`

### 6.2 Proof Generation Flow

```
┌──────────────────────────────────────────────────────────────────────┐
│                         HOLDER'S DEVICE                              │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Decrypt credential payload with holder's private key             │
│  2. Select disclosure type and parameters                           │
│  3. Generate witness (private inputs)                                │
│  4. Run circuit prover (Groth16/PLONK)                              │
│  5. Output: proof, public inputs                                     │
│                                                                      │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         VERIFIER (ON-CHAIN)                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Receive proof and public inputs                                  │
│  2. Verify credential exists and is ACTIVE                           │
│  3. Verify commitment matches credential's stored commitment         │
│  4. Run circuit verifier                                             │
│  5. Check proof not previously used (replay prevention)              │
│  6. Return verification result                                       │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 6.3 Commitment Scheme

Credentials store Poseidon hash commitments for ZK compatibility:

```
commitment[0] = Poseidon(birthdate, salt_0)           // For age proofs
commitment[1] = Poseidon(issuanceDate, salt_1)        // For issuance proofs
commitment[2] = Poseidon(expirationDate, salt_2)      // For validity proofs
commitment[3] = Poseidon(fieldHash, salt_3)           // For custom field proofs
```

Salts are encrypted in the credential payload, known only to the holder.

---

## 7. NatLangChain Integration

### 7.1 Intent Record Format

Credentials are recorded on NatLangChain as intent records:

```json
{
  "intentType": "CREDENTIAL_ISSUANCE",
  "version": "1.0",
  "timestamp": 1736582400,
  "issuer": {
    "address": "0x...",
    "name": "State of Oregon DMV",
    "jurisdiction": "US-OR"
  },
  "subject": {
    "address": "0x...",
    "identifier": "hashed_ssn_or_equivalent"
  },
  "claim": {
    "type": "LICENSE_OPERATOR",
    "subtype": "DRIVERS_LICENSE",
    "prose": "The State of Oregon certifies that the subject is authorized to operate motor vehicles of class C.",
    "effectiveDate": "2024-01-15",
    "expirationDate": "2032-01-15"
  },
  "credentialTokenId": 12345,
  "payloadHash": "0x...",
  "signature": "0x..."
}
```

### 7.2 Prose-First Principles

Following NatLangChain's prose-first architecture:

1. **Human-readable claims**: The `prose` field contains the natural language statement of the claim
2. **Structured data secondary**: Structured fields support machine processing but prose is authoritative
3. **Intent preservation**: The credential preserves the issuer's intent, not just data points
4. **Semantic searchability**: Claims are indexable by semantic meaning via NatLangChain's lexicon

### 7.3 Cross-Reference Protocol

Credentials can reference other NatLangChain records:

```solidity
struct CrossReference {
    bytes32 recordHash;       // Hash of referenced NatLangChain record
    string relationship;      // "SUPERSEDES", "AMENDS", "SUPPORTS", etc.
    string prose;             // Natural language description of relationship
}
```

---

## 8. FIE Bridge Protocol

### 8.1 Trigger Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  FIE Trigger    │     │   FIE Bridge    │     │  Credential     │
│  Mechanism      │     │                 │     │  Lifecycle      │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │  1. Death trigger     │                       │
         │   confirmed           │                       │
         ├──────────────────────▶│                       │
         │                       │                       │
         │                       │  2. Query credentials │
         │                       │   with inheritance    │
         │                       │   directives          │
         │                       ├──────────────────────▶│
         │                       │                       │
         │                       │  3. Return matching   │
         │                       │◀──────────────────────┤
         │                       │                       │
         │                       │  4. Execute transfers │
         │                       │   to beneficiaries    │
         │                       ├──────────────────────▶│
         │                       │                       │
         │                       │  5. Confirm           │
         │                       │◀──────────────────────┤
         │                       │                       │
         │  6. Log completion    │                       │
         │◀──────────────────────┤                       │
         │                       │                       │
```

### 8.2 Verification Requirements

Before executing inheritance:

1. **FIE trigger verified**: Valid proof from FIE TriggerMechanism
2. **Intent hash matches**: Credential's `fieIntentHash` matches triggered intent
3. **Beneficiary valid**: Beneficiary address is non-zero and not blocked
4. **Credential transferable**: Credential status allows transfer
5. **Not already processed**: Trigger hasn't been processed before

### 8.3 Partial Inheritance

Some credentials support partial inheritance (e.g., property with multiple heirs):

```solidity
// Split credential into multiple tokens
function splitCredential(
    uint256 tokenId,
    address[] beneficiaries,
    uint8[] shares  // Must sum to 100
) external returns (uint256[] newTokenIds);
```

---

## 9. Security Requirements

### 9.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Fraudulent issuance | Issuer registry, reputation system, multi-sig keys |
| Credential theft | Encryption to holder key, transfer restrictions |
| Key compromise (holder) | Social recovery, FIE inheritance fallback |
| Key compromise (issuer) | Key rotation, time-locked issuance, revocation |
| Replay attacks | Proof nonce tracking, expiration timestamps |
| Front-running | Commit-reveal for sensitive operations |
| Oracle manipulation | Multiple oracle sources, dispute resolution |
| Contract upgrade attacks | Timelock, multi-sig, upgrade delay |

### 9.2 Access Control Matrix

| Operation | Admin | Registrar | Issuer | Holder | Public |
|-----------|-------|-----------|--------|--------|--------|
| Register issuer | | ✓ | | | |
| Authorize claim type | | ✓ | | | |
| Mint credential | | | ✓ | | |
| Revoke credential | | | ✓ | | |
| Transfer credential | | | | ✓ | |
| Set inheritance | | | | ✓ | |
| Verify credential | | | | | ✓ |
| Verify ZK proof | | | | | ✓ |
| Upgrade contracts | ✓ | | | | |

### 9.3 Cryptographic Requirements

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| Credential encryption | ECIES (secp256k1) | 128-bit |
| Payload hashing | Keccak256 | 256-bit |
| ZK commitments | Poseidon | ~128-bit |
| ZK proofs | Groth16 / PLONK | 128-bit |
| Signatures | ECDSA (secp256k1) | 128-bit |

---

## 10. Formal Invariants

### 10.1 Safety Invariants

```
INV-01: ∀ credential c: c.status == ACTIVE → isAuthorized(c.issuer, c.claimType)
        "Active credentials must have authorized issuers"

INV-02: ∀ credential c: c.status == REVOKED → ∀ future_time t: c.status == REVOKED
        "Revocation is permanent"

INV-03: ∀ credential c: verify(c) == true → c.status ∈ {ACTIVE, INHERITED}
        "Only active or inherited credentials pass verification"

INV-04: ∀ proof p: verifyProof(p) == true → ¬usedProofs[hash(p)]
        "Proofs cannot be replayed"

INV-05: ∀ credential c: c.holder == c.subject ∨ hasTransferAuthorization(c)
        "Credentials stay with subject unless explicitly transferred"
```

### 10.2 Liveness Invariants

```
INV-06: ∀ renewal request r: ∃ response within RENEWAL_TIMEOUT
        "Renewal requests must be answered"

INV-07: ∀ FIE trigger t: processedWithin(t, INHERITANCE_TIMEOUT)
        "Inheritance executes within bounded time"
```

### 10.3 Economic Invariants

```
INV-08: ∀ issuer i: i.reputationScore >= MIN_REPUTATION → i.canIssue
        "Issuers below reputation threshold cannot issue"

INV-09: totalIssued(i) >= totalRevoked(i) + totalActive(i)
        "Credential accounting is consistent"
```

---

## 11. Implementation Status

### 11.1 Contract Status

**Core contracts (v1.0 scope):**

| Contract | LOC | Status | Tests | Notes |
|----------|-----|--------|-------|-------|
| ClaimToken | 987 | Implemented | Unit + integration + invariant + fuzz | ERC721 credential NFT |
| IssuerRegistry | 670 | Implemented | Unit + integration + invariant | Reputation gating disabled for v1.0 (`MIN_REPUTATION = 0`) |
| ZKDisclosureEngine | 928 | Implemented | Unit + integration | ZK proof management and replay prevention |
| CredentialRenewalManager | 398 | Implemented | Via legacy CLM tests | Extracted from CredentialLifecycleManager (Phase 3) |

**Optional modules (v1.1 scope):**

| Contract | LOC | Status | Notes |
|----------|-----|--------|-------|
| InheritanceManager | ~520 | Implemented | Extracted from CredentialLifecycleManager (Phase 3); depends on FIE |
| FIEBridge | 449 | Implemented | Bridge to external FIE system (not yet in production) |
| CredentialLifecycleManager | 1,204 | Legacy | Monolithic predecessor; superseded by RenewalManager + InheritanceManager |

### 11.2 ZK Circuit Status

| Circuit | Status | Constraints | Proving Time |
|---------|--------|-------------|--------------|
| AgeThreshold | Implemented | ~5,000 | <1s |
| DateRange | Implemented | ~6,000 | <1s |
| ValueRange | Implemented | ~5,500 | <1s |
| SetMembership | Implemented | ~10,000 | <2s |
| Existence | Implemented | - | - |
| Compound (2/3/4) | Implemented | Varies | Varies |

### 11.3 Integration Status

| Integration | Status | Notes |
|-------------|--------|-------|
| SDK Encryption | Implemented | secp256k1 ECDH + HKDF-SHA256 + AES-256-GCM (Phase 1) |
| CI/CD Pipeline | Implemented | `.github/workflows/ci.yml` — compile, test, coverage, lint (Phase 1) |
| Demo Script | Implemented | `scripts/demo.ts` — 7-step E2E flow (Phase 2) |
| Gas Benchmarks | Implemented | `test/gas-benchmark.test.ts` — NFR-01/NFR-02 targets (Phase 4) |
| Testnet Deployment | Pending | Scripts ready; Sepolia deployment not yet executed |
| NatLangChain | Not Started | Depends on NatLangChain v1.0 |
| FIE Bridge | Contract implemented | FIE system not yet in production |
| IPFS Metadata | Not Started | |
| Frontend Wallet | Not Started | |

### 11.4 Milestone Roadmap

| Milestone | Target | Status |
|-----------|--------|--------|
| M1: Core contracts | Q2 2026 | Complete |
| M2: Basic lifecycle | Q2 2026 | Complete |
| M3: ZK circuits (age, range) | Q3 2026 | Complete |
| M4: FIE integration | Q3 2026 | Contract complete, FIE pending |
| M5: Contract refactor (CLM split) | 2026-02-12 | Complete (Phase 3) |
| M6: Production hardening | 2026-02-12 | Complete (Phase 4) |
| M7: Testnet launch | Q4 2026 | Pending — deployment scripts ready |
| M8: Security audit | Q1 2027 | Scope documented in `AUDIT_SCOPE.md` |
| M9: Mainnet launch | Q2 2027 | Not Started |

---

## Appendix A: Error Codes

| Code | Name | Description |
|------|------|-------------|
| `SC001` | `UNAUTHORIZED_ISSUER` | Issuer not authorized for claim type |
| `SC002` | `INVALID_SIGNATURE` | Issuer signature verification failed |
| `SC003` | `CREDENTIAL_NOT_FOUND` | Token ID does not exist |
| `SC004` | `CREDENTIAL_REVOKED` | Credential has been revoked |
| `SC005` | `CREDENTIAL_EXPIRED` | Credential past expiration |
| `SC006` | `CREDENTIAL_SUSPENDED` | Credential currently suspended |
| `SC007` | `INVALID_PROOF` | ZK proof verification failed |
| `SC008` | `PROOF_EXPIRED` | ZK proof past validity window |
| `SC009` | `PROOF_REPLAYED` | ZK proof already used |
| `SC010` | `TRANSFER_UNAUTHORIZED` | Caller cannot transfer credential |
| `SC011` | `INHERITANCE_NOT_SET` | No inheritance directive for credential |
| `SC012` | `FIE_TRIGGER_INVALID` | FIE trigger verification failed |
| `SC013` | `BENEFICIARY_INVALID` | Beneficiary address invalid |
| `SC014` | `RENEWAL_DENIED` | Issuer denied renewal request |
| `SC015` | `REPUTATION_INSUFFICIENT` | Issuer below reputation threshold |

---

## Appendix B: Metadata Schema

Credential metadata stored on IPFS follows this schema:

```json
{
  "$schema": "https://sovereign-credential.io/schema/v1.0/credential.json",
  "name": "Oregon Driver's License",
  "description": "Class C motor vehicle operator license issued by Oregon DMV",
  "image": "ipfs://Qm.../license-template.png",
  "claimType": "LICENSE_OPERATOR",
  "issuer": {
    "name": "Oregon Department of Motor Vehicles",
    "url": "https://www.oregon.gov/odot/dmv",
    "logo": "ipfs://Qm.../oregon-dmv-logo.png"
  },
  "displayFields": [
    { "name": "License Class", "path": "$.class" },
    { "name": "Expiration", "path": "$.expiresAt", "format": "date" },
    { "name": "Endorsements", "path": "$.endorsements", "format": "list" }
  ],
  "disclosureSchemas": {
    "AGE_THRESHOLD": {
      "description": "Prove age above or below threshold",
      "fields": ["birthdate"]
    },
    "LICENSE_VALID": {
      "description": "Prove license is currently valid",
      "fields": ["expiresAt", "status"]
    }
  }
}
```

---

**Specification Version:** 1.0  
**Last Updated:** 2026-02-12  
**Authors:** Kase / Claude collaboration
