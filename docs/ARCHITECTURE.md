# Sovereign Credential Architecture

This document describes the technical architecture of the Sovereign Credential system.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SOVEREIGN CREDENTIAL SYSTEM                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────────┐ │
│  │   Issuers   │───▶│ ClaimToken  │◀───│  Credential Holders         │ │
│  │ (Minting)   │    │   (ERC-721) │    │  (Ownership/Disclosure)     │ │
│  └─────────────┘    └──────┬──────┘    └─────────────────────────────┘ │
│         │                  │                         │                 │
│         ▼                  ▼                         ▼                 │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────────────────┐│
│  │  Issuer     │    │  Lifecycle   │    │    ZKDisclosureEngine       ││
│  │  Registry   │    │   Manager    │    │  (Selective Disclosure)     ││
│  └─────────────┘    └──────────────┘    └─────────────────────────────┘│
│                            │                         │                 │
│                            ▼                         ▼                 │
│                     ┌─────────────┐          ┌─────────────┐          │
│                     │  FIEBridge  │          │ ZK Verifiers│          │
│                     │ (Inheritance)│          │  (Groth16)  │          │
│                     └─────────────┘          └─────────────┘          │
│                            │                                           │
│                            ▼                                           │
│                     ┌─────────────┐                                    │
│                     │     FIE     │                                    │
│                     │   (Oracle)  │                                    │
│                     └─────────────┘                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. IssuerRegistry

**Purpose**: Manages authorized credential issuers and their permissions.

**Key Features**:
- Issuer registration and authorization
- Claim type permissions
- Reputation tracking
- Suspension/reinstatement

**Storage**:
```solidity
mapping(address => IssuerInfo) public issuers;
mapping(address => mapping(bytes32 => bool)) public authorizedTypes;
```

**Interactions**:
- ClaimToken queries authorization before minting
- CredentialLifecycleManager checks issuer status
- Admin manages issuer lifecycle

### 2. ClaimToken (ERC-721)

**Purpose**: Represents credentials as non-fungible tokens.

**Key Features**:
- ERC-721 compliance
- Credential minting by authorized issuers
- Revocation by issuer
- Verification function
- Soulbound (non-transferable except inheritance)

**Storage**:
```solidity
mapping(uint256 => Credential) public credentials;
uint256 public nextTokenId;
IIssuerRegistry public issuerRegistry;
```

**Credential Struct**:
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
```

### 3. CredentialLifecycleManager

**Purpose**: Handles credential lifecycle operations beyond issuance.

**Key Features**:
- Renewal requests and approvals
- Inheritance directive management
- Dispute handling
- Status transitions

**Workflows**:

```
Renewal Flow:
Subject ──requestRenewal()──▶ Pending ──approveRenewal()──▶ Extended
                                    └──rejectRenewal()──▶ Unchanged

Inheritance Flow:
Subject ──setInheritanceDirective()──▶ Directive Set
FIE ──notifyTrigger()──▶ FIEBridge ──executeInheritance()──▶ Transferred
```

### 4. ZKDisclosureEngine

**Purpose**: Verifies zero-knowledge proofs for selective disclosure.

**Key Features**:
- Multiple disclosure types
- Proof replay prevention
- Verifier contract registration
- Credential validation integration

**Disclosure Types**:
| Type | Use Case |
|------|----------|
| AGE_THRESHOLD | Prove over/under age |
| DATE_RANGE | Prove date in range |
| VALUE_RANGE | Prove value in bounds |
| SET_MEMBERSHIP | Prove value in set |
| COMPOUND | Multiple disclosures |

**Verification Flow**:
```
1. Receive proof request
2. Verify credential is valid
3. Check proof not replayed
4. Decode proof parameters
5. Call appropriate verifier
6. Mark proof as used
7. Emit result event
```

### 5. FIEBridge

**Purpose**: Bridges to Finite Intent Executor for posthumous credential transfer.

**Key Features**:
- Death trigger notification handling
- Credential inheritance execution
- Double-execution prevention
- FIE proof verification

**Integration**:
```
FIE Oracle ──notifyTrigger()──▶ FIEBridge ──executeInheritance()──▶ LifecycleManager
```

## Data Flows

### Credential Issuance

```
1. Issuer prepares credential data
2. Issuer encrypts payload with subject's key
3. Issuer generates Poseidon hash commitments
4. Issuer calls ClaimToken.mint()
5. ClaimToken verifies issuer authorization (IssuerRegistry)
6. ClaimToken mints NFT to subject
7. Credential stored on-chain
8. Event emitted for indexing
```

### Credential Verification

```
1. Verifier calls ClaimToken.verify(tokenId)
2. ClaimToken checks:
   a. Status is ACTIVE or INHERITED
   b. Not expired (expiresAt > now)
   c. Issuer is still active
   d. Issuer was authorized for claim type
3. Returns true/false
```

### ZK Proof Verification

```
1. Subject generates proof off-chain (using SDK)
2. Verifier calls ZKDisclosureEngine.verifyX()
3. Engine checks credential validity
4. Engine checks proof not replayed
5. Engine decodes proof components
6. Engine calls specific verifier contract
7. Verifier runs Groth16 verification
8. Engine marks proof as used
9. Engine emits result
```

### Inheritance Execution

```
1. Subject sets inheritance directive (LifecycleManager)
2. FIE receives death notification (off-chain)
3. FIE calls FIEBridge.notifyTrigger()
4. FIEBridge validates trigger
5. FIEBridge calls LifecycleManager.executeInheritance()
6. LifecycleManager transfers credential to beneficiary
7. Credential status changes to INHERITED
```

## Upgrade Architecture

All core contracts use UUPS (Universal Upgradeable Proxy Standard):

```
┌────────────────┐      ┌────────────────────┐
│     Proxy      │─────▶│   Implementation   │
│  (Stable Addr) │      │   (Upgradeable)    │
└────────────────┘      └────────────────────┘
        │
        ▼
┌────────────────┐
│    Storage     │
│  (Preserved)   │
└────────────────┘
```

**Upgrade Process**:
1. Deploy new implementation
2. Call `upgradeToAndCall(newImpl, data)`
3. Proxy points to new implementation
4. Storage preserved

**Upgrade Guards**:
- Only UPGRADER_ROLE can upgrade
- OpenZeppelin upgrade-safety checks
- Implementation has `_disableInitializers()`

## Security Model

### Access Control

```
┌─────────────────────────────────────────────────────────────────┐
│                        ROLE HIERARCHY                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  DEFAULT_ADMIN_ROLE                                             │
│       │                                                         │
│       ├───▶ UPGRADER_ROLE (can upgrade contracts)              │
│       │                                                         │
│       ├───▶ REGISTRAR_ROLE (can register issuers)              │
│       │                                                         │
│       └───▶ DISPUTE_RESOLVER_ROLE (can resolve disputes)       │
│                                                                 │
│  CREDENTIAL_CONTRACT_ROLE (ClaimToken in IssuerRegistry)       │
│                                                                 │
│  LIFECYCLE_MANAGER_ROLE (LifecycleManager in ClaimToken)       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| INV-01 | Active credentials have authorized issuers | Checked at mint |
| INV-02 | Revocation is permanent | No status transition from REVOKED |
| INV-03 | Only ACTIVE/INHERITED pass verification | verify() logic |
| INV-04 | Proofs cannot be replayed | usedProofs mapping |
| INV-05 | Non-transferable except inheritance | _update() override |
| INV-06 | Renewal within timeout | Block-based deadline |
| INV-07 | Inheritance executes once | processedTriggers mapping |
| INV-08 | Below-reputation issuers cannot issue | mintGuard modifier |
| INV-09 | Credential accounting consistent | totalSupply tracking |

## ZK Circuit Architecture

### Circuit Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                      ZK CIRCUIT LAYERS                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Private Inputs                                            │ │
│  │  • Credential data (birthdate, values, etc.)               │ │
│  │  • Salt for commitment                                     │ │
│  │  • Merkle proof path (for set membership)                  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                             │                                   │
│                             ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Circuit Logic                                             │ │
│  │  • Poseidon hash commitment verification                   │ │
│  │  • Comparator circuits (for thresholds/ranges)             │ │
│  │  • Merkle tree verification (for set membership)           │ │
│  └────────────────────────────────────────────────────────────┘ │
│                             │                                   │
│                             ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Public Outputs                                            │ │
│  │  • Commitment (matches on-chain)                           │ │
│  │  • Threshold/range parameters                              │ │
│  │  • Verification result (implicit in valid proof)           │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Available Circuits

| Circuit | Public Signals | Private Inputs |
|---------|---------------|----------------|
| AgeThreshold | commitment, threshold, timestamp, comparisonType | birthdate, salt |
| DateRange | commitment, rangeStart, rangeEnd | date, salt |
| ValueRange | commitment, min, max | value, salt |
| SetMembership | commitment, merkleRoot | value, salt, merkleProof |
| CompoundProof | commitment, type[N], params[N*4] | values[N], salts[N] |

## Deployment Architecture

### Contract Deployment Order

```
1. IssuerRegistry (no dependencies)
        │
        ▼
2. ClaimToken (depends on IssuerRegistry)
        │
        ▼
3. CredentialLifecycleManager (depends on ClaimToken, IssuerRegistry)
        │
        ▼
4. ZKDisclosureEngine (depends on ClaimToken)
        │
        ▼
5. FIEBridge (depends on CredentialLifecycleManager)
        │
        ▼
6. ZK Verifiers (standalone)
        │
        ▼
7. Cross-reference configuration
        │
        ▼
8. Verifier registration
```

### Network Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                         PRODUCTION                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Mainnet / NatLangChain                                         │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐       │
│  │ Contract  │ │ Contract  │ │ Contract  │ │ Contract  │       │
│  │  Proxies  │ │  Impls    │ │ Verifiers │ │  Admin    │       │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘       │
│                                                                 │
│  Multisig controls: Admin role, Upgrader role                   │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                         TESTNET                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Sepolia                                                        │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐                     │
│  │ Contract  │ │  Test     │ │  Test     │                     │
│  │  Proxies  │ │  Issuers  │ │  Data     │                     │
│  └───────────┘ └───────────┘ └───────────┘                     │
│                                                                 │
│  Dev wallet controls all roles                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## External Integrations

### FIE (Finite Intent Executor)

```
┌────────────────────────────────────────────────────────────────┐
│                    FIE INTEGRATION                             │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌───────────┐         ┌───────────┐         ┌───────────┐    │
│  │   User    │───▶     │    FIE    │───▶     │ FIEBridge │    │
│  │  Intent   │         │  Oracle   │         │ Contract  │    │
│  └───────────┘         └───────────┘         └───────────┘    │
│       │                      │                      │          │
│  Records intent       Monitors for          Executes          │
│  on NatLangChain      trigger event        inheritance        │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### IPFS (Metadata Storage)

```
┌────────────────────────────────────────────────────────────────┐
│                    IPFS INTEGRATION                            │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  On-Chain                          Off-Chain                   │
│  ┌───────────┐                     ┌───────────┐              │
│  │ ClaimToken│                     │   IPFS    │              │
│  │ tokenURI  │─────────────────────│  Gateway  │              │
│  └───────────┘                     └───────────┘              │
│       │                                  │                     │
│  Returns IPFS CID                  Serves metadata             │
│  ipfs://Qm...                      JSON with details           │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

## Performance Characteristics

| Operation | Gas Cost | Latency |
|-----------|----------|---------|
| Mint | ~350,000 | 1 block |
| Revoke | ~50,000 | 1 block |
| Verify | ~25,000 | View call |
| ZK Verify | ~200,000 | 1 block |
| Set Inheritance | ~75,000 | 1 block |
| Execute Inheritance | ~100,000 | 1 block |

## Monitoring & Observability

### Key Events

```solidity
// Track issuance
event CredentialMinted(tokenId, subject, issuer, claimType);

// Track verification
event ProofVerified(tokenId, disclosureType, verifier);
event ProofRejected(tokenId, disclosureType, reason);

// Track lifecycle
event CredentialRevoked(tokenId, reason);
event InheritanceExecuted(tokenId, beneficiary);

// Track issuer changes
event IssuerRegistered(issuer, jurisdiction);
event ReputationUpdated(issuer, newScore);
```

### Metrics to Monitor

- Credentials minted per day
- Verification success rate
- ZK proof verification rate
- Active issuer count
- Revocation rate
- Gas usage trends
