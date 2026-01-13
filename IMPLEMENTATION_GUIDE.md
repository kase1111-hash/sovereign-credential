# Sovereign Credential Implementation Guide

> A 20-step guide to building custodian-independent verifiable claims as sovereign NFTs

---

## Overview

This guide breaks the Sovereign Credential system into 20 workable chunks, organized into 6 phases. Each step builds on the previous, creating a logical path from project setup to mainnet deployment.

**Estimated Complexity Distribution:**
- 🟢 Low complexity (setup, configuration)
- 🟡 Medium complexity (standard smart contracts)
- 🔴 High complexity (ZK circuits, integrations)

---

## Phase 1: Project Setup & Foundation (Steps 1-4)

### Step 1: Initialize Development Environment 🟢

**Goal:** Set up the Hardhat project with all required dependencies and tooling.

**Tasks:**
- [ ] Initialize npm project with `package.json`
- [ ] Install Hardhat, ethers.js, OpenZeppelin contracts
- [ ] Install ZK tooling (snarkjs, circom)
- [ ] Configure TypeScript for type safety
- [ ] Set up ESLint and Prettier for code quality
- [ ] Create `.env.example` with required environment variables

**Files to Create:**
```
package.json
hardhat.config.ts
tsconfig.json
.eslintrc.js
.prettierrc
.env.example
.gitignore
```

**Dependencies:**
```json
{
  "devDependencies": {
    "@nomicfoundation/hardhat-toolbox": "^4.0.0",
    "@openzeppelin/contracts": "^5.0.0",
    "@openzeppelin/contracts-upgradeable": "^5.0.0",
    "hardhat": "^2.19.0",
    "snarkjs": "^0.7.0",
    "circomlib": "^2.0.0",
    "typescript": "^5.0.0"
  }
}
```

**Verification Criteria:**
- `npm install` completes without errors
- `npx hardhat compile` runs (even with no contracts)
- TypeScript compilation works

---

### Step 2: Define Core Data Structures & Interfaces 🟢

**Goal:** Create Solidity libraries for shared data types and interfaces for all contracts.

**Tasks:**
- [ ] Create `CredentialTypes.sol` with all struct definitions
- [ ] Create `IClaimToken.sol` interface
- [ ] Create `IIssuerRegistry.sol` interface
- [ ] Create `IZKDisclosureEngine.sol` interface
- [ ] Create `ICredentialLifecycleManager.sol` interface
- [ ] Create `IFIEBridge.sol` interface
- [ ] Create `Errors.sol` with custom error definitions

**Files to Create:**
```
contracts/
├── interfaces/
│   ├── IClaimToken.sol
│   ├── IIssuerRegistry.sol
│   ├── IZKDisclosureEngine.sol
│   ├── ICredentialLifecycleManager.sol
│   └── IFIEBridge.sol
├── libraries/
│   ├── CredentialTypes.sol
│   └── Errors.sol
```

**Key Data Structures from Spec:**
```solidity
// CredentialTypes.sol
struct Credential {
    uint256 tokenId;
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
}

enum CredentialStatus {
    PENDING,
    ACTIVE,
    SUSPENDED,
    REVOKED,
    EXPIRED,
    INHERITED
}
```

**Verification Criteria:**
- All interfaces compile without errors
- Structs match spec definitions in Section 3

---

### Step 3: Create Claim Type Constants & Registry Schema 🟢

**Goal:** Define all claim type constants and the metadata schema structure.

**Tasks:**
- [ ] Create `ClaimTypes.sol` with type ID constants (0x01-0xFF)
- [ ] Create metadata JSON schema for IPFS storage
- [ ] Create TypeScript types mirroring Solidity structs
- [ ] Write helper functions for claim type validation

**Files to Create:**
```
contracts/libraries/ClaimTypes.sol
schemas/credential-metadata.schema.json
types/credential.ts
```

**Claim Type Constants (from Spec 1.3):**
```solidity
library ClaimTypes {
    bytes32 constant IDENTITY_BIRTH = bytes32(uint256(0x01));
    bytes32 constant IDENTITY_CITIZENSHIP = bytes32(uint256(0x02));
    bytes32 constant IDENTITY_RESIDENCE = bytes32(uint256(0x03));
    bytes32 constant LICENSE_PROFESSIONAL = bytes32(uint256(0x10));
    bytes32 constant LICENSE_OPERATOR = bytes32(uint256(0x11));
    bytes32 constant LICENSE_CONTRACTOR = bytes32(uint256(0x12));
    bytes32 constant EDUCATION_DEGREE = bytes32(uint256(0x20));
    bytes32 constant EDUCATION_CERTIFICATION = bytes32(uint256(0x21));
    bytes32 constant EDUCATION_COURSE = bytes32(uint256(0x22));
    bytes32 constant PROPERTY_DEED = bytes32(uint256(0x30));
    bytes32 constant PROPERTY_TITLE = bytes32(uint256(0x31));
    bytes32 constant PROPERTY_LIEN = bytes32(uint256(0x32));
    bytes32 constant HEALTH_IMMUNIZATION = bytes32(uint256(0x40));
    bytes32 constant HEALTH_INSURANCE = bytes32(uint256(0x41));
    bytes32 constant HEALTH_PRESCRIPTION = bytes32(uint256(0x42));
    bytes32 constant CUSTOM = bytes32(uint256(0xFF));
}
```

**Verification Criteria:**
- Constants match spec Section 1.3
- Schema validates against Appendix B example

---

### Step 4: Set Up Testing Infrastructure 🟢

**Goal:** Create the testing framework with fixtures, helpers, and mock contracts.

**Tasks:**
- [ ] Create test fixtures for common scenarios
- [ ] Create mock contracts for external dependencies
- [ ] Set up test helpers for signature generation
- [ ] Create ECIES encryption helpers for tests
- [ ] Set up gas reporting and coverage

**Files to Create:**
```
test/
├── fixtures/
│   ├── credentialFixtures.ts
│   └── issuerFixtures.ts
├── helpers/
│   ├── signatures.ts
│   ├── encryption.ts
│   └── time.ts
├── mocks/
│   └── MockFIE.sol
```

**Key Test Helpers:**
```typescript
// helpers/signatures.ts
export async function signCredential(
  issuer: Signer,
  credential: Credential
): Promise<string> {
  const hash = hashCredential(credential);
  return issuer.signMessage(ethers.getBytes(hash));
}

// helpers/encryption.ts
export function encryptPayload(
  payload: string,
  holderPublicKey: string
): string {
  // ECIES encryption
}
```

**Verification Criteria:**
- `npx hardhat test` runs (even with no tests)
- Fixtures can be imported without errors
- Coverage reporting configured

---

## Phase 2: Core Contracts (Steps 5-9)

### Step 5: Implement IssuerRegistry Contract 🟡

**Goal:** Build the issuer management system with registration, authorization, and reputation tracking.

**Tasks:**
- [ ] Implement `IssuerRegistry.sol` with AccessControl
- [ ] Add issuer registration with REGISTRAR_ROLE
- [ ] Add claim type authorization system
- [ ] Implement delegate management for issuers
- [ ] Add reputation scoring system (0-10000 basis points)
- [ ] Implement reputation threshold checks
- [ ] Write comprehensive unit tests

**Files to Create:**
```
contracts/IssuerRegistry.sol
test/IssuerRegistry.test.ts
```

**Key Functions (from Spec 4.2):**
```solidity
function registerIssuer(Issuer memory issuer) external onlyRole(REGISTRAR_ROLE);
function deactivateIssuer(address issuer) external onlyRole(REGISTRAR_ROLE);
function authorizeType(address issuer, bytes32 claimType) external onlyRole(REGISTRAR_ROLE);
function revokeType(address issuer, bytes32 claimType) external onlyRole(REGISTRAR_ROLE);
function addDelegate(address delegate) external; // Called by issuer
function adjustReputation(address issuer, int256 delta, string reason) external onlyRole(ARBITER_ROLE);
function isAuthorized(address issuer, bytes32 claimType) external view returns (bool);
function meetsReputationThreshold(address issuer, uint256 threshold) external view returns (bool);
```

**State Variables:**
```solidity
mapping(address => Issuer) public issuers;
mapping(bytes32 => address[]) public issuersByType;
mapping(address => mapping(bytes32 => bool)) public typeAuthorization;
uint256 public constant MIN_REPUTATION = 1000;
uint256 public constant MAX_REPUTATION = 10000;
```

**Test Cases:**
- Register issuer successfully
- Reject unauthorized registration
- Authorize/revoke claim types
- Delegate management
- Reputation adjustments (positive and negative)
- Reputation threshold enforcement

**Verification Criteria:**
- All functions match spec 4.2
- Events emitted correctly
- Access control enforced
- 100% test coverage

---

### Step 6: Implement ClaimToken Contract (ERC721 Base) 🟡

**Goal:** Build the core credential NFT with minting, storage, and basic verification.

**Tasks:**
- [ ] Implement ERC721 with Enumerable extension
- [ ] Add credential storage mapping
- [ ] Implement mint function with issuer verification
- [ ] Add signature verification for issuance
- [ ] Implement basic verify function
- [ ] Add credential getters (by type, subject, issuer)
- [ ] Implement transfer hooks (credential-specific rules)
- [ ] Write comprehensive unit tests

**Files to Create:**
```
contracts/ClaimToken.sol
test/ClaimToken.test.ts
```

**Key Functions (from Spec 4.1):**
```solidity
function mint(
    Credential memory credential,
    bytes memory signature
) external onlyRole(ISSUER_ROLE) returns (uint256);

function batchMint(
    Credential[] memory credentials,
    bytes[] memory signatures
) external onlyRole(ISSUER_ROLE) returns (uint256[] memory);

function verify(uint256 tokenId) external view returns (bool);
function getCredential(uint256 tokenId) external view returns (Credential memory);
function isExpired(uint256 tokenId) external view returns (bool);
function isRevoked(uint256 tokenId) external view returns (bool);
function getCredentialsBySubject(address subject) external view returns (uint256[] memory);
function getCredentialsByType(bytes32 claimType) external view returns (uint256[] memory);
```

**Minting Validation:**
1. Verify issuer is authorized for claim type (via IssuerRegistry)
2. Verify signature is valid from issuer
3. Verify subject address is valid
4. Verify payload hash matches encrypted payload hash
5. Store credential and mint token

**Test Cases:**
- Mint credential with valid signature
- Reject mint from unauthorized issuer
- Reject mint with invalid signature
- Batch minting works correctly
- Verify returns correct status
- Query credentials by subject/type/issuer

**Verification Criteria:**
- ERC721 compliance (transfer, approval, etc.)
- Signature verification works
- Integration with IssuerRegistry
- Gas cost < 500,000 for mint (NFR-01)

---

### Step 7: Add Credential Status Management to ClaimToken 🟡

**Goal:** Implement revocation, suspension, and status transitions per the state machine.

**Tasks:**
- [ ] Implement `revoke()` function
- [ ] Implement `suspend()` function
- [ ] Implement `reinstate()` function
- [ ] Add status transition validation (per state machine)
- [ ] Implement automatic expiration checks
- [ ] Add events for all status changes
- [ ] Update verify() to check all status conditions
- [ ] Write status transition tests

**State Machine Implementation (from Spec 5.1):**
```solidity
function revoke(uint256 tokenId, string calldata reason) external onlyRole(REVOKER_ROLE) {
    Credential storage cred = credentials[tokenId];
    require(
        cred.status == uint8(CredentialStatus.ACTIVE) ||
        cred.status == uint8(CredentialStatus.SUSPENDED),
        Errors.INVALID_STATUS_TRANSITION
    );
    cred.status = uint8(CredentialStatus.REVOKED);
    emit CredentialRevoked(tokenId, msg.sender, reason);
}

function suspend(uint256 tokenId, string calldata reason) external onlyRole(REVOKER_ROLE) {
    Credential storage cred = credentials[tokenId];
    require(cred.status == uint8(CredentialStatus.ACTIVE), Errors.INVALID_STATUS_TRANSITION);
    cred.status = uint8(CredentialStatus.SUSPENDED);
    emit CredentialSuspended(tokenId, msg.sender, reason);
}

function reinstate(uint256 tokenId) external onlyRole(REVOKER_ROLE) {
    Credential storage cred = credentials[tokenId];
    require(cred.status == uint8(CredentialStatus.SUSPENDED), Errors.INVALID_STATUS_TRANSITION);
    cred.status = uint8(CredentialStatus.ACTIVE);
    emit CredentialReinstated(tokenId, msg.sender);
}
```

**Test Cases:**
- Revoke active credential
- Revoke suspended credential
- Cannot revoke already revoked credential
- Suspend active credential
- Cannot suspend non-active credential
- Reinstate suspended credential
- Cannot reinstate non-suspended credential
- Expired credential detection

**Verification Criteria:**
- State machine matches Spec 5.1
- INV-02 enforced: revocation is permanent
- All transitions emit correct events

---

### Step 8: Implement CredentialLifecycleManager 🟡

**Goal:** Build the renewal workflow and inheritance directive management.

**Tasks:**
- [ ] Implement renewal request/approval workflow
- [ ] Add grace period handling (90 days for expired)
- [ ] Implement inheritance directive storage
- [ ] Add batch transfer functionality
- [ ] Create events for lifecycle actions
- [ ] Write comprehensive tests

**Files to Create:**
```
contracts/CredentialLifecycleManager.sol
test/CredentialLifecycleManager.test.ts
```

**Key Functions (from Spec 4.4):**
```solidity
function requestRenewal(uint256 tokenId) external;
function approveRenewal(uint256 tokenId, uint64 newExpiry, bytes calldata signature) external;
function denyRenewal(uint256 tokenId, string calldata reason) external;
function setInheritanceDirective(uint256 tokenId, InheritanceDirective calldata directive) external;
function getInheritanceDirective(uint256 tokenId) external view returns (InheritanceDirective memory);
function executeInheritance(uint256 tokenId, bytes calldata fieProof) external;
function batchTransfer(uint256[] calldata tokenIds, address to) external;
```

**Renewal Logic:**
```solidity
function approveRenewal(uint256 tokenId, uint64 newExpiry, bytes calldata signature) external {
    require(renewalRequests[tokenId] != address(0), "No renewal request");

    Credential storage cred = claimToken.getCredential(tokenId);
    require(
        cred.status == uint8(CredentialStatus.EXPIRED) ||
        cred.status == uint8(CredentialStatus.ACTIVE),
        "Cannot renew"
    );

    // Verify within grace period if expired
    if (cred.status == uint8(CredentialStatus.EXPIRED)) {
        require(block.timestamp <= cred.expiresAt + GRACE_PERIOD, "Grace period expired");
    }

    // Verify issuer signature
    // Update credential expiry
    // Emit event
}
```

**Test Cases:**
- Request renewal as holder
- Approve renewal with valid signature
- Deny renewal
- Cannot renew after grace period
- Set and get inheritance directive
- Execute inheritance (basic flow)
- Batch transfer multiple credentials

**Verification Criteria:**
- Grace periods match Spec 5.3
- Only holders can set inheritance
- Renewal requires issuer signature

---

### Step 9: Add Upgradeability via Transparent Proxy 🟡

**Goal:** Make all contracts upgradeable per constraint C-01.

**Tasks:**
- [ ] Refactor ClaimToken to ClaimTokenUpgradeable
- [ ] Refactor IssuerRegistry to IssuerRegistryUpgradeable
- [ ] Refactor CredentialLifecycleManager
- [ ] Use OpenZeppelin Upgrades plugin
- [ ] Create deployment scripts with proxies
- [ ] Add UPGRADER_ROLE access control
- [ ] Write upgrade tests

**Files to Create/Modify:**
```
contracts/
├── ClaimTokenUpgradeable.sol
├── IssuerRegistryUpgradeable.sol
├── CredentialLifecycleManagerUpgradeable.sol
scripts/
├── deploy.ts
├── upgrade.ts
test/
├── upgrades.test.ts
```

**Upgradeable Pattern:**
```solidity
import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract ClaimTokenUpgradeable is
    Initializable,
    ERC721Upgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    function initialize(address issuerRegistry) public initializer {
        __ERC721_init("SovereignCredential", "SCRED");
        __AccessControl_init();
        __UUPSUpgradeable_init();
        // ...
    }

    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}
}
```

**Test Cases:**
- Deploy via proxy
- Upgrade maintains state
- Only UPGRADER_ROLE can upgrade
- Storage layout preserved

**Verification Criteria:**
- All contracts use transparent proxy pattern
- Upgrade path tested and verified
- State preserved across upgrades

---

## Phase 3: Zero-Knowledge Circuits (Steps 10-13)

### Step 10: Set Up Circom Circuit Development Environment 🟡

**Goal:** Configure the ZK circuit development and compilation pipeline.

**Tasks:**
- [ ] Install circom compiler
- [ ] Set up snarkjs for proof generation
- [ ] Create circuit directory structure
- [ ] Set up Powers of Tau ceremony files
- [ ] Create circuit compilation scripts
- [ ] Set up test harness for circuits

**Files to Create:**
```
circuits/
├── lib/
│   ├── poseidon.circom
│   ├── comparators.circom
│   └── merkle.circom
├── compile.sh
├── setup.sh
├── generate_proof.sh
```

**Compilation Script:**
```bash
#!/bin/bash
# compile.sh
circom circuits/$1.circom --r1cs --wasm --sym -o build/
snarkjs groth16 setup build/$1.r1cs pot12_final.ptau build/$1_0000.zkey
snarkjs zkey contribute build/$1_0000.zkey build/$1_final.zkey --name="First contribution"
snarkjs zkey export verificationkey build/$1_final.zkey build/$1_verification_key.json
snarkjs zkey export solidityverifier build/$1_final.zkey contracts/verifiers/$1Verifier.sol
```

**Verification Criteria:**
- circom compiles example circuit
- snarkjs generates proofs
- Verifier contract generated

---

### Step 11: Implement Age Threshold ZK Circuit 🔴

**Goal:** Build the circuit that proves age above/below threshold without revealing birthdate.

**Tasks:**
- [ ] Implement AgeThreshold.circom
- [ ] Add Poseidon commitment verification
- [ ] Add age calculation from birthdate
- [ ] Add comparison (greater than / less than)
- [ ] Generate Solidity verifier
- [ ] Write circuit tests with witness generation
- [ ] Optimize constraint count

**Files to Create:**
```
circuits/AgeThreshold.circom
test/circuits/AgeThreshold.test.ts
contracts/verifiers/AgeThresholdVerifier.sol
```

**Circuit Implementation (from Spec 6.1.1):**
```circom
pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

template AgeThreshold() {
    // Public inputs
    signal input credentialCommitment;
    signal input threshold;
    signal input currentTimestamp;
    signal input comparisonType; // 0 = greater than, 1 = less than

    // Private inputs
    signal input birthdate;
    signal input credentialData[16]; // Flattened credential fields
    signal input salt;

    // Constants
    var SECONDS_PER_YEAR = 31536000;

    // Verify commitment
    component hasher = Poseidon(17);
    for (var i = 0; i < 16; i++) {
        hasher.inputs[i] <== credentialData[i];
    }
    hasher.inputs[16] <== salt;
    credentialCommitment === hasher.out;

    // Calculate age
    signal age;
    age <-- (currentTimestamp - birthdate) / SECONDS_PER_YEAR;

    // Comparison based on type
    component gt = GreaterThan(64);
    gt.in[0] <== age;
    gt.in[1] <== threshold;

    component lt = LessThan(64);
    lt.in[0] <== age;
    lt.in[1] <== threshold;

    // Select based on comparison type
    signal result;
    result <== (1 - comparisonType) * gt.out + comparisonType * lt.out;
    result === 1;
}

component main {public [credentialCommitment, threshold, currentTimestamp, comparisonType]} = AgeThreshold();
```

**Test Cases:**
- Prove age > 18 when age is 25
- Prove age > 18 when age is 17 (should fail)
- Prove age < 65 when age is 40
- Invalid commitment rejected
- Proof verification on-chain

**Verification Criteria:**
- Circuit constraints < 50,000
- Proving time < 5 seconds
- Verification gas < 300,000 (NFR-02)

---

### Step 12: Implement Date Range & Value Range Circuits 🔴 ✅

**Goal:** Build circuits for proving dates and values within ranges.

**Tasks:**
- [x] Implement DateRange.circom
- [x] Implement ValueRange.circom
- [x] Reuse commitment verification component
- [x] Add range comparison components
- [x] Generate Solidity verifiers (placeholders created, snarkjs generates real ones)
- [x] Write comprehensive tests

**Files to Create:**
```
circuits/DateRange.circom
circuits/ValueRange.circom
test/circuits/DateRange.test.ts
test/circuits/ValueRange.test.ts
contracts/verifiers/DateRangeVerifier.sol
contracts/verifiers/ValueRangeVerifier.sol
```

**DateRange Circuit (from Spec 6.1.2):**
```circom
template DateRange() {
    signal input credentialCommitment;
    signal input rangeStart;
    signal input rangeEnd;
    signal input fieldIndex;

    signal input dateValue;
    signal input credentialData[16];
    signal input salt;

    // Verify commitment (same as AgeThreshold)
    // ...

    // Verify dateValue matches credential field
    signal selectedField;
    selectedField <== credentialData[fieldIndex];
    dateValue === selectedField;

    // Verify date in range
    component gte = GreaterEqThan(64);
    gte.in[0] <== dateValue;
    gte.in[1] <== rangeStart;
    gte.out === 1;

    component lte = LessEqThan(64);
    lte.in[0] <== dateValue;
    lte.in[1] <== rangeEnd;
    lte.out === 1;
}
```

**Test Cases:**
- Date within range passes
- Date before range fails
- Date after range fails
- Value within range passes
- Edge cases (exact boundaries)

**Verification Criteria:**
- Both circuits compile and verify
- Gas costs within limits
- Reusable components work

---

### Step 13: Implement Set Membership Circuit 🔴 ✅

**Goal:** Build circuit proving a value is in an allowed set (via Merkle proof).

**Tasks:**
- [x] Implement SetMembership.circom
- [x] Add Merkle tree verification
- [x] Create Merkle tree helper utilities
- [x] Generate Solidity verifier (placeholder created, snarkjs generates real ones)
- [x] Write tests with various set sizes

**Files to Create:**
```
circuits/SetMembership.circom
circuits/lib/merkle.circom
test/circuits/SetMembership.test.ts
contracts/verifiers/SetMembershipVerifier.sol
utils/merkleTree.ts
```

**Set Membership Circuit (from Spec 6.1.4):**
```circom
template SetMembership(TREE_DEPTH) {
    signal input credentialCommitment;
    signal input setRoot;
    signal input fieldIndex;

    signal input actualValue;
    signal input merkleProof[TREE_DEPTH];
    signal input merklePathIndices[TREE_DEPTH];
    signal input credentialData[16];
    signal input salt;

    // Verify commitment
    // ...

    // Verify field matches
    actualValue === credentialData[fieldIndex];

    // Verify Merkle proof
    component merkleVerifier = MerkleTreeChecker(TREE_DEPTH);
    merkleVerifier.leaf <== actualValue;
    merkleVerifier.root <== setRoot;
    for (var i = 0; i < TREE_DEPTH; i++) {
        merkleVerifier.pathElements[i] <== merkleProof[i];
        merkleVerifier.pathIndices[i] <== merklePathIndices[i];
    }
}
```

**Merkle Tree Utility:**
```typescript
// utils/merkleTree.ts
export class MerkleTree {
  constructor(leaves: bigint[], hasher: (inputs: bigint[]) => bigint);
  getRoot(): bigint;
  getProof(index: number): { proof: bigint[], indices: number[] };
  verify(leaf: bigint, proof: bigint[], indices: number[], root: bigint): boolean;
}
```

**Test Cases:**
- Value in set passes
- Value not in set fails
- Different tree depths work
- Large sets (1000+ elements)

**Verification Criteria:**
- Supports trees up to depth 20
- Proof size reasonable
- Verification efficient

---

## Phase 4: ZK Engine & Integration (Steps 14-16)

### Step 14: Implement ZKDisclosureEngine Contract 🔴

**Goal:** Build the on-chain engine that manages verifiers and validates proofs.

**Tasks:**
- [ ] Implement ZKDisclosureEngine.sol
- [ ] Add verifier registration system
- [ ] Integrate generated verifier contracts
- [ ] Add proof replay prevention
- [ ] Implement each verification function
- [ ] Add credential status checks before verification
- [ ] Write comprehensive integration tests

**Files to Create:**
```
contracts/ZKDisclosureEngine.sol
test/ZKDisclosureEngine.test.ts
```

**Key Functions (from Spec 4.3):**
```solidity
contract ZKDisclosureEngine is AccessControl {
    mapping(bytes32 => address) public verifiers;
    mapping(bytes32 => bool) public usedProofs;
    IClaimToken public claimToken;

    function registerVerifier(
        bytes32 disclosureType,
        address verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE);

    function verifyAgeThreshold(
        uint256 tokenId,
        uint256 threshold,
        bool greaterThan,
        bytes calldata proof
    ) external returns (bool) {
        // 1. Verify credential exists and is active
        require(claimToken.verify(tokenId), "Credential not valid");

        // 2. Get credential commitment
        Credential memory cred = claimToken.getCredential(tokenId);

        // 3. Verify proof hasn't been used
        bytes32 proofHash = keccak256(proof);
        require(!usedProofs[proofHash], Errors.PROOF_REPLAYED);

        // 4. Call verifier contract
        IAgeThresholdVerifier verifier = IAgeThresholdVerifier(verifiers[DISCLOSURE_AGE_THRESHOLD]);
        bool valid = verifier.verifyProof(/* format proof inputs */);

        // 5. Mark proof as used
        if (valid) {
            usedProofs[proofHash] = true;
            emit ProofVerified(tokenId, DISCLOSURE_AGE_THRESHOLD, msg.sender);
        }

        return valid;
    }

    function verifyDateRange(uint256 tokenId, uint64 start, uint64 end, bytes calldata proof) external returns (bool);
    function verifyValueRange(uint256 tokenId, bytes32 field, uint256 min, uint256 max, bytes calldata proof) external returns (bool);
    function verifySetMembership(uint256 tokenId, bytes32 field, bytes32 setRoot, bytes calldata proof) external returns (bool);
    function verifyExistence(uint256 tokenId, bytes calldata proof) external returns (bool);
}
```

**Test Cases:**
- Register verifier successfully
- Verify valid age proof
- Reject invalid age proof
- Reject proof for invalid credential
- Reject replayed proof
- All disclosure types work

**Verification Criteria:**
- Integration with all verifier contracts
- INV-04 enforced: no proof replay
- Gas costs within NFR-02

---

### Step 15: Create Proof Generation SDK 🟡

**Goal:** Build TypeScript SDK for off-chain proof generation.

**Tasks:**
- [ ] Create ProofGenerator class
- [ ] Implement credential decryption helper
- [ ] Add witness generation for each circuit
- [ ] Integrate snarkjs for proof creation
- [ ] Add proof serialization for on-chain submission
- [ ] Write SDK documentation and examples

**Files to Create:**
```
sdk/
├── src/
│   ├── index.ts
│   ├── ProofGenerator.ts
│   ├── WitnessBuilder.ts
│   ├── encryption.ts
│   └── types.ts
├── package.json
├── tsconfig.json
└── README.md
```

**SDK Interface:**
```typescript
// sdk/src/ProofGenerator.ts
export class ProofGenerator {
    constructor(
        circuitsPath: string,
        provingKeys: Map<DisclosureType, string>
    );

    async generateAgeProof(
        credential: DecryptedCredential,
        threshold: number,
        comparisonType: 'gt' | 'lt',
        currentTimestamp: number
    ): Promise<Proof>;

    async generateDateRangeProof(
        credential: DecryptedCredential,
        fieldIndex: number,
        rangeStart: number,
        rangeEnd: number
    ): Promise<Proof>;

    async generateValueRangeProof(
        credential: DecryptedCredential,
        fieldIndex: number,
        min: bigint,
        max: bigint
    ): Promise<Proof>;

    async generateSetMembershipProof(
        credential: DecryptedCredential,
        fieldIndex: number,
        merkleTree: MerkleTree
    ): Promise<Proof>;

    serializeProofForChain(proof: Proof): string;
}
```

**Usage Example:**
```typescript
import { ProofGenerator, decryptCredential } from '@sovereign-credential/sdk';

const generator = new ProofGenerator('./circuits', provingKeys);
const decrypted = await decryptCredential(encryptedPayload, privateKey);
const proof = await generator.generateAgeProof(decrypted, 18, 'gt', Date.now() / 1000);
const serialized = generator.serializeProofForChain(proof);

// Submit to chain
await zkEngine.verifyAgeThreshold(tokenId, 18, true, serialized);
```

**Test Cases:**
- Generate valid proofs for each type
- Proof verification succeeds on-chain
- Invalid inputs produce errors
- Serialization/deserialization works

**Verification Criteria:**
- SDK is fully typed
- Documentation complete
- Integration tests pass

---

### Step 16: Implement Compound Proof Support 🔴

**Goal:** Enable combining multiple disclosures in a single proof.

**Tasks:**
- [ ] Design compound proof architecture
- [ ] Implement CompoundProof.circom
- [ ] Add compound verification to ZKDisclosureEngine
- [ ] Update SDK with compound proof generation
- [ ] Write integration tests

**Files to Create:**
```
circuits/CompoundProof.circom
contracts/verifiers/CompoundProofVerifier.sol
sdk/src/CompoundProofBuilder.ts
test/CompoundProof.test.ts
```

**Compound Proof Architecture:**
```circom
template CompoundProof(NUM_DISCLOSURES) {
    // Shared credential commitment (verified once)
    signal input credentialCommitment;
    signal input credentialData[16];
    signal input salt;

    // Array of disclosure specifications
    signal input disclosureTypes[NUM_DISCLOSURES];
    signal input disclosureParams[NUM_DISCLOSURES][4]; // Max 4 params per disclosure

    // Verify commitment once
    // ...

    // Verify each disclosure
    for (var i = 0; i < NUM_DISCLOSURES; i++) {
        // Select and verify based on type
        // Uses multiplexer to select correct verification
    }
}
```

**SDK Builder Pattern:**
```typescript
const proof = await new CompoundProofBuilder(credential)
    .addAgeThreshold(18, 'gt')
    .addDateRange('issuedAt', startDate, endDate)
    .addSetMembership('licenseClass', allowedClasses)
    .build();
```

**Test Cases:**
- Combine 2 disclosures
- Combine 3+ disclosures
- Mixed disclosure types
- Single disclosure fails, compound fails

**Verification Criteria:**
- Single proof for multiple facts
- More efficient than separate proofs
- Clean builder API

---

## Phase 5: FIE Integration (Steps 17-18)

### Step 17: Implement FIEBridge Contract 🟡

**Goal:** Build the bridge connecting Sovereign Credential to Finite Intent Executor.

**Tasks:**
- [ ] Implement FIEBridge.sol
- [ ] Add FIE execution agent authorization
- [ ] Implement trigger notification handling
- [ ] Add inheritance execution logic
- [ ] Implement FIE proof verification
- [ ] Add double-execution prevention
- [ ] Write integration tests with mock FIE

**Files to Create:**
```
contracts/FIEBridge.sol
test/FIEBridge.test.ts
test/mocks/MockFIE.sol
```

**Key Functions (from Spec 4.5):**
```solidity
contract FIEBridge is AccessControl {
    ICredentialLifecycleManager public lifecycleManager;
    address public fieExecutionAgent;
    mapping(bytes32 => bool) public processedTriggers;

    function setFIEExecutionAgent(address agent) external onlyRole(DEFAULT_ADMIN_ROLE) {
        fieExecutionAgent = agent;
        emit FIEAgentUpdated(agent);
    }

    function notifyTrigger(
        bytes32 intentHash,
        address subject
    ) external onlyFIE {
        require(!processedTriggers[intentHash], "Already processed");
        emit FIETriggerReceived(intentHash, subject);

        // Query credentials with inheritance directives for this subject
        // Execute inheritance for each matching credential
    }

    function executeCredentialInheritance(
        uint256 tokenId,
        bytes32 intentHash
    ) external onlyFIE {
        require(!processedTriggers[intentHash], "Already processed");

        InheritanceDirective memory directive = lifecycleManager.getInheritanceDirective(tokenId);
        require(directive.requiresFIETrigger, "Does not require FIE");
        require(directive.fieIntentHash == intentHash, "Intent mismatch");

        // Execute transfer to beneficiaries
        lifecycleManager.executeInheritance(tokenId, abi.encode(intentHash));

        processedTriggers[intentHash] = true;
        emit CredentialInheritanceExecuted(tokenId, intentHash, directive.beneficiaries[0]);
    }

    modifier onlyFIE() {
        require(msg.sender == fieExecutionAgent, "Not FIE agent");
        _;
    }
}
```

**Test Cases:**
- Set FIE agent successfully
- Only FIE can call protected functions
- Trigger notification works
- Inheritance execution works
- Double execution prevented
- Intent hash verification works

**Verification Criteria:**
- Matches FIE Bridge Protocol (Spec 8)
- All verification requirements met (Spec 8.2)
- Events emitted correctly

---

### Step 18: Implement Partial Inheritance & Advanced Scenarios 🟡

**Goal:** Support credential splitting and complex inheritance rules.

**Tasks:**
- [ ] Implement credential splitting for partial inheritance
- [ ] Add conditional inheritance support
- [ ] Implement time-bounded access during settlement
- [ ] Add inheritance dispute handling
- [ ] Write complex scenario tests

**Files to Modify:**
```
contracts/CredentialLifecycleManager.sol
contracts/FIEBridge.sol
test/inheritance-scenarios.test.ts
```

**Partial Inheritance (from Spec 8.3):**
```solidity
function splitCredential(
    uint256 tokenId,
    address[] calldata beneficiaries,
    uint8[] calldata shares
) external returns (uint256[] memory newTokenIds) {
    require(shares.length == beneficiaries.length, "Length mismatch");

    uint8 totalShares;
    for (uint i = 0; i < shares.length; i++) {
        totalShares += shares[i];
    }
    require(totalShares == 100, "Shares must sum to 100");

    Credential memory original = claimToken.getCredential(tokenId);
    require(_isSplittable(original.claimType), "Not splittable");

    // Burn original
    claimToken.burn(tokenId);

    // Mint new credentials with share metadata
    newTokenIds = new uint256[](beneficiaries.length);
    for (uint i = 0; i < beneficiaries.length; i++) {
        newTokenIds[i] = _mintSplitCredential(original, beneficiaries[i], shares[i]);
    }

    emit CredentialSplit(tokenId, newTokenIds, beneficiaries, shares);
}
```

**Conditional Inheritance:**
```solidity
struct InheritanceCondition {
    bytes32 conditionType;  // "AGE_THRESHOLD", "DATE_AFTER", "CUSTOM"
    bytes params;           // Encoded condition parameters
}

function evaluateCondition(
    InheritanceCondition memory condition,
    address beneficiary
) internal view returns (bool);
```

**Test Cases:**
- Split property deed 50/50
- Split with 3 beneficiaries (40/35/25)
- Conditional inheritance (beneficiary must be 21+)
- Time-bounded access (executor access for 90 days)
- Dispute freezes inheritance

**Verification Criteria:**
- Splitting maintains total value
- Conditions properly evaluated
- Time bounds enforced

---

## Phase 6: Testing, Deployment & Documentation (Steps 19-20)

### Step 19: Comprehensive Integration Testing & Security Hardening 🔴

**Goal:** Complete end-to-end testing and security review preparation.

**Tasks:**
- [ ] Write full integration test suite
- [ ] Test all invariants from Spec Section 10
- [ ] Add fuzz testing for edge cases
- [ ] Perform gas optimization
- [ ] Add reentrancy guards review
- [ ] Document all security considerations
- [ ] Create test coverage report (target: 95%+)

**Files to Create:**
```
test/
├── integration/
│   ├── full-lifecycle.test.ts
│   ├── multi-issuer.test.ts
│   ├── inheritance-e2e.test.ts
│   └── zk-disclosure-e2e.test.ts
├── invariants/
│   ├── safety.test.ts
│   └── liveness.test.ts
├── fuzz/
│   └── credential-fuzz.test.ts
docs/
├── SECURITY.md
└── AUDIT_PREPARATION.md
```

**Invariant Tests (from Spec 10):**
```typescript
describe("Safety Invariants", () => {
    it("INV-01: Active credentials must have authorized issuers", async () => {
        // Test that deactivating an issuer affects credential validity
    });

    it("INV-02: Revocation is permanent", async () => {
        // Attempt to reinstate revoked credential (should fail)
    });

    it("INV-03: Only active/inherited credentials pass verification", async () => {
        // Test verify() for all statuses
    });

    it("INV-04: Proofs cannot be replayed", async () => {
        // Use proof twice (second should fail)
    });

    it("INV-05: Credentials stay with subject unless transferred", async () => {
        // Test unauthorized transfer attempts
    });
});
```

**Security Checklist:**
- [ ] Reentrancy protection on all external calls
- [ ] Integer overflow/underflow (covered by Solidity 0.8+)
- [ ] Access control on all privileged functions
- [ ] Signature malleability prevention
- [ ] Front-running protection (commit-reveal where needed)
- [ ] Oracle manipulation resistance
- [ ] Upgrade timelock implemented

**Gas Optimization:**
- Batch operations where possible
- Storage packing
- Use events instead of storage for historical data
- Optimize loops

**Verification Criteria:**
- All invariants have passing tests
- Test coverage > 95%
- No critical findings in internal review
- Gas costs meet NFRs

---

### Step 20: Deployment Scripts & Documentation 🟢

**Goal:** Create production deployment infrastructure and complete documentation.

**Tasks:**
- [ ] Create deployment scripts for testnet
- [ ] Create deployment scripts for mainnet
- [ ] Write deployment verification script
- [ ] Create contract interaction scripts
- [ ] Write complete API documentation
- [ ] Create user guide
- [ ] Write issuer onboarding guide
- [ ] Create architecture documentation

**Files to Create:**
```
scripts/
├── deploy-testnet.ts
├── deploy-mainnet.ts
├── verify-deployment.ts
├── setup-issuer.ts
├── mint-credential.ts
└── verify-credential.ts
docs/
├── API.md
├── USER_GUIDE.md
├── ISSUER_GUIDE.md
├── ARCHITECTURE.md
└── DEPLOYMENT.md
```

**Deployment Script:**
```typescript
// scripts/deploy-mainnet.ts
import { ethers, upgrades } from "hardhat";

async function main() {
    console.log("Deploying Sovereign Credential to mainnet...");

    // 1. Deploy IssuerRegistry
    const IssuerRegistry = await ethers.getContractFactory("IssuerRegistryUpgradeable");
    const issuerRegistry = await upgrades.deployProxy(IssuerRegistry, []);
    await issuerRegistry.waitForDeployment();
    console.log("IssuerRegistry:", await issuerRegistry.getAddress());

    // 2. Deploy ClaimToken
    const ClaimToken = await ethers.getContractFactory("ClaimTokenUpgradeable");
    const claimToken = await upgrades.deployProxy(ClaimToken, [
        await issuerRegistry.getAddress()
    ]);
    await claimToken.waitForDeployment();
    console.log("ClaimToken:", await claimToken.getAddress());

    // 3. Deploy ZK Verifiers
    // ...

    // 4. Deploy ZKDisclosureEngine
    // ...

    // 5. Deploy CredentialLifecycleManager
    // ...

    // 6. Deploy FIEBridge
    // ...

    // 7. Set up cross-references
    // ...

    // 8. Transfer admin to multisig
    // ...

    console.log("Deployment complete!");
}
```

**Verification Script:**
```typescript
// scripts/verify-deployment.ts
async function verifyDeployment(addresses: DeploymentAddresses) {
    // Verify all contracts are deployed
    // Verify proxy implementations
    // Verify cross-references are correct
    // Verify access control setup
    // Verify ZK verifiers registered
}
```

**Documentation Structure:**
```markdown
# API.md
- Contract addresses (per network)
- ABI references
- Function documentation
- Event documentation
- Error codes

# USER_GUIDE.md
- Wallet setup
- Viewing credentials
- Generating disclosures
- Transferring credentials
- Setting inheritance

# ISSUER_GUIDE.md
- Registration process
- Minting credentials
- Revocation procedures
- Reputation system
- Best practices

# DEPLOYMENT.md
- Prerequisites
- Network configuration
- Deployment steps
- Verification steps
- Upgrade procedures
```

**Verification Criteria:**
- Deployment scripts work on testnet
- All contracts verified on block explorer
- Documentation complete and accurate
- Issuer can complete full workflow

---

## Summary: Implementation Phases

| Phase | Steps | Focus Area | Complexity |
|-------|-------|------------|------------|
| **1** | 1-4 | Project Setup & Foundation | 🟢 Low |
| **2** | 5-9 | Core Smart Contracts | 🟡 Medium |
| **3** | 10-13 | Zero-Knowledge Circuits | 🔴 High |
| **4** | 14-16 | ZK Engine & SDK | 🔴 High |
| **5** | 17-18 | FIE Integration | 🟡 Medium |
| **6** | 19-20 | Testing & Deployment | 🟡 Medium |

## Dependencies Between Steps

```
1 ──► 2 ──► 3 ──► 4
            │
            ▼
      5 ──► 6 ──► 7 ──► 8 ──► 9
      │                       │
      │                       ▼
      ├────────────────────► 14 ──► 15 ──► 16
      │                       ▲
      │     10 ──► 11 ──► 12 ──► 13
      │
      ▼
     17 ──► 18
      │
      ▼
     19 ──► 20
```

## Critical Path

The critical path for MVP is:
1. Steps 1-4 (Foundation)
2. Steps 5-7 (Core contracts with basic minting/verification)
3. Step 10-11 (Age threshold circuit - most common use case)
4. Step 14 (ZK engine integration)
5. Step 19-20 (Testing and deployment)

This gives you a functional credential system with age verification in approximately 10 steps.

---

**Document Version:** 1.0
**Created:** 2026-01-12
**Based on:** SPEC.md v1.0
