# Sovereign Credential SDK

TypeScript SDK for generating zero-knowledge proofs for Sovereign Credential selective disclosures.

## Overview

This SDK enables credential holders to generate ZK proofs that reveal specific facts about their credentials without exposing the underlying data. For example, prove you're over 18 without revealing your exact birthdate.

## Installation

```bash
npm install @sovereign-credential/sdk
# or
yarn add @sovereign-credential/sdk
```

### Peer Dependencies

```bash
npm install ethers snarkjs
```

## Quick Start

```typescript
import {
  ProofGenerator,
  createDecryptedCredential,
  generateSalt,
  initPoseidon,
} from '@sovereign-credential/sdk';

// Initialize Poseidon hash (required for commitments)
await initPoseidon();

// Create proof generator with circuit paths
const generator = new ProofGenerator({
  circuitsBasePath: './circuits/build',
});

// Create credential from decrypted payload
const credential = createDecryptedCredential(
  1n,                           // tokenId
  '0x01',                       // claimType (IDENTITY_BIRTH)
  '0x1234...',                  // subject address
  '0xABCD...',                  // issuer address
  { birthdate: 631152000 },     // payload (Jan 1, 1990 as Unix timestamp)
  generateSalt(),               // random salt for commitment
);

// Generate proof that holder is over 18
const result = await generator.generateAgeProof(
  credential,
  commitment,  // Poseidon commitment from on-chain credential
  18,          // threshold age
  'gt',        // "greater than"
);

if (result.success) {
  console.log('Proof generated in', result.duration, 'ms');

  // Submit to chain
  const tx = await zkEngine.verifyAgeThreshold(
    tokenId,
    18,
    true,  // greater than
    result.serialized.proofBytes
  );
}
```

## Supported Proof Types

### Age Threshold

Prove age is above or below a threshold without revealing birthdate.

```typescript
const result = await generator.generateAgeProof(
  credential,
  commitment,
  21,       // threshold
  'gt',     // 'gt' (greater than) or 'lt' (less than)
);
```

### Date Range

Prove a date field is within a range.

```typescript
const result = await generator.generateDateRangeProof(
  credential,
  commitment,
  1,                    // fieldIndex (e.g., issuedAt)
  1577836800,           // rangeStart (Jan 1, 2020)
  1704067199,           // rangeEnd (Dec 31, 2023)
);
```

### Value Range

Prove a numeric value is within a range.

```typescript
const result = await generator.generateValueRangeProof(
  credential,
  commitment,
  5,                    // fieldIndex (e.g., score field)
  700n,                 // minValue
  850n,                 // maxValue
);
```

### Set Membership

Prove a field value is in an allowed set (e.g., approved license classes).

```typescript
const allowedValues = [
  BigInt('0x41'), // 'A'
  BigInt('0x42'), // 'B'
  BigInt('0x43'), // 'C'
];

const result = await generator.generateSetMembershipProof(
  credential,
  commitment,
  7,                    // fieldIndex
  allowedValues,
);
```

## API Reference

### ProofGenerator

Main class for generating ZK proofs.

```typescript
const generator = new ProofGenerator({
  circuitsBasePath: './circuits/build',
  numFields: 16,  // optional, default is 16
  circuits: {     // optional custom paths
    ageThreshold: {
      wasm: './custom/AgeThreshold.wasm',
      zkey: './custom/AgeThreshold.zkey',
    },
  },
});
```

#### Methods

- `generateAgeProof(credential, commitment, threshold, comparison, timestamp?)` - Generate age threshold proof
- `generateDateRangeProof(credential, commitment, fieldIndex, start, end)` - Generate date range proof
- `generateValueRangeProof(credential, commitment, fieldIndex, min, max)` - Generate value range proof
- `generateSetMembershipProof(credential, commitment, fieldIndex, values)` - Generate set membership proof
- `verifyProof(disclosureType, proof)` - Verify a proof locally
- `serializeProofForChain(proof)` - Serialize proof for on-chain submission
- `getVerifierCalldata(proof)` - Get formatted calldata for verifier contract
- `isCircuitAvailable(disclosureType)` - Check if circuit files exist
- `getAvailableCircuits()` - List available circuit types

### WitnessBuilder

Low-level class for building circuit witness inputs.

```typescript
const builder = new WitnessBuilder(16);

const inputs = builder.buildAgeThresholdWitness(
  credential,
  commitment,
  18,
  ComparisonType.GREATER_THAN,
  currentTimestamp,
);
```

### MerkleTree

Poseidon-based Merkle tree for set membership proofs.

```typescript
import { MerkleTree, createMerkleTree, initPoseidon } from '@sovereign-credential/sdk';

// Initialize Poseidon hash
await initPoseidon();

// Create tree from values
const tree = new MerkleTree([1n, 2n, 3n, 4n]);

// Get proof for a value
const proof = tree.getProof(2n);

// Verify proof
const isValid = tree.verify(proof);

// Get root
const root = tree.getRoot();
```

### Encryption Utilities

Helpers for credential payload encryption/decryption.

```typescript
import {
  encryptPayload,
  decryptPayload,
  createDecryptedCredential,
  generateSalt,
} from '@sovereign-credential/sdk';

// Encrypt payload for holder
const encrypted = encryptPayload(
  { birthdate: 631152000, name: 'Alice' },
  holderPublicKey,
);

// Decrypt payload
const decrypted = decryptPayload(encrypted, holderPrivateKey);

// Create credential object from decrypted data
const credential = createDecryptedCredential(
  tokenId,
  claimType,
  subject,
  issuer,
  decrypted,
  generateSalt(),
);
```

## Credential Field Layout

Standard credentials use 16 fields. The default field mapping is:

| Index | Field Name | Description |
|-------|------------|-------------|
| 0 | birthdate | Unix timestamp of birth date |
| 1 | issuedAt | Unix timestamp of issuance |
| 2 | expiresAt | Unix timestamp of expiration |
| 3 | value | Generic numeric value |
| 4 | status | Credential status code |
| 5 | score | Numeric score (e.g., credit score) |
| 6 | level | Level or grade |
| 7 | type | Type identifier |
| 8-15 | (custom) | Application-specific fields |

You can provide custom field mappings when creating credentials:

```typescript
const credential = createDecryptedCredential(
  tokenId,
  claimType,
  subject,
  issuer,
  { salary: 75000, department: 'engineering' },
  generateSalt(),
  { salary: 3, department: 8 },  // custom field mapping
);
```

## Circuit Requirements

Before generating proofs, you need compiled circuit files:

1. **WASM file** - WebAssembly witness calculator
2. **ZKey file** - Proving key from trusted setup
3. **VKey file** - Verification key (optional, for local verification)

Expected file structure:

```
circuits/build/
├── AgeThreshold_js/
│   └── AgeThreshold.wasm
├── AgeThreshold_final.zkey
├── AgeThreshold_verification_key.json
├── DateRange_js/
│   └── DateRange.wasm
├── DateRange_final.zkey
├── DateRange_verification_key.json
├── ValueRange_js/
│   └── ValueRange.wasm
├── ValueRange_final.zkey
├── ValueRange_verification_key.json
├── SetMembership_js/
│   └── SetMembership.wasm
├── SetMembership_final.zkey
└── SetMembership_verification_key.json
```

Compile circuits using:

```bash
npm run circuits:compile
npm run circuits:setup
```

## Error Handling

All proof generation methods return a `ProofGenerationResult`:

```typescript
interface ProofGenerationResult {
  success: boolean;
  proof?: Proof;
  serialized?: SerializedProof;
  error?: string;
  duration?: number;
}
```

Example error handling:

```typescript
const result = await generator.generateAgeProof(credential, commitment, 18, 'gt');

if (!result.success) {
  console.error('Proof generation failed:', result.error);
  return;
}

// Use result.proof or result.serialized
```

## On-Chain Submission

After generating a proof, submit it to the `ZKDisclosureEngine` contract:

```typescript
import { ethers } from 'ethers';

const result = await generator.generateAgeProof(credential, commitment, 18, 'gt');

if (result.success) {
  // Get formatted calldata
  const calldata = generator.getVerifierCalldata(result.proof);

  // Call verifier contract
  const zkEngine = new ethers.Contract(zkEngineAddress, zkEngineAbi, signer);

  const tx = await zkEngine.verifyAgeThreshold(
    tokenId,
    18,           // threshold
    true,         // greaterThan
    calldata.a,
    calldata.b,
    calldata.c,
    calldata.input,
  );

  await tx.wait();
}
```

## Testing

```bash
cd sdk
npm install
npm test
```

## License

CC0-1.0
