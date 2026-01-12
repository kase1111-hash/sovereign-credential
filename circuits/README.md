# Zero-Knowledge Circuits

This directory contains the Circom circuits for zero-knowledge proofs in the Sovereign Credential system.

## Directory Structure

```
circuits/
├── lib/                    # Shared circuit components
│   ├── commitment.circom   # Credential commitment verification
│   ├── comparators.circom  # Safe numeric comparisons
│   └── merkle.circom       # Merkle tree verification
├── build/                  # Compiled circuit artifacts (gitignored)
├── keys/                   # Proving/verification keys (gitignored)
├── ptau/                   # Powers of Tau files (gitignored)
├── test/                   # Circuit tests
│   ├── circuitTestUtils.ts # Testing utilities
│   └── *.test.ts           # Circuit-specific tests
├── compile.sh              # Circuit compilation script
├── setup.sh                # Trusted setup script
├── generate_proof.sh       # Proof generation script
├── AgeThreshold.circom     # Age verification circuit (Step 11)
├── DateRange.circom        # Date range circuit (Step 12)
├── ValueRange.circom       # Value range circuit (Step 12)
└── SetMembership.circom    # Set membership circuit (Step 13)
```

## Prerequisites

1. **Circom Compiler** (v2.1.6+)
   ```bash
   # Install via npm
   npm install -g circom

   # Or via Rust
   cargo install circom
   ```

2. **snarkjs** (included in package.json)
   ```bash
   npm install
   ```

## Workflow

### 1. Compile Circuit

```bash
# Compile a circuit (e.g., AgeThreshold)
./compile.sh AgeThreshold

# Or use npm script
npm run circuits:compile AgeThreshold
```

This generates:
- `build/AgeThreshold.r1cs` - Constraint system
- `build/AgeThreshold_js/` - WASM witness generator
- `build/AgeThreshold.sym` - Debug symbols

### 2. Trusted Setup

```bash
# Run setup ceremony
./setup.sh AgeThreshold

# For larger circuits, specify a bigger ptau file
./setup.sh AgeThreshold pot15_final.ptau
```

This generates:
- `keys/AgeThreshold_final.zkey` - Proving key
- `keys/AgeThreshold_verification_key.json` - Verification key
- `contracts/verifiers/AgeThresholdVerifier.sol` - Solidity verifier

### 3. Generate Proof

```bash
# Generate a proof
./generate_proof.sh AgeThreshold test/age_input.json

# Or use npm script
npm run circuits:proof AgeThreshold test/age_input.json
```

This generates:
- `build/proofs/AgeThreshold/proof.json` - ZK proof
- `build/proofs/AgeThreshold/public.json` - Public signals
- `build/proofs/AgeThreshold/calldata.txt` - Solidity calldata

### 4. Verify Proof

Proofs are verified automatically during generation. For on-chain verification:

1. Deploy the generated verifier contract
2. Call `verifyProof()` with the calldata

## Circuit Library

### commitment.circom

Templates for verifying credential commitments:
- `CredentialCommitment(N)` - Verify commitment matches credential data
- `FieldExtractor(N)` - Extract specific field from credential
- `Selector(N)` - Select value from array by index

### comparators.circom

Safe comparison templates with range checks:
- `SafeGreaterThan(N)` - a > b with overflow protection
- `SafeLessThan(N)` - a < b with overflow protection
- `InRange(N)` - min <= value <= max
- `ThresholdCheck(N)` - Configurable threshold comparison

### merkle.circom

Merkle tree templates for set membership:
- `MerkleTreeChecker(DEPTH)` - Verify Merkle inclusion proof
- `MerkleTreeInclusionProof(DEPTH)` - Returns 1 if included
- `ComputeMerkleRoot(DEPTH)` - Compute root from leaf and path

## Testing

```bash
# Run circuit tests
npm run circuits:test

# Run specific test
npx mocha --require ts-node/register circuits/test/AgeThreshold.test.ts
```

## Powers of Tau

The setup uses pre-computed Powers of Tau files from the Hermez ceremony:
- `pot12_final.ptau` - Up to 4,096 constraints
- `pot14_final.ptau` - Up to 16,384 constraints
- `pot16_final.ptau` - Up to 65,536 constraints

Files are automatically downloaded during setup if not present.

## Security Considerations

1. **Trusted Setup**: The proving keys contain toxic waste from the setup ceremony. In production, use a multi-party computation ceremony.

2. **Range Checks**: All comparators include range checks to prevent overflow attacks.

3. **Commitment Binding**: Commitments use Poseidon hash with salt for hiding and binding properties.

4. **Proof Replay**: Each proof should only be used once. The on-chain verifier tracks used proofs.

## Circuit Specifications

| Circuit | Public Inputs | Constraints | Proving Time |
|---------|---------------|-------------|--------------|
| AgeThreshold | commitment, threshold, timestamp, type | ~5,000 | <1s |
| DateRange | commitment, start, end, fieldIndex | ~6,000 | <1s |
| ValueRange | commitment, min, max, fieldIndex | ~5,500 | <1s |
| SetMembership | commitment, setRoot, fieldIndex | ~10,000 | <2s |

## References

- [Circom Documentation](https://docs.circom.io/)
- [snarkjs Documentation](https://github.com/iden3/snarkjs)
- [circomlib](https://github.com/iden3/circomlib)
- [SPEC.md Section 6](../SPEC.md) - ZK Circuit Specifications
