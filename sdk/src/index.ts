/**
 * @file Sovereign Credential SDK
 * @description TypeScript SDK for generating zero-knowledge proofs for Sovereign Credential
 * @version 0.1.0-alpha
 *
 * @example
 * ```typescript
 * import {
 *   ProofGenerator,
 *   createDecryptedCredential,
 *   generateSalt,
 *   DisclosureType,
 * } from '@sovereign-credential/sdk';
 *
 * // Create proof generator
 * const generator = new ProofGenerator({
 *   circuitsBasePath: './circuits/build',
 * });
 *
 * // Create credential from decrypted payload
 * const credential = createDecryptedCredential(
 *   1n,                                    // tokenId
 *   '0x01',                                // claimType
 *   '0x1234...',                           // subject
 *   '0xABCD...',                           // issuer
 *   { birthdate: 631152000 },              // payload (Jan 1, 1990)
 *   generateSalt(),                        // salt
 * );
 *
 * // Generate age proof
 * const result = await generator.generateAgeProof(
 *   credential,
 *   commitment,    // Pre-computed Poseidon commitment
 *   18,            // threshold: prove age > 18
 *   'gt',          // greater than
 * );
 *
 * if (result.success) {
 *   // Submit to chain
 *   await zkEngine.verifyAgeThreshold(
 *     tokenId,
 *     18,
 *     true,
 *     result.serialized.proofBytes
 *   );
 * }
 * ```
 */

// ============================================
// Main Classes
// ============================================

export { ProofGenerator } from "./ProofGenerator";
export { WitnessBuilder, inputsToSnarkjsFormat } from "./WitnessBuilder";
export {
  MerkleTree,
  createMerkleTree,
  initPoseidon,
  hashLeaf,
  hashValues,
} from "./MerkleTree";

// ============================================
// Encryption Utilities
// ============================================

export {
  encryptPayload,
  decryptPayload,
  encodeEncryptedPayload,
  decodeEncryptedPayload,
  payloadToFields,
  createDecryptedCredential,
  hashPayload,
  generateCommitmentKeccak,
  generateSalt,
} from "./encryption";

// ============================================
// Types
// ============================================

export {
  // Enums
  DisclosureType,
  ComparisonType,

  // Credential types
  type DecryptedCredential,
  type CredentialPayload,
  StandardFieldIndices,

  // Proof types
  type Groth16Proof,
  type Proof,
  type SerializedProof,
  type ProofGenerationResult,
  type VerificationResult,

  // Circuit input types
  type BaseCircuitInputs,
  type AgeThresholdInputs,
  type DateRangeInputs,
  type ValueRangeInputs,
  type SetMembershipInputs,

  // Configuration types
  type CircuitPaths,
  type ProofGeneratorConfig,

  // Merkle tree types
  type MerkleProof,
  type MerkleTreeConfig,

  // Encryption types
  type EncryptedPayload,
  type KeyPair,

  // Utility types
  type Logger,
  defaultLogger,
} from "./types";

// ============================================
// Version Info
// ============================================

/** SDK version */
export const SDK_VERSION = "0.1.0-alpha";

/** Supported circuit version */
export const CIRCUIT_VERSION = "1.0.0";

/** Number of credential fields */
export const DEFAULT_NUM_FIELDS = 16;
