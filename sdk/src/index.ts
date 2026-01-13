/**
 * @file index.ts
 * @description Sovereign Credential SDK entry point
 *
 * Provides tools for generating zero-knowledge proofs for credential disclosures.
 */

// Export types
export type {
  DecryptedCredential,
  MerkleTree,
  MerkleProof,
  Proof,
  SerializedProof,
  ProofGeneratorConfig,
  DisclosureSpec,
  AgeThresholdSpec,
  DateRangeSpec,
  ValueRangeSpec,
  SetMembershipSpec,
  ExistenceSpec,
  CompoundProofInput,
} from "./types";

export { DisclosureType, ComparisonType } from "./types";

// Export CompoundProofBuilder
export {
  CompoundProofBuilder,
  createCompoundProofBuilder,
} from "./CompoundProofBuilder";
