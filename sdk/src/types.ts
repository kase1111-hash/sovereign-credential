/**
 * @file types.ts
 * @description Type definitions for the Sovereign Credential SDK
 */

/**
 * Disclosure types supported by the ZK circuits
 */
export enum DisclosureType {
  AGE_THRESHOLD = 0,
  DATE_RANGE = 1,
  VALUE_RANGE = 2,
  SET_MEMBERSHIP = 3,
  EXISTENCE = 4,
}

/**
 * Comparison types for threshold checks
 */
export enum ComparisonType {
  GREATER_THAN = 0,
  LESS_THAN = 1,
  GREATER_EQUAL = 2,
  LESS_EQUAL = 3,
}

/**
 * Decrypted credential data for proof generation
 */
export interface DecryptedCredential {
  /** Token ID of the credential */
  tokenId: bigint;
  /** Credential data fields (16 elements) */
  credentialData: bigint[];
  /** Salt used for commitment generation */
  salt: bigint;
  /** Poseidon commitment of credentialData + salt */
  commitment: bigint;
}

/**
 * Merkle tree for set membership proofs
 */
export interface MerkleTree {
  /** Root of the Merkle tree */
  root: bigint;
  /** Depth of the tree */
  depth: number;
  /** Get proof for a leaf at given index */
  getProof(index: number): MerkleProof;
  /** Get index of a value in the tree (-1 if not found) */
  indexOf(value: bigint): number;
}

/**
 * Merkle proof for set membership
 */
export interface MerkleProof {
  /** Sibling hashes along the path */
  pathElements: bigint[];
  /** Path direction at each level (0=left, 1=right) */
  pathIndices: number[];
}

/**
 * Groth16 proof structure
 */
export interface Proof {
  /** G1 point A */
  pi_a: [string, string];
  /** G2 point B */
  pi_b: [[string, string], [string, string]];
  /** G1 point C */
  pi_c: [string, string];
  /** Protocol used */
  protocol: "groth16";
  /** Public signals */
  publicSignals: string[];
}

/**
 * Age threshold disclosure specification
 */
export interface AgeThresholdSpec {
  type: DisclosureType.AGE_THRESHOLD;
  /** Age threshold in years */
  threshold: number;
  /** Current timestamp for age calculation */
  currentTimestamp: number;
  /** Comparison type (0 = greater than, 1 = less than) */
  comparisonType: ComparisonType.GREATER_THAN | ComparisonType.LESS_THAN;
}

/**
 * Date range disclosure specification
 */
export interface DateRangeSpec {
  type: DisclosureType.DATE_RANGE;
  /** Start of range (Unix timestamp) */
  rangeStart: number;
  /** End of range (Unix timestamp) */
  rangeEnd: number;
  /** Field index in credential data */
  fieldIndex: number;
}

/**
 * Value range disclosure specification
 */
export interface ValueRangeSpec {
  type: DisclosureType.VALUE_RANGE;
  /** Minimum value */
  minValue: bigint;
  /** Maximum value */
  maxValue: bigint;
  /** Field index in credential data */
  fieldIndex: number;
}

/**
 * Set membership disclosure specification
 */
export interface SetMembershipSpec {
  type: DisclosureType.SET_MEMBERSHIP;
  /** Root of the allowed values Merkle tree */
  setRoot: bigint;
  /** Field index in credential data */
  fieldIndex: number;
  /** Merkle proof for the value */
  merkleProof: MerkleProof;
}

/**
 * Existence disclosure specification
 */
export interface ExistenceSpec {
  type: DisclosureType.EXISTENCE;
}

/**
 * Union of all disclosure specifications
 */
export type DisclosureSpec =
  | AgeThresholdSpec
  | DateRangeSpec
  | ValueRangeSpec
  | SetMembershipSpec
  | ExistenceSpec;

/**
 * Compound proof input for witness generation
 */
export interface CompoundProofInput {
  /** Public credential commitment */
  credentialCommitment: bigint;
  /** Array of disclosure types */
  disclosureTypes: DisclosureType[];
  /** Parameters for each disclosure [NUM_DISCLOSURES][4] */
  disclosureParams: bigint[][];
  /** Private credential data */
  credentialData: bigint[];
  /** Commitment salt */
  salt: bigint;
  /** Private values for each disclosure */
  privateValues: bigint[];
  /** Merkle proofs for set membership (or zeros) */
  merkleProofs: bigint[][];
  /** Merkle path indices for set membership (or zeros) */
  merklePathIndices: number[][];
}

/**
 * Serialized proof ready for on-chain submission
 */
export interface SerializedProof {
  /** ABI-encoded proof bytes */
  proof: string;
  /** ABI-encoded public inputs */
  publicInputs: string;
  /** Disclosure types as bytes32 array */
  disclosureTypes: string[];
}

/**
 * Configuration for proof generation
 */
export interface ProofGeneratorConfig {
  /** Path to compiled circuit WASM files */
  circuitsPath: string;
  /** Path to proving key (zkey) files */
  provingKeysPath: string;
  /** Tree depth for set membership proofs */
  merkleTreeDepth?: number;
}
