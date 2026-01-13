/**
 * @file SDK Type Definitions
 * @description TypeScript types for the Sovereign Credential Proof Generation SDK
 */

// ============================================
// Disclosure Types
// ============================================

/**
 * Types of ZK disclosures supported by the system
 */
export enum DisclosureType {
  AGE_THRESHOLD = "AGE_THRESHOLD",
  DATE_RANGE = "DATE_RANGE",
  VALUE_RANGE = "VALUE_RANGE",
  SET_MEMBERSHIP = "SET_MEMBERSHIP",
}

/**
 * Comparison types for threshold proofs
 */
export enum ComparisonType {
  GREATER_THAN = 0,
  LESS_THAN = 1,
  GREATER_THAN_OR_EQUAL = 2,
  LESS_THAN_OR_EQUAL = 3,
}

// ============================================
// Credential Types
// ============================================

/**
 * Decrypted credential data ready for proof generation
 * The payload contains the actual credential fields
 */
export interface DecryptedCredential {
  /** On-chain credential token ID */
  tokenId: bigint;
  /** Claim type identifier (bytes32) */
  claimType: string;
  /** Subject address */
  subject: string;
  /** Issuer address */
  issuer: string;
  /** Decrypted payload as field values */
  payload: CredentialPayload;
  /** Salt used in commitment */
  salt: bigint;
  /** Pre-computed commitment (if available) */
  commitment?: bigint;
}

/**
 * Credential payload structure
 * Fields are stored as bigints for circuit compatibility
 */
export interface CredentialPayload {
  /** Field values array (16 fields for standard credentials) */
  fields: bigint[];
  /** Optional named field mappings for convenience */
  namedFields?: Record<string, number>;
}

/**
 * Standard credential field indices
 */
export const StandardFieldIndices = {
  BIRTHDATE: 0,
  ISSUED_AT: 1,
  EXPIRES_AT: 2,
  VALUE: 3,
  STATUS: 4,
  ISSUER_ID: 5,
  SUBJECT_ID: 6,
  CLAIM_TYPE: 7,
  // Fields 8-15 are custom/reserved
} as const;

// ============================================
// Proof Types
// ============================================

/**
 * Groth16 proof structure (compatible with snarkjs output)
 */
export interface Groth16Proof {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
  protocol: "groth16";
  curve: "bn128";
}

/**
 * Complete proof with public signals
 */
export interface Proof {
  /** The ZK proof */
  proof: Groth16Proof;
  /** Public input signals */
  publicSignals: string[];
}

/**
 * Serialized proof ready for on-chain submission
 */
export interface SerializedProof {
  /** ABI-encoded proof bytes */
  proofBytes: string;
  /** Public signals as uint256 array */
  publicSignals: bigint[];
}

// ============================================
// Circuit Input Types
// ============================================

/**
 * Base circuit inputs (common to all circuits)
 */
export interface BaseCircuitInputs {
  credentialCommitment: bigint;
  credentialData: bigint[];
  salt: bigint;
}

/**
 * Age threshold circuit inputs
 */
export interface AgeThresholdInputs extends BaseCircuitInputs {
  threshold: bigint;
  currentTimestamp: bigint;
  comparisonType: bigint;
  birthdate: bigint;
}

/**
 * Date range circuit inputs
 */
export interface DateRangeInputs extends BaseCircuitInputs {
  rangeStart: bigint;
  rangeEnd: bigint;
  fieldIndex: bigint;
  dateValue: bigint;
}

/**
 * Value range circuit inputs
 */
export interface ValueRangeInputs extends BaseCircuitInputs {
  minValue: bigint;
  maxValue: bigint;
  fieldIndex: bigint;
  actualValue: bigint;
}

/**
 * Set membership circuit inputs
 */
export interface SetMembershipInputs extends BaseCircuitInputs {
  setRoot: bigint;
  fieldIndex: bigint;
  actualValue: bigint;
  merkleProof: bigint[];
  merklePathIndices: bigint[];
}

// ============================================
// Circuit Configuration
// ============================================

/**
 * Circuit file paths configuration
 */
export interface CircuitPaths {
  /** Path to the WASM file for witness generation */
  wasm: string;
  /** Path to the proving key (zkey) */
  zkey: string;
  /** Optional: Path to the verification key */
  vkey?: string;
}

/**
 * SDK configuration options
 */
export interface ProofGeneratorConfig {
  /** Base path where circuit files are located */
  circuitsBasePath: string;
  /** Number of fields in credential data (default: 16) */
  numFields?: number;
  /** Optional: Pre-loaded circuit paths */
  circuits?: {
    ageThreshold?: CircuitPaths;
    dateRange?: CircuitPaths;
    valueRange?: CircuitPaths;
    setMembership?: CircuitPaths;
  };
}

// ============================================
// Merkle Tree Types
// ============================================

/**
 * Merkle proof structure
 */
export interface MerkleProof {
  /** Root of the Merkle tree */
  root: bigint;
  /** Leaf value being proven */
  leaf: bigint;
  /** Sibling hashes along the path */
  pathElements: bigint[];
  /** Path direction at each level (0 = left, 1 = right) */
  pathIndices: number[];
}

/**
 * Merkle tree configuration
 */
export interface MerkleTreeConfig {
  /** Depth of the tree (supports 2^depth leaves) */
  depth: number;
  /** Hash function to use (default: Poseidon) */
  hashFunction?: (inputs: bigint[]) => bigint;
}

// ============================================
// Encryption Types
// ============================================

/**
 * Encrypted payload structure (as stored on-chain)
 */
export interface EncryptedPayload {
  /** Encrypted data bytes (hex) */
  encryptedData: string;
  /** Ephemeral public key used for encryption */
  ephemeralPublicKey: string;
  /** Initialization vector */
  iv: string;
}

/**
 * Key pair for ECIES encryption
 */
export interface KeyPair {
  /** Private key (hex) */
  privateKey: string;
  /** Public key (hex) */
  publicKey: string;
}

// ============================================
// Result Types
// ============================================

/**
 * Result of proof generation
 */
export interface ProofGenerationResult {
  /** Whether proof generation succeeded */
  success: boolean;
  /** The generated proof (if successful) */
  proof?: Proof;
  /** Serialized proof ready for chain submission */
  serialized?: SerializedProof;
  /** Error message (if failed) */
  error?: string;
  /** Time taken to generate proof in milliseconds */
  duration?: number;
}

/**
 * Result of proof verification
 */
export interface VerificationResult {
  /** Whether verification succeeded */
  valid: boolean;
  /** Error message (if invalid) */
  error?: string;
}

// ============================================
// Utility Types
// ============================================

/**
 * Logger interface for SDK operations
 */
export interface Logger {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

/**
 * Default console logger
 */
export const defaultLogger: Logger = {
  debug: (msg, ...args) => console.debug(`[SDK] ${msg}`, ...args),
  info: (msg, ...args) => console.info(`[SDK] ${msg}`, ...args),
  warn: (msg, ...args) => console.warn(`[SDK] ${msg}`, ...args),
  error: (msg, ...args) => console.error(`[SDK] ${msg}`, ...args),
};
