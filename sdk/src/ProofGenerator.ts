/**
 * @file ProofGenerator
 * @description Main SDK class for generating zero-knowledge proofs
 */

import * as snarkjs from "snarkjs";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import type {
  DecryptedCredential,
  Proof,
  ProofGenerationResult,
  SerializedProof,
  ProofGeneratorConfig,
  CircuitPaths,
  DisclosureType,
  ComparisonType,
  MerkleProof,
  VerificationResult,
  Logger,
  Groth16Proof,
} from "./types";
import { defaultLogger } from "./types";
import { WitnessBuilder, inputsToSnarkjsFormat } from "./WitnessBuilder";
import { MerkleTree } from "./MerkleTree";

/**
 * Default circuit file names
 */
const CIRCUIT_FILES = {
  ageThreshold: {
    wasm: "AgeThreshold_js/AgeThreshold.wasm",
    zkey: "AgeThreshold_final.zkey",
    vkey: "AgeThreshold_verification_key.json",
  },
  dateRange: {
    wasm: "DateRange_js/DateRange.wasm",
    zkey: "DateRange_final.zkey",
    vkey: "DateRange_verification_key.json",
  },
  valueRange: {
    wasm: "ValueRange_js/ValueRange.wasm",
    zkey: "ValueRange_final.zkey",
    vkey: "ValueRange_verification_key.json",
  },
  setMembership: {
    wasm: "SetMembership_js/SetMembership.wasm",
    zkey: "SetMembership_final.zkey",
    vkey: "SetMembership_verification_key.json",
  },
};

/**
 * Main class for generating ZK proofs for Sovereign Credential disclosures
 */
export class ProofGenerator {
  private config: ProofGeneratorConfig;
  private witnessBuilder: WitnessBuilder;
  private logger: Logger;
  private circuitPaths: Map<DisclosureType, CircuitPaths>;
  private verificationKeys: Map<DisclosureType, object>;

  /**
   * Create a new ProofGenerator instance
   *
   * @param config - Configuration including circuit paths
   * @param logger - Optional logger for debug output
   */
  constructor(config: ProofGeneratorConfig, logger: Logger = defaultLogger) {
    this.config = config;
    this.logger = logger;
    this.witnessBuilder = new WitnessBuilder(config.numFields ?? 16);
    this.circuitPaths = new Map();
    this.verificationKeys = new Map();

    this.initializeCircuitPaths();
  }

  /**
   * Initialize circuit paths from config or defaults
   */
  private initializeCircuitPaths(): void {
    const basePath = this.config.circuitsBasePath;

    // Age Threshold
    this.circuitPaths.set(
      DisclosureType.AGE_THRESHOLD,
      this.config.circuits?.ageThreshold ?? {
        wasm: join(basePath, CIRCUIT_FILES.ageThreshold.wasm),
        zkey: join(basePath, CIRCUIT_FILES.ageThreshold.zkey),
        vkey: join(basePath, CIRCUIT_FILES.ageThreshold.vkey),
      }
    );

    // Date Range
    this.circuitPaths.set(
      DisclosureType.DATE_RANGE,
      this.config.circuits?.dateRange ?? {
        wasm: join(basePath, CIRCUIT_FILES.dateRange.wasm),
        zkey: join(basePath, CIRCUIT_FILES.dateRange.zkey),
        vkey: join(basePath, CIRCUIT_FILES.dateRange.vkey),
      }
    );

    // Value Range
    this.circuitPaths.set(
      DisclosureType.VALUE_RANGE,
      this.config.circuits?.valueRange ?? {
        wasm: join(basePath, CIRCUIT_FILES.valueRange.wasm),
        zkey: join(basePath, CIRCUIT_FILES.valueRange.zkey),
        vkey: join(basePath, CIRCUIT_FILES.valueRange.vkey),
      }
    );

    // Set Membership
    this.circuitPaths.set(
      DisclosureType.SET_MEMBERSHIP,
      this.config.circuits?.setMembership ?? {
        wasm: join(basePath, CIRCUIT_FILES.setMembership.wasm),
        zkey: join(basePath, CIRCUIT_FILES.setMembership.zkey),
        vkey: join(basePath, CIRCUIT_FILES.setMembership.vkey),
      }
    );
  }

  /**
   * Generate a proof that the credential holder's age meets a threshold
   *
   * @param credential - Decrypted credential with birthdate
   * @param commitment - Poseidon commitment of credential data
   * @param threshold - Age threshold in years
   * @param comparisonType - "gt" for greater than, "lt" for less than
   * @param currentTimestamp - Optional current timestamp (defaults to now)
   * @returns Proof generation result
   */
  async generateAgeProof(
    credential: DecryptedCredential,
    commitment: bigint,
    threshold: number,
    comparisonType: "gt" | "lt",
    currentTimestamp?: number
  ): Promise<ProofGenerationResult> {
    const startTime = Date.now();
    this.logger.info(`Generating age proof: age ${comparisonType === "gt" ? ">" : "<"} ${threshold}`);

    try {
      const comparison =
        comparisonType === "gt"
          ? ComparisonType.GREATER_THAN
          : ComparisonType.LESS_THAN;

      // Build witness inputs
      const inputs = this.witnessBuilder.buildAgeThresholdWitness(
        credential,
        commitment,
        threshold,
        comparison,
        currentTimestamp
      );

      // Generate proof
      const proof = await this.generateProof(
        DisclosureType.AGE_THRESHOLD,
        inputsToSnarkjsFormat(inputs)
      );

      const duration = Date.now() - startTime;
      this.logger.info(`Age proof generated in ${duration}ms`);

      return {
        success: true,
        proof,
        serialized: this.serializeProofForChain(proof),
        duration,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(`Age proof generation failed: ${errorMessage}`);
      return {
        success: false,
        error: errorMessage,
        duration: Date.now() - startTime,
      };
    }
  }

  /**
   * Generate a proof that a date field is within a range
   *
   * @param credential - Decrypted credential
   * @param commitment - Poseidon commitment of credential data
   * @param fieldIndex - Index of the date field
   * @param rangeStart - Start of range (Unix timestamp)
   * @param rangeEnd - End of range (Unix timestamp)
   * @returns Proof generation result
   */
  async generateDateRangeProof(
    credential: DecryptedCredential,
    commitment: bigint,
    fieldIndex: number,
    rangeStart: number,
    rangeEnd: number
  ): Promise<ProofGenerationResult> {
    const startTime = Date.now();
    this.logger.info(`Generating date range proof: field[${fieldIndex}] in [${rangeStart}, ${rangeEnd}]`);

    try {
      // Build witness inputs
      const inputs = this.witnessBuilder.buildDateRangeWitness(
        credential,
        commitment,
        fieldIndex,
        rangeStart,
        rangeEnd
      );

      // Generate proof
      const proof = await this.generateProof(
        DisclosureType.DATE_RANGE,
        inputsToSnarkjsFormat(inputs)
      );

      const duration = Date.now() - startTime;
      this.logger.info(`Date range proof generated in ${duration}ms`);

      return {
        success: true,
        proof,
        serialized: this.serializeProofForChain(proof),
        duration,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(`Date range proof generation failed: ${errorMessage}`);
      return {
        success: false,
        error: errorMessage,
        duration: Date.now() - startTime,
      };
    }
  }

  /**
   * Generate a proof that a value field is within a range
   *
   * @param credential - Decrypted credential
   * @param commitment - Poseidon commitment of credential data
   * @param fieldIndex - Index of the value field
   * @param minValue - Minimum value (inclusive)
   * @param maxValue - Maximum value (inclusive)
   * @returns Proof generation result
   */
  async generateValueRangeProof(
    credential: DecryptedCredential,
    commitment: bigint,
    fieldIndex: number,
    minValue: bigint,
    maxValue: bigint
  ): Promise<ProofGenerationResult> {
    const startTime = Date.now();
    this.logger.info(`Generating value range proof: field[${fieldIndex}] in [${minValue}, ${maxValue}]`);

    try {
      // Build witness inputs
      const inputs = this.witnessBuilder.buildValueRangeWitness(
        credential,
        commitment,
        fieldIndex,
        minValue,
        maxValue
      );

      // Generate proof
      const proof = await this.generateProof(
        DisclosureType.VALUE_RANGE,
        inputsToSnarkjsFormat(inputs)
      );

      const duration = Date.now() - startTime;
      this.logger.info(`Value range proof generated in ${duration}ms`);

      return {
        success: true,
        proof,
        serialized: this.serializeProofForChain(proof),
        duration,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(`Value range proof generation failed: ${errorMessage}`);
      return {
        success: false,
        error: errorMessage,
        duration: Date.now() - startTime,
      };
    }
  }

  /**
   * Generate a proof that a field value is a member of a set
   *
   * @param credential - Decrypted credential
   * @param commitment - Poseidon commitment of credential data
   * @param fieldIndex - Index of the field to prove membership for
   * @param allowedValues - Array of allowed values (will build Merkle tree)
   * @returns Proof generation result
   */
  async generateSetMembershipProof(
    credential: DecryptedCredential,
    commitment: bigint,
    fieldIndex: number,
    allowedValues: bigint[]
  ): Promise<ProofGenerationResult> {
    const startTime = Date.now();
    this.logger.info(`Generating set membership proof: field[${fieldIndex}] in set of ${allowedValues.length} values`);

    try {
      const fieldValue = credential.payload.fields[fieldIndex];

      // Build Merkle tree from allowed values
      const tree = new MerkleTree(allowedValues);
      const merkleProof = tree.getProof(fieldValue);

      if (!merkleProof) {
        throw new Error(`Field value is not in the allowed set`);
      }

      // Build witness inputs
      const inputs = this.witnessBuilder.buildSetMembershipWitness(
        credential,
        commitment,
        fieldIndex,
        merkleProof
      );

      // Generate proof
      const proof = await this.generateProof(
        DisclosureType.SET_MEMBERSHIP,
        inputsToSnarkjsFormat(inputs)
      );

      const duration = Date.now() - startTime;
      this.logger.info(`Set membership proof generated in ${duration}ms`);

      return {
        success: true,
        proof,
        serialized: this.serializeProofForChain(proof),
        duration,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error(`Set membership proof generation failed: ${errorMessage}`);
      return {
        success: false,
        error: errorMessage,
        duration: Date.now() - startTime,
      };
    }
  }

  /**
   * Generate proof using snarkjs
   */
  private async generateProof(
    disclosureType: DisclosureType,
    inputs: Record<string, string | string[]>
  ): Promise<Proof> {
    const paths = this.circuitPaths.get(disclosureType);
    if (!paths) {
      throw new Error(`No circuit paths configured for disclosure type: ${disclosureType}`);
    }

    // Verify circuit files exist
    if (!existsSync(paths.wasm)) {
      throw new Error(`WASM file not found: ${paths.wasm}`);
    }
    if (!existsSync(paths.zkey)) {
      throw new Error(`ZKey file not found: ${paths.zkey}`);
    }

    // Generate witness and proof using snarkjs
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      inputs,
      paths.wasm,
      paths.zkey
    );

    return {
      proof: proof as Groth16Proof,
      publicSignals,
    };
  }

  /**
   * Verify a proof locally (for testing)
   *
   * @param disclosureType - Type of disclosure
   * @param proof - Proof to verify
   * @returns Verification result
   */
  async verifyProof(
    disclosureType: DisclosureType,
    proof: Proof
  ): Promise<VerificationResult> {
    try {
      const vkey = await this.loadVerificationKey(disclosureType);

      const isValid = await snarkjs.groth16.verify(
        vkey,
        proof.publicSignals,
        proof.proof
      );

      return { valid: isValid };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return { valid: false, error: errorMessage };
    }
  }

  /**
   * Load verification key for a circuit
   */
  private async loadVerificationKey(disclosureType: DisclosureType): Promise<object> {
    // Check cache
    const cached = this.verificationKeys.get(disclosureType);
    if (cached) {
      return cached;
    }

    const paths = this.circuitPaths.get(disclosureType);
    if (!paths?.vkey) {
      throw new Error(`No verification key path configured for: ${disclosureType}`);
    }

    if (!existsSync(paths.vkey)) {
      throw new Error(`Verification key not found: ${paths.vkey}`);
    }

    let vkey: object;
    try {
      vkey = JSON.parse(readFileSync(paths.vkey, "utf-8"));
    } catch (error) {
      throw new Error(`Failed to parse verification key at ${paths.vkey}: ${error instanceof Error ? error.message : "invalid JSON"}`);
    }
    this.verificationKeys.set(disclosureType, vkey);

    return vkey;
  }

  /**
   * Serialize proof for on-chain submission
   *
   * @param proof - Proof to serialize
   * @returns Serialized proof with calldata
   */
  serializeProofForChain(proof: Proof): SerializedProof {
    // Convert proof to calldata format used by Solidity verifiers
    // Format: a[2], b[2][2], c[2], input[n]
    const { pi_a, pi_b, pi_c } = proof.proof;

    // Build the proof bytes in the format expected by Groth16 verifiers
    // a = [a[0], a[1]]
    // b = [[b[0][1], b[0][0]], [b[1][1], b[1][0]]] (note: swapped for pairing)
    // c = [c[0], c[1]]
    const proofArray = [
      BigInt(pi_a[0]),
      BigInt(pi_a[1]),
      BigInt(pi_b[0][1]),
      BigInt(pi_b[0][0]),
      BigInt(pi_b[1][1]),
      BigInt(pi_b[1][0]),
      BigInt(pi_c[0]),
      BigInt(pi_c[1]),
    ];

    // ABI encode the proof
    const proofBytes = this.encodeProofBytes(proofArray);

    // Convert public signals to bigints
    const publicSignals = proof.publicSignals.map((s) => BigInt(s));

    return {
      proofBytes,
      publicSignals,
    };
  }

  /**
   * Encode proof array to bytes
   */
  private encodeProofBytes(proofArray: bigint[]): string {
    // Simple hex encoding - each uint256 is 32 bytes
    let result = "0x";
    for (const value of proofArray) {
      result += value.toString(16).padStart(64, "0");
    }
    return result;
  }

  /**
   * Get calldata for direct contract call
   * Returns the proof in the format expected by the verifier contract
   *
   * @param proof - Proof to format
   * @returns Formatted calldata arrays
   */
  getVerifierCalldata(proof: Proof): {
    a: [bigint, bigint];
    b: [[bigint, bigint], [bigint, bigint]];
    c: [bigint, bigint];
    input: bigint[];
  } {
    const { pi_a, pi_b, pi_c } = proof.proof;

    return {
      a: [BigInt(pi_a[0]), BigInt(pi_a[1])],
      b: [
        [BigInt(pi_b[0][1]), BigInt(pi_b[0][0])],
        [BigInt(pi_b[1][1]), BigInt(pi_b[1][0])],
      ],
      c: [BigInt(pi_c[0]), BigInt(pi_c[1])],
      input: proof.publicSignals.map((s) => BigInt(s)),
    };
  }

  /**
   * Check if circuit files are available
   */
  isCircuitAvailable(disclosureType: DisclosureType): boolean {
    const paths = this.circuitPaths.get(disclosureType);
    if (!paths) return false;

    return existsSync(paths.wasm) && existsSync(paths.zkey);
  }

  /**
   * Get list of available circuits
   */
  getAvailableCircuits(): DisclosureType[] {
    const available: DisclosureType[] = [];

    for (const type of this.circuitPaths.keys()) {
      if (this.isCircuitAvailable(type)) {
        available.push(type);
      }
    }

    return available;
  }
}
