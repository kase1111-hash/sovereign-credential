/**
 * @file CompoundProofBuilder.ts
 * @description Builder pattern for generating compound ZK proofs
 *
 * This builder allows combining multiple disclosure types into a single
 * efficient proof. The credential commitment is verified only once,
 * making compound proofs more efficient than separate proofs.
 *
 * @example
 * ```typescript
 * const proof = await new CompoundProofBuilder(credential, config)
 *   .addAgeThreshold(18, 'gt')
 *   .addDateRange('issuedAt', startDate, endDate)
 *   .addValueRange('income', 50000n, 100000n)
 *   .build();
 *
 * // Submit to chain
 * await zkEngine.verifyCompound(tokenId, proof.disclosureTypes, proof.publicInputs, proof.proof);
 * ```
 */

import type {
  DecryptedCredential,
  DisclosureType,
  DisclosureSpec,
  AgeThresholdSpec,
  DateRangeSpec,
  ValueRangeSpec,
  SetMembershipSpec,
  ExistenceSpec,
  CompoundProofInput,
  Proof,
  SerializedProof,
  MerkleTree,
  MerkleProof,
  ProofGeneratorConfig,
  ComparisonType,
} from "./types";

// Re-export types
export { DisclosureType, ComparisonType } from "./types";

/**
 * Maximum number of disclosures supported in a compound proof
 */
const MAX_DISCLOSURES = 4;

/**
 * Number of credential data fields
 */
const NUM_FIELDS = 16;

/**
 * Default Merkle tree depth for set membership
 */
const DEFAULT_TREE_DEPTH = 10;

/**
 * Field index for birthdate in credential data
 */
const BIRTHDATE_FIELD_INDEX = 0;

/**
 * Disclosure type to bytes32 mapping
 */
const DISCLOSURE_TYPE_HASHES: Record<DisclosureType, string> = {
  [0]: "0x" + Buffer.from("AGE_THRESHOLD").toString("hex").padStart(64, "0"),
  [1]: "0x" + Buffer.from("DATE_RANGE").toString("hex").padStart(64, "0"),
  [2]: "0x" + Buffer.from("VALUE_RANGE").toString("hex").padStart(64, "0"),
  [3]: "0x" + Buffer.from("SET_MEMBERSHIP").toString("hex").padStart(64, "0"),
  [4]: "0x" + Buffer.from("EXISTENCE").toString("hex").padStart(64, "0"),
};

/**
 * Builder class for creating compound ZK proofs
 *
 * Supports fluent API for adding multiple disclosures and generating
 * a single proof that verifies all of them.
 */
export class CompoundProofBuilder {
  private credential: DecryptedCredential;
  private config: ProofGeneratorConfig;
  private disclosures: DisclosureSpec[] = [];
  private treeDepth: number;

  /**
   * Create a new CompoundProofBuilder
   *
   * @param credential - Decrypted credential with data and salt
   * @param config - Configuration for proof generation
   */
  constructor(credential: DecryptedCredential, config: ProofGeneratorConfig) {
    if (credential.credentialData.length !== NUM_FIELDS) {
      throw new Error(
        `Credential data must have ${NUM_FIELDS} fields, got ${credential.credentialData.length}`
      );
    }

    this.credential = credential;
    this.config = config;
    this.treeDepth = config.merkleTreeDepth ?? DEFAULT_TREE_DEPTH;
  }

  /**
   * Add an age threshold disclosure
   *
   * @param threshold - Age threshold in years
   * @param comparison - 'gt' for greater than, 'lt' for less than
   * @param currentTimestamp - Optional current timestamp (defaults to now)
   * @returns this for chaining
   *
   * @example
   * ```typescript
   * builder.addAgeThreshold(18, 'gt'); // Prove age > 18
   * builder.addAgeThreshold(65, 'lt'); // Prove age < 65
   * ```
   */
  addAgeThreshold(
    threshold: number,
    comparison: "gt" | "lt",
    currentTimestamp?: number
  ): this {
    this.checkDisclosureLimit();

    const spec: AgeThresholdSpec = {
      type: DisclosureType.AGE_THRESHOLD,
      threshold,
      currentTimestamp: currentTimestamp ?? Math.floor(Date.now() / 1000),
      comparisonType:
        comparison === "gt"
          ? ComparisonType.GREATER_THAN
          : ComparisonType.LESS_THAN,
    };

    this.disclosures.push(spec);
    return this;
  }

  /**
   * Add a date range disclosure
   *
   * @param fieldIndex - Index of date field in credential data (or field name)
   * @param rangeStart - Start of range (Unix timestamp or Date)
   * @param rangeEnd - End of range (Unix timestamp or Date)
   * @returns this for chaining
   *
   * @example
   * ```typescript
   * builder.addDateRange(1, new Date('2020-01-01'), new Date('2023-12-31'));
   * ```
   */
  addDateRange(
    fieldIndex: number,
    rangeStart: number | Date,
    rangeEnd: number | Date
  ): this {
    this.checkDisclosureLimit();

    const start =
      rangeStart instanceof Date
        ? Math.floor(rangeStart.getTime() / 1000)
        : rangeStart;
    const end =
      rangeEnd instanceof Date
        ? Math.floor(rangeEnd.getTime() / 1000)
        : rangeEnd;

    const spec: DateRangeSpec = {
      type: DisclosureType.DATE_RANGE,
      rangeStart: start,
      rangeEnd: end,
      fieldIndex,
    };

    this.disclosures.push(spec);
    return this;
  }

  /**
   * Add a value range disclosure
   *
   * @param fieldIndex - Index of value field in credential data
   * @param minValue - Minimum value (inclusive)
   * @param maxValue - Maximum value (inclusive)
   * @returns this for chaining
   *
   * @example
   * ```typescript
   * builder.addValueRange(5, 50000n, 100000n); // Field 5 in range [50000, 100000]
   * ```
   */
  addValueRange(fieldIndex: number, minValue: bigint, maxValue: bigint): this {
    this.checkDisclosureLimit();

    const spec: ValueRangeSpec = {
      type: DisclosureType.VALUE_RANGE,
      minValue,
      maxValue,
      fieldIndex,
    };

    this.disclosures.push(spec);
    return this;
  }

  /**
   * Add a set membership disclosure
   *
   * @param fieldIndex - Index of field in credential data
   * @param merkleTree - Merkle tree of allowed values
   * @returns this for chaining
   *
   * @example
   * ```typescript
   * const allowedStates = new MerkleTree(['CA', 'NY', 'TX'].map(poseidon));
   * builder.addSetMembership(3, allowedStates);
   * ```
   */
  addSetMembership(fieldIndex: number, merkleTree: MerkleTree): this {
    this.checkDisclosureLimit();

    // Get the value from credential data
    const value = this.credential.credentialData[fieldIndex];

    // Find the value in the tree and get proof
    const index = merkleTree.indexOf(value);
    if (index < 0) {
      throw new Error(
        `Value at field ${fieldIndex} not found in Merkle tree`
      );
    }

    const proof = merkleTree.getProof(index);

    const spec: SetMembershipSpec = {
      type: DisclosureType.SET_MEMBERSHIP,
      setRoot: merkleTree.root,
      fieldIndex,
      merkleProof: proof,
    };

    this.disclosures.push(spec);
    return this;
  }

  /**
   * Add an existence disclosure (proves credential exists and is valid)
   *
   * @returns this for chaining
   */
  addExistence(): this {
    this.checkDisclosureLimit();

    const spec: ExistenceSpec = {
      type: DisclosureType.EXISTENCE,
    };

    this.disclosures.push(spec);
    return this;
  }

  /**
   * Get the number of disclosures added
   */
  get disclosureCount(): number {
    return this.disclosures.length;
  }

  /**
   * Build the compound proof
   *
   * @returns Proof object ready for serialization
   * @throws Error if no disclosures added or proof generation fails
   */
  async build(): Promise<Proof> {
    if (this.disclosures.length === 0) {
      throw new Error("At least one disclosure must be added");
    }

    if (this.disclosures.length > MAX_DISCLOSURES) {
      throw new Error(
        `Maximum ${MAX_DISCLOSURES} disclosures supported, got ${this.disclosures.length}`
      );
    }

    // Build witness input
    const input = this.buildWitnessInput();

    // Generate proof using snarkjs
    const proof = await this.generateProof(input);

    return proof;
  }

  /**
   * Build and serialize the proof for on-chain submission
   *
   * @returns Serialized proof with encoded bytes
   */
  async buildForChain(): Promise<SerializedProof> {
    const proof = await this.build();
    return this.serializeForChain(proof);
  }

  /**
   * Build the witness input for the circuit
   */
  private buildWitnessInput(): CompoundProofInput {
    const numDisclosures = this.disclosures.length;

    // Initialize arrays
    const disclosureTypes: DisclosureType[] = [];
    const disclosureParams: bigint[][] = [];
    const privateValues: bigint[] = [];
    const merkleProofs: bigint[][] = [];
    const merklePathIndices: number[][] = [];

    // Process each disclosure
    for (const spec of this.disclosures) {
      disclosureTypes.push(spec.type);

      switch (spec.type) {
        case DisclosureType.AGE_THRESHOLD: {
          // params: [threshold, currentTimestamp, comparisonType, 0]
          disclosureParams.push([
            BigInt(spec.threshold),
            BigInt(spec.currentTimestamp),
            BigInt(spec.comparisonType),
            0n,
          ]);
          // privateValue: birthdate (field 0)
          privateValues.push(this.credential.credentialData[BIRTHDATE_FIELD_INDEX]);
          // Empty merkle proof
          merkleProofs.push(new Array(this.treeDepth).fill(0n));
          merklePathIndices.push(new Array(this.treeDepth).fill(0));
          break;
        }

        case DisclosureType.DATE_RANGE: {
          // params: [rangeStart, rangeEnd, fieldIndex, 0]
          disclosureParams.push([
            BigInt(spec.rangeStart),
            BigInt(spec.rangeEnd),
            BigInt(spec.fieldIndex),
            0n,
          ]);
          // privateValue: actual date value
          privateValues.push(this.credential.credentialData[spec.fieldIndex]);
          // Empty merkle proof
          merkleProofs.push(new Array(this.treeDepth).fill(0n));
          merklePathIndices.push(new Array(this.treeDepth).fill(0));
          break;
        }

        case DisclosureType.VALUE_RANGE: {
          // params: [minValue, maxValue, fieldIndex, 0]
          disclosureParams.push([
            spec.minValue,
            spec.maxValue,
            BigInt(spec.fieldIndex),
            0n,
          ]);
          // privateValue: actual value
          privateValues.push(this.credential.credentialData[spec.fieldIndex]);
          // Empty merkle proof
          merkleProofs.push(new Array(this.treeDepth).fill(0n));
          merklePathIndices.push(new Array(this.treeDepth).fill(0));
          break;
        }

        case DisclosureType.SET_MEMBERSHIP: {
          // params: [setRoot, fieldIndex, 0, 0]
          disclosureParams.push([
            spec.setRoot,
            BigInt(spec.fieldIndex),
            0n,
            0n,
          ]);
          // privateValue: actual value
          privateValues.push(this.credential.credentialData[spec.fieldIndex]);
          // Merkle proof
          merkleProofs.push(spec.merkleProof.pathElements);
          merklePathIndices.push(spec.merkleProof.pathIndices);
          break;
        }

        case DisclosureType.EXISTENCE: {
          // params: all zeros (not used)
          disclosureParams.push([0n, 0n, 0n, 0n]);
          // privateValue: not used
          privateValues.push(0n);
          // Empty merkle proof
          merkleProofs.push(new Array(this.treeDepth).fill(0n));
          merklePathIndices.push(new Array(this.treeDepth).fill(0));
          break;
        }
      }
    }

    return {
      credentialCommitment: this.credential.commitment,
      disclosureTypes,
      disclosureParams,
      credentialData: this.credential.credentialData,
      salt: this.credential.salt,
      privateValues,
      merkleProofs,
      merklePathIndices,
    };
  }

  /**
   * Generate the ZK proof using snarkjs
   */
  private async generateProof(input: CompoundProofInput): Promise<Proof> {
    // Dynamically import snarkjs (it's a CommonJS module)
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const snarkjs = await import("snarkjs");

    const numDisclosures = input.disclosureTypes.length;

    // Select circuit based on number of disclosures
    let circuitName: string;
    if (numDisclosures === 2) {
      circuitName = "CompoundProof";
    } else if (numDisclosures === 3) {
      circuitName = "CompoundProof3";
    } else if (numDisclosures === 4) {
      circuitName = "CompoundProof4";
    } else {
      throw new Error(
        `Unsupported number of disclosures: ${numDisclosures}. Supported: 2, 3, 4`
      );
    }

    const wasmPath = `${this.config.circuitsPath}/${circuitName}.wasm`;
    const zkeyPath = `${this.config.provingKeysPath}/${circuitName}_final.zkey`;

    // Format input for snarkjs
    const witnessInput = this.formatWitnessInput(input);

    // Generate proof
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      witnessInput,
      wasmPath,
      zkeyPath
    );

    return {
      pi_a: [proof.pi_a[0], proof.pi_a[1]] as [string, string],
      pi_b: [
        [proof.pi_b[0][1], proof.pi_b[0][0]],
        [proof.pi_b[1][1], proof.pi_b[1][0]],
      ] as [[string, string], [string, string]],
      pi_c: [proof.pi_c[0], proof.pi_c[1]] as [string, string],
      protocol: "groth16",
      publicSignals,
    };
  }

  /**
   * Format witness input for snarkjs
   */
  private formatWitnessInput(
    input: CompoundProofInput
  ): Record<string, string | string[] | string[][]> {
    return {
      credentialCommitment: input.credentialCommitment.toString(),
      disclosureTypes: input.disclosureTypes.map((t) => t.toString()),
      disclosureParams: input.disclosureParams.map((params) =>
        params.map((p) => p.toString())
      ),
      credentialData: input.credentialData.map((d) => d.toString()),
      salt: input.salt.toString(),
      privateValues: input.privateValues.map((v) => v.toString()),
      merkleProofs: input.merkleProofs.map((proof) =>
        proof.map((p) => p.toString())
      ),
      merklePathIndices: input.merklePathIndices.map((indices) =>
        indices.map((i) => i.toString())
      ),
    };
  }

  /**
   * Serialize proof for on-chain submission
   */
  private serializeForChain(proof: Proof): SerializedProof {
    // Import ethers for ABI encoding
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { ethers } = require("ethers");

    // Encode proof points
    const proofEncoded = ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint[2]", "uint[2][2]", "uint[2]"],
      [
        proof.pi_a.map((x) => BigInt(x)),
        proof.pi_b.map((row) => row.map((x) => BigInt(x))),
        proof.pi_c.map((x) => BigInt(x)),
      ]
    );

    // Encode public inputs based on number of disclosures
    const numDisclosures = this.disclosures.length;
    const types: bigint[] = [];
    const params: bigint[] = [];

    for (let i = 0; i < numDisclosures; i++) {
      types.push(BigInt(this.disclosures[i].type));
    }

    // Flatten params
    for (let i = 0; i < numDisclosures; i++) {
      const sigIdx = 1 + numDisclosures + i * 4; // Skip commitment + types
      for (let j = 0; j < 4; j++) {
        params.push(BigInt(proof.publicSignals[sigIdx + j]));
      }
    }

    // Encode based on disclosure count
    let typesAndParams: string;
    if (numDisclosures === 2) {
      typesAndParams = ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256", "uint256[8]"],
        [types[0], types[1], params]
      );
    } else if (numDisclosures === 3) {
      typesAndParams = ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256", "uint256", "uint256[12]"],
        [types[0], types[1], types[2], params]
      );
    } else {
      typesAndParams = ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256", "uint256", "uint256", "uint256[16]"],
        [types[0], types[1], types[2], types[3], params]
      );
    }

    // Get disclosure type hashes
    const disclosureTypeHashes = this.disclosures.map(
      (d) => DISCLOSURE_TYPE_HASHES[d.type]
    );

    return {
      proof: proofEncoded,
      publicInputs: typesAndParams,
      disclosureTypes: disclosureTypeHashes,
    };
  }

  /**
   * Check if adding another disclosure would exceed the limit
   */
  private checkDisclosureLimit(): void {
    if (this.disclosures.length >= MAX_DISCLOSURES) {
      throw new Error(
        `Maximum ${MAX_DISCLOSURES} disclosures allowed in a compound proof`
      );
    }
  }
}

/**
 * Create a new CompoundProofBuilder
 *
 * @param credential - Decrypted credential
 * @param config - Proof generation configuration
 * @returns New builder instance
 */
export function createCompoundProofBuilder(
  credential: DecryptedCredential,
  config: ProofGeneratorConfig
): CompoundProofBuilder {
  return new CompoundProofBuilder(credential, config);
}
