/**
 * @file merkleTree.ts
 * @description Merkle tree utilities for set membership proofs
 * @dev Uses Poseidon hash to match the circom circuit implementation
 *
 * Spec Reference: SPEC.md Section 6.1.4
 */

// @ts-ignore - snarkjs types
import * as snarkjs from "snarkjs";

/**
 * Poseidon hash function wrapper
 * Uses snarkjs buildPoseidon which matches circomlib's implementation
 */
let poseidonInstance: any = null;

async function getPoseidon(): Promise<any> {
  if (!poseidonInstance) {
    poseidonInstance = await snarkjs.buildPoseidon();
  }
  return poseidonInstance;
}

/**
 * Hash inputs using Poseidon
 * @param inputs Array of bigint values to hash
 * @returns Hash as bigint
 */
export async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  const poseidon = await getPoseidon();
  const hash = poseidon(inputs);
  return poseidon.F.toObject(hash);
}

/**
 * Hash a single value to create a Merkle leaf
 * This matches the MerkleLeafHasher template in merkle.circom
 * @param value Value to hash
 * @returns Leaf hash as bigint
 */
export async function hashLeaf(value: bigint): Promise<bigint> {
  return await poseidonHash([value]);
}

/**
 * Hash two children to create a parent node
 * @param left Left child hash
 * @param right Right child hash
 * @returns Parent hash as bigint
 */
export async function hashPair(left: bigint, right: bigint): Promise<bigint> {
  return await poseidonHash([left, right]);
}

/**
 * Merkle proof structure
 */
export interface MerkleProof {
  /** Sibling hashes along the path (bottom to top) */
  proof: bigint[];
  /** Path indices (0 = left, 1 = right) at each level */
  indices: number[];
  /** The leaf value */
  leaf: bigint;
  /** The leaf hash */
  leafHash: bigint;
  /** Index of the leaf in the tree */
  leafIndex: number;
}

/**
 * Merkle tree for set membership proofs
 *
 * Features:
 * - Uses Poseidon hash for ZK-friendly operations
 * - Supports variable depth trees
 * - Pads with zero hashes for non-power-of-2 leaf counts
 * - Generates proofs compatible with SetMembership.circom
 *
 * @example
 * ```typescript
 * const values = [1n, 2n, 3n, 4n];
 * const tree = await MerkleTree.build(values, 10);
 * const root = tree.getRoot();
 * const proof = tree.getProof(0); // Proof for first value
 * ```
 */
export class MerkleTree {
  /** Raw values stored in the tree */
  private values: bigint[];

  /** Hashed leaf values */
  private leaves: bigint[];

  /** All tree nodes, indexed by level then position */
  private nodes: bigint[][];

  /** Tree depth (number of levels) */
  private depth: number;

  /** Zero hash values for each level (for padding) */
  private zeroHashes: bigint[];

  private constructor(
    values: bigint[],
    leaves: bigint[],
    nodes: bigint[][],
    depth: number,
    zeroHashes: bigint[]
  ) {
    this.values = values;
    this.leaves = leaves;
    this.nodes = nodes;
    this.depth = depth;
    this.zeroHashes = zeroHashes;
  }

  /**
   * Build a Merkle tree from values
   * @param values Array of values to include in the tree
   * @param depth Tree depth (supports 2^depth leaves)
   * @returns MerkleTree instance
   */
  static async build(values: bigint[], depth: number): Promise<MerkleTree> {
    const maxLeaves = 2 ** depth;

    if (values.length > maxLeaves) {
      throw new Error(
        `Too many values: ${values.length} > ${maxLeaves} (max for depth ${depth})`
      );
    }

    // Compute zero hashes for padding
    const zeroHashes = await MerkleTree.computeZeroHashes(depth);

    // Hash all values to create leaves
    const leaves: bigint[] = [];
    for (const value of values) {
      const leafHash = await hashLeaf(value);
      leaves.push(leafHash);
    }

    // Pad with zero hashes to fill the tree
    while (leaves.length < maxLeaves) {
      leaves.push(zeroHashes[0]);
    }

    // Build tree bottom-up
    const nodes: bigint[][] = [leaves];

    let currentLevel = leaves;
    for (let level = 0; level < depth; level++) {
      const nextLevel: bigint[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = currentLevel[i + 1];
        const parent = await hashPair(left, right);
        nextLevel.push(parent);
      }
      nodes.push(nextLevel);
      currentLevel = nextLevel;
    }

    return new MerkleTree(values, nodes[0], nodes, depth, zeroHashes);
  }

  /**
   * Compute zero hashes for each level
   * Zero hashes are used to pad the tree for non-power-of-2 leaf counts
   * @param depth Tree depth
   * @returns Array of zero hashes, one per level
   */
  private static async computeZeroHashes(depth: number): Promise<bigint[]> {
    const zeroHashes: bigint[] = [];

    // Level 0: hash of 0
    let current = await hashLeaf(0n);
    zeroHashes.push(current);

    // Higher levels: hash of (zero[i-1], zero[i-1])
    for (let i = 1; i <= depth; i++) {
      current = await hashPair(zeroHashes[i - 1], zeroHashes[i - 1]);
      zeroHashes.push(current);
    }

    return zeroHashes;
  }

  /**
   * Get the Merkle root
   * @returns Root hash
   */
  getRoot(): bigint {
    return this.nodes[this.depth][0];
  }

  /**
   * Get the tree depth
   * @returns Depth
   */
  getDepth(): number {
    return this.depth;
  }

  /**
   * Get the number of actual values (not including padding)
   * @returns Number of values
   */
  getValueCount(): number {
    return this.values.length;
  }

  /**
   * Get a Merkle proof for a value by its index
   * @param index Index of the value (0-based)
   * @returns Merkle proof
   */
  getProof(index: number): MerkleProof {
    if (index < 0 || index >= this.values.length) {
      throw new Error(`Invalid index: ${index}. Must be 0-${this.values.length - 1}`);
    }

    const proof: bigint[] = [];
    const indices: number[] = [];

    let currentIndex = index;

    // Traverse from leaf to root
    for (let level = 0; level < this.depth; level++) {
      // Determine if current node is left or right child
      const isRightChild = currentIndex % 2 === 1;
      const siblingIndex = isRightChild ? currentIndex - 1 : currentIndex + 1;

      // Get sibling hash
      const sibling = this.nodes[level][siblingIndex];
      proof.push(sibling);

      // Store path direction (0 = current is left, 1 = current is right)
      indices.push(isRightChild ? 1 : 0);

      // Move to parent level
      currentIndex = Math.floor(currentIndex / 2);
    }

    return {
      proof,
      indices,
      leaf: this.values[index],
      leafHash: this.leaves[index],
      leafIndex: index,
    };
  }

  /**
   * Get a Merkle proof for a value by searching for it
   * @param value Value to find
   * @returns Merkle proof or null if not found
   */
  getProofByValue(value: bigint): MerkleProof | null {
    const index = this.values.findIndex((v) => v === value);
    if (index === -1) {
      return null;
    }
    return this.getProof(index);
  }

  /**
   * Verify a Merkle proof
   * @param value Value that should be in the tree
   * @param proof Sibling hashes
   * @param indices Path directions
   * @param root Expected root
   * @returns True if proof is valid
   */
  static async verify(
    value: bigint,
    proof: bigint[],
    indices: number[],
    root: bigint
  ): Promise<boolean> {
    if (proof.length !== indices.length) {
      return false;
    }

    // Hash the value to get the leaf
    let current = await hashLeaf(value);

    // Traverse up the tree
    for (let i = 0; i < proof.length; i++) {
      const sibling = proof[i];
      const isRightChild = indices[i] === 1;

      if (isRightChild) {
        current = await hashPair(sibling, current);
      } else {
        current = await hashPair(current, sibling);
      }
    }

    return current === root;
  }

  /**
   * Verify a Merkle proof (instance method)
   * @param proof MerkleProof object
   * @returns True if proof is valid
   */
  async verifyProof(proof: MerkleProof): Promise<boolean> {
    return MerkleTree.verify(
      proof.leaf,
      proof.proof,
      proof.indices,
      this.getRoot()
    );
  }

  /**
   * Check if a value is in the tree
   * @param value Value to check
   * @returns True if value exists in tree
   */
  contains(value: bigint): boolean {
    return this.values.includes(value);
  }

  /**
   * Get all values in the tree
   * @returns Array of values
   */
  getValues(): bigint[] {
    return [...this.values];
  }

  /**
   * Get all leaf hashes
   * @returns Array of leaf hashes
   */
  getLeaves(): bigint[] {
    return [...this.leaves];
  }

  /**
   * Convert to JSON-serializable format
   */
  toJSON(): {
    values: string[];
    root: string;
    depth: number;
  } {
    return {
      values: this.values.map((v) => v.toString()),
      root: this.getRoot().toString(),
      depth: this.depth,
    };
  }

  /**
   * Build from JSON format
   * @param json JSON representation
   * @returns MerkleTree instance
   */
  static async fromJSON(json: {
    values: string[];
    depth: number;
  }): Promise<MerkleTree> {
    const values = json.values.map((v) => BigInt(v));
    return MerkleTree.build(values, json.depth);
  }
}

/**
 * Create a Merkle tree from an array of values
 * Convenience function for quick tree creation
 *
 * @param values Array of values (numbers, strings, or bigints)
 * @param depth Tree depth (default: 10 for up to 1024 values)
 * @returns MerkleTree instance
 */
export async function createMerkleTree(
  values: (number | string | bigint)[],
  depth: number = 10
): Promise<MerkleTree> {
  const bigintValues = values.map((v) => BigInt(v));
  return MerkleTree.build(bigintValues, depth);
}

/**
 * Format proof for circuit input
 * Converts a MerkleProof to the format expected by SetMembership.circom
 *
 * @param proof MerkleProof object
 * @returns Object with arrays formatted for circuit input
 */
export function formatProofForCircuit(proof: MerkleProof): {
  actualValue: bigint;
  merkleProof: bigint[];
  merklePathIndices: bigint[];
} {
  return {
    actualValue: proof.leaf,
    merkleProof: proof.proof,
    merklePathIndices: proof.indices.map((i) => BigInt(i)),
  };
}

/**
 * Generate circuit inputs for set membership proof
 * Helper function that creates all required inputs for SetMembership.circom
 *
 * @param value Value to prove membership of
 * @param allowedValues Array of allowed values in the set
 * @param credentialData Full credential data array
 * @param fieldIndex Index of field containing the value
 * @param salt Salt used for commitment
 * @param treeDepth Merkle tree depth
 * @returns Circuit input object
 */
export async function generateSetMembershipInputs(
  value: bigint,
  allowedValues: bigint[],
  credentialData: bigint[],
  fieldIndex: number,
  salt: bigint,
  treeDepth: number = 10
): Promise<{
  credentialCommitment: bigint;
  setRoot: bigint;
  fieldIndex: bigint;
  actualValue: bigint;
  merkleProof: bigint[];
  merklePathIndices: bigint[];
  credentialData: bigint[];
  salt: bigint;
}> {
  // Build the Merkle tree from allowed values
  const tree = await MerkleTree.build(allowedValues, treeDepth);

  // Get proof for the specific value
  const proof = tree.getProofByValue(value);
  if (!proof) {
    throw new Error(`Value ${value} not found in allowed values`);
  }

  // Compute credential commitment
  const commitment = await poseidonHash([...credentialData, salt]);

  // Format for circuit
  const formattedProof = formatProofForCircuit(proof);

  return {
    credentialCommitment: commitment,
    setRoot: tree.getRoot(),
    fieldIndex: BigInt(fieldIndex),
    actualValue: formattedProof.actualValue,
    merkleProof: formattedProof.merkleProof,
    merklePathIndices: formattedProof.merklePathIndices,
    credentialData,
    salt,
  };
}

// MerkleProof is already exported above as an interface
