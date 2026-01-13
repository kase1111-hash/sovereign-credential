/**
 * @file MerkleTree
 * @description Poseidon-based Merkle tree for set membership proofs
 */

import type { MerkleProof, MerkleTreeConfig } from "./types";

// Poseidon hash function type
type HashFunction = (inputs: bigint[]) => bigint;

/**
 * Default Poseidon hash constants
 * These would be loaded from circomlibjs in a real implementation
 * For now, we use a placeholder that should be replaced with actual Poseidon
 */
let poseidonHash: HashFunction | null = null;

/**
 * Initialize Poseidon hash function
 * Must be called before using MerkleTree with Poseidon hashing
 */
export async function initPoseidon(): Promise<void> {
  try {
    // Dynamic import of circomlibjs
    const circomlibjs = await import("circomlibjs");
    const poseidon = await circomlibjs.buildPoseidon();

    poseidonHash = (inputs: bigint[]): bigint => {
      const hash = poseidon(inputs.map((i) => poseidon.F.e(i)));
      return BigInt(poseidon.F.toString(hash));
    };
  } catch {
    console.warn(
      "Failed to load circomlibjs Poseidon. Using fallback hash function."
    );
    // Fallback to keccak-style hash (not ZK-friendly, but works for testing)
    poseidonHash = fallbackHash;
  }
}

/**
 * Fallback hash function for testing when Poseidon is not available
 * WARNING: This is NOT ZK-friendly and should only be used for testing
 */
function fallbackHash(inputs: bigint[]): bigint {
  // Simple combination for testing - NOT suitable for production
  let result = 0n;
  const prime = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

  for (let i = 0; i < inputs.length; i++) {
    result = (result + inputs[i] * BigInt(i + 1)) % prime;
  }

  return result;
}

/**
 * Get the hash function (Poseidon or fallback)
 */
function getHashFunction(): HashFunction {
  if (poseidonHash) {
    return poseidonHash;
  }

  // Auto-initialize with fallback
  poseidonHash = fallbackHash;
  console.warn("Using fallback hash. Call initPoseidon() for production use.");
  return poseidonHash;
}

/**
 * Poseidon-based Merkle tree implementation
 * Used for set membership proofs in ZK circuits
 */
export class MerkleTree {
  private depth: number;
  private leaves: bigint[];
  private layers: bigint[][];
  private hashFn: HashFunction;
  private leafToIndex: Map<string, number>;

  /**
   * Create a new Merkle tree
   *
   * @param leaves - Array of leaf values
   * @param config - Optional configuration
   */
  constructor(leaves: bigint[], config?: Partial<MerkleTreeConfig>) {
    this.hashFn = config?.hashFunction ?? getHashFunction();
    this.leaves = [...leaves];
    this.leafToIndex = new Map();

    // Calculate required depth
    const minDepth = Math.ceil(Math.log2(Math.max(leaves.length, 1)));
    this.depth = config?.depth ?? Math.max(minDepth, 1);

    // Pad leaves to power of 2
    const targetSize = Math.pow(2, this.depth);
    while (this.leaves.length < targetSize) {
      this.leaves.push(0n); // Zero padding
    }

    // Build leaf index map
    for (let i = 0; i < leaves.length; i++) {
      this.leafToIndex.set(leaves[i].toString(), i);
    }

    // Build tree layers
    this.layers = this.buildTree();
  }

  /**
   * Build the tree layers from leaves to root
   */
  private buildTree(): bigint[][] {
    const layers: bigint[][] = [this.leaves];

    let currentLayer = this.leaves;

    while (currentLayer.length > 1) {
      const nextLayer: bigint[] = [];

      for (let i = 0; i < currentLayer.length; i += 2) {
        const left = currentLayer[i];
        const right = currentLayer[i + 1] ?? 0n;
        nextLayer.push(this.hashFn([left, right]));
      }

      layers.push(nextLayer);
      currentLayer = nextLayer;
    }

    return layers;
  }

  /**
   * Get the Merkle root
   */
  getRoot(): bigint {
    if (this.layers.length === 0 || this.layers[this.layers.length - 1].length === 0) {
      return 0n;
    }
    return this.layers[this.layers.length - 1][0];
  }

  /**
   * Get the depth of the tree
   */
  getDepth(): number {
    return this.depth;
  }

  /**
   * Get a Merkle proof for a leaf value
   *
   * @param leaf - The leaf value to prove
   * @returns MerkleProof or null if leaf is not in tree
   */
  getProof(leaf: bigint): MerkleProof | null {
    const index = this.leafToIndex.get(leaf.toString());
    if (index === undefined) {
      return null;
    }

    return this.getProofByIndex(index);
  }

  /**
   * Get a Merkle proof by leaf index
   *
   * @param index - Index of the leaf
   * @returns MerkleProof
   */
  getProofByIndex(index: number): MerkleProof {
    if (index < 0 || index >= this.leaves.length) {
      throw new Error(`Invalid index: ${index}`);
    }

    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];

    let currentIndex = index;

    for (let i = 0; i < this.depth; i++) {
      const siblingIndex = currentIndex % 2 === 0 ? currentIndex + 1 : currentIndex - 1;
      const sibling = this.layers[i][siblingIndex] ?? 0n;

      pathElements.push(sibling);
      pathIndices.push(currentIndex % 2); // 0 if left, 1 if right

      currentIndex = Math.floor(currentIndex / 2);
    }

    return {
      root: this.getRoot(),
      leaf: this.leaves[index],
      pathElements,
      pathIndices,
    };
  }

  /**
   * Verify a Merkle proof
   *
   * @param proof - The proof to verify
   * @returns true if proof is valid
   */
  verify(proof: MerkleProof): boolean {
    let currentHash = proof.leaf;

    for (let i = 0; i < proof.pathElements.length; i++) {
      const sibling = proof.pathElements[i];
      const isRight = proof.pathIndices[i] === 1;

      if (isRight) {
        currentHash = this.hashFn([sibling, currentHash]);
      } else {
        currentHash = this.hashFn([currentHash, sibling]);
      }
    }

    return currentHash === proof.root;
  }

  /**
   * Check if a value is in the tree
   */
  contains(value: bigint): boolean {
    return this.leafToIndex.has(value.toString());
  }

  /**
   * Get all leaves
   */
  getLeaves(): bigint[] {
    return [...this.leaves];
  }

  /**
   * Get leaf at index
   */
  getLeaf(index: number): bigint {
    return this.leaves[index];
  }

  /**
   * Static method to verify a proof without instantiating a tree
   */
  static verifyProof(
    proof: MerkleProof,
    hashFn?: HashFunction
  ): boolean {
    const hash = hashFn ?? getHashFunction();
    let currentHash = proof.leaf;

    for (let i = 0; i < proof.pathElements.length; i++) {
      const sibling = proof.pathElements[i];
      const isRight = proof.pathIndices[i] === 1;

      if (isRight) {
        currentHash = hash([sibling, currentHash]);
      } else {
        currentHash = hash([currentHash, sibling]);
      }
    }

    return currentHash === proof.root;
  }

  /**
   * Compute Merkle root from a single leaf and proof
   * Useful for computing expected root in tests
   */
  static computeRoot(
    leaf: bigint,
    pathElements: bigint[],
    pathIndices: number[],
    hashFn?: HashFunction
  ): bigint {
    const hash = hashFn ?? getHashFunction();
    let currentHash = leaf;

    for (let i = 0; i < pathElements.length; i++) {
      const sibling = pathElements[i];
      const isRight = pathIndices[i] === 1;

      if (isRight) {
        currentHash = hash([sibling, currentHash]);
      } else {
        currentHash = hash([currentHash, sibling]);
      }
    }

    return currentHash;
  }
}

/**
 * Create a Merkle tree from an array of values
 * Convenience function that initializes Poseidon if needed
 */
export async function createMerkleTree(
  values: bigint[],
  depth?: number
): Promise<MerkleTree> {
  await initPoseidon();
  return new MerkleTree(values, { depth });
}

/**
 * Hash a single value to create a leaf
 */
export function hashLeaf(value: bigint): bigint {
  const hash = getHashFunction();
  return hash([value]);
}

/**
 * Hash multiple values together
 */
export function hashValues(values: bigint[]): bigint {
  const hash = getHashFunction();
  return hash(values);
}
