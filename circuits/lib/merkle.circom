/**
 * @file merkle.circom
 * @description Merkle tree verification templates for set membership proofs
 * @dev Uses Poseidon hash for ZK-friendly Merkle trees
 */

pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/**
 * @title MerkleTreeChecker
 * @notice Verifies a Merkle proof for set membership
 * @param DEPTH Depth of the Merkle tree (supports 2^DEPTH leaves)
 *
 * @input leaf - The leaf value to verify membership of
 * @input root - The Merkle root to verify against
 * @input pathElements[DEPTH] - Sibling hashes along the path
 * @input pathIndices[DEPTH] - Path direction at each level (0=left, 1=right)
 *
 * The proof verifies that: hash(hash(hash(leaf, path[0]), path[1]), ...) == root
 */
template MerkleTreeChecker(DEPTH) {
    signal input leaf;
    signal input root;
    signal input pathElements[DEPTH];
    signal input pathIndices[DEPTH];

    // Compute the root from leaf and path
    component hashers[DEPTH];
    component selectors[DEPTH];

    signal computedHashes[DEPTH + 1];
    computedHashes[0] <== leaf;

    for (var i = 0; i < DEPTH; i++) {
        // Ensure pathIndices are binary
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // Select order of hash inputs based on path direction
        selectors[i] = DualMux();
        selectors[i].in[0] <== computedHashes[i];
        selectors[i].in[1] <== pathElements[i];
        selectors[i].sel <== pathIndices[i];

        // Hash the pair
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== selectors[i].out[0];
        hashers[i].inputs[1] <== selectors[i].out[1];

        computedHashes[i + 1] <== hashers[i].out;
    }

    // Verify computed root matches expected root
    root === computedHashes[DEPTH];
}

/**
 * @title MerkleTreeInclusionProof
 * @notice Outputs 1 if leaf is in tree, 0 otherwise (for conditional proofs)
 * @param DEPTH Depth of the Merkle tree
 */
template MerkleTreeInclusionProof(DEPTH) {
    signal input leaf;
    signal input root;
    signal input pathElements[DEPTH];
    signal input pathIndices[DEPTH];

    signal output isIncluded;

    // Compute the root from leaf and path
    component hashers[DEPTH];
    component selectors[DEPTH];

    signal computedHashes[DEPTH + 1];
    computedHashes[0] <== leaf;

    for (var i = 0; i < DEPTH; i++) {
        // Ensure pathIndices are binary
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        selectors[i] = DualMux();
        selectors[i].in[0] <== computedHashes[i];
        selectors[i].in[1] <== pathElements[i];
        selectors[i].sel <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== selectors[i].out[0];
        hashers[i].inputs[1] <== selectors[i].out[1];

        computedHashes[i + 1] <== hashers[i].out;
    }

    // Check if computed root matches expected root
    component eq = IsEqual();
    eq.in[0] <== root;
    eq.in[1] <== computedHashes[DEPTH];

    isIncluded <== eq.out;
}

/**
 * @title DualMux
 * @notice 2-to-2 multiplexer for swapping inputs based on selector
 *
 * If sel == 0: out[0] = in[0], out[1] = in[1]
 * If sel == 1: out[0] = in[1], out[1] = in[0]
 */
template DualMux() {
    signal input in[2];
    signal input sel;

    signal output out[2];

    // sel must be binary (enforced by caller)
    out[0] <== (in[1] - in[0]) * sel + in[0];
    out[1] <== (in[0] - in[1]) * sel + in[1];
}

/**
 * @title MerkleLeafHasher
 * @notice Hashes a value to create a Merkle leaf
 * @dev Uses Poseidon for ZK-efficiency
 *
 * @input value - The value to hash
 * @output leaf - The leaf hash
 */
template MerkleLeafHasher() {
    signal input value;
    signal output leaf;

    component hasher = Poseidon(1);
    hasher.inputs[0] <== value;

    leaf <== hasher.out;
}

/**
 * @title MerkleMultiLeafHasher
 * @notice Hashes multiple values into a single Merkle leaf
 * @param N Number of values to hash
 *
 * @input values[N] - Values to hash together
 * @output leaf - The combined leaf hash
 */
template MerkleMultiLeafHasher(N) {
    signal input values[N];
    signal output leaf;

    component hasher = Poseidon(N);
    for (var i = 0; i < N; i++) {
        hasher.inputs[i] <== values[i];
    }

    leaf <== hasher.out;
}

/**
 * @title SparseMerkleTreeChecker
 * @notice Verifies inclusion/exclusion in a Sparse Merkle Tree
 * @param DEPTH Depth of the SMT
 *
 * Sparse Merkle Trees allow proving non-membership as well as membership.
 * Empty leaves are represented by a fixed empty hash.
 */
template SparseMerkleTreeChecker(DEPTH) {
    signal input key;
    signal input value;
    signal input root;
    signal input siblings[DEPTH];
    signal input isIncluded; // 1 if proving inclusion, 0 if proving exclusion

    // Convert key to bits for path direction
    component keyBits = Num2Bits(DEPTH);
    keyBits.in <== key;

    // Empty leaf hash (Poseidon(0))
    var EMPTY_LEAF = 14744269619966411208579211824598458697587494354926760081771325075741142829156;

    // Compute leaf based on whether proving inclusion or exclusion
    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== key;
    leafHasher.inputs[1] <== value;

    signal leaf;
    // If isIncluded == 1, use computed hash; if 0, use empty hash
    leaf <== isIncluded * leafHasher.out + (1 - isIncluded) * EMPTY_LEAF;

    // Verify Merkle path
    component checker = MerkleTreeChecker(DEPTH);
    checker.leaf <== leaf;
    checker.root <== root;

    for (var i = 0; i < DEPTH; i++) {
        checker.pathElements[i] <== siblings[i];
        checker.pathIndices[i] <== keyBits.out[i];
    }
}

/**
 * @title ComputeMerkleRoot
 * @notice Computes a Merkle root from leaf and proof (helper for generating proofs)
 * @param DEPTH Depth of the Merkle tree
 *
 * @input leaf - The leaf value
 * @input pathElements[DEPTH] - Sibling hashes
 * @input pathIndices[DEPTH] - Path directions
 * @output root - Computed Merkle root
 */
template ComputeMerkleRoot(DEPTH) {
    signal input leaf;
    signal input pathElements[DEPTH];
    signal input pathIndices[DEPTH];

    signal output root;

    component hashers[DEPTH];
    component selectors[DEPTH];

    signal computedHashes[DEPTH + 1];
    computedHashes[0] <== leaf;

    for (var i = 0; i < DEPTH; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        selectors[i] = DualMux();
        selectors[i].in[0] <== computedHashes[i];
        selectors[i].in[1] <== pathElements[i];
        selectors[i].sel <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== selectors[i].out[0];
        hashers[i].inputs[1] <== selectors[i].out[1];

        computedHashes[i + 1] <== hashers[i].out;
    }

    root <== computedHashes[DEPTH];
}
