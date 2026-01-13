/**
 * @file SetMembership.circom
 * @description Zero-knowledge circuit for proving a credential field value
 *              is a member of an allowed set, without revealing the actual value
 *
 * @dev This circuit allows a credential holder to prove statements like
 *      "My license type is one of [A, B, C]" without revealing which one,
 *      using Merkle tree proofs for efficient set membership verification
 *
 * Spec Reference: SPEC.md Section 6.1.4
 */

pragma circom 2.1.6;

include "lib/commitment.circom";
include "lib/comparators.circom";
include "lib/merkle.circom";

/**
 * @title SetMembership
 * @notice Proves a credential field value is a member of a set defined by a Merkle root
 * @param NUM_FIELDS Number of credential fields (default 16)
 * @param TREE_DEPTH Depth of the Merkle tree (supports 2^TREE_DEPTH members)
 *
 * Public Inputs:
 *   - credentialCommitment: Poseidon hash of credential data + salt
 *   - setRoot: Merkle root of the allowed set of values
 *   - fieldIndex: Index of the field in credential data to verify
 *
 * Private Inputs:
 *   - actualValue: The actual field value (proven to be in set)
 *   - merkleProof: Sibling hashes along the Merkle path
 *   - merklePathIndices: Path direction at each level (0=left, 1=right)
 *   - credentialData: Full credential field array
 *   - salt: Randomness used in commitment
 *
 * Constraints:
 *   1. Commitment verification: credentialCommitment == Poseidon(credentialData, salt)
 *   2. Field extraction: actualValue == credentialData[fieldIndex]
 *   3. Set membership: MerkleRoot(actualValue, proof, indices) == setRoot
 */
template SetMembership(NUM_FIELDS, TREE_DEPTH) {
    // ===== PUBLIC INPUTS =====
    signal input credentialCommitment;
    signal input setRoot;               // Merkle root of allowed values
    signal input fieldIndex;            // Index of field to verify membership

    // ===== PRIVATE INPUTS =====
    signal input actualValue;           // The actual value to prove is in set
    signal input merkleProof[TREE_DEPTH];        // Merkle proof siblings
    signal input merklePathIndices[TREE_DEPTH];  // Path directions
    signal input credentialData[NUM_FIELDS];     // Full credential payload
    signal input salt;                  // Randomness for commitment hiding

    // ===== STEP 1: Verify Credential Commitment =====
    // Ensures the private credential data matches the public commitment
    component commitmentVerifier = CredentialCommitment(NUM_FIELDS);

    for (var i = 0; i < NUM_FIELDS; i++) {
        commitmentVerifier.credentialData[i] <== credentialData[i];
    }
    commitmentVerifier.salt <== salt;
    commitmentVerifier.commitment <== credentialCommitment;

    // ===== STEP 2: Validate Field Index =====
    // Ensure fieldIndex is within valid bounds [0, NUM_FIELDS-1]
    component indexRangeCheck = SafeLessThan(8);
    indexRangeCheck.a <== fieldIndex;
    indexRangeCheck.b <== NUM_FIELDS;
    indexRangeCheck.out === 1;

    // ===== STEP 3: Extract and Verify Field Value =====
    // Use selector to extract the field at fieldIndex
    component fieldExtractor = FieldExtractor(NUM_FIELDS);

    for (var i = 0; i < NUM_FIELDS; i++) {
        fieldExtractor.credentialData[i] <== credentialData[i];
    }
    fieldExtractor.fieldIndex <== fieldIndex;

    // Verify the actualValue input matches the extracted field
    actualValue === fieldExtractor.fieldValue;

    // ===== STEP 4: Hash Value to Leaf =====
    // Create the leaf from the actual value using Poseidon hash
    component leafHasher = MerkleLeafHasher();
    leafHasher.value <== actualValue;

    // ===== STEP 5: Verify Merkle Proof =====
    // Check that the leaf is included in the set defined by setRoot
    component merkleChecker = MerkleTreeChecker(TREE_DEPTH);
    merkleChecker.leaf <== leafHasher.leaf;
    merkleChecker.root <== setRoot;

    for (var i = 0; i < TREE_DEPTH; i++) {
        merkleChecker.pathElements[i] <== merkleProof[i];
        merkleChecker.pathIndices[i] <== merklePathIndices[i];
    }
    // The MerkleTreeChecker will constrain that the computed root equals setRoot
}

/**
 * @title SetMembershipWithOutput
 * @notice Same as SetMembership but outputs a success signal (for compound proofs)
 * @param NUM_FIELDS Number of credential fields
 * @param TREE_DEPTH Depth of the Merkle tree
 */
template SetMembershipWithOutput(NUM_FIELDS, TREE_DEPTH) {
    // ===== PUBLIC INPUTS =====
    signal input credentialCommitment;
    signal input setRoot;
    signal input fieldIndex;

    // ===== PRIVATE INPUTS =====
    signal input actualValue;
    signal input merkleProof[TREE_DEPTH];
    signal input merklePathIndices[TREE_DEPTH];
    signal input credentialData[NUM_FIELDS];
    signal input salt;

    // ===== OUTPUT =====
    signal output isInSet;

    // Verify credential commitment
    component commitmentVerifier = CredentialCommitment(NUM_FIELDS);
    for (var i = 0; i < NUM_FIELDS; i++) {
        commitmentVerifier.credentialData[i] <== credentialData[i];
    }
    commitmentVerifier.salt <== salt;
    commitmentVerifier.commitment <== credentialCommitment;

    // Validate field index
    component indexRangeCheck = SafeLessThan(8);
    indexRangeCheck.a <== fieldIndex;
    indexRangeCheck.b <== NUM_FIELDS;
    indexRangeCheck.out === 1;

    // Extract and verify field value
    component fieldExtractor = FieldExtractor(NUM_FIELDS);
    for (var i = 0; i < NUM_FIELDS; i++) {
        fieldExtractor.credentialData[i] <== credentialData[i];
    }
    fieldExtractor.fieldIndex <== fieldIndex;
    actualValue === fieldExtractor.fieldValue;

    // Hash value to leaf
    component leafHasher = MerkleLeafHasher();
    leafHasher.value <== actualValue;

    // Verify Merkle proof with output
    component merkleChecker = MerkleTreeInclusionProof(TREE_DEPTH);
    merkleChecker.leaf <== leafHasher.leaf;
    merkleChecker.root <== setRoot;

    for (var i = 0; i < TREE_DEPTH; i++) {
        merkleChecker.pathElements[i] <== merkleProof[i];
        merkleChecker.pathIndices[i] <== merklePathIndices[i];
    }

    isInSet <== merkleChecker.isIncluded;
}

/**
 * @title SetMembershipDirect
 * @notice Proves a raw value is in a set (without credential verification)
 * @param TREE_DEPTH Depth of the Merkle tree
 *
 * Useful for standalone set membership checks or compound proof building
 */
template SetMembershipDirect(TREE_DEPTH) {
    // Public inputs
    signal input value;
    signal input setRoot;

    // Private inputs
    signal input merkleProof[TREE_DEPTH];
    signal input merklePathIndices[TREE_DEPTH];

    // Hash value to leaf
    component leafHasher = MerkleLeafHasher();
    leafHasher.value <== value;

    // Verify Merkle proof
    component merkleChecker = MerkleTreeChecker(TREE_DEPTH);
    merkleChecker.leaf <== leafHasher.leaf;
    merkleChecker.root <== setRoot;

    for (var i = 0; i < TREE_DEPTH; i++) {
        merkleChecker.pathElements[i] <== merkleProof[i];
        merkleChecker.pathIndices[i] <== merklePathIndices[i];
    }
}

// Main component with 16 credential fields and tree depth of 10 (supports up to 1024 members)
// Tree depth can be adjusted based on expected set sizes:
// - Depth 10: up to 1,024 members
// - Depth 15: up to 32,768 members
// - Depth 20: up to 1,048,576 members
component main {public [credentialCommitment, setRoot, fieldIndex]} = SetMembership(16, 10);
