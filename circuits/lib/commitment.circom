/**
 * @file commitment.circom
 * @description Commitment verification template using Poseidon hash
 * @dev Used across all disclosure circuits to verify credential commitments
 */

pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";

/**
 * @title CredentialCommitment
 * @notice Verifies that credential data matches a public commitment
 * @param NUM_FIELDS Number of credential fields (default 16 for standard credentials)
 *
 * @input credentialData[NUM_FIELDS] - Private credential field values
 * @input salt - Private randomness for commitment binding
 * @input commitment - Public commitment to verify against
 */
template CredentialCommitment(NUM_FIELDS) {
    // Private inputs
    signal input credentialData[NUM_FIELDS];
    signal input salt;

    // Public input
    signal input commitment;

    // Compute commitment using Poseidon hash
    // Poseidon can handle up to 16 inputs efficiently
    component hasher = Poseidon(NUM_FIELDS + 1);

    for (var i = 0; i < NUM_FIELDS; i++) {
        hasher.inputs[i] <== credentialData[i];
    }
    hasher.inputs[NUM_FIELDS] <== salt;

    // Verify commitment matches
    commitment === hasher.out;
}

/**
 * @title MultiFieldCommitment
 * @notice Creates commitment over multiple fields with indices
 * @param NUM_FIELDS Number of fields to commit to
 *
 * Used for selective disclosure where specific fields need to be proven
 */
template MultiFieldCommitment(NUM_FIELDS) {
    signal input fields[NUM_FIELDS];
    signal input fieldIndices[NUM_FIELDS];
    signal input salt;

    signal output commitment;

    // Hash fields with their indices to create ordered commitment
    component hasher = Poseidon(NUM_FIELDS * 2 + 1);

    for (var i = 0; i < NUM_FIELDS; i++) {
        hasher.inputs[i * 2] <== fieldIndices[i];
        hasher.inputs[i * 2 + 1] <== fields[i];
    }
    hasher.inputs[NUM_FIELDS * 2] <== salt;

    commitment <== hasher.out;
}

/**
 * @title FieldExtractor
 * @notice Extracts and verifies a specific field from credential data
 * @param NUM_FIELDS Total number of credential fields
 *
 * @input credentialData[NUM_FIELDS] - All credential fields
 * @input fieldIndex - Index of field to extract (0 to NUM_FIELDS-1)
 * @output fieldValue - The extracted field value
 */
template FieldExtractor(NUM_FIELDS) {
    signal input credentialData[NUM_FIELDS];
    signal input fieldIndex;

    signal output fieldValue;

    // Use selector to pick the right field
    component selector = Selector(NUM_FIELDS);
    selector.index <== fieldIndex;

    for (var i = 0; i < NUM_FIELDS; i++) {
        selector.values[i] <== credentialData[i];
    }

    fieldValue <== selector.out;
}

/**
 * @title Selector
 * @notice Selects one value from an array based on index
 * @param N Size of the array
 *
 * Uses quadratic constraints for security (no lookup tables)
 */
template Selector(N) {
    signal input values[N];
    signal input index;

    signal output out;

    // Create selection signals
    signal selector[N];
    signal products[N];

    var sum = 0;

    for (var i = 0; i < N; i++) {
        // selector[i] = 1 if index == i, else 0
        selector[i] <-- (index == i) ? 1 : 0;

        // Constrain selector to be binary
        selector[i] * (1 - selector[i]) === 0;

        // Constrain selector to match index
        selector[i] * (index - i) === 0;

        // Multiply value by selector
        products[i] <== values[i] * selector[i];
        sum += products[i];
    }

    // Ensure exactly one selector is 1
    var selectorSum = 0;
    for (var i = 0; i < N; i++) {
        selectorSum += selector[i];
    }
    selectorSum === 1;

    out <== sum;
}
