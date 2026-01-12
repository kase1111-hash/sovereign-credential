/**
 * @file ValueRange.circom
 * @description Zero-knowledge circuit for proving a numeric field falls within a range
 *              without revealing the actual value
 *
 * @dev This circuit allows a credential holder to prove statements like
 *      "my credit score is between 700 and 850" without revealing the exact score
 *
 * Spec Reference: SPEC.md Section 6.1.3
 */

pragma circom 2.1.6;

include "lib/commitment.circom";
include "lib/comparators.circom";

/**
 * @title ValueRange
 * @notice Proves a numeric field is within a specified range
 * @param NUM_FIELDS Number of credential fields (default 16)
 *
 * Public Inputs:
 *   - credentialCommitment: Poseidon hash of credential data + salt
 *   - minValue: Minimum acceptable value (inclusive)
 *   - maxValue: Maximum acceptable value (inclusive)
 *   - fieldIndex: Which numeric field to check (0 to NUM_FIELDS-1)
 *
 * Private Inputs:
 *   - actualValue: The actual numeric value to prove is in range
 *   - credentialData: Full credential field array
 *   - salt: Randomness used in commitment
 *
 * Constraints:
 *   1. Commitment verification: credentialCommitment == Poseidon(credentialData, salt)
 *   2. Field extraction: actualValue == credentialData[fieldIndex]
 *   3. Range minimum: actualValue >= minValue
 *   4. Range maximum: actualValue <= maxValue
 */
template ValueRange(NUM_FIELDS) {
    // ===== PUBLIC INPUTS =====
    signal input credentialCommitment;
    signal input minValue;        // Minimum acceptable value (inclusive)
    signal input maxValue;        // Maximum acceptable value (inclusive)
    signal input fieldIndex;      // Which field contains the value (0-indexed)

    // ===== PRIVATE INPUTS =====
    signal input actualValue;     // The actual numeric value
    signal input credentialData[NUM_FIELDS];  // Full credential payload
    signal input salt;            // Randomness for commitment hiding

    // ===== STEP 1: Verify Credential Commitment =====
    // Ensures the private credential data matches the public commitment
    component commitmentVerifier = CredentialCommitment(NUM_FIELDS);

    for (var i = 0; i < NUM_FIELDS; i++) {
        commitmentVerifier.credentialData[i] <== credentialData[i];
    }
    commitmentVerifier.salt <== salt;
    commitmentVerifier.commitment <== credentialCommitment;

    // ===== STEP 2: Extract and Verify Field =====
    // Verify that actualValue matches the credential field at fieldIndex
    component fieldExtractor = FieldExtractor(NUM_FIELDS);
    for (var i = 0; i < NUM_FIELDS; i++) {
        fieldExtractor.credentialData[i] <== credentialData[i];
    }
    fieldExtractor.fieldIndex <== fieldIndex;

    // The provided actualValue must match the extracted field
    actualValue === fieldExtractor.fieldValue;

    // ===== STEP 3: Validate Range Ordering =====
    // minValue must be <= maxValue (sanity check)
    component rangeValid = SafeLessEqThan(64);
    rangeValid.a <== minValue;
    rangeValid.b <== maxValue;
    rangeValid.out === 1;

    // ===== STEP 4: Check Value in Range =====
    // Use InRange from comparators library
    component inRange = InRange(64);
    inRange.value <== actualValue;
    inRange.min <== minValue;
    inRange.max <== maxValue;

    // The value must be within the range
    inRange.out === 1;
}

// Main component with 16 credential fields (standard for Sovereign Credential)
component main {public [credentialCommitment, minValue, maxValue, fieldIndex]} = ValueRange(16);
