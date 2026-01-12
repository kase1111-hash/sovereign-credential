/**
 * @file DateRange.circom
 * @description Zero-knowledge circuit for proving a date field falls within a range
 *              without revealing the actual date value
 *
 * @dev This circuit allows a credential holder to prove statements like
 *      "my credential was issued between 2020 and 2024" without revealing exact dates
 *
 * Spec Reference: SPEC.md Section 6.1.2
 */

pragma circom 2.1.6;

include "lib/commitment.circom";
include "lib/comparators.circom";

/**
 * @title DateRange
 * @notice Proves a date field is within a specified range
 * @param NUM_FIELDS Number of credential fields (default 16)
 *
 * Public Inputs:
 *   - credentialCommitment: Poseidon hash of credential data + salt
 *   - rangeStart: Start of valid range (Unix timestamp, inclusive)
 *   - rangeEnd: End of valid range (Unix timestamp, inclusive)
 *   - fieldIndex: Which date field to check (0 to NUM_FIELDS-1)
 *
 * Private Inputs:
 *   - dateValue: The actual date value to prove is in range
 *   - credentialData: Full credential field array
 *   - salt: Randomness used in commitment
 *
 * Constraints:
 *   1. Commitment verification: credentialCommitment == Poseidon(credentialData, salt)
 *   2. Field extraction: dateValue == credentialData[fieldIndex]
 *   3. Range start: dateValue >= rangeStart
 *   4. Range end: dateValue <= rangeEnd
 */
template DateRange(NUM_FIELDS) {
    // ===== PUBLIC INPUTS =====
    signal input credentialCommitment;
    signal input rangeStart;      // Start of valid range (inclusive)
    signal input rangeEnd;        // End of valid range (inclusive)
    signal input fieldIndex;      // Which field contains the date (0-indexed)

    // ===== PRIVATE INPUTS =====
    signal input dateValue;       // The actual date value
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
    // Verify that dateValue matches the credential field at fieldIndex
    component fieldExtractor = FieldExtractor(NUM_FIELDS);
    for (var i = 0; i < NUM_FIELDS; i++) {
        fieldExtractor.credentialData[i] <== credentialData[i];
    }
    fieldExtractor.fieldIndex <== fieldIndex;

    // The provided dateValue must match the extracted field
    dateValue === fieldExtractor.fieldValue;

    // ===== STEP 3: Validate Range Ordering =====
    // rangeStart must be <= rangeEnd (sanity check)
    component rangeValid = SafeLessEqThan(64);
    rangeValid.a <== rangeStart;
    rangeValid.b <== rangeEnd;
    rangeValid.out === 1;

    // ===== STEP 4: Check Date in Range =====
    // Use InRange from comparators library
    component inRange = InRange(64);
    inRange.value <== dateValue;
    inRange.min <== rangeStart;
    inRange.max <== rangeEnd;

    // The date must be within the range
    inRange.out === 1;
}

// Main component with 16 credential fields (standard for Sovereign Credential)
component main {public [credentialCommitment, rangeStart, rangeEnd, fieldIndex]} = DateRange(16);
