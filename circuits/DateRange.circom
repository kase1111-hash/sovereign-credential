/**
 * @file DateRange.circom
 * @description Zero-knowledge circuit for proving a date field is within a range
 *              without revealing the actual date value
 *
 * @dev This circuit allows a credential holder to prove statements like
 *      "My license was issued between 2020 and 2023" without revealing
 *      the exact issuance date
 *
 * Spec Reference: SPEC.md Section 6.1.2
 */

pragma circom 2.1.6;

include "lib/commitment.circom";
include "lib/comparators.circom";

/**
 * @title DateRange
 * @notice Proves a date field value is within a specified range [rangeStart, rangeEnd]
 * @param NUM_FIELDS Number of credential fields (default 16)
 *
 * Public Inputs:
 *   - credentialCommitment: Poseidon hash of credential data + salt
 *   - rangeStart: Start of valid date range (Unix timestamp, inclusive)
 *   - rangeEnd: End of valid date range (Unix timestamp, inclusive)
 *   - fieldIndex: Index of the date field in credential data
 *
 * Private Inputs:
 *   - dateValue: The actual date value to prove is in range
 *   - credentialData: Full credential field array
 *   - salt: Randomness used in commitment
 *
 * Constraints:
 *   1. Commitment verification: credentialCommitment == Poseidon(credentialData, salt)
 *   2. Field extraction: dateValue == credentialData[fieldIndex]
 *   3. Range check: rangeStart <= dateValue <= rangeEnd
 */
template DateRange(NUM_FIELDS) {
    // ===== PUBLIC INPUTS =====
    signal input credentialCommitment;
    signal input rangeStart;           // Start of valid range (inclusive)
    signal input rangeEnd;             // End of valid range (inclusive)
    signal input fieldIndex;           // Index of date field in credential

    // ===== PRIVATE INPUTS =====
    signal input dateValue;            // The actual date to verify
    signal input credentialData[NUM_FIELDS];  // Full credential payload
    signal input salt;                 // Randomness for commitment hiding

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

    // ===== STEP 3: Extract and Verify Date Field =====
    // Use selector to extract the field at fieldIndex
    component fieldExtractor = FieldExtractor(NUM_FIELDS);

    for (var i = 0; i < NUM_FIELDS; i++) {
        fieldExtractor.credentialData[i] <== credentialData[i];
    }
    fieldExtractor.fieldIndex <== fieldIndex;

    // Verify the dateValue input matches the extracted field
    dateValue === fieldExtractor.fieldValue;

    // ===== STEP 4: Validate Range Ordering =====
    // rangeStart must be <= rangeEnd (sanity check)
    component rangeOrderCheck = SafeLessEqThan(64);
    rangeOrderCheck.a <== rangeStart;
    rangeOrderCheck.b <== rangeEnd;
    rangeOrderCheck.out === 1;

    // ===== STEP 5: Check Date is in Range =====
    // Verify: rangeStart <= dateValue <= rangeEnd
    component inRange = InRange(64);
    inRange.value <== dateValue;
    inRange.min <== rangeStart;
    inRange.max <== rangeEnd;
    inRange.out === 1;
}

// Main component with 16 credential fields (standard for Sovereign Credential)
component main {public [credentialCommitment, rangeStart, rangeEnd, fieldIndex]} = DateRange(16);
