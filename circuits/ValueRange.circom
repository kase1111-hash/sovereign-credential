/**
 * @file ValueRange.circom
 * @description Zero-knowledge circuit for proving a numeric field is within a range
 *              without revealing the actual value
 *
 * @dev This circuit allows a credential holder to prove statements like
 *      "My income is between $50,000 and $100,000" or
 *      "My credit score is above 700" without revealing the exact value
 *
 * Spec Reference: SPEC.md Section 6.1.3
 */

pragma circom 2.1.6;

include "lib/commitment.circom";
include "lib/comparators.circom";

/**
 * @title ValueRange
 * @notice Proves a numeric field value is within a specified range [min, max]
 * @param NUM_FIELDS Number of credential fields (default 16)
 *
 * Public Inputs:
 *   - credentialCommitment: Poseidon hash of credential data + salt
 *   - minValue: Minimum allowed value (inclusive)
 *   - maxValue: Maximum allowed value (inclusive)
 *   - fieldIndex: Index of the value field in credential data
 *
 * Private Inputs:
 *   - actualValue: The actual value to prove is in range
 *   - credentialData: Full credential field array
 *   - salt: Randomness used in commitment
 *
 * Constraints:
 *   1. Commitment verification: credentialCommitment == Poseidon(credentialData, salt)
 *   2. Field extraction: actualValue == credentialData[fieldIndex]
 *   3. Range check: minValue <= actualValue <= maxValue
 *
 * Note: To prove only lower bound (e.g., "value >= 700"), set maxValue to MAX_UINT64.
 *       To prove only upper bound (e.g., "value <= 100"), set minValue to 0.
 */
template ValueRange(NUM_FIELDS) {
    // ===== PUBLIC INPUTS =====
    signal input credentialCommitment;
    signal input minValue;             // Minimum value (inclusive)
    signal input maxValue;             // Maximum value (inclusive)
    signal input fieldIndex;           // Index of value field in credential

    // ===== PRIVATE INPUTS =====
    signal input actualValue;          // The actual value to verify
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

    // ===== STEP 3: Extract and Verify Value Field =====
    // Use selector to extract the field at fieldIndex
    component fieldExtractor = FieldExtractor(NUM_FIELDS);

    for (var i = 0; i < NUM_FIELDS; i++) {
        fieldExtractor.credentialData[i] <== credentialData[i];
    }
    fieldExtractor.fieldIndex <== fieldIndex;

    // Verify the actualValue input matches the extracted field
    actualValue === fieldExtractor.fieldValue;

    // ===== STEP 4: Validate Range Ordering =====
    // minValue must be <= maxValue (sanity check)
    component rangeOrderCheck = SafeLessEqThan(64);
    rangeOrderCheck.a <== minValue;
    rangeOrderCheck.b <== maxValue;
    rangeOrderCheck.out === 1;

    // ===== STEP 5: Check Value is in Range =====
    // Verify: minValue <= actualValue <= maxValue
    component inRange = InRange(64);
    inRange.value <== actualValue;
    inRange.min <== minValue;
    inRange.max <== maxValue;
    inRange.out === 1;
}

/**
 * @title ValueThreshold
 * @notice Simplified version for threshold-only checks (>, <, >=, <=)
 * @param NUM_FIELDS Number of credential fields
 *
 * Public Inputs:
 *   - credentialCommitment: Hash of credential data
 *   - threshold: Value to compare against
 *   - fieldIndex: Field containing the value to check
 *   - comparisonType: 0=GT, 1=LT, 2=GTE, 3=LTE
 *
 * Private Inputs:
 *   - actualValue: Value to check
 *   - credentialData: Full credential
 *   - salt: Commitment salt
 */
template ValueThreshold(NUM_FIELDS) {
    // ===== PUBLIC INPUTS =====
    signal input credentialCommitment;
    signal input threshold;
    signal input fieldIndex;
    signal input comparisonType;       // 0=GT, 1=LT, 2=GTE, 3=LTE

    // ===== PRIVATE INPUTS =====
    signal input actualValue;
    signal input credentialData[NUM_FIELDS];
    signal input salt;

    // ===== STEP 1: Verify Credential Commitment =====
    component commitmentVerifier = CredentialCommitment(NUM_FIELDS);

    for (var i = 0; i < NUM_FIELDS; i++) {
        commitmentVerifier.credentialData[i] <== credentialData[i];
    }
    commitmentVerifier.salt <== salt;
    commitmentVerifier.commitment <== credentialCommitment;

    // ===== STEP 2: Validate Field Index =====
    component indexRangeCheck = SafeLessThan(8);
    indexRangeCheck.a <== fieldIndex;
    indexRangeCheck.b <== NUM_FIELDS;
    indexRangeCheck.out === 1;

    // ===== STEP 3: Extract and Verify Value Field =====
    component fieldExtractor = FieldExtractor(NUM_FIELDS);

    for (var i = 0; i < NUM_FIELDS; i++) {
        fieldExtractor.credentialData[i] <== credentialData[i];
    }
    fieldExtractor.fieldIndex <== fieldIndex;

    actualValue === fieldExtractor.fieldValue;

    // ===== STEP 4: Validate Comparison Type =====
    // comparisonType must be 0, 1, 2, or 3
    component typeCheck = SafeLessThan(8);
    typeCheck.a <== comparisonType;
    typeCheck.b <== 4;
    typeCheck.out === 1;

    // ===== STEP 5: Perform Comparison =====
    // Compute all comparison results
    component gt = SafeGreaterThan(64);
    gt.a <== actualValue;
    gt.b <== threshold;

    component lt = SafeLessThan(64);
    lt.a <== actualValue;
    lt.b <== threshold;

    component gte = SafeGreaterEqThan(64);
    gte.a <== actualValue;
    gte.b <== threshold;

    component lte = SafeLessEqThan(64);
    lte.a <== actualValue;
    lte.b <== threshold;

    // Use selection logic based on comparisonType
    // We need to compute: result = sum of (isType_i * comparison_i)
    signal isGT;
    signal isLT;
    signal isGTE;
    signal isLTE;

    // Decode comparisonType into one-hot encoding
    isGT <-- (comparisonType == 0) ? 1 : 0;
    isLT <-- (comparisonType == 1) ? 1 : 0;
    isGTE <-- (comparisonType == 2) ? 1 : 0;
    isLTE <-- (comparisonType == 3) ? 1 : 0;

    // Constrain to be binary
    isGT * (1 - isGT) === 0;
    isLT * (1 - isLT) === 0;
    isGTE * (1 - isGTE) === 0;
    isLTE * (1 - isLTE) === 0;

    // Constrain to match comparisonType
    isGT * comparisonType === 0;           // isGT=1 only when type=0
    isLT * (comparisonType - 1) === 0;     // isLT=1 only when type=1
    isGTE * (comparisonType - 2) === 0;    // isGTE=1 only when type=2
    isLTE * (comparisonType - 3) === 0;    // isLTE=1 only when type=3

    // Exactly one must be selected
    isGT + isLT + isGTE + isLTE === 1;

    // Compute weighted result
    signal gtContrib;
    signal ltContrib;
    signal gteContrib;
    signal lteContrib;

    gtContrib <== isGT * gt.out;
    ltContrib <== isLT * lt.out;
    gteContrib <== isGTE * gte.out;
    lteContrib <== isLTE * lte.out;

    signal result;
    result <== gtContrib + ltContrib + gteContrib + lteContrib;

    // The comparison must pass
    result === 1;
}

// Main component with 16 credential fields (standard for Sovereign Credential)
component main {public [credentialCommitment, minValue, maxValue, fieldIndex]} = ValueRange(16);
