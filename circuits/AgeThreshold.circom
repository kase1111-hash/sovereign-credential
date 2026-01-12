/**
 * @file AgeThreshold.circom
 * @description Zero-knowledge circuit for proving age above/below a threshold
 *              without revealing the actual birthdate
 *
 * @dev This circuit allows a credential holder to prove statements like
 *      "I am over 18" or "I am under 65" without revealing their exact age
 *
 * Spec Reference: SPEC.md Section 6.1.1
 */

pragma circom 2.1.6;

include "lib/commitment.circom";
include "lib/comparators.circom";

/**
 * @title AgeThreshold
 * @notice Proves age meets a threshold without revealing birthdate
 * @param NUM_FIELDS Number of credential fields (default 16)
 *
 * Public Inputs:
 *   - credentialCommitment: Poseidon hash of credential data + salt
 *   - threshold: Age threshold in years
 *   - currentTimestamp: Verifier-provided current Unix timestamp
 *   - comparisonType: 0 = greater than, 1 = less than
 *
 * Private Inputs:
 *   - birthdate: Unix timestamp of birth date
 *   - credentialData: Full credential field array
 *   - salt: Randomness used in commitment
 *
 * Constraints:
 *   1. Commitment verification: credentialCommitment == Poseidon(credentialData, salt)
 *   2. Birthdate is in credentialData[0]
 *   3. Age calculation: age = (currentTimestamp - birthdate) / SECONDS_PER_YEAR
 *   4. If comparisonType == 0: age > threshold
 *   5. If comparisonType == 1: age < threshold
 */
template AgeThreshold(NUM_FIELDS) {
    // ===== PUBLIC INPUTS =====
    signal input credentialCommitment;
    signal input threshold;           // Age threshold in years
    signal input currentTimestamp;    // Verifier-provided current time
    signal input comparisonType;      // 0 = greater than, 1 = less than

    // ===== PRIVATE INPUTS =====
    signal input birthdate;           // Unix timestamp of birth
    signal input credentialData[NUM_FIELDS];  // Full credential payload
    signal input salt;                // Randomness for commitment hiding

    // ===== CONSTANTS =====
    // Seconds per year (365.25 days to account for leap years)
    var SECONDS_PER_YEAR = 31557600;  // 365.25 * 24 * 60 * 60

    // Birthdate field index in credential data (field 0 by convention)
    var BIRTHDATE_FIELD_INDEX = 0;

    // ===== STEP 1: Verify Credential Commitment =====
    // Ensures the private credential data matches the public commitment
    component commitmentVerifier = CredentialCommitment(NUM_FIELDS);

    for (var i = 0; i < NUM_FIELDS; i++) {
        commitmentVerifier.credentialData[i] <== credentialData[i];
    }
    commitmentVerifier.salt <== salt;
    commitmentVerifier.commitment <== credentialCommitment;

    // ===== STEP 2: Verify Birthdate in Credential =====
    // The birthdate input must match the credential's birthdate field
    birthdate === credentialData[BIRTHDATE_FIELD_INDEX];

    // ===== STEP 3: Validate Timestamp Ordering =====
    // Current timestamp must be greater than birthdate (sanity check)
    component timestampCheck = SafeGreaterThan(64);
    timestampCheck.a <== currentTimestamp;
    timestampCheck.b <== birthdate;
    timestampCheck.out === 1;

    // ===== STEP 4: Calculate Age =====
    // Age in years (integer division)
    // Note: We use <-- for division as it's a hint, then constrain the result
    signal ageSeconds;
    signal age;
    signal remainder;

    ageSeconds <== currentTimestamp - birthdate;

    // Compute age with integer division (witness computation)
    age <-- ageSeconds \ SECONDS_PER_YEAR;
    remainder <-- ageSeconds % SECONDS_PER_YEAR;

    // Constrain the division: ageSeconds = age * SECONDS_PER_YEAR + remainder
    signal ageTimesYear;
    ageTimesYear <== age * SECONDS_PER_YEAR;
    ageTimesYear + remainder === ageSeconds;

    // Constrain remainder to be in valid range [0, SECONDS_PER_YEAR)
    component remainderCheck = SafeLessThan(64);
    remainderCheck.a <== remainder;
    remainderCheck.b <== SECONDS_PER_YEAR;
    remainderCheck.out === 1;

    // Constrain remainder to be non-negative (already guaranteed by SafeLessThan range check)
    component remainderNonNeg = SafeGreaterEqThan(64);
    remainderNonNeg.a <== remainder;
    remainderNonNeg.b <== 0;
    remainderNonNeg.out === 1;

    // ===== STEP 5: Range Check Age =====
    // Ensure age is a reasonable value (0 to 150 years)
    component ageRangeCheck = SafeLessThan(64);
    ageRangeCheck.a <== age;
    ageRangeCheck.b <== 150;  // Max reasonable age
    ageRangeCheck.out === 1;

    // ===== STEP 6: Threshold Comparison =====
    // Check age against threshold based on comparison type
    component thresholdChecker = ThresholdCheck(64);
    thresholdChecker.value <== age;
    thresholdChecker.threshold <== threshold;
    thresholdChecker.comparisonType <== comparisonType;

    // The threshold check must pass
    thresholdChecker.out === 1;
}

// Main component with 16 credential fields (standard for Sovereign Credential)
component main {public [credentialCommitment, threshold, currentTimestamp, comparisonType]} = AgeThreshold(16);
