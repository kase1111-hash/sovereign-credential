/**
 * @file CompoundProof.circom
 * @description Zero-knowledge circuit for proving multiple disclosures in a single proof
 *
 * @dev This circuit allows a credential holder to combine multiple disclosure types
 *      (e.g., "I am over 18 AND my license was issued in the last 5 years")
 *      into a single efficient proof. The credential commitment is verified only once,
 *      making compound proofs more efficient than separate proofs.
 *
 * Spec Reference: SPEC.md Section 6.1.5 (Compound Proofs)
 *
 * Architecture:
 * 1. Single credential commitment verification (shared)
 * 2. Array of disclosure specifications with type and params
 * 3. Multiplexer-based verification for each disclosure slot
 * 4. All disclosures must pass for proof to be valid
 *
 * Supported Disclosure Types:
 *   0 = AGE_THRESHOLD: Prove age > or < threshold
 *   1 = DATE_RANGE: Prove date field is within [start, end]
 *   2 = VALUE_RANGE: Prove value field is within [min, max]
 *   3 = SET_MEMBERSHIP: Prove field value is in a Merkle set
 *   4 = EXISTENCE: Prove credential exists (always passes if commitment valid)
 */

pragma circom 2.1.6;

include "lib/commitment.circom";
include "lib/comparators.circom";
include "lib/merkle.circom";

/**
 * @title AgeDisclosure
 * @notice Internal template for age threshold check within compound proof
 * @param NUM_FIELDS Number of credential fields
 *
 * @input credentialData[NUM_FIELDS] - Full credential array
 * @input params[4] - [threshold, currentTimestamp, comparisonType, 0]
 * @input privateValue - birthdate (private)
 * @output result - 1 if check passes, 0 otherwise
 */
template AgeDisclosure(NUM_FIELDS) {
    signal input credentialData[NUM_FIELDS];
    signal input params[4];  // [threshold, currentTimestamp, comparisonType, _]
    signal input privateValue;  // birthdate

    signal output result;

    // Constants
    var SECONDS_PER_YEAR = 31557600;  // 365.25 * 24 * 60 * 60
    var BIRTHDATE_FIELD_INDEX = 0;

    // Extract params
    signal threshold;
    signal currentTimestamp;
    signal comparisonType;

    threshold <== params[0];
    currentTimestamp <== params[1];
    comparisonType <== params[2];

    // Verify birthdate matches credential field
    privateValue === credentialData[BIRTHDATE_FIELD_INDEX];

    // Validate timestamp ordering
    component timestampCheck = SafeGreaterThan(64);
    timestampCheck.a <== currentTimestamp;
    timestampCheck.b <== privateValue;

    // Calculate age
    signal ageSeconds;
    signal age;
    signal remainder;

    ageSeconds <== currentTimestamp - privateValue;
    age <-- ageSeconds \ SECONDS_PER_YEAR;
    remainder <-- ageSeconds % SECONDS_PER_YEAR;

    // Constrain division
    signal ageTimesYear;
    ageTimesYear <== age * SECONDS_PER_YEAR;
    ageTimesYear + remainder === ageSeconds;

    // Range check remainder
    component remainderCheck = SafeLessThan(64);
    remainderCheck.a <== remainder;
    remainderCheck.b <== SECONDS_PER_YEAR;

    // Age range check (0-150)
    component ageRangeCheck = SafeLessThan(64);
    ageRangeCheck.a <== age;
    ageRangeCheck.b <== 150;

    // Threshold comparison
    component thresholdChecker = ThresholdCheck(64);
    thresholdChecker.value <== age;
    thresholdChecker.threshold <== threshold;
    thresholdChecker.comparisonType <== comparisonType;

    // All checks must pass
    result <== timestampCheck.out * remainderCheck.out * ageRangeCheck.out * thresholdChecker.out;
}

/**
 * @title DateRangeDisclosure
 * @notice Internal template for date range check within compound proof
 * @param NUM_FIELDS Number of credential fields
 *
 * @input credentialData[NUM_FIELDS] - Full credential array
 * @input params[4] - [rangeStart, rangeEnd, fieldIndex, 0]
 * @input privateValue - actual date value
 * @output result - 1 if check passes, 0 otherwise
 */
template DateRangeDisclosure(NUM_FIELDS) {
    signal input credentialData[NUM_FIELDS];
    signal input params[4];  // [rangeStart, rangeEnd, fieldIndex, _]
    signal input privateValue;  // dateValue

    signal output result;

    // Extract params
    signal rangeStart;
    signal rangeEnd;
    signal fieldIndex;

    rangeStart <== params[0];
    rangeEnd <== params[1];
    fieldIndex <== params[2];

    // Validate field index
    component indexCheck = SafeLessThan(8);
    indexCheck.a <== fieldIndex;
    indexCheck.b <== NUM_FIELDS;

    // Extract and verify field
    component fieldExtractor = FieldExtractor(NUM_FIELDS);
    for (var i = 0; i < NUM_FIELDS; i++) {
        fieldExtractor.credentialData[i] <== credentialData[i];
    }
    fieldExtractor.fieldIndex <== fieldIndex;

    privateValue === fieldExtractor.fieldValue;

    // Range ordering check
    component rangeOrderCheck = SafeLessEqThan(64);
    rangeOrderCheck.a <== rangeStart;
    rangeOrderCheck.b <== rangeEnd;

    // In-range check
    component inRange = InRange(64);
    inRange.value <== privateValue;
    inRange.min <== rangeStart;
    inRange.max <== rangeEnd;

    result <== indexCheck.out * rangeOrderCheck.out * inRange.out;
}

/**
 * @title ValueRangeDisclosure
 * @notice Internal template for value range check within compound proof
 * @param NUM_FIELDS Number of credential fields
 *
 * @input credentialData[NUM_FIELDS] - Full credential array
 * @input params[4] - [minValue, maxValue, fieldIndex, 0]
 * @input privateValue - actual value
 * @output result - 1 if check passes, 0 otherwise
 */
template ValueRangeDisclosure(NUM_FIELDS) {
    signal input credentialData[NUM_FIELDS];
    signal input params[4];  // [minValue, maxValue, fieldIndex, _]
    signal input privateValue;  // actualValue

    signal output result;

    // Extract params
    signal minValue;
    signal maxValue;
    signal fieldIndex;

    minValue <== params[0];
    maxValue <== params[1];
    fieldIndex <== params[2];

    // Validate field index
    component indexCheck = SafeLessThan(8);
    indexCheck.a <== fieldIndex;
    indexCheck.b <== NUM_FIELDS;

    // Extract and verify field
    component fieldExtractor = FieldExtractor(NUM_FIELDS);
    for (var i = 0; i < NUM_FIELDS; i++) {
        fieldExtractor.credentialData[i] <== credentialData[i];
    }
    fieldExtractor.fieldIndex <== fieldIndex;

    privateValue === fieldExtractor.fieldValue;

    // Range ordering check
    component rangeOrderCheck = SafeLessEqThan(64);
    rangeOrderCheck.a <== minValue;
    rangeOrderCheck.b <== maxValue;

    // In-range check
    component inRange = InRange(64);
    inRange.value <== privateValue;
    inRange.min <== minValue;
    inRange.max <== maxValue;

    result <== indexCheck.out * rangeOrderCheck.out * inRange.out;
}

/**
 * @title SetMembershipDisclosure
 * @notice Internal template for set membership check within compound proof
 * @param NUM_FIELDS Number of credential fields
 * @param TREE_DEPTH Depth of Merkle tree
 *
 * @input credentialData[NUM_FIELDS] - Full credential array
 * @input params[4] - [setRoot, fieldIndex, 0, 0]
 * @input privateValue - actual value
 * @input merkleProof[TREE_DEPTH] - Merkle path elements
 * @input merklePathIndices[TREE_DEPTH] - Merkle path directions
 * @output result - 1 if check passes, 0 otherwise
 */
template SetMembershipDisclosure(NUM_FIELDS, TREE_DEPTH) {
    signal input credentialData[NUM_FIELDS];
    signal input params[4];  // [setRoot, fieldIndex, 0, 0]
    signal input privateValue;  // actualValue
    signal input merkleProof[TREE_DEPTH];
    signal input merklePathIndices[TREE_DEPTH];

    signal output result;

    // Extract params
    signal setRoot;
    signal fieldIndex;

    setRoot <== params[0];
    fieldIndex <== params[1];

    // Validate field index
    component indexCheck = SafeLessThan(8);
    indexCheck.a <== fieldIndex;
    indexCheck.b <== NUM_FIELDS;

    // Extract and verify field
    component fieldExtractor = FieldExtractor(NUM_FIELDS);
    for (var i = 0; i < NUM_FIELDS; i++) {
        fieldExtractor.credentialData[i] <== credentialData[i];
    }
    fieldExtractor.fieldIndex <== fieldIndex;

    privateValue === fieldExtractor.fieldValue;

    // Verify Merkle proof
    component merkleChecker = MerkleTreeInclusionProof(TREE_DEPTH);
    merkleChecker.leaf <== privateValue;
    merkleChecker.root <== setRoot;

    for (var i = 0; i < TREE_DEPTH; i++) {
        merkleChecker.pathElements[i] <== merkleProof[i];
        merkleChecker.pathIndices[i] <== merklePathIndices[i];
    }

    result <== indexCheck.out * merkleChecker.isIncluded;
}

/**
 * @title ExistenceDisclosure
 * @notice Internal template for existence check (always passes if commitment is valid)
 *
 * @input params[4] - Unused for existence check
 * @output result - Always 1 (existence is verified by commitment)
 */
template ExistenceDisclosure() {
    signal input params[4];  // Unused
    signal output result;

    // Existence is proven by valid commitment - always passes
    result <== 1;
}

/**
 * @title DisclosureVerifier
 * @notice Verifies a single disclosure based on its type using multiplexer
 * @param NUM_FIELDS Number of credential fields
 * @param TREE_DEPTH Merkle tree depth for set membership
 *
 * Disclosure Types:
 *   0 = AGE_THRESHOLD
 *   1 = DATE_RANGE
 *   2 = VALUE_RANGE
 *   3 = SET_MEMBERSHIP
 *   4 = EXISTENCE
 */
template DisclosureVerifier(NUM_FIELDS, TREE_DEPTH) {
    signal input credentialData[NUM_FIELDS];
    signal input disclosureType;
    signal input params[4];
    signal input privateValue;
    signal input merkleProof[TREE_DEPTH];
    signal input merklePathIndices[TREE_DEPTH];

    signal output result;

    // Validate disclosure type (0-4)
    component typeCheck = SafeLessThan(8);
    typeCheck.a <== disclosureType;
    typeCheck.b <== 5;
    typeCheck.out === 1;

    // Compute results for all disclosure types
    component ageDisclosure = AgeDisclosure(NUM_FIELDS);
    for (var i = 0; i < NUM_FIELDS; i++) {
        ageDisclosure.credentialData[i] <== credentialData[i];
    }
    for (var i = 0; i < 4; i++) {
        ageDisclosure.params[i] <== params[i];
    }
    ageDisclosure.privateValue <== privateValue;

    component dateRangeDisclosure = DateRangeDisclosure(NUM_FIELDS);
    for (var i = 0; i < NUM_FIELDS; i++) {
        dateRangeDisclosure.credentialData[i] <== credentialData[i];
    }
    for (var i = 0; i < 4; i++) {
        dateRangeDisclosure.params[i] <== params[i];
    }
    dateRangeDisclosure.privateValue <== privateValue;

    component valueRangeDisclosure = ValueRangeDisclosure(NUM_FIELDS);
    for (var i = 0; i < NUM_FIELDS; i++) {
        valueRangeDisclosure.credentialData[i] <== credentialData[i];
    }
    for (var i = 0; i < 4; i++) {
        valueRangeDisclosure.params[i] <== params[i];
    }
    valueRangeDisclosure.privateValue <== privateValue;

    component setMembershipDisclosure = SetMembershipDisclosure(NUM_FIELDS, TREE_DEPTH);
    for (var i = 0; i < NUM_FIELDS; i++) {
        setMembershipDisclosure.credentialData[i] <== credentialData[i];
    }
    for (var i = 0; i < 4; i++) {
        setMembershipDisclosure.params[i] <== params[i];
    }
    setMembershipDisclosure.privateValue <== privateValue;
    for (var i = 0; i < TREE_DEPTH; i++) {
        setMembershipDisclosure.merkleProof[i] <== merkleProof[i];
        setMembershipDisclosure.merklePathIndices[i] <== merklePathIndices[i];
    }

    component existenceDisclosure = ExistenceDisclosure();
    for (var i = 0; i < 4; i++) {
        existenceDisclosure.params[i] <== params[i];
    }

    // Select result based on disclosure type using one-hot encoding
    signal isAge;
    signal isDateRange;
    signal isValueRange;
    signal isSetMembership;
    signal isExistence;

    isAge <-- (disclosureType == 0) ? 1 : 0;
    isDateRange <-- (disclosureType == 1) ? 1 : 0;
    isValueRange <-- (disclosureType == 2) ? 1 : 0;
    isSetMembership <-- (disclosureType == 3) ? 1 : 0;
    isExistence <-- (disclosureType == 4) ? 1 : 0;

    // Constrain to binary
    isAge * (1 - isAge) === 0;
    isDateRange * (1 - isDateRange) === 0;
    isValueRange * (1 - isValueRange) === 0;
    isSetMembership * (1 - isSetMembership) === 0;
    isExistence * (1 - isExistence) === 0;

    // Constrain to match type
    isAge * disclosureType === 0;
    isDateRange * (disclosureType - 1) === 0;
    isValueRange * (disclosureType - 2) === 0;
    isSetMembership * (disclosureType - 3) === 0;
    isExistence * (disclosureType - 4) === 0;

    // Exactly one must be selected
    isAge + isDateRange + isValueRange + isSetMembership + isExistence === 1;

    // Compute weighted result
    signal ageContrib;
    signal dateRangeContrib;
    signal valueRangeContrib;
    signal setMembershipContrib;
    signal existenceContrib;

    ageContrib <== isAge * ageDisclosure.result;
    dateRangeContrib <== isDateRange * dateRangeDisclosure.result;
    valueRangeContrib <== isValueRange * valueRangeDisclosure.result;
    setMembershipContrib <== isSetMembership * setMembershipDisclosure.result;
    existenceContrib <== isExistence * existenceDisclosure.result;

    result <== ageContrib + dateRangeContrib + valueRangeContrib + setMembershipContrib + existenceContrib;
}

/**
 * @title CompoundProof
 * @notice Main compound proof template combining multiple disclosures
 * @param NUM_FIELDS Number of credential fields (default 16)
 * @param NUM_DISCLOSURES Number of disclosure slots (typically 2-5)
 * @param TREE_DEPTH Merkle tree depth for set membership proofs
 *
 * Public Inputs:
 *   - credentialCommitment: Poseidon hash of credential data + salt
 *   - disclosureTypes[NUM_DISCLOSURES]: Type of each disclosure (0-4)
 *   - disclosureParams[NUM_DISCLOSURES][4]: Parameters for each disclosure
 *
 * Private Inputs:
 *   - credentialData[NUM_FIELDS]: Full credential field array
 *   - salt: Randomness used in commitment
 *   - privateValues[NUM_DISCLOSURES]: Private value for each disclosure
 *   - merkleProofs[NUM_DISCLOSURES][TREE_DEPTH]: Merkle proofs (for SET_MEMBERSHIP)
 *   - merklePathIndices[NUM_DISCLOSURES][TREE_DEPTH]: Merkle path indices
 *
 * Constraints:
 *   1. Credential commitment verification (done once)
 *   2. All NUM_DISCLOSURES must pass their respective checks
 */
template CompoundProof(NUM_FIELDS, NUM_DISCLOSURES, TREE_DEPTH) {
    // ===== PUBLIC INPUTS =====
    signal input credentialCommitment;
    signal input disclosureTypes[NUM_DISCLOSURES];
    signal input disclosureParams[NUM_DISCLOSURES][4];

    // ===== PRIVATE INPUTS =====
    signal input credentialData[NUM_FIELDS];
    signal input salt;
    signal input privateValues[NUM_DISCLOSURES];
    signal input merkleProofs[NUM_DISCLOSURES][TREE_DEPTH];
    signal input merklePathIndices[NUM_DISCLOSURES][TREE_DEPTH];

    // ===== STEP 1: Verify Credential Commitment (ONCE) =====
    component commitmentVerifier = CredentialCommitment(NUM_FIELDS);

    for (var i = 0; i < NUM_FIELDS; i++) {
        commitmentVerifier.credentialData[i] <== credentialData[i];
    }
    commitmentVerifier.salt <== salt;
    commitmentVerifier.commitment <== credentialCommitment;

    // ===== STEP 2: Verify Each Disclosure =====
    component disclosures[NUM_DISCLOSURES];
    signal disclosureResults[NUM_DISCLOSURES];

    for (var d = 0; d < NUM_DISCLOSURES; d++) {
        disclosures[d] = DisclosureVerifier(NUM_FIELDS, TREE_DEPTH);

        // Pass credential data to each disclosure verifier
        for (var i = 0; i < NUM_FIELDS; i++) {
            disclosures[d].credentialData[i] <== credentialData[i];
        }

        // Pass disclosure-specific inputs
        disclosures[d].disclosureType <== disclosureTypes[d];

        for (var p = 0; p < 4; p++) {
            disclosures[d].params[p] <== disclosureParams[d][p];
        }

        disclosures[d].privateValue <== privateValues[d];

        // Pass Merkle proof (used only for SET_MEMBERSHIP type)
        for (var m = 0; m < TREE_DEPTH; m++) {
            disclosures[d].merkleProof[m] <== merkleProofs[d][m];
            disclosures[d].merklePathIndices[m] <== merklePathIndices[d][m];
        }

        disclosureResults[d] <== disclosures[d].result;
    }

    // ===== STEP 3: All Disclosures Must Pass =====
    signal runningProduct[NUM_DISCLOSURES + 1];
    runningProduct[0] <== 1;

    for (var d = 0; d < NUM_DISCLOSURES; d++) {
        runningProduct[d + 1] <== runningProduct[d] * disclosureResults[d];
    }

    // Final product must be 1 (all disclosures passed)
    runningProduct[NUM_DISCLOSURES] === 1;
}

// ===== MAIN COMPONENT INSTANTIATIONS =====

// Standard compound proof with 2 disclosures (most common use case)
// Parameters: 16 fields, 2 disclosures, 10 tree depth
component main {public [credentialCommitment, disclosureTypes, disclosureParams]} = CompoundProof(16, 2, 10);
