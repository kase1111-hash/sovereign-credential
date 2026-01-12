/**
 * @file comparators.circom
 * @description Comparison templates for ZK proofs
 * @dev Wraps circomlib comparators with credential-specific helpers
 */

pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/**
 * @title SafeGreaterThan
 * @notice Compares two values with overflow protection
 * @param N Bit width of inputs (e.g., 64 for timestamps, 252 for field elements)
 *
 * @input a - First value
 * @input b - Second value
 * @output out - 1 if a > b, else 0
 */
template SafeGreaterThan(N) {
    signal input a;
    signal input b;
    signal output out;

    // Range check inputs
    component aBits = Num2Bits(N);
    component bBits = Num2Bits(N);
    aBits.in <== a;
    bBits.in <== b;

    // Use circomlib GreaterThan
    component gt = GreaterThan(N);
    gt.in[0] <== a;
    gt.in[1] <== b;

    out <== gt.out;
}

/**
 * @title SafeLessThan
 * @notice Compares two values (a < b) with overflow protection
 * @param N Bit width of inputs
 */
template SafeLessThan(N) {
    signal input a;
    signal input b;
    signal output out;

    // Range check inputs
    component aBits = Num2Bits(N);
    component bBits = Num2Bits(N);
    aBits.in <== a;
    bBits.in <== b;

    // Use circomlib LessThan
    component lt = LessThan(N);
    lt.in[0] <== a;
    lt.in[1] <== b;

    out <== lt.out;
}

/**
 * @title SafeGreaterEqThan
 * @notice Compares two values (a >= b) with overflow protection
 * @param N Bit width of inputs
 */
template SafeGreaterEqThan(N) {
    signal input a;
    signal input b;
    signal output out;

    // Range check inputs
    component aBits = Num2Bits(N);
    component bBits = Num2Bits(N);
    aBits.in <== a;
    bBits.in <== b;

    // a >= b is equivalent to NOT (a < b)
    component lt = LessThan(N);
    lt.in[0] <== a;
    lt.in[1] <== b;

    out <== 1 - lt.out;
}

/**
 * @title SafeLessEqThan
 * @notice Compares two values (a <= b) with overflow protection
 * @param N Bit width of inputs
 */
template SafeLessEqThan(N) {
    signal input a;
    signal input b;
    signal output out;

    // Range check inputs
    component aBits = Num2Bits(N);
    component bBits = Num2Bits(N);
    aBits.in <== a;
    bBits.in <== b;

    // a <= b is equivalent to NOT (a > b)
    component gt = GreaterThan(N);
    gt.in[0] <== a;
    gt.in[1] <== b;

    out <== 1 - gt.out;
}

/**
 * @title InRange
 * @notice Checks if a value is within a range [min, max] inclusive
 * @param N Bit width of inputs
 *
 * @input value - Value to check
 * @input min - Minimum value (inclusive)
 * @input max - Maximum value (inclusive)
 * @output out - 1 if min <= value <= max, else 0
 */
template InRange(N) {
    signal input value;
    signal input min;
    signal input max;
    signal output out;

    // Range check all inputs
    component valueBits = Num2Bits(N);
    component minBits = Num2Bits(N);
    component maxBits = Num2Bits(N);
    valueBits.in <== value;
    minBits.in <== min;
    maxBits.in <== max;

    // Check value >= min
    component geMin = SafeGreaterEqThan(N);
    geMin.a <== value;
    geMin.b <== min;

    // Check value <= max
    component leMax = SafeLessEqThan(N);
    leMax.a <== value;
    leMax.b <== max;

    // Both conditions must be true
    out <== geMin.out * leMax.out;
}

/**
 * @title ThresholdCheck
 * @notice Checks if a value meets a threshold based on comparison type
 * @param N Bit width of inputs
 *
 * @input value - Value to check
 * @input threshold - Threshold to compare against
 * @input comparisonType - 0 for greater than, 1 for less than
 * @output out - 1 if condition met, else 0
 */
template ThresholdCheck(N) {
    signal input value;
    signal input threshold;
    signal input comparisonType;

    signal output out;

    // Ensure comparisonType is binary
    comparisonType * (1 - comparisonType) === 0;

    // Check both conditions
    component gt = SafeGreaterThan(N);
    gt.a <== value;
    gt.b <== threshold;

    component lt = SafeLessThan(N);
    lt.a <== value;
    lt.b <== threshold;

    // Select based on comparison type
    // comparisonType == 0 -> use gt.out
    // comparisonType == 1 -> use lt.out
    out <== (1 - comparisonType) * gt.out + comparisonType * lt.out;
}

/**
 * @title IsEqual
 * @notice Checks if two values are equal
 * @param N Bit width for range checks
 *
 * @input a - First value
 * @input b - Second value
 * @output out - 1 if a == b, else 0
 */
template SafeIsEqual(N) {
    signal input a;
    signal input b;
    signal output out;

    // Range check inputs
    component aBits = Num2Bits(N);
    component bBits = Num2Bits(N);
    aBits.in <== a;
    bBits.in <== b;

    // Use circomlib IsEqual
    component eq = IsEqual();
    eq.in[0] <== a;
    eq.in[1] <== b;

    out <== eq.out;
}

/**
 * @title IsNonZero
 * @notice Checks if a value is non-zero
 *
 * @input value - Value to check
 * @output out - 1 if value != 0, else 0
 */
template IsNonZero() {
    signal input value;
    signal output out;

    component iz = IsZero();
    iz.in <== value;

    out <== 1 - iz.out;
}
