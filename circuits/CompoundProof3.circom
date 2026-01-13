/**
 * @file CompoundProof3.circom
 * @description Compound proof variant with 3 disclosure slots
 *
 * @dev Same as CompoundProof.circom but with NUM_DISCLOSURES=3
 * Use when you need to prove 3 statements simultaneously.
 *
 * Example use case:
 * - Prove age > 21 AND license issued in last 5 years AND income > 50000
 */

pragma circom 2.1.6;

include "CompoundProof.circom";

// Compound proof with 3 disclosures
// Parameters: 16 fields, 3 disclosures, 10 tree depth
component main {public [credentialCommitment, disclosureTypes, disclosureParams]} = CompoundProof(16, 3, 10);
