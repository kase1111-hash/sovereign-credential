/**
 * @file CompoundProof4.circom
 * @description Compound proof variant with 4 disclosure slots
 *
 * @dev Same as CompoundProof.circom but with NUM_DISCLOSURES=4
 * Use when you need to prove 4 statements simultaneously.
 *
 * Example use case:
 * - Prove age > 18 AND state in allowed set AND license valid AND income in range
 */

pragma circom 2.1.6;

include "CompoundProof.circom";

// Compound proof with 4 disclosures
// Parameters: 16 fields, 4 disclosures, 10 tree depth
component main {public [credentialCommitment, disclosureTypes, disclosureParams]} = CompoundProof(16, 4, 10);
