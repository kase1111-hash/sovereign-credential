/**
 * @file AgeThreshold.test.ts
 * @description Tests for the AgeThreshold ZK circuit
 *
 * Test cases from IMPLEMENTATION_GUIDE.md:
 * - Prove age > 18 when age is 25
 * - Prove age > 18 when age is 17 (should fail)
 * - Prove age < 65 when age is 40
 * - Invalid commitment rejected
 * - Proof verification on-chain format
 */

import { expect } from "chai";
import * as path from "path";
import * as fs from "fs";
import {
  initCircuit,
  generateProof,
  verifyProof,
  generateCalldata,
  parseCalldata,
  createCommitment,
  toTimestamp,
  expectProofToFail,
  CircuitTest,
} from "./circuitTestUtils";

// Test constants
const NUM_FIELDS = 16;
const COMPARISON_GREATER_THAN = 0n;
const COMPARISON_LESS_THAN = 1n;

// Seconds per year (matching circuit constant - 365.25 days)
const SECONDS_PER_YEAR = 31557600n;

// Test dates
const JAN_1_2000 = 946684800n;  // Unix timestamp for 2000-01-01
const JAN_1_2005 = 1104537600n; // Unix timestamp for 2005-01-01
const JAN_1_2010 = 1262304000n; // Unix timestamp for 2010-01-01
const JAN_1_2025 = 1735689600n; // Unix timestamp for 2025-01-01

/**
 * Helper to create test credential data with birthdate
 */
function createCredentialData(birthdate: bigint): bigint[] {
  const data: bigint[] = new Array(NUM_FIELDS).fill(0n);
  data[0] = birthdate; // Birthdate is field 0 by convention
  return data;
}

/**
 * Helper to create test inputs for AgeThreshold circuit
 */
async function createTestInputs(params: {
  birthdate: bigint;
  currentTimestamp: bigint;
  threshold: bigint;
  comparisonType: bigint;
  salt?: bigint;
}) {
  const salt = params.salt ?? 12345n;
  const credentialData = createCredentialData(params.birthdate);
  const commitment = await createCommitment(credentialData, salt);

  return {
    credentialCommitment: commitment,
    threshold: params.threshold,
    currentTimestamp: params.currentTimestamp,
    comparisonType: params.comparisonType,
    birthdate: params.birthdate,
    credentialData: credentialData,
    salt: salt,
  };
}

describe("AgeThreshold Circuit", function () {
  // Increase timeout for proof generation
  this.timeout(60000);

  let circuit: CircuitTest;
  let isCompiled: boolean = false;

  before(async function () {
    // Check if circuit is compiled
    const wasmPath = path.join(
      __dirname,
      "..",
      "build",
      "AgeThreshold_js",
      "AgeThreshold.wasm"
    );

    if (!fs.existsSync(wasmPath)) {
      console.log(
        "\n  Skipping AgeThreshold tests - circuit not compiled.\n" +
          "  Run: cd circuits && ./compile.sh AgeThreshold && ./setup.sh AgeThreshold\n"
      );
      isCompiled = false;
    } else {
      try {
        circuit = initCircuit("AgeThreshold");
        isCompiled = true;
      } catch (error: any) {
        console.log(`\n  Skipping tests: ${error.message}\n`);
        isCompiled = false;
      }
    }
  });

  describe("Valid Age Proofs", function () {
    it("should prove age > 18 for 25-year-old", async function () {
      if (!isCompiled) this.skip();

      // Person born Jan 1, 2000 - age 25 on Jan 1, 2025
      const inputs = await createTestInputs({
        birthdate: JAN_1_2000,
        currentTimestamp: JAN_1_2025,
        threshold: 18n,
        comparisonType: COMPARISON_GREATER_THAN,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);

      // Verify proof
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;

      // Verify public signals are correct
      expect(BigInt(publicSignals[0])).to.equal(inputs.credentialCommitment);
      expect(BigInt(publicSignals[1])).to.equal(18n); // threshold
      expect(BigInt(publicSignals[2])).to.equal(JAN_1_2025); // currentTimestamp
      expect(BigInt(publicSignals[3])).to.equal(COMPARISON_GREATER_THAN);
    });

    it("should prove age > 21 for 25-year-old", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        birthdate: JAN_1_2000,
        currentTimestamp: JAN_1_2025,
        threshold: 21n,
        comparisonType: COMPARISON_GREATER_THAN,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove age < 65 for 40-year-old", async function () {
      if (!isCompiled) this.skip();

      // Born 1985 = 40 years old in 2025
      const birthdate1985 = JAN_1_2025 - (40n * SECONDS_PER_YEAR);

      const inputs = await createTestInputs({
        birthdate: birthdate1985,
        currentTimestamp: JAN_1_2025,
        threshold: 65n,
        comparisonType: COMPARISON_LESS_THAN,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove age < 30 for 20-year-old", async function () {
      if (!isCompiled) this.skip();

      // Person born Jan 1, 2005 - age 20 on Jan 1, 2025
      const inputs = await createTestInputs({
        birthdate: JAN_1_2005,
        currentTimestamp: JAN_1_2025,
        threshold: 30n,
        comparisonType: COMPARISON_LESS_THAN,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove exact age boundary (age > 17 when age is 18)", async function () {
      if (!isCompiled) this.skip();

      // Person exactly 18 years old
      const birthdate = JAN_1_2025 - (18n * SECONDS_PER_YEAR);

      const inputs = await createTestInputs({
        birthdate: birthdate,
        currentTimestamp: JAN_1_2025,
        threshold: 17n,
        comparisonType: COMPARISON_GREATER_THAN,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Invalid Age Proofs (Should Fail)", function () {
    it("should fail to prove age > 18 for 17-year-old", async function () {
      if (!isCompiled) this.skip();

      // Person born 2008 = 17 years old in 2025
      const birthdate2008 = JAN_1_2025 - (17n * SECONDS_PER_YEAR);

      const inputs = await createTestInputs({
        birthdate: birthdate2008,
        currentTimestamp: JAN_1_2025,
        threshold: 18n,
        comparisonType: COMPARISON_GREATER_THAN,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail to prove age > 21 for 18-year-old", async function () {
      if (!isCompiled) this.skip();

      // Person born 2007 = 18 years old in 2025
      const birthdate = JAN_1_2025 - (18n * SECONDS_PER_YEAR);

      const inputs = await createTestInputs({
        birthdate: birthdate,
        currentTimestamp: JAN_1_2025,
        threshold: 21n,
        comparisonType: COMPARISON_GREATER_THAN,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail to prove age < 30 for 40-year-old", async function () {
      if (!isCompiled) this.skip();

      const birthdate = JAN_1_2025 - (40n * SECONDS_PER_YEAR);

      const inputs = await createTestInputs({
        birthdate: birthdate,
        currentTimestamp: JAN_1_2025,
        threshold: 30n,
        comparisonType: COMPARISON_LESS_THAN,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail at exact threshold (age > 18 when age is exactly 18)", async function () {
      if (!isCompiled) this.skip();

      // Person exactly 18 - should fail "greater than 18"
      const birthdate = JAN_1_2025 - (18n * SECONDS_PER_YEAR);

      const inputs = await createTestInputs({
        birthdate: birthdate,
        currentTimestamp: JAN_1_2025,
        threshold: 18n,
        comparisonType: COMPARISON_GREATER_THAN,
      });

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Invalid Commitment", function () {
    it("should reject proof with wrong commitment", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        birthdate: JAN_1_2000,
        currentTimestamp: JAN_1_2025,
        threshold: 18n,
        comparisonType: COMPARISON_GREATER_THAN,
      });

      // Use wrong commitment
      inputs.credentialCommitment = 12345678901234567890n;

      await expectProofToFail(circuit, inputs);
    });

    it("should reject proof with wrong salt", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        birthdate: JAN_1_2000,
        currentTimestamp: JAN_1_2025,
        threshold: 18n,
        comparisonType: COMPARISON_GREATER_THAN,
        salt: 12345n,
      });

      // Use different salt that doesn't match commitment
      inputs.salt = 99999n;

      await expectProofToFail(circuit, inputs);
    });

    it("should reject proof with mismatched birthdate in credential", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        birthdate: JAN_1_2000,
        currentTimestamp: JAN_1_2025,
        threshold: 18n,
        comparisonType: COMPARISON_GREATER_THAN,
      });

      // Change birthdate input but not credential data
      inputs.birthdate = JAN_1_2005;

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Edge Cases", function () {
    it("should handle very young person (age 0)", async function () {
      if (!isCompiled) this.skip();

      // Person born in current year (age 0)
      const birthdate = JAN_1_2025;

      const inputs = await createTestInputs({
        birthdate: birthdate,
        currentTimestamp: JAN_1_2025 + 1000n, // Slightly after birth
        threshold: 0n,
        comparisonType: COMPARISON_GREATER_THAN,
      });

      // Age 0 is not > 0, should fail
      await expectProofToFail(circuit, inputs);
    });

    it("should handle elderly person (age 100)", async function () {
      if (!isCompiled) this.skip();

      // Person 100 years old
      const birthdate = JAN_1_2025 - (100n * SECONDS_PER_YEAR);

      const inputs = await createTestInputs({
        birthdate: birthdate,
        currentTimestamp: JAN_1_2025,
        threshold: 65n,
        comparisonType: COMPARISON_GREATER_THAN,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should fail for future birthdate", async function () {
      if (!isCompiled) this.skip();

      // Birthdate in future (invalid)
      const futureBirthdate = JAN_1_2025 + SECONDS_PER_YEAR;

      const credentialData = createCredentialData(futureBirthdate);
      const salt = 12345n;
      const commitment = await createCommitment(credentialData, salt);

      const inputs = {
        credentialCommitment: commitment,
        threshold: 18n,
        currentTimestamp: JAN_1_2025,
        comparisonType: COMPARISON_GREATER_THAN,
        birthdate: futureBirthdate,
        credentialData: credentialData,
        salt: salt,
      };

      // Should fail because currentTimestamp < birthdate
      await expectProofToFail(circuit, inputs);
    });

    it("should reject invalid comparison type (not 0 or 1)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        birthdate: JAN_1_2000,
        currentTimestamp: JAN_1_2025,
        threshold: 18n,
        comparisonType: 2n, // Invalid - must be 0 or 1
      });

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Deterministic Proofs", function () {
    it("should generate same commitment for same inputs", async function () {
      if (!isCompiled) this.skip();

      const credentialData = createCredentialData(JAN_1_2000);
      const salt = 12345n;

      const commitment1 = await createCommitment(credentialData, salt);
      const commitment2 = await createCommitment(credentialData, salt);

      expect(commitment1).to.equal(commitment2);
    });

    it("should generate different commitments for different salts", async function () {
      if (!isCompiled) this.skip();

      const credentialData = createCredentialData(JAN_1_2000);

      const commitment1 = await createCommitment(credentialData, 12345n);
      const commitment2 = await createCommitment(credentialData, 67890n);

      expect(commitment1).to.not.equal(commitment2);
    });
  });

  describe("Solidity Calldata Generation", function () {
    it("should generate valid Solidity calldata", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        birthdate: JAN_1_2000,
        currentTimestamp: JAN_1_2025,
        threshold: 18n,
        comparisonType: COMPARISON_GREATER_THAN,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const calldata = await generateCalldata(proof, publicSignals);

      // Parse and verify calldata structure
      const parsed = parseCalldata(calldata);

      expect(parsed.a).to.have.length(2);
      expect(parsed.b).to.have.length(2);
      expect(parsed.b[0]).to.have.length(2);
      expect(parsed.b[1]).to.have.length(2);
      expect(parsed.c).to.have.length(2);
      expect(parsed.inputs).to.have.length(4); // 4 public inputs

      // Verify inputs match
      expect(parsed.inputs[1]).to.equal("18"); // threshold
    });
  });
});

// Export helper functions for use in other tests
export {
  createCredentialData,
  createTestInputs,
  NUM_FIELDS,
  COMPARISON_GREATER_THAN,
  COMPARISON_LESS_THAN,
  SECONDS_PER_YEAR,
  JAN_1_2000,
  JAN_1_2005,
  JAN_1_2010,
  JAN_1_2025,
};
