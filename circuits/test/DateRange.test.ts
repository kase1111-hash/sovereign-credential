/**
 * @file DateRange.test.ts
 * @description Tests for the DateRange ZK circuit
 *
 * Test cases from IMPLEMENTATION_GUIDE.md:
 * - Date within range passes
 * - Date before range fails
 * - Date after range fails
 * - Edge cases (exact boundaries)
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
  expectProofToFail,
  CircuitTest,
} from "./circuitTestUtils";

// Test constants
const NUM_FIELDS = 16;

// Test dates (Unix timestamps)
const JAN_1_2020 = 1577836800n;  // 2020-01-01 00:00:00 UTC
const JAN_1_2021 = 1609459200n;  // 2021-01-01 00:00:00 UTC
const JAN_1_2022 = 1640995200n;  // 2022-01-01 00:00:00 UTC
const JAN_1_2023 = 1672531200n;  // 2023-01-01 00:00:00 UTC
const JAN_1_2024 = 1704067200n;  // 2024-01-01 00:00:00 UTC
const JAN_1_2025 = 1735689600n;  // 2025-01-01 00:00:00 UTC

const JULY_1_2022 = 1656633600n; // 2022-07-01 00:00:00 UTC

/**
 * Helper to create test credential data with a date value at a specific field
 */
function createCredentialData(dateValue: bigint, fieldIndex: number = 1): bigint[] {
  const data: bigint[] = new Array(NUM_FIELDS).fill(0n);
  data[fieldIndex] = dateValue;
  return data;
}

/**
 * Helper to create test inputs for DateRange circuit
 */
async function createTestInputs(params: {
  dateValue: bigint;
  fieldIndex: number;
  rangeStart: bigint;
  rangeEnd: bigint;
  salt?: bigint;
}) {
  const salt = params.salt ?? 12345n;
  const credentialData = createCredentialData(params.dateValue, params.fieldIndex);
  const commitment = await createCommitment(credentialData, salt);

  return {
    credentialCommitment: commitment,
    rangeStart: params.rangeStart,
    rangeEnd: params.rangeEnd,
    fieldIndex: BigInt(params.fieldIndex),
    dateValue: params.dateValue,
    credentialData: credentialData,
    salt: salt,
  };
}

describe("DateRange Circuit", function () {
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
      "DateRange_js",
      "DateRange.wasm"
    );

    if (!fs.existsSync(wasmPath)) {
      console.log(
        "\n  Skipping DateRange tests - circuit not compiled.\n" +
          "  Run: cd circuits && ./compile.sh DateRange && ./setup.sh DateRange\n"
      );
      isCompiled = false;
    } else {
      try {
        circuit = initCircuit("DateRange");
        isCompiled = true;
      } catch (error: any) {
        console.log(`\n  Skipping tests: ${error.message}\n`);
        isCompiled = false;
      }
    }
  });

  describe("Valid Date Range Proofs", function () {
    it("should prove date within range (middle of range)", async function () {
      if (!isCompiled) this.skip();

      // Date: July 2022, Range: 2021-2023
      const inputs = await createTestInputs({
        dateValue: JULY_1_2022,
        fieldIndex: 1,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);

      // Verify proof
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;

      // Verify public signals are correct
      expect(BigInt(publicSignals[0])).to.equal(inputs.credentialCommitment);
      expect(BigInt(publicSignals[1])).to.equal(JAN_1_2021); // rangeStart
      expect(BigInt(publicSignals[2])).to.equal(JAN_1_2023); // rangeEnd
      expect(BigInt(publicSignals[3])).to.equal(1n); // fieldIndex
    });

    it("should prove date at exact start of range", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JAN_1_2021,
        fieldIndex: 1,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove date at exact end of range", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JAN_1_2023,
        fieldIndex: 1,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove date for different field indices", async function () {
      if (!isCompiled) this.skip();

      // Test with date in field 5
      const inputs = await createTestInputs({
        dateValue: JAN_1_2022,
        fieldIndex: 5,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove for single-day range", async function () {
      if (!isCompiled) this.skip();

      // Range of exactly one day
      const inputs = await createTestInputs({
        dateValue: JAN_1_2022,
        fieldIndex: 1,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2022,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Invalid Date Range Proofs (Should Fail)", function () {
    it("should fail for date before range", async function () {
      if (!isCompiled) this.skip();

      // Date: 2020, Range: 2021-2023
      const inputs = await createTestInputs({
        dateValue: JAN_1_2020,
        fieldIndex: 1,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail for date after range", async function () {
      if (!isCompiled) this.skip();

      // Date: 2024, Range: 2021-2023
      const inputs = await createTestInputs({
        dateValue: JAN_1_2024,
        fieldIndex: 1,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail for date just before range start", async function () {
      if (!isCompiled) this.skip();

      // Date: Dec 31, 2020 (one second before range start)
      const dateJustBefore = JAN_1_2021 - 1n;

      const inputs = await createTestInputs({
        dateValue: dateJustBefore,
        fieldIndex: 1,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail for date just after range end", async function () {
      if (!isCompiled) this.skip();

      // Date: Jan 1, 2023 + 1 second
      const dateJustAfter = JAN_1_2023 + 1n;

      const inputs = await createTestInputs({
        dateValue: dateJustAfter,
        fieldIndex: 1,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
      });

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Invalid Commitment", function () {
    it("should reject proof with wrong commitment", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JAN_1_2022,
        fieldIndex: 1,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
      });

      // Use wrong commitment
      inputs.credentialCommitment = 12345678901234567890n;

      await expectProofToFail(circuit, inputs);
    });

    it("should reject proof with wrong salt", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JAN_1_2022,
        fieldIndex: 1,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
        salt: 12345n,
      });

      // Use different salt that doesn't match commitment
      inputs.salt = 99999n;

      await expectProofToFail(circuit, inputs);
    });

    it("should reject proof with mismatched date value", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JAN_1_2022,
        fieldIndex: 1,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
      });

      // Change date value input but not credential data
      inputs.dateValue = JAN_1_2020;

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Invalid Field Index", function () {
    it("should reject proof with wrong field index", async function () {
      if (!isCompiled) this.skip();

      // Create credential with date in field 1
      const inputs = await createTestInputs({
        dateValue: JAN_1_2022,
        fieldIndex: 1,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
      });

      // But claim it's in field 2
      inputs.fieldIndex = 2n;

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Edge Cases", function () {
    it("should handle timestamp 0", async function () {
      if (!isCompiled) this.skip();

      // Unix epoch start
      const inputs = await createTestInputs({
        dateValue: 0n,
        fieldIndex: 1,
        rangeStart: 0n,
        rangeEnd: JAN_1_2020,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle large timestamps (year 3000)", async function () {
      if (!isCompiled) this.skip();

      // Year 3000 timestamp (approximately)
      const year3000 = 32503680000n;

      const inputs = await createTestInputs({
        dateValue: year3000,
        fieldIndex: 1,
        rangeStart: JAN_1_2025,
        rangeEnd: year3000 + 1000n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle first field (index 0)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JAN_1_2022,
        fieldIndex: 0,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle last field (index 15)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JAN_1_2022,
        fieldIndex: 15,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Deterministic Proofs", function () {
    it("should generate same commitment for same inputs", async function () {
      if (!isCompiled) this.skip();

      const credentialData = createCredentialData(JAN_1_2022, 1);
      const salt = 12345n;

      const commitment1 = await createCommitment(credentialData, salt);
      const commitment2 = await createCommitment(credentialData, salt);

      expect(commitment1).to.equal(commitment2);
    });

    it("should generate different commitments for different dates", async function () {
      if (!isCompiled) this.skip();

      const credentialData1 = createCredentialData(JAN_1_2022, 1);
      const credentialData2 = createCredentialData(JAN_1_2023, 1);
      const salt = 12345n;

      const commitment1 = await createCommitment(credentialData1, salt);
      const commitment2 = await createCommitment(credentialData2, salt);

      expect(commitment1).to.not.equal(commitment2);
    });
  });

  describe("Solidity Calldata Generation", function () {
    it("should generate valid Solidity calldata", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JAN_1_2022,
        fieldIndex: 1,
        rangeStart: JAN_1_2021,
        rangeEnd: JAN_1_2023,
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
    });
  });
});

// Export helper functions for use in other tests
export {
  createCredentialData,
  createTestInputs,
  NUM_FIELDS,
  JAN_1_2020,
  JAN_1_2021,
  JAN_1_2022,
  JAN_1_2023,
  JAN_1_2024,
  JAN_1_2025,
  JULY_1_2022,
};
