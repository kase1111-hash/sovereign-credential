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
const JAN_1_2020 = 1577836800n;   // 2020-01-01 00:00:00 UTC
const JAN_1_2022 = 1640995200n;   // 2022-01-01 00:00:00 UTC
const JAN_1_2023 = 1672531200n;   // 2023-01-01 00:00:00 UTC
const JAN_1_2024 = 1704067200n;   // 2024-01-01 00:00:00 UTC
const JAN_1_2025 = 1735689600n;   // 2025-01-01 00:00:00 UTC
const JUL_1_2023 = 1688169600n;   // 2023-07-01 00:00:00 UTC

// Field indices
const ISSUANCE_DATE_FIELD = 1n;
const EXPIRATION_DATE_FIELD = 2n;
const CUSTOM_DATE_FIELD = 5n;

/**
 * Helper to create test credential data with dates
 */
function createCredentialData(dates: { [fieldIndex: number]: bigint }): bigint[] {
  const data: bigint[] = new Array(NUM_FIELDS).fill(0n);
  for (const [index, value] of Object.entries(dates)) {
    data[parseInt(index)] = value;
  }
  return data;
}

/**
 * Helper to create test inputs for DateRange circuit
 */
async function createTestInputs(params: {
  dateValue: bigint;
  fieldIndex: bigint;
  rangeStart: bigint;
  rangeEnd: bigint;
  salt?: bigint;
}) {
  const salt = params.salt ?? 12345n;
  const credentialData = createCredentialData({
    [Number(params.fieldIndex)]: params.dateValue,
  });
  const commitment = await createCommitment(credentialData, salt);

  return {
    credentialCommitment: commitment,
    rangeStart: params.rangeStart,
    rangeEnd: params.rangeEnd,
    fieldIndex: params.fieldIndex,
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
    it("should prove date is within range (middle of range)", async function () {
      if (!isCompiled) this.skip();

      // Date: July 2023, Range: 2022-2024
      const inputs = await createTestInputs({
        dateValue: JUL_1_2023,
        fieldIndex: ISSUANCE_DATE_FIELD,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2024,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);

      // Verify proof
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;

      // Verify public signals are correct
      expect(BigInt(publicSignals[0])).to.equal(inputs.credentialCommitment);
      expect(BigInt(publicSignals[1])).to.equal(JAN_1_2022); // rangeStart
      expect(BigInt(publicSignals[2])).to.equal(JAN_1_2024); // rangeEnd
      expect(BigInt(publicSignals[3])).to.equal(ISSUANCE_DATE_FIELD); // fieldIndex
    });

    it("should prove date at exact start of range (boundary)", async function () {
      if (!isCompiled) this.skip();

      // Date exactly at range start
      const inputs = await createTestInputs({
        dateValue: JAN_1_2022,
        fieldIndex: ISSUANCE_DATE_FIELD,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2024,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove date at exact end of range (boundary)", async function () {
      if (!isCompiled) this.skip();

      // Date exactly at range end
      const inputs = await createTestInputs({
        dateValue: JAN_1_2024,
        fieldIndex: ISSUANCE_DATE_FIELD,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2024,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove with single-point range (start == end)", async function () {
      if (!isCompiled) this.skip();

      // Range is a single point
      const inputs = await createTestInputs({
        dateValue: JAN_1_2023,
        fieldIndex: ISSUANCE_DATE_FIELD,
        rangeStart: JAN_1_2023,
        rangeEnd: JAN_1_2023,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should work with different field indices", async function () {
      if (!isCompiled) this.skip();

      // Use expiration date field
      const inputs = await createTestInputs({
        dateValue: JAN_1_2025,
        fieldIndex: EXPIRATION_DATE_FIELD,
        rangeStart: JAN_1_2024,
        rangeEnd: JAN_1_2025 + 86400n * 365n, // 1 year after
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Invalid Date Range Proofs (Should Fail)", function () {
    it("should fail when date is before range", async function () {
      if (!isCompiled) this.skip();

      // Date: 2020, Range: 2022-2024
      const inputs = await createTestInputs({
        dateValue: JAN_1_2020,
        fieldIndex: ISSUANCE_DATE_FIELD,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2024,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail when date is after range", async function () {
      if (!isCompiled) this.skip();

      // Date: 2025, Range: 2022-2024
      const inputs = await createTestInputs({
        dateValue: JAN_1_2025,
        fieldIndex: ISSUANCE_DATE_FIELD,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2024,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail when date is 1 second before range start", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JAN_1_2022 - 1n,
        fieldIndex: ISSUANCE_DATE_FIELD,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2024,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail when date is 1 second after range end", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JAN_1_2024 + 1n,
        fieldIndex: ISSUANCE_DATE_FIELD,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2024,
      });

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Invalid Commitment", function () {
    it("should reject proof with wrong commitment", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JUL_1_2023,
        fieldIndex: ISSUANCE_DATE_FIELD,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2024,
      });

      // Use wrong commitment
      inputs.credentialCommitment = 12345678901234567890n;

      await expectProofToFail(circuit, inputs);
    });

    it("should reject proof with mismatched date in credential", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JUL_1_2023,
        fieldIndex: ISSUANCE_DATE_FIELD,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2024,
      });

      // Change dateValue input but not credential data
      inputs.dateValue = JAN_1_2023;

      await expectProofToFail(circuit, inputs);
    });

    it("should reject proof with wrong field index", async function () {
      if (!isCompiled) this.skip();

      const salt = 12345n;
      const credentialData = createCredentialData({
        1: JUL_1_2023,  // issuance date
        2: JAN_1_2025,  // expiration date (out of range)
      });
      const commitment = await createCommitment(credentialData, salt);

      const inputs = {
        credentialCommitment: commitment,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2024,
        fieldIndex: ISSUANCE_DATE_FIELD,  // Correct field
        dateValue: JAN_1_2025,  // But using expiration date value
        credentialData: credentialData,
        salt: salt,
      };

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Edge Cases", function () {
    it("should handle timestamp 0 (Unix epoch)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: 0n,
        fieldIndex: ISSUANCE_DATE_FIELD,
        rangeStart: 0n,
        rangeEnd: JAN_1_2020,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle very large timestamps (year 2100)", async function () {
      if (!isCompiled) this.skip();

      const year2100 = 4102444800n; // 2100-01-01
      const year2099 = 4070908800n; // 2099-01-01

      const inputs = await createTestInputs({
        dateValue: year2099,
        fieldIndex: ISSUANCE_DATE_FIELD,
        rangeStart: JAN_1_2025,
        rangeEnd: year2100,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should work with field index 0", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JAN_1_2023,
        fieldIndex: 0n,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2024,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should work with last field index (15)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JAN_1_2023,
        fieldIndex: 15n,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2024,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Solidity Calldata Generation", function () {
    it("should generate valid Solidity calldata", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        dateValue: JUL_1_2023,
        fieldIndex: ISSUANCE_DATE_FIELD,
        rangeStart: JAN_1_2022,
        rangeEnd: JAN_1_2024,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const calldata = await generateCalldata(proof, publicSignals);

      // Parse and verify calldata structure
      const parsed = parseCalldata(calldata);

      expect(parsed.a).to.have.length(2);
      expect(parsed.b).to.have.length(2);
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
  JAN_1_2022,
  JAN_1_2023,
  JAN_1_2024,
  JAN_1_2025,
  JUL_1_2023,
  ISSUANCE_DATE_FIELD,
  EXPIRATION_DATE_FIELD,
  CUSTOM_DATE_FIELD,
};
