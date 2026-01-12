/**
 * @file ValueRange.test.ts
 * @description Tests for the ValueRange ZK circuit
 *
 * Test cases from IMPLEMENTATION_GUIDE.md:
 * - Value within range passes
 * - Value below minimum fails
 * - Value above maximum fails
 * - Edge cases (exact boundaries)
 * - Large sets with different field indices
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

// Test values for common use cases
const CREDIT_SCORE_MIN = 300n;
const CREDIT_SCORE_MAX = 850n;
const CREDIT_SCORE_EXCELLENT = 800n;
const CREDIT_SCORE_GOOD = 700n;
const CREDIT_SCORE_FAIR = 650n;
const CREDIT_SCORE_POOR = 500n;

const INCOME_50K = 50000n;
const INCOME_75K = 75000n;
const INCOME_100K = 100000n;
const INCOME_150K = 150000n;

const MAX_UINT64 = (1n << 64n) - 1n;

/**
 * Helper to create test credential data with a value at a specific field
 */
function createCredentialData(value: bigint, fieldIndex: number = 2): bigint[] {
  const data: bigint[] = new Array(NUM_FIELDS).fill(0n);
  data[fieldIndex] = value;
  return data;
}

/**
 * Helper to create test inputs for ValueRange circuit
 */
async function createTestInputs(params: {
  actualValue: bigint;
  fieldIndex: number;
  minValue: bigint;
  maxValue: bigint;
  salt?: bigint;
}) {
  const salt = params.salt ?? 12345n;
  const credentialData = createCredentialData(params.actualValue, params.fieldIndex);
  const commitment = await createCommitment(credentialData, salt);

  return {
    credentialCommitment: commitment,
    minValue: params.minValue,
    maxValue: params.maxValue,
    fieldIndex: BigInt(params.fieldIndex),
    actualValue: params.actualValue,
    credentialData: credentialData,
    salt: salt,
  };
}

describe("ValueRange Circuit", function () {
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
      "ValueRange_js",
      "ValueRange.wasm"
    );

    if (!fs.existsSync(wasmPath)) {
      console.log(
        "\n  Skipping ValueRange tests - circuit not compiled.\n" +
          "  Run: cd circuits && ./compile.sh ValueRange && ./setup.sh ValueRange\n"
      );
      isCompiled = false;
    } else {
      try {
        circuit = initCircuit("ValueRange");
        isCompiled = true;
      } catch (error: any) {
        console.log(`\n  Skipping tests: ${error.message}\n`);
        isCompiled = false;
      }
    }
  });

  describe("Valid Value Range Proofs - Credit Score", function () {
    it("should prove credit score 800 is within 700-850 range", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: CREDIT_SCORE_EXCELLENT,
        fieldIndex: 2,
        minValue: CREDIT_SCORE_GOOD,
        maxValue: CREDIT_SCORE_MAX,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);

      // Verify proof
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;

      // Verify public signals are correct
      expect(BigInt(publicSignals[0])).to.equal(inputs.credentialCommitment);
      expect(BigInt(publicSignals[1])).to.equal(CREDIT_SCORE_GOOD); // minValue
      expect(BigInt(publicSignals[2])).to.equal(CREDIT_SCORE_MAX); // maxValue
      expect(BigInt(publicSignals[3])).to.equal(2n); // fieldIndex
    });

    it("should prove credit score at exact minimum", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: CREDIT_SCORE_GOOD,
        fieldIndex: 2,
        minValue: CREDIT_SCORE_GOOD,
        maxValue: CREDIT_SCORE_MAX,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove credit score at exact maximum", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: CREDIT_SCORE_MAX,
        fieldIndex: 2,
        minValue: CREDIT_SCORE_GOOD,
        maxValue: CREDIT_SCORE_MAX,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Valid Value Range Proofs - Income", function () {
    it("should prove income $75K is within $50K-$100K range", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: INCOME_75K,
        fieldIndex: 3,
        minValue: INCOME_50K,
        maxValue: INCOME_100K,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove income >= $100K (open-ended upper bound)", async function () {
      if (!isCompiled) this.skip();

      // Use MAX_UINT64 as upper bound to prove "at least $100K"
      const inputs = await createTestInputs({
        actualValue: INCOME_150K,
        fieldIndex: 3,
        minValue: INCOME_100K,
        maxValue: MAX_UINT64,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove income <= $100K (open-ended lower bound)", async function () {
      if (!isCompiled) this.skip();

      // Use 0 as lower bound to prove "at most $100K"
      const inputs = await createTestInputs({
        actualValue: INCOME_75K,
        fieldIndex: 3,
        minValue: 0n,
        maxValue: INCOME_100K,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Invalid Value Range Proofs (Should Fail)", function () {
    it("should fail for value below minimum", async function () {
      if (!isCompiled) this.skip();

      // Credit score 650 is below minimum of 700
      const inputs = await createTestInputs({
        actualValue: CREDIT_SCORE_FAIR,
        fieldIndex: 2,
        minValue: CREDIT_SCORE_GOOD,
        maxValue: CREDIT_SCORE_MAX,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail for value above maximum", async function () {
      if (!isCompiled) this.skip();

      // Income $150K is above maximum of $100K
      const inputs = await createTestInputs({
        actualValue: INCOME_150K,
        fieldIndex: 3,
        minValue: INCOME_50K,
        maxValue: INCOME_100K,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail for value just below minimum", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 699n,
        fieldIndex: 2,
        minValue: CREDIT_SCORE_GOOD,
        maxValue: CREDIT_SCORE_MAX,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail for value just above maximum", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 851n,
        fieldIndex: 2,
        minValue: CREDIT_SCORE_GOOD,
        maxValue: CREDIT_SCORE_MAX,
      });

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Invalid Commitment", function () {
    it("should reject proof with wrong commitment", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: CREDIT_SCORE_EXCELLENT,
        fieldIndex: 2,
        minValue: CREDIT_SCORE_GOOD,
        maxValue: CREDIT_SCORE_MAX,
      });

      // Use wrong commitment
      inputs.credentialCommitment = 12345678901234567890n;

      await expectProofToFail(circuit, inputs);
    });

    it("should reject proof with wrong salt", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: CREDIT_SCORE_EXCELLENT,
        fieldIndex: 2,
        minValue: CREDIT_SCORE_GOOD,
        maxValue: CREDIT_SCORE_MAX,
        salt: 12345n,
      });

      // Use different salt that doesn't match commitment
      inputs.salt = 99999n;

      await expectProofToFail(circuit, inputs);
    });

    it("should reject proof with mismatched actual value", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: CREDIT_SCORE_EXCELLENT,
        fieldIndex: 2,
        minValue: CREDIT_SCORE_GOOD,
        maxValue: CREDIT_SCORE_MAX,
      });

      // Change actual value input but not credential data
      inputs.actualValue = CREDIT_SCORE_POOR;

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Invalid Field Index", function () {
    it("should reject proof with wrong field index", async function () {
      if (!isCompiled) this.skip();

      // Create credential with value in field 2
      const inputs = await createTestInputs({
        actualValue: CREDIT_SCORE_EXCELLENT,
        fieldIndex: 2,
        minValue: CREDIT_SCORE_GOOD,
        maxValue: CREDIT_SCORE_MAX,
      });

      // But claim it's in field 3
      inputs.fieldIndex = 3n;

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Edge Cases", function () {
    it("should handle value 0", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 0n,
        fieldIndex: 2,
        minValue: 0n,
        maxValue: 100n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle large values", async function () {
      if (!isCompiled) this.skip();

      const largeValue = 1000000000000000000n; // 10^18

      const inputs = await createTestInputs({
        actualValue: largeValue,
        fieldIndex: 2,
        minValue: largeValue - 1000n,
        maxValue: largeValue + 1000n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle single value range (min == max)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 500n,
        fieldIndex: 2,
        minValue: 500n,
        maxValue: 500n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle first field (index 0)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 100n,
        fieldIndex: 0,
        minValue: 50n,
        maxValue: 150n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle last field (index 15)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 100n,
        fieldIndex: 15,
        minValue: 50n,
        maxValue: 150n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Deterministic Proofs", function () {
    it("should generate same commitment for same inputs", async function () {
      if (!isCompiled) this.skip();

      const credentialData = createCredentialData(CREDIT_SCORE_EXCELLENT, 2);
      const salt = 12345n;

      const commitment1 = await createCommitment(credentialData, salt);
      const commitment2 = await createCommitment(credentialData, salt);

      expect(commitment1).to.equal(commitment2);
    });

    it("should generate different commitments for different values", async function () {
      if (!isCompiled) this.skip();

      const credentialData1 = createCredentialData(CREDIT_SCORE_EXCELLENT, 2);
      const credentialData2 = createCredentialData(CREDIT_SCORE_GOOD, 2);
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
        actualValue: CREDIT_SCORE_EXCELLENT,
        fieldIndex: 2,
        minValue: CREDIT_SCORE_GOOD,
        maxValue: CREDIT_SCORE_MAX,
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
  CREDIT_SCORE_MIN,
  CREDIT_SCORE_MAX,
  CREDIT_SCORE_EXCELLENT,
  CREDIT_SCORE_GOOD,
  CREDIT_SCORE_FAIR,
  CREDIT_SCORE_POOR,
  INCOME_50K,
  INCOME_75K,
  INCOME_100K,
  INCOME_150K,
  MAX_UINT64,
};
