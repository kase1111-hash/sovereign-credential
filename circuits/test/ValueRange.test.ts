/**
 * @file ValueRange.test.ts
 * @description Tests for the ValueRange ZK circuit
 *
 * Test cases from IMPLEMENTATION_GUIDE.md:
 * - Value within range passes
 * - Value below minimum fails
 * - Value above maximum fails
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

// Field indices for different credential types
const CREDIT_SCORE_FIELD = 3n;
const INCOME_FIELD = 4n;
const AGE_FIELD = 0n;
const BALANCE_FIELD = 6n;

/**
 * Helper to create test credential data with values
 */
function createCredentialData(values: { [fieldIndex: number]: bigint }): bigint[] {
  const data: bigint[] = new Array(NUM_FIELDS).fill(0n);
  for (const [index, value] of Object.entries(values)) {
    data[parseInt(index)] = value;
  }
  return data;
}

/**
 * Helper to create test inputs for ValueRange circuit
 */
async function createTestInputs(params: {
  actualValue: bigint;
  fieldIndex: bigint;
  minValue: bigint;
  maxValue: bigint;
  salt?: bigint;
}) {
  const salt = params.salt ?? 12345n;
  const credentialData = createCredentialData({
    [Number(params.fieldIndex)]: params.actualValue,
  });
  const commitment = await createCommitment(credentialData, salt);

  return {
    credentialCommitment: commitment,
    minValue: params.minValue,
    maxValue: params.maxValue,
    fieldIndex: params.fieldIndex,
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

  describe("Valid Value Range Proofs", function () {
    it("should prove credit score within range (middle of range)", async function () {
      if (!isCompiled) this.skip();

      // Credit score 750, proving it's between 700-850
      const inputs = await createTestInputs({
        actualValue: 750n,
        fieldIndex: CREDIT_SCORE_FIELD,
        minValue: 700n,
        maxValue: 850n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);

      // Verify proof
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;

      // Verify public signals are correct
      expect(BigInt(publicSignals[0])).to.equal(inputs.credentialCommitment);
      expect(BigInt(publicSignals[1])).to.equal(700n); // minValue
      expect(BigInt(publicSignals[2])).to.equal(850n); // maxValue
      expect(BigInt(publicSignals[3])).to.equal(CREDIT_SCORE_FIELD); // fieldIndex
    });

    it("should prove value at exact minimum (boundary)", async function () {
      if (!isCompiled) this.skip();

      // Value exactly at minimum
      const inputs = await createTestInputs({
        actualValue: 700n,
        fieldIndex: CREDIT_SCORE_FIELD,
        minValue: 700n,
        maxValue: 850n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove value at exact maximum (boundary)", async function () {
      if (!isCompiled) this.skip();

      // Value exactly at maximum
      const inputs = await createTestInputs({
        actualValue: 850n,
        fieldIndex: CREDIT_SCORE_FIELD,
        minValue: 700n,
        maxValue: 850n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove with single-point range (min == max)", async function () {
      if (!isCompiled) this.skip();

      // Range is a single point
      const inputs = await createTestInputs({
        actualValue: 750n,
        fieldIndex: CREDIT_SCORE_FIELD,
        minValue: 750n,
        maxValue: 750n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove income within range", async function () {
      if (!isCompiled) this.skip();

      // Income $75,000, proving it's between $50,000-$100,000
      const inputs = await createTestInputs({
        actualValue: 75000n,
        fieldIndex: INCOME_FIELD,
        minValue: 50000n,
        maxValue: 100000n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should work with different field indices", async function () {
      if (!isCompiled) this.skip();

      // Use balance field
      const inputs = await createTestInputs({
        actualValue: 10000n,
        fieldIndex: BALANCE_FIELD,
        minValue: 1000n,
        maxValue: 1000000n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Invalid Value Range Proofs (Should Fail)", function () {
    it("should fail when value is below minimum", async function () {
      if (!isCompiled) this.skip();

      // Credit score 650, trying to prove >= 700
      const inputs = await createTestInputs({
        actualValue: 650n,
        fieldIndex: CREDIT_SCORE_FIELD,
        minValue: 700n,
        maxValue: 850n,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail when value is above maximum", async function () {
      if (!isCompiled) this.skip();

      // Credit score 900, trying to prove <= 850
      const inputs = await createTestInputs({
        actualValue: 900n,
        fieldIndex: CREDIT_SCORE_FIELD,
        minValue: 700n,
        maxValue: 850n,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail when value is 1 below minimum", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 699n,
        fieldIndex: CREDIT_SCORE_FIELD,
        minValue: 700n,
        maxValue: 850n,
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail when value is 1 above maximum", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 851n,
        fieldIndex: CREDIT_SCORE_FIELD,
        minValue: 700n,
        maxValue: 850n,
      });

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Invalid Commitment", function () {
    it("should reject proof with wrong commitment", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 750n,
        fieldIndex: CREDIT_SCORE_FIELD,
        minValue: 700n,
        maxValue: 850n,
      });

      // Use wrong commitment
      inputs.credentialCommitment = 12345678901234567890n;

      await expectProofToFail(circuit, inputs);
    });

    it("should reject proof with mismatched value in credential", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 750n,
        fieldIndex: CREDIT_SCORE_FIELD,
        minValue: 700n,
        maxValue: 850n,
      });

      // Change actualValue input but not credential data
      inputs.actualValue = 800n;

      await expectProofToFail(circuit, inputs);
    });

    it("should reject proof with wrong salt", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 750n,
        fieldIndex: CREDIT_SCORE_FIELD,
        minValue: 700n,
        maxValue: 850n,
        salt: 12345n,
      });

      // Change salt without updating commitment
      inputs.salt = 99999n;

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Edge Cases", function () {
    it("should handle value of 0", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 0n,
        fieldIndex: BALANCE_FIELD,
        minValue: 0n,
        maxValue: 1000n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle very large values", async function () {
      if (!isCompiled) this.skip();

      // Large value (1 trillion)
      const largeValue = 1000000000000n;

      const inputs = await createTestInputs({
        actualValue: largeValue,
        fieldIndex: BALANCE_FIELD,
        minValue: largeValue - 1000n,
        maxValue: largeValue + 1000n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should work with field index 0", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 25n,
        fieldIndex: 0n,
        minValue: 18n,
        maxValue: 65n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should work with last field index (15)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 100n,
        fieldIndex: 15n,
        minValue: 50n,
        maxValue: 150n,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle range from 0 to max uint64 approximation", async function () {
      if (!isCompiled) this.skip();

      // Near max 64-bit value
      const maxValue = (1n << 63n) - 1n; // Max safe 63-bit value

      const inputs = await createTestInputs({
        actualValue: 12345678n,
        fieldIndex: BALANCE_FIELD,
        minValue: 0n,
        maxValue: maxValue,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Multiple Fields in Same Credential", function () {
    it("should prove range for specific field with multiple populated fields", async function () {
      if (!isCompiled) this.skip();

      const salt = 12345n;
      const credentialData = createCredentialData({
        0: 30n,           // age
        3: 750n,          // credit score (target)
        4: 75000n,        // income
        6: 10000n,        // balance
      });
      const commitment = await createCommitment(credentialData, salt);

      const inputs = {
        credentialCommitment: commitment,
        minValue: 700n,
        maxValue: 850n,
        fieldIndex: CREDIT_SCORE_FIELD,
        actualValue: 750n,
        credentialData: credentialData,
        salt: salt,
      };

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Solidity Calldata Generation", function () {
    it("should generate valid Solidity calldata", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        actualValue: 750n,
        fieldIndex: CREDIT_SCORE_FIELD,
        minValue: 700n,
        maxValue: 850n,
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
  CREDIT_SCORE_FIELD,
  INCOME_FIELD,
  AGE_FIELD,
  BALANCE_FIELD,
};
