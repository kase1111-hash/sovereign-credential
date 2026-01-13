/**
 * @file CompoundProof.test.ts
 * @description Tests for the CompoundProof ZK circuit
 *
 * Test cases from IMPLEMENTATION_GUIDE.md:
 * - Combine 2 disclosures
 * - Combine 3+ disclosures
 * - Mixed disclosure types
 * - Single disclosure fails, compound fails
 */

import { expect } from "chai";
import * as path from "path";
import * as fs from "fs";
import {
  initCircuit,
  generateProof,
  verifyProof,
  createCommitment,
  expectProofToFail,
  CircuitTest,
} from "./circuitTestUtils";

// Test constants
const NUM_FIELDS = 16;
const TREE_DEPTH = 10;

// Disclosure types (matching circuit constants)
const DISCLOSURE_AGE_THRESHOLD = 0n;
const DISCLOSURE_DATE_RANGE = 1n;
const DISCLOSURE_VALUE_RANGE = 2n;
const DISCLOSURE_SET_MEMBERSHIP = 3n;
const DISCLOSURE_EXISTENCE = 4n;

// Comparison types
const COMPARISON_GREATER_THAN = 0n;
const COMPARISON_LESS_THAN = 1n;

// Seconds per year (matching circuit constant)
const SECONDS_PER_YEAR = 31557600n;

// Test dates
const JAN_1_2000 = 946684800n;  // Unix timestamp for 2000-01-01
const JAN_1_2020 = 1577836800n; // Unix timestamp for 2020-01-01
const JAN_1_2023 = 1672531200n; // Unix timestamp for 2023-01-01
const JAN_1_2025 = 1735689600n; // Unix timestamp for 2025-01-01

/**
 * Helper to create test credential data
 */
function createCredentialData(overrides: Partial<Record<number, bigint>> = {}): bigint[] {
  const data: bigint[] = new Array(NUM_FIELDS).fill(0n);
  // Field 0: birthdate (default: Jan 1, 2000 = age 25 in 2025)
  data[0] = JAN_1_2000;
  // Field 1: issuedAt date
  data[1] = JAN_1_2020;
  // Field 2: expiresAt date
  data[2] = JAN_1_2025 + SECONDS_PER_YEAR * 5n; // 5 years from now
  // Field 3: license class (e.g., 1 = Class A)
  data[3] = 1n;
  // Field 4: state code
  data[4] = 6n; // California
  // Field 5: income
  data[5] = 75000n;
  // Field 6: credit score
  data[6] = 750n;
  // Field 7-15: reserved

  // Apply overrides
  for (const [index, value] of Object.entries(overrides)) {
    data[parseInt(index)] = value;
  }

  return data;
}

/**
 * Helper to create empty Merkle proof inputs
 */
function createEmptyMerkleProofs(numDisclosures: number): {
  merkleProofs: bigint[][];
  merklePathIndices: number[][];
} {
  const merkleProofs: bigint[][] = [];
  const merklePathIndices: number[][] = [];

  for (let i = 0; i < numDisclosures; i++) {
    merkleProofs.push(new Array(TREE_DEPTH).fill(0n));
    merklePathIndices.push(new Array(TREE_DEPTH).fill(0));
  }

  return { merkleProofs, merklePathIndices };
}

/**
 * Create inputs for compound proof with 2 disclosures
 */
async function createCompound2Inputs(params: {
  credentialData: bigint[];
  salt: bigint;
  disclosure1: {
    type: bigint;
    params: [bigint, bigint, bigint, bigint];
    privateValue: bigint;
  };
  disclosure2: {
    type: bigint;
    params: [bigint, bigint, bigint, bigint];
    privateValue: bigint;
  };
}) {
  const commitment = await createCommitment(params.credentialData, params.salt);
  const { merkleProofs, merklePathIndices } = createEmptyMerkleProofs(2);

  return {
    credentialCommitment: commitment,
    disclosureTypes: [params.disclosure1.type, params.disclosure2.type],
    disclosureParams: [
      params.disclosure1.params,
      params.disclosure2.params,
    ],
    credentialData: params.credentialData,
    salt: params.salt,
    privateValues: [params.disclosure1.privateValue, params.disclosure2.privateValue],
    merkleProofs,
    merklePathIndices,
  };
}

describe("CompoundProof Circuit (2 Disclosures)", function () {
  this.timeout(120000); // Compound proofs take longer

  let circuit: CircuitTest;
  let isCompiled: boolean = false;

  before(async function () {
    const wasmPath = path.join(
      __dirname,
      "..",
      "build",
      "CompoundProof_js",
      "CompoundProof.wasm"
    );

    if (!fs.existsSync(wasmPath)) {
      console.log(
        "\n  Skipping CompoundProof tests - circuit not compiled.\n" +
          "  Run: cd circuits && ./compile.sh CompoundProof && ./setup.sh CompoundProof\n"
      );
      isCompiled = false;
    } else {
      try {
        circuit = initCircuit("CompoundProof");
        isCompiled = true;
      } catch (error: any) {
        console.log(`\n  Skipping tests: ${error.message}\n`);
        isCompiled = false;
      }
    }
  });

  describe("Age + DateRange Compound Proof", function () {
    it("should prove age > 18 AND issuedAt in range", async function () {
      if (!isCompiled) this.skip();

      const credentialData = createCredentialData();
      const salt = 12345n;

      const inputs = await createCompound2Inputs({
        credentialData,
        salt,
        disclosure1: {
          // Age > 18
          type: DISCLOSURE_AGE_THRESHOLD,
          params: [18n, JAN_1_2025, COMPARISON_GREATER_THAN, 0n],
          privateValue: credentialData[0], // birthdate
        },
        disclosure2: {
          // IssuedAt in range [2019, 2024]
          type: DISCLOSURE_DATE_RANGE,
          params: [JAN_1_2020 - SECONDS_PER_YEAR, JAN_1_2023, 1n, 0n], // field 1
          privateValue: credentialData[1], // issuedAt
        },
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;

      // Verify public signals
      expect(BigInt(publicSignals[0])).to.equal(inputs.credentialCommitment);
      expect(BigInt(publicSignals[1])).to.equal(DISCLOSURE_AGE_THRESHOLD);
      expect(BigInt(publicSignals[2])).to.equal(DISCLOSURE_DATE_RANGE);
    });

    it("should fail when age check fails", async function () {
      if (!isCompiled) this.skip();

      // Create person who is 17 (fails age > 18)
      const credentialData = createCredentialData({
        0: JAN_1_2025 - (17n * SECONDS_PER_YEAR), // 17 years old
      });
      const salt = 12345n;

      const inputs = await createCompound2Inputs({
        credentialData,
        salt,
        disclosure1: {
          type: DISCLOSURE_AGE_THRESHOLD,
          params: [18n, JAN_1_2025, COMPARISON_GREATER_THAN, 0n],
          privateValue: credentialData[0],
        },
        disclosure2: {
          type: DISCLOSURE_DATE_RANGE,
          params: [JAN_1_2020 - SECONDS_PER_YEAR, JAN_1_2023, 1n, 0n],
          privateValue: credentialData[1],
        },
      });

      await expectProofToFail(circuit, inputs);
    });

    it("should fail when date range check fails", async function () {
      if (!isCompiled) this.skip();

      // Date is outside range
      const credentialData = createCredentialData({
        1: JAN_1_2025, // Too late - outside range
      });
      const salt = 12345n;

      const inputs = await createCompound2Inputs({
        credentialData,
        salt,
        disclosure1: {
          type: DISCLOSURE_AGE_THRESHOLD,
          params: [18n, JAN_1_2025, COMPARISON_GREATER_THAN, 0n],
          privateValue: credentialData[0],
        },
        disclosure2: {
          type: DISCLOSURE_DATE_RANGE,
          params: [JAN_1_2020 - SECONDS_PER_YEAR, JAN_1_2023, 1n, 0n],
          privateValue: credentialData[1], // This is outside range
        },
      });

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Age + ValueRange Compound Proof", function () {
    it("should prove age > 21 AND income in range", async function () {
      if (!isCompiled) this.skip();

      const credentialData = createCredentialData();
      const salt = 12345n;

      const inputs = await createCompound2Inputs({
        credentialData,
        salt,
        disclosure1: {
          type: DISCLOSURE_AGE_THRESHOLD,
          params: [21n, JAN_1_2025, COMPARISON_GREATER_THAN, 0n],
          privateValue: credentialData[0],
        },
        disclosure2: {
          // Income in range [50000, 100000]
          type: DISCLOSURE_VALUE_RANGE,
          params: [50000n, 100000n, 5n, 0n], // field 5 = income
          privateValue: credentialData[5], // income = 75000
        },
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove age < 65 AND credit score >= 700", async function () {
      if (!isCompiled) this.skip();

      const credentialData = createCredentialData();
      const salt = 12345n;

      const inputs = await createCompound2Inputs({
        credentialData,
        salt,
        disclosure1: {
          type: DISCLOSURE_AGE_THRESHOLD,
          params: [65n, JAN_1_2025, COMPARISON_LESS_THAN, 0n],
          privateValue: credentialData[0],
        },
        disclosure2: {
          // Credit score in range [700, MAX]
          type: DISCLOSURE_VALUE_RANGE,
          params: [700n, 850n, 6n, 0n], // field 6 = credit score
          privateValue: credentialData[6], // credit = 750
        },
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should fail when income outside range", async function () {
      if (!isCompiled) this.skip();

      const credentialData = createCredentialData({
        5: 30000n, // Income too low
      });
      const salt = 12345n;

      const inputs = await createCompound2Inputs({
        credentialData,
        salt,
        disclosure1: {
          type: DISCLOSURE_AGE_THRESHOLD,
          params: [21n, JAN_1_2025, COMPARISON_GREATER_THAN, 0n],
          privateValue: credentialData[0],
        },
        disclosure2: {
          type: DISCLOSURE_VALUE_RANGE,
          params: [50000n, 100000n, 5n, 0n],
          privateValue: credentialData[5], // 30000 < 50000
        },
      });

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Two ValueRange Disclosures", function () {
    it("should prove income AND credit score in ranges", async function () {
      if (!isCompiled) this.skip();

      const credentialData = createCredentialData();
      const salt = 12345n;

      const inputs = await createCompound2Inputs({
        credentialData,
        salt,
        disclosure1: {
          type: DISCLOSURE_VALUE_RANGE,
          params: [50000n, 100000n, 5n, 0n], // income
          privateValue: credentialData[5],
        },
        disclosure2: {
          type: DISCLOSURE_VALUE_RANGE,
          params: [700n, 850n, 6n, 0n], // credit
          privateValue: credentialData[6],
        },
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Age + Existence Compound Proof", function () {
    it("should prove age > 18 AND credential exists", async function () {
      if (!isCompiled) this.skip();

      const credentialData = createCredentialData();
      const salt = 12345n;

      const inputs = await createCompound2Inputs({
        credentialData,
        salt,
        disclosure1: {
          type: DISCLOSURE_AGE_THRESHOLD,
          params: [18n, JAN_1_2025, COMPARISON_GREATER_THAN, 0n],
          privateValue: credentialData[0],
        },
        disclosure2: {
          type: DISCLOSURE_EXISTENCE,
          params: [0n, 0n, 0n, 0n], // Existence doesn't use params
          privateValue: 0n,
        },
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Commitment Verification", function () {
    it("should fail with wrong commitment", async function () {
      if (!isCompiled) this.skip();

      const credentialData = createCredentialData();
      const salt = 12345n;

      const inputs = await createCompound2Inputs({
        credentialData,
        salt,
        disclosure1: {
          type: DISCLOSURE_AGE_THRESHOLD,
          params: [18n, JAN_1_2025, COMPARISON_GREATER_THAN, 0n],
          privateValue: credentialData[0],
        },
        disclosure2: {
          type: DISCLOSURE_EXISTENCE,
          params: [0n, 0n, 0n, 0n],
          privateValue: 0n,
        },
      });

      // Corrupt commitment
      inputs.credentialCommitment = 12345678901234567890n;

      await expectProofToFail(circuit, inputs);
    });

    it("should fail with wrong salt", async function () {
      if (!isCompiled) this.skip();

      const credentialData = createCredentialData();
      const salt = 12345n;

      const inputs = await createCompound2Inputs({
        credentialData,
        salt,
        disclosure1: {
          type: DISCLOSURE_AGE_THRESHOLD,
          params: [18n, JAN_1_2025, COMPARISON_GREATER_THAN, 0n],
          privateValue: credentialData[0],
        },
        disclosure2: {
          type: DISCLOSURE_EXISTENCE,
          params: [0n, 0n, 0n, 0n],
          privateValue: 0n,
        },
      });

      // Use wrong salt
      inputs.salt = 99999n;

      await expectProofToFail(circuit, inputs);
    });

    it("should fail with mismatched private value", async function () {
      if (!isCompiled) this.skip();

      const credentialData = createCredentialData();
      const salt = 12345n;

      const inputs = await createCompound2Inputs({
        credentialData,
        salt,
        disclosure1: {
          type: DISCLOSURE_AGE_THRESHOLD,
          params: [18n, JAN_1_2025, COMPARISON_GREATER_THAN, 0n],
          privateValue: JAN_1_2000 + 1000n, // Wrong birthdate
        },
        disclosure2: {
          type: DISCLOSURE_EXISTENCE,
          params: [0n, 0n, 0n, 0n],
          privateValue: 0n,
        },
      });

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Edge Cases", function () {
    it("should handle boundary values correctly", async function () {
      if (!isCompiled) this.skip();

      // Person exactly 18 years old
      const birthdate = JAN_1_2025 - (18n * SECONDS_PER_YEAR);
      const credentialData = createCredentialData({ 0: birthdate });
      const salt = 12345n;

      const inputs = await createCompound2Inputs({
        credentialData,
        salt,
        disclosure1: {
          // age > 17 (should pass for 18-year-old)
          type: DISCLOSURE_AGE_THRESHOLD,
          params: [17n, JAN_1_2025, COMPARISON_GREATER_THAN, 0n],
          privateValue: credentialData[0],
        },
        disclosure2: {
          // Income exactly at min boundary
          type: DISCLOSURE_VALUE_RANGE,
          params: [75000n, 75000n, 5n, 0n], // Exact match
          privateValue: credentialData[5],
        },
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should fail at exact age threshold", async function () {
      if (!isCompiled) this.skip();

      // Person exactly 18 years old
      const birthdate = JAN_1_2025 - (18n * SECONDS_PER_YEAR);
      const credentialData = createCredentialData({ 0: birthdate });
      const salt = 12345n;

      const inputs = await createCompound2Inputs({
        credentialData,
        salt,
        disclosure1: {
          // age > 18 (should fail for exactly 18-year-old)
          type: DISCLOSURE_AGE_THRESHOLD,
          params: [18n, JAN_1_2025, COMPARISON_GREATER_THAN, 0n],
          privateValue: credentialData[0],
        },
        disclosure2: {
          type: DISCLOSURE_EXISTENCE,
          params: [0n, 0n, 0n, 0n],
          privateValue: 0n,
        },
      });

      await expectProofToFail(circuit, inputs);
    });
  });
});

describe("CompoundProof3 Circuit (3 Disclosures)", function () {
  this.timeout(180000);

  let circuit: CircuitTest;
  let isCompiled: boolean = false;

  before(async function () {
    const wasmPath = path.join(
      __dirname,
      "..",
      "build",
      "CompoundProof3_js",
      "CompoundProof3.wasm"
    );

    if (!fs.existsSync(wasmPath)) {
      console.log(
        "\n  Skipping CompoundProof3 tests - circuit not compiled.\n" +
          "  Run: cd circuits && ./compile.sh CompoundProof3 && ./setup.sh CompoundProof3\n"
      );
      isCompiled = false;
    } else {
      try {
        circuit = initCircuit("CompoundProof3");
        isCompiled = true;
      } catch (error: any) {
        console.log(`\n  Skipping tests: ${error.message}\n`);
        isCompiled = false;
      }
    }
  });

  it("should prove age + date range + value range", async function () {
    if (!isCompiled) this.skip();

    const credentialData = createCredentialData();
    const salt = 12345n;
    const commitment = await createCommitment(credentialData, salt);
    const { merkleProofs, merklePathIndices } = createEmptyMerkleProofs(3);

    const inputs = {
      credentialCommitment: commitment,
      disclosureTypes: [
        DISCLOSURE_AGE_THRESHOLD,
        DISCLOSURE_DATE_RANGE,
        DISCLOSURE_VALUE_RANGE,
      ],
      disclosureParams: [
        [18n, JAN_1_2025, COMPARISON_GREATER_THAN, 0n],
        [JAN_1_2020 - SECONDS_PER_YEAR, JAN_1_2023, 1n, 0n],
        [50000n, 100000n, 5n, 0n],
      ],
      credentialData,
      salt,
      privateValues: [credentialData[0], credentialData[1], credentialData[5]],
      merkleProofs,
      merklePathIndices,
    };

    const { proof, publicSignals } = await generateProof(circuit, inputs);
    const isValid = await verifyProof(circuit, proof, publicSignals);
    expect(isValid).to.be.true;
  });

  it("should fail when any one disclosure fails", async function () {
    if (!isCompiled) this.skip();

    const credentialData = createCredentialData({
      5: 30000n, // Income too low
    });
    const salt = 12345n;
    const commitment = await createCommitment(credentialData, salt);
    const { merkleProofs, merklePathIndices } = createEmptyMerkleProofs(3);

    const inputs = {
      credentialCommitment: commitment,
      disclosureTypes: [
        DISCLOSURE_AGE_THRESHOLD, // Will pass
        DISCLOSURE_DATE_RANGE,   // Will pass
        DISCLOSURE_VALUE_RANGE,  // Will fail
      ],
      disclosureParams: [
        [18n, JAN_1_2025, COMPARISON_GREATER_THAN, 0n],
        [JAN_1_2020 - SECONDS_PER_YEAR, JAN_1_2023, 1n, 0n],
        [50000n, 100000n, 5n, 0n], // 30000 is outside range
      ],
      credentialData,
      salt,
      privateValues: [credentialData[0], credentialData[1], credentialData[5]],
      merkleProofs,
      merklePathIndices,
    };

    await expectProofToFail(circuit, inputs);
  });
});

// Export helpers for other tests
export {
  createCredentialData,
  createEmptyMerkleProofs,
  createCompound2Inputs,
  DISCLOSURE_AGE_THRESHOLD,
  DISCLOSURE_DATE_RANGE,
  DISCLOSURE_VALUE_RANGE,
  DISCLOSURE_SET_MEMBERSHIP,
  DISCLOSURE_EXISTENCE,
  COMPARISON_GREATER_THAN,
  COMPARISON_LESS_THAN,
  JAN_1_2000,
  JAN_1_2020,
  JAN_1_2023,
  JAN_1_2025,
  SECONDS_PER_YEAR,
  NUM_FIELDS,
  TREE_DEPTH,
};
