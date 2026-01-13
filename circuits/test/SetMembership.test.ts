/**
 * @file SetMembership.test.ts
 * @description Tests for the SetMembership ZK circuit
 *
 * Test cases from IMPLEMENTATION_GUIDE.md:
 * - Value in set passes
 * - Value not in set fails
 * - Different tree depths work
 * - Large sets (1000+ elements)
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
import {
  MerkleTree,
  formatProofForCircuit,
} from "../../utils/merkleTree";

// Test constants
const NUM_FIELDS = 16;
const TREE_DEPTH = 10; // Matches the circuit's default depth

// Example set values (e.g., allowed license classes)
const LICENSE_CLASS_A = 1n;
const LICENSE_CLASS_B = 2n;
const LICENSE_CLASS_C = 3n;
const LICENSE_CLASS_D = 4n;
const LICENSE_CLASS_E = 5n;

// Allowed license classes for a particular verification
const ALLOWED_LICENSES = [
  LICENSE_CLASS_A,
  LICENSE_CLASS_B,
  LICENSE_CLASS_C,
];

// Country codes (for citizenship verification example)
const COUNTRY_USA = 840n;
const COUNTRY_CANADA = 124n;
const COUNTRY_UK = 826n;
const COUNTRY_GERMANY = 276n;
const COUNTRY_FRANCE = 250n;

/**
 * Helper to create test credential data with a value at a specific field
 */
function createCredentialData(value: bigint, fieldIndex: number = 1): bigint[] {
  const data: bigint[] = new Array(NUM_FIELDS).fill(0n);
  data[fieldIndex] = value;
  return data;
}

/**
 * Helper to create test inputs for SetMembership circuit
 */
async function createTestInputs(params: {
  value: bigint;
  allowedValues: bigint[];
  fieldIndex: number;
  treeDepth?: number;
  salt?: bigint;
}) {
  const salt = params.salt ?? 12345n;
  const treeDepth = params.treeDepth ?? TREE_DEPTH;
  const credentialData = createCredentialData(params.value, params.fieldIndex);
  const commitment = await createCommitment(credentialData, salt);

  // Build Merkle tree
  const tree = await MerkleTree.build(params.allowedValues, treeDepth);
  const proof = tree.getProofByValue(params.value);

  if (!proof) {
    throw new Error(`Value ${params.value} not in allowed set`);
  }

  const formattedProof = formatProofForCircuit(proof);

  return {
    credentialCommitment: commitment,
    setRoot: tree.getRoot(),
    fieldIndex: BigInt(params.fieldIndex),
    actualValue: params.value,
    merkleProof: formattedProof.merkleProof,
    merklePathIndices: formattedProof.merklePathIndices,
    credentialData: credentialData,
    salt: salt,
  };
}

/**
 * Helper to create inputs where value is NOT in the set
 * Creates a valid-looking proof but with wrong value
 * Note: Prefixed with _ as it's reserved for future use
 */
async function _createInvalidTestInputs(params: {
  value: bigint; // Value that's actually in credential
  fakeValue: bigint; // Value we'll claim is in set (but isn't in credential)
  allowedValues: bigint[];
  fieldIndex: number;
  salt?: bigint;
}) {
  const salt = params.salt ?? 12345n;
  const credentialData = createCredentialData(params.value, params.fieldIndex);
  const commitment = await createCommitment(credentialData, salt);

  // Build Merkle tree
  const tree = await MerkleTree.build(params.allowedValues, TREE_DEPTH);

  // Try to get proof for fake value (if it's in the set)
  const proof = tree.getProofByValue(params.fakeValue);

  if (proof) {
    const formattedProof = formatProofForCircuit(proof);
    return {
      credentialCommitment: commitment,
      setRoot: tree.getRoot(),
      fieldIndex: BigInt(params.fieldIndex),
      actualValue: params.fakeValue, // This won't match credential data
      merkleProof: formattedProof.merkleProof,
      merklePathIndices: formattedProof.merklePathIndices,
      credentialData: credentialData,
      salt: salt,
    };
  }

  // If fake value isn't in set, use first valid value's proof
  const validProof = tree.getProof(0);
  const formattedProof = formatProofForCircuit(validProof);

  return {
    credentialCommitment: commitment,
    setRoot: tree.getRoot(),
    fieldIndex: BigInt(params.fieldIndex),
    actualValue: params.value, // Real value, but tree doesn't contain it
    merkleProof: formattedProof.merkleProof,
    merklePathIndices: formattedProof.merklePathIndices,
    credentialData: credentialData,
    salt: salt,
  };
}

describe("SetMembership Circuit", function () {
  // Increase timeout for proof generation
  this.timeout(120000);

  let circuit: CircuitTest;
  let isCompiled: boolean = false;

  before(async function () {
    // Check if circuit is compiled
    const wasmPath = path.join(
      __dirname,
      "..",
      "build",
      "SetMembership_js",
      "SetMembership.wasm"
    );

    if (!fs.existsSync(wasmPath)) {
      console.log(
        "\n  Skipping SetMembership tests - circuit not compiled.\n" +
          "  Run: cd circuits && ./compile.sh SetMembership && ./setup.sh SetMembership\n"
      );
      isCompiled = false;
    } else {
      try {
        circuit = initCircuit("SetMembership");
        isCompiled = true;
      } catch (error: any) {
        console.log(`\n  Skipping tests: ${error.message}\n`);
        isCompiled = false;
      }
    }
  });

  describe("MerkleTree Utility", function () {
    it("should build a tree and compute correct root", async function () {
      const values = [1n, 2n, 3n, 4n];
      const tree = await MerkleTree.build(values, 3);

      expect(tree.getRoot()).to.not.equal(0n);
      expect(tree.getValueCount()).to.equal(4);
      expect(tree.getDepth()).to.equal(3);
    });

    it("should generate and verify proofs", async function () {
      const values = [10n, 20n, 30n, 40n];
      const tree = await MerkleTree.build(values, 4);

      for (let i = 0; i < values.length; i++) {
        const proof = tree.getProof(i);
        const isValid = await tree.verifyProof(proof);
        expect(isValid).to.be.true;
        expect(proof.leaf).to.equal(values[i]);
      }
    });

    it("should find proofs by value", async function () {
      const values = [100n, 200n, 300n];
      const tree = await MerkleTree.build(values, 3);

      const proof = tree.getProofByValue(200n);
      expect(proof).to.not.be.null;
      expect(proof!.leaf).to.equal(200n);
      expect(proof!.leafIndex).to.equal(1);
    });

    it("should return null for missing values", async function () {
      const values = [1n, 2n, 3n];
      const tree = await MerkleTree.build(values, 3);

      const proof = tree.getProofByValue(999n);
      expect(proof).to.be.null;
    });

    it("should handle single-element trees", async function () {
      const tree = await MerkleTree.build([42n], 3);
      const proof = tree.getProof(0);
      const isValid = await tree.verifyProof(proof);
      expect(isValid).to.be.true;
    });

    it("should produce consistent roots for same inputs", async function () {
      const values = [5n, 10n, 15n];
      const tree1 = await MerkleTree.build(values, 4);
      const tree2 = await MerkleTree.build(values, 4);

      expect(tree1.getRoot()).to.equal(tree2.getRoot());
    });
  });

  describe("Valid Set Membership Proofs", function () {
    it("should prove value is in allowed set (first element)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: LICENSE_CLASS_A,
        allowedValues: ALLOWED_LICENSES,
        fieldIndex: 1,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;

      // Verify public signals
      expect(BigInt(publicSignals[0])).to.equal(inputs.credentialCommitment);
      expect(BigInt(publicSignals[1])).to.equal(inputs.setRoot);
      expect(BigInt(publicSignals[2])).to.equal(1n); // fieldIndex
    });

    it("should prove value is in allowed set (middle element)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: LICENSE_CLASS_B,
        allowedValues: ALLOWED_LICENSES,
        fieldIndex: 1,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove value is in allowed set (last element)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: LICENSE_CLASS_C,
        allowedValues: ALLOWED_LICENSES,
        fieldIndex: 1,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove country citizenship in allowed set", async function () {
      if (!isCompiled) this.skip();

      const allowedCountries = [COUNTRY_USA, COUNTRY_CANADA, COUNTRY_UK];

      const inputs = await createTestInputs({
        value: COUNTRY_CANADA,
        allowedValues: allowedCountries,
        fieldIndex: 2, // Citizenship field
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove with different field indices", async function () {
      if (!isCompiled) this.skip();

      // Test with value in field 5
      const inputs = await createTestInputs({
        value: LICENSE_CLASS_A,
        allowedValues: ALLOWED_LICENSES,
        fieldIndex: 5,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should prove with single-element set", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: 42n,
        allowedValues: [42n],
        fieldIndex: 1,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Invalid Set Membership Proofs (Should Fail)", function () {
    it("should fail when value is not in allowed set", async function () {
      if (!isCompiled) this.skip();

      // Credential has LICENSE_CLASS_D, but it's not in allowed set
      const salt = 12345n;
      const credentialData = createCredentialData(LICENSE_CLASS_D, 1);
      const commitment = await createCommitment(credentialData, salt);

      // Build tree with allowed values
      const tree = await MerkleTree.build(ALLOWED_LICENSES, TREE_DEPTH);

      // Get proof for first allowed value (won't match credential)
      const validProof = tree.getProof(0);
      const formattedProof = formatProofForCircuit(validProof);

      const inputs = {
        credentialCommitment: commitment,
        setRoot: tree.getRoot(),
        fieldIndex: 1n,
        actualValue: LICENSE_CLASS_D, // This is not in the tree!
        merkleProof: formattedProof.merkleProof,
        merklePathIndices: formattedProof.merklePathIndices,
        credentialData: credentialData,
        salt: salt,
      };

      await expectProofToFail(circuit, inputs);
    });

    it("should fail when actualValue doesn't match credential field", async function () {
      if (!isCompiled) this.skip();

      // Create credential with one value but claim another
      const salt = 12345n;
      const credentialData = createCredentialData(LICENSE_CLASS_D, 1); // D in credential
      const commitment = await createCommitment(credentialData, salt);

      // Build tree including A (which we'll claim to have)
      const tree = await MerkleTree.build(ALLOWED_LICENSES, TREE_DEPTH);
      const proof = tree.getProof(0); // Proof for LICENSE_CLASS_A
      const formattedProof = formatProofForCircuit(proof);

      const inputs = {
        credentialCommitment: commitment,
        setRoot: tree.getRoot(),
        fieldIndex: 1n,
        actualValue: LICENSE_CLASS_A, // Claiming A, but credential has D
        merkleProof: formattedProof.merkleProof,
        merklePathIndices: formattedProof.merklePathIndices,
        credentialData: credentialData,
        salt: salt,
      };

      await expectProofToFail(circuit, inputs);
    });

    it("should fail with wrong Merkle proof", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: LICENSE_CLASS_A,
        allowedValues: ALLOWED_LICENSES,
        fieldIndex: 1,
      });

      // Corrupt the Merkle proof
      inputs.merkleProof[0] = 999999n;

      await expectProofToFail(circuit, inputs);
    });

    it("should fail with wrong path indices", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: LICENSE_CLASS_A,
        allowedValues: ALLOWED_LICENSES,
        fieldIndex: 1,
      });

      // Flip all path indices
      inputs.merklePathIndices = inputs.merklePathIndices.map((i) =>
        i === 0n ? 1n : 0n
      );

      await expectProofToFail(circuit, inputs);
    });

    it("should fail with wrong set root", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: LICENSE_CLASS_A,
        allowedValues: ALLOWED_LICENSES,
        fieldIndex: 1,
      });

      // Use wrong root
      inputs.setRoot = 12345678901234567890n;

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Invalid Commitment", function () {
    it("should reject proof with wrong commitment", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: LICENSE_CLASS_A,
        allowedValues: ALLOWED_LICENSES,
        fieldIndex: 1,
      });

      inputs.credentialCommitment = 12345678901234567890n;

      await expectProofToFail(circuit, inputs);
    });

    it("should reject proof with wrong salt", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: LICENSE_CLASS_A,
        allowedValues: ALLOWED_LICENSES,
        fieldIndex: 1,
        salt: 12345n,
      });

      inputs.salt = 99999n;

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Invalid Field Index", function () {
    it("should reject proof with wrong field index", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: LICENSE_CLASS_A,
        allowedValues: ALLOWED_LICENSES,
        fieldIndex: 1,
      });

      // Claim value is in field 2 when it's actually in field 1
      inputs.fieldIndex = 2n;

      await expectProofToFail(circuit, inputs);
    });
  });

  describe("Edge Cases", function () {
    it("should handle value 0", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: 0n,
        allowedValues: [0n, 1n, 2n],
        fieldIndex: 1,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle large values", async function () {
      if (!isCompiled) this.skip();

      const largeValue = BigInt(2) ** BigInt(200); // Very large number

      const inputs = await createTestInputs({
        value: largeValue,
        allowedValues: [largeValue, 1n, 2n],
        fieldIndex: 1,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle first field (index 0)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: LICENSE_CLASS_A,
        allowedValues: ALLOWED_LICENSES,
        fieldIndex: 0,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle last field (index 15)", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: LICENSE_CLASS_A,
        allowedValues: ALLOWED_LICENSES,
        fieldIndex: 15,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Large Sets", function () {
    it("should handle set with 100 elements", async function () {
      if (!isCompiled) this.skip();

      // Generate 100 values
      const allowedValues = Array.from({ length: 100 }, (_, i) => BigInt(i + 1));
      const testValue = 50n; // Middle of the set

      const inputs = await createTestInputs({
        value: testValue,
        allowedValues: allowedValues,
        fieldIndex: 1,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle set with 500 elements", async function () {
      if (!isCompiled) this.skip();

      // Generate 500 values
      const allowedValues = Array.from({ length: 500 }, (_, i) => BigInt(i + 1));
      const testValue = 250n;

      const inputs = await createTestInputs({
        value: testValue,
        allowedValues: allowedValues,
        fieldIndex: 1,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("should handle set with 1000 elements", async function () {
      if (!isCompiled) this.skip();

      // Generate 1000 values (approaching max for depth 10)
      const allowedValues = Array.from({ length: 1000 }, (_, i) => BigInt(i + 1));
      const testValue = 999n;

      const inputs = await createTestInputs({
        value: testValue,
        allowedValues: allowedValues,
        fieldIndex: 1,
      });

      const { proof, publicSignals } = await generateProof(circuit, inputs);
      const isValid = await verifyProof(circuit, proof, publicSignals);
      expect(isValid).to.be.true;
    });
  });

  describe("Deterministic Behavior", function () {
    it("should generate same commitment for same inputs", async function () {
      const credentialData = createCredentialData(LICENSE_CLASS_A, 1);
      const salt = 12345n;

      const commitment1 = await createCommitment(credentialData, salt);
      const commitment2 = await createCommitment(credentialData, salt);

      expect(commitment1).to.equal(commitment2);
    });

    it("should generate same tree root for same set", async function () {
      const values = [1n, 2n, 3n, 4n, 5n];

      const tree1 = await MerkleTree.build(values, TREE_DEPTH);
      const tree2 = await MerkleTree.build(values, TREE_DEPTH);

      expect(tree1.getRoot()).to.equal(tree2.getRoot());
    });

    it("should generate different roots for different sets", async function () {
      const values1 = [1n, 2n, 3n];
      const values2 = [1n, 2n, 4n]; // Different last element

      const tree1 = await MerkleTree.build(values1, TREE_DEPTH);
      const tree2 = await MerkleTree.build(values2, TREE_DEPTH);

      expect(tree1.getRoot()).to.not.equal(tree2.getRoot());
    });

    it("should generate different roots for different order", async function () {
      const values1 = [1n, 2n, 3n];
      const values2 = [3n, 2n, 1n]; // Same values, different order

      const tree1 = await MerkleTree.build(values1, TREE_DEPTH);
      const tree2 = await MerkleTree.build(values2, TREE_DEPTH);

      expect(tree1.getRoot()).to.not.equal(tree2.getRoot());
    });
  });

  describe("Solidity Calldata Generation", function () {
    it("should generate valid Solidity calldata", async function () {
      if (!isCompiled) this.skip();

      const inputs = await createTestInputs({
        value: LICENSE_CLASS_A,
        allowedValues: ALLOWED_LICENSES,
        fieldIndex: 1,
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
      expect(parsed.inputs).to.have.length(3); // 3 public inputs
    });
  });
});

// Export helpers for use in other tests
export {
  createCredentialData,
  createTestInputs,
  NUM_FIELDS,
  TREE_DEPTH,
  LICENSE_CLASS_A,
  LICENSE_CLASS_B,
  LICENSE_CLASS_C,
  LICENSE_CLASS_D,
  LICENSE_CLASS_E,
  ALLOWED_LICENSES,
  COUNTRY_USA,
  COUNTRY_CANADA,
  COUNTRY_UK,
  COUNTRY_GERMANY,
  COUNTRY_FRANCE,
};
