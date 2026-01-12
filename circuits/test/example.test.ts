/**
 * @file example.test.ts
 * @description Example circuit test demonstrating test utilities usage
 * @dev This file shows how to write circuit tests - actual tests will be added in Steps 11-13
 */

import { expect } from "chai";
import {
  initCircuit,
  generateProof,
  verifyProof,
  generateCalldata,
  parseCalldata,
  poseidonHash,
  createCommitment,
  toFieldElement,
  toTimestamp,
  calculateAge,
} from "./circuitTestUtils";

describe("Circuit Test Utilities", function () {
  // These tests verify the test utilities work correctly
  // Actual circuit tests will be added in Steps 11-13

  describe("Utility Functions", function () {
    it("should convert numbers to field elements", function () {
      const result = toFieldElement(100);
      expect(result).to.equal(100n);

      // Negative numbers should wrap
      const negative = toFieldElement(-1);
      expect(negative).to.be.gt(0n);
    });

    it("should convert dates to timestamps", function () {
      const date = new Date("2000-01-01T00:00:00Z");
      const timestamp = toTimestamp(date);
      expect(timestamp).to.equal(946684800n);

      // Also accept raw numbers
      const raw = toTimestamp(1000000);
      expect(raw).to.equal(1000000n);
    });

    it("should calculate age correctly", function () {
      // Born Jan 1, 2000
      const birthdate = 946684800n; // 2000-01-01
      // Current: Jan 1, 2025
      const currentTime = 1735689600n; // 2025-01-01

      const age = calculateAge(birthdate, currentTime);
      expect(age).to.equal(25n);
    });

    it("should handle age calculation for young person", function () {
      // Born Jan 1, 2020
      const birthdate = 1577836800n; // 2020-01-01
      // Current: Jan 1, 2025
      const currentTime = 1735689600n; // 2025-01-01

      const age = calculateAge(birthdate, currentTime);
      expect(age).to.equal(5n);
    });
  });

  describe("Poseidon Hash", function () {
    it("should compute Poseidon hash", async function () {
      // This test requires snarkjs to be installed
      // Skip if not available
      try {
        const hash = await poseidonHash([1n, 2n, 3n]);
        expect(hash).to.be.a("bigint");
        expect(hash).to.be.gt(0n);
      } catch (error: any) {
        if (error.message.includes("Cannot find module")) {
          console.log("Skipping Poseidon test - snarkjs not installed");
          this.skip();
        }
        throw error;
      }
    });

    it("should create deterministic commitments", async function () {
      try {
        const credentialData = [1n, 2n, 3n, 4n];
        const salt = 12345n;

        const commitment1 = await createCommitment(credentialData, salt);
        const commitment2 = await createCommitment(credentialData, salt);

        expect(commitment1).to.equal(commitment2);

        // Different salt should produce different commitment
        const commitment3 = await createCommitment(credentialData, 67890n);
        expect(commitment1).to.not.equal(commitment3);
      } catch (error: any) {
        if (error.message.includes("Cannot find module")) {
          console.log("Skipping commitment test - snarkjs not installed");
          this.skip();
        }
        throw error;
      }
    });
  });

  describe("Calldata Parsing", function () {
    it("should parse Solidity calldata", function () {
      // Example calldata format from snarkjs
      const calldata = `["0x1234", "0x5678"],` +
        `[["0xaaaa", "0xbbbb"], ["0xcccc", "0xdddd"]],` +
        `["0xeeee", "0xffff"],` +
        `["0x1111", "0x2222"]`;

      const parsed = parseCalldata(calldata);

      expect(parsed.a).to.have.length(2);
      expect(parsed.b).to.have.length(2);
      expect(parsed.b[0]).to.have.length(2);
      expect(parsed.c).to.have.length(2);
      expect(parsed.inputs).to.have.length(2);
    });
  });

  describe("Circuit Initialization", function () {
    it("should throw error for non-existent circuit", function () {
      expect(() => initCircuit("NonExistentCircuit")).to.throw(
        "WASM file not found"
      );
    });
  });
});

/**
 * Example of how actual circuit tests will look (for Steps 11-13)
 *
 * describe("AgeThreshold Circuit", function () {
 *   let circuit: CircuitTest;
 *
 *   before(async function () {
 *     circuit = initCircuit("AgeThreshold");
 *   });
 *
 *   it("should prove age > 18 for 25-year-old", async function () {
 *     const birthdate = 946684800n; // Jan 1, 2000
 *     const currentTime = 1735689600n; // Jan 1, 2025
 *
 *     const credentialData = [birthdate, ...Array(15).fill(0n)];
 *     const salt = 12345n;
 *     const commitment = await createCommitment(credentialData, salt);
 *
 *     const inputs = {
 *       credentialCommitment: commitment,
 *       threshold: 18n,
 *       currentTimestamp: currentTime,
 *       comparisonType: 0n, // greater than
 *       birthdate: birthdate,
 *       credentialData: credentialData,
 *       salt: salt,
 *     };
 *
 *     const { proof, publicSignals } = await generateProof(circuit, inputs);
 *     const isValid = await verifyProof(circuit, proof, publicSignals);
 *
 *     expect(isValid).to.be.true;
 *   });
 *
 *   it("should fail to prove age > 21 for 18-year-old", async function () {
 *     const birthdate = 1104537600n; // Jan 1, 2005
 *     const currentTime = 1735689600n; // Jan 1, 2025 (age = 20)
 *
 *     const inputs = {
 *       // ... similar setup
 *       threshold: 21n,
 *     };
 *
 *     await expectProofToFail(circuit, inputs);
 *   });
 * });
 */
