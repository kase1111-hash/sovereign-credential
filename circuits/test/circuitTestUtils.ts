/**
 * @file circuitTestUtils.ts
 * @description Utilities for testing ZK circuits with TypeScript
 * @dev Provides helpers for witness generation, proof creation, and verification
 */

import * as path from "path";
import * as fs from "fs";
// @ts-ignore - snarkjs types
import * as snarkjs from "snarkjs";

// Build directory paths
const CIRCUITS_DIR = path.join(__dirname, "..");
const BUILD_DIR = path.join(CIRCUITS_DIR, "build");
const KEYS_DIR = path.join(CIRCUITS_DIR, "keys");

/**
 * Circuit testing interface
 */
export interface CircuitTest {
  name: string;
  wasmPath: string;
  zkeyPath: string;
  vkeyPath: string;
}

/**
 * Proof result interface
 */
export interface ProofResult {
  proof: snarkjs.Groth16Proof;
  publicSignals: string[];
}

/**
 * Initialize a circuit for testing
 * @param circuitName Name of the circuit (e.g., "AgeThreshold")
 * @returns CircuitTest object with paths
 */
export function initCircuit(circuitName: string): CircuitTest {
  const wasmPath = path.join(BUILD_DIR, `${circuitName}_js`, `${circuitName}.wasm`);
  const zkeyPath = path.join(KEYS_DIR, `${circuitName}_final.zkey`);
  const vkeyPath = path.join(KEYS_DIR, `${circuitName}_verification_key.json`);

  // Check files exist
  if (!fs.existsSync(wasmPath)) {
    throw new Error(`WASM file not found: ${wasmPath}. Run ./compile.sh ${circuitName} first.`);
  }

  return {
    name: circuitName,
    wasmPath,
    zkeyPath,
    vkeyPath,
  };
}

/**
 * Calculate witness for a circuit
 * @param circuit Circuit test object
 * @param inputs Input signals object
 * @returns Witness array
 */
export async function calculateWitness(
  circuit: CircuitTest,
  inputs: Record<string, any>
): Promise<bigint[]> {
  // Use wasm_tester for witness calculation
  const wasmBuffer = fs.readFileSync(circuit.wasmPath);

  // Calculate witness using snarkjs
  const { witness } = await snarkjs.wtns.calculate(
    inputs,
    circuit.wasmPath,
  );

  return witness;
}

/**
 * Generate a Groth16 proof
 * @param circuit Circuit test object
 * @param inputs Input signals object
 * @returns Proof and public signals
 */
export async function generateProof(
  circuit: CircuitTest,
  inputs: Record<string, any>
): Promise<ProofResult> {
  if (!fs.existsSync(circuit.zkeyPath)) {
    throw new Error(`Proving key not found: ${circuit.zkeyPath}. Run ./setup.sh ${circuit.name} first.`);
  }

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs,
    circuit.wasmPath,
    circuit.zkeyPath
  );

  return { proof, publicSignals };
}

/**
 * Verify a Groth16 proof
 * @param circuit Circuit test object
 * @param proof Proof object
 * @param publicSignals Public signals array
 * @returns True if valid, false otherwise
 */
export async function verifyProof(
  circuit: CircuitTest,
  proof: snarkjs.Groth16Proof,
  publicSignals: string[]
): Promise<boolean> {
  if (!fs.existsSync(circuit.vkeyPath)) {
    throw new Error(`Verification key not found: ${circuit.vkeyPath}`);
  }

  const vkey = JSON.parse(fs.readFileSync(circuit.vkeyPath, "utf-8"));

  return await snarkjs.groth16.verify(vkey, publicSignals, proof);
}

/**
 * Generate Solidity calldata for on-chain verification
 * @param proof Proof object
 * @param publicSignals Public signals array
 * @returns Calldata string
 */
export async function generateCalldata(
  proof: snarkjs.Groth16Proof,
  publicSignals: string[]
): Promise<string> {
  return await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
}

/**
 * Parse Solidity calldata into structured format
 * @param calldata Raw calldata string
 * @returns Parsed calldata components
 */
export function parseCalldata(calldata: string): {
  a: [string, string];
  b: [[string, string], [string, string]];
  c: [string, string];
  inputs: string[];
} {
  // Calldata format: [a[0], a[1]], [[b[0][0], b[0][1]], [b[1][0], b[1][1]]], [c[0], c[1]], [inputs...]
  const parts = calldata.split(",").map((s) => s.trim().replace(/[\[\]"]/g, ""));

  return {
    a: [parts[0], parts[1]] as [string, string],
    b: [
      [parts[2], parts[3]] as [string, string],
      [parts[4], parts[5]] as [string, string],
    ] as [[string, string], [string, string]],
    c: [parts[6], parts[7]] as [string, string],
    inputs: parts.slice(8),
  };
}

/**
 * Poseidon hash function (matches circomlib implementation)
 * @param inputs Array of field elements to hash
 * @returns Hash as bigint
 */
export async function poseidonHash(inputs: bigint[]): Promise<bigint> {
  // Use snarkjs buildPoseidon
  const poseidon = await snarkjs.buildPoseidon();
  const hash = poseidon(inputs);
  return poseidon.F.toObject(hash);
}

/**
 * Create a credential commitment
 * @param credentialData Array of credential field values
 * @param salt Random salt for binding
 * @returns Commitment hash
 */
export async function createCommitment(
  credentialData: bigint[],
  salt: bigint
): Promise<bigint> {
  const inputs = [...credentialData, salt];
  return await poseidonHash(inputs);
}

/**
 * Test helper: expect proof to fail
 * @param circuit Circuit test object
 * @param inputs Input signals that should fail
 * @param errorMessage Expected error message (optional)
 */
export async function expectProofToFail(
  circuit: CircuitTest,
  inputs: Record<string, any>,
  errorMessage?: string
): Promise<void> {
  try {
    await generateProof(circuit, inputs);
    throw new Error("Expected proof generation to fail, but it succeeded");
  } catch (error: any) {
    if (errorMessage && !error.message.includes(errorMessage)) {
      throw new Error(`Expected error containing "${errorMessage}", got: ${error.message}`);
    }
    // Proof failed as expected
  }
}

/**
 * Convert a number to field element (mod p)
 * @param n Number to convert
 * @returns Field element as bigint
 */
export function toFieldElement(n: number | bigint): bigint {
  // BN128 field prime
  const p = BigInt(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
  );
  const bn = BigInt(n);
  return ((bn % p) + p) % p;
}

/**
 * Convert timestamp to circuit-compatible value
 * @param date Date object or Unix timestamp
 * @returns Timestamp as bigint
 */
export function toTimestamp(date: Date | number): bigint {
  if (date instanceof Date) {
    return BigInt(Math.floor(date.getTime() / 1000));
  }
  return BigInt(date);
}

/**
 * Calculate age from birthdate
 * @param birthdate Birth date as Unix timestamp
 * @param currentTime Current time as Unix timestamp
 * @returns Age in years
 */
export function calculateAge(birthdate: bigint, currentTime: bigint): bigint {
  // Use 365.25 days to match the AgeThreshold circuit constant
  const SECONDS_PER_YEAR = BigInt(31557600); // 365.25 * 24 * 60 * 60
  return (currentTime - birthdate) / SECONDS_PER_YEAR;
}
