/**
 * @file WitnessBuilder
 * @description Builds circuit witness inputs for each proof type
 */

import type {
  DecryptedCredential,
  AgeThresholdInputs,
  DateRangeInputs,
  ValueRangeInputs,
  SetMembershipInputs,
  ComparisonType,
  MerkleProof,
} from "./types";
import { StandardFieldIndices } from "./types";

// Default number of credential fields (matches circuit configuration)
const DEFAULT_NUM_FIELDS = 16;

// Seconds per year (365.25 days to account for leap years)
const SECONDS_PER_YEAR = 31557600n;

/**
 * Builds witness inputs for ZK circuits
 */
export class WitnessBuilder {
  private numFields: number;

  constructor(numFields: number = DEFAULT_NUM_FIELDS) {
    this.numFields = numFields;
  }

  /**
   * Build witness inputs for the AgeThreshold circuit
   *
   * @param credential - Decrypted credential with birthdate in field 0
   * @param commitment - Poseidon commitment of credential data
   * @param threshold - Age threshold in years
   * @param comparisonType - 0 = greater than, 1 = less than
   * @param currentTimestamp - Current Unix timestamp (optional, defaults to now)
   * @returns Circuit inputs ready for witness generation
   */
  buildAgeThresholdWitness(
    credential: DecryptedCredential,
    commitment: bigint,
    threshold: number,
    comparisonType: ComparisonType.GREATER_THAN | ComparisonType.LESS_THAN,
    currentTimestamp?: number
  ): AgeThresholdInputs {
    const timestamp = currentTimestamp ?? Math.floor(Date.now() / 1000);
    const birthdate = credential.payload.fields[StandardFieldIndices.BIRTHDATE];

    // Validate inputs
    if (birthdate <= 0n) {
      throw new Error("Invalid birthdate: must be a positive Unix timestamp");
    }
    if (BigInt(timestamp) <= birthdate) {
      throw new Error("Current timestamp must be after birthdate");
    }
    if (threshold < 0 || threshold > 150) {
      throw new Error("Invalid threshold: must be between 0 and 150 years");
    }

    // Ensure credential data has correct number of fields
    const credentialData = this.padFields(credential.payload.fields);

    return {
      // Public inputs
      credentialCommitment: commitment,
      threshold: BigInt(threshold),
      currentTimestamp: BigInt(timestamp),
      comparisonType: BigInt(comparisonType),
      // Private inputs
      birthdate,
      credentialData,
      salt: credential.salt,
    };
  }

  /**
   * Build witness inputs for the DateRange circuit
   *
   * @param credential - Decrypted credential
   * @param commitment - Poseidon commitment of credential data
   * @param fieldIndex - Index of the date field to check
   * @param rangeStart - Start of valid range (Unix timestamp, inclusive)
   * @param rangeEnd - End of valid range (Unix timestamp, inclusive)
   * @returns Circuit inputs ready for witness generation
   */
  buildDateRangeWitness(
    credential: DecryptedCredential,
    commitment: bigint,
    fieldIndex: number,
    rangeStart: number,
    rangeEnd: number
  ): DateRangeInputs {
    // Validate inputs
    if (fieldIndex < 0 || fieldIndex >= this.numFields) {
      throw new Error(`Invalid field index: must be between 0 and ${this.numFields - 1}`);
    }
    if (rangeStart > rangeEnd) {
      throw new Error("Invalid range: start must be <= end");
    }

    const dateValue = credential.payload.fields[fieldIndex];
    const credentialData = this.padFields(credential.payload.fields);

    return {
      // Public inputs
      credentialCommitment: commitment,
      rangeStart: BigInt(rangeStart),
      rangeEnd: BigInt(rangeEnd),
      fieldIndex: BigInt(fieldIndex),
      // Private inputs
      dateValue,
      credentialData,
      salt: credential.salt,
    };
  }

  /**
   * Build witness inputs for the ValueRange circuit
   *
   * @param credential - Decrypted credential
   * @param commitment - Poseidon commitment of credential data
   * @param fieldIndex - Index of the value field to check
   * @param minValue - Minimum value (inclusive)
   * @param maxValue - Maximum value (inclusive)
   * @returns Circuit inputs ready for witness generation
   */
  buildValueRangeWitness(
    credential: DecryptedCredential,
    commitment: bigint,
    fieldIndex: number,
    minValue: bigint,
    maxValue: bigint
  ): ValueRangeInputs {
    // Validate inputs
    if (fieldIndex < 0 || fieldIndex >= this.numFields) {
      throw new Error(`Invalid field index: must be between 0 and ${this.numFields - 1}`);
    }
    if (minValue > maxValue) {
      throw new Error("Invalid range: min must be <= max");
    }

    const actualValue = credential.payload.fields[fieldIndex];
    const credentialData = this.padFields(credential.payload.fields);

    return {
      // Public inputs
      credentialCommitment: commitment,
      minValue,
      maxValue,
      fieldIndex: BigInt(fieldIndex),
      // Private inputs
      actualValue,
      credentialData,
      salt: credential.salt,
    };
  }

  /**
   * Build witness inputs for the SetMembership circuit
   *
   * @param credential - Decrypted credential
   * @param commitment - Poseidon commitment of credential data
   * @param fieldIndex - Index of the field to check membership for
   * @param merkleProof - Merkle proof showing field value is in the set
   * @returns Circuit inputs ready for witness generation
   */
  buildSetMembershipWitness(
    credential: DecryptedCredential,
    commitment: bigint,
    fieldIndex: number,
    merkleProof: MerkleProof
  ): SetMembershipInputs {
    // Validate inputs
    if (fieldIndex < 0 || fieldIndex >= this.numFields) {
      throw new Error(`Invalid field index: must be between 0 and ${this.numFields - 1}`);
    }

    const actualValue = credential.payload.fields[fieldIndex];
    const credentialData = this.padFields(credential.payload.fields);

    // Verify the merkle proof leaf matches the field value
    if (merkleProof.leaf !== actualValue) {
      throw new Error("Merkle proof leaf does not match field value");
    }

    return {
      // Public inputs
      credentialCommitment: commitment,
      setRoot: merkleProof.root,
      fieldIndex: BigInt(fieldIndex),
      // Private inputs
      actualValue,
      credentialData,
      salt: credential.salt,
      merkleProof: merkleProof.pathElements,
      merklePathIndices: merkleProof.pathIndices.map(BigInt),
    };
  }

  /**
   * Pad credential fields to the expected number
   */
  private padFields(fields: bigint[]): bigint[] {
    if (fields.length === this.numFields) {
      return fields;
    }
    if (fields.length > this.numFields) {
      return fields.slice(0, this.numFields);
    }
    // Pad with zeros
    const padded = [...fields];
    while (padded.length < this.numFields) {
      padded.push(0n);
    }
    return padded;
  }

  /**
   * Estimate age from birthdate and current timestamp
   * Useful for pre-validation before proof generation
   */
  static calculateAge(birthdateTimestamp: number, currentTimestamp?: number): number {
    const now = currentTimestamp ?? Math.floor(Date.now() / 1000);
    const ageSeconds = BigInt(now) - BigInt(birthdateTimestamp);
    return Number(ageSeconds / SECONDS_PER_YEAR);
  }

  /**
   * Validate that a date value is within range
   * Useful for pre-validation before proof generation
   */
  static isInDateRange(dateValue: number, rangeStart: number, rangeEnd: number): boolean {
    return dateValue >= rangeStart && dateValue <= rangeEnd;
  }

  /**
   * Validate that a value is within range
   * Useful for pre-validation before proof generation
   */
  static isInValueRange(value: bigint, min: bigint, max: bigint): boolean {
    return value >= min && value <= max;
  }
}

/**
 * Convert circuit inputs to snarkjs-compatible format
 * All bigints are converted to decimal strings
 */
export function inputsToSnarkjsFormat(
  inputs: AgeThresholdInputs | DateRangeInputs | ValueRangeInputs | SetMembershipInputs
): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};

  for (const [key, value] of Object.entries(inputs)) {
    if (Array.isArray(value)) {
      result[key] = value.map((v) => v.toString());
    } else if (typeof value === "bigint") {
      result[key] = value.toString();
    } else {
      result[key] = String(value);
    }
  }

  return result;
}
