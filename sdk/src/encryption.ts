/**
 * @file Encryption Utilities
 * @description ECIES encryption/decryption for credential payloads
 */

import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { keccak256, getBytes, concat, hexlify, toUtf8Bytes, AbiCoder } from "ethers";
import type {
  EncryptedPayload,
  KeyPair,
  DecryptedCredential,
  CredentialPayload,
} from "./types";

// ============================================
// Key Management
// ============================================

/**
 * Generate a random 32-byte salt for commitments
 */
export function generateSalt(): bigint {
  const saltBytes = randomBytes(32);
  return BigInt("0x" + saltBytes.toString("hex"));
}

/**
 * Derive a simple shared secret from private and public keys
 * Note: In production, use proper ECDH key agreement
 */
function deriveSharedSecret(privateKey: string, publicKey: string): Uint8Array {
  const combined = concat([getBytes(privateKey), getBytes(publicKey)]);
  return getBytes(keccak256(combined));
}

/**
 * Derive encryption key from shared secret and IV
 */
function deriveEncryptionKey(sharedSecret: Uint8Array, iv: Uint8Array): Uint8Array {
  const combined = concat([sharedSecret, iv]);
  return getBytes(keccak256(combined)).slice(0, 32);
}

// ============================================
// Encryption/Decryption
// ============================================

/**
 * Encrypt a credential payload using ECIES-like scheme
 *
 * @param payload - The payload object to encrypt
 * @param recipientPublicKey - Public key of the recipient (hex)
 * @param ephemeralPrivateKey - Optional ephemeral private key for deterministic encryption
 * @returns Encrypted payload structure
 */
export function encryptPayload(
  payload: Record<string, unknown>,
  recipientPublicKey: string,
  ephemeralPrivateKey?: string
): EncryptedPayload {
  const payloadStr = JSON.stringify(payload);
  const payloadBytes = Buffer.from(payloadStr, "utf8");

  // Generate ephemeral key if not provided
  const ephemeralKey = ephemeralPrivateKey || hexlify(randomBytes(32));
  // In a real implementation, derive public key from private key using secp256k1
  const ephemeralPublicKey = keccak256(getBytes(ephemeralKey));

  // Generate IV
  const iv = randomBytes(16);

  // Derive shared secret
  const sharedSecret = deriveSharedSecret(ephemeralKey, recipientPublicKey);

  // Derive encryption key
  const encryptionKey = deriveEncryptionKey(sharedSecret, iv);

  // Encrypt using AES-256-GCM
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(payloadBytes), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Combine encrypted data and auth tag
  const encryptedWithTag = Buffer.concat([encrypted, authTag]);

  return {
    encryptedData: "0x" + encryptedWithTag.toString("hex"),
    ephemeralPublicKey,
    iv: "0x" + iv.toString("hex"),
  };
}

/**
 * Decrypt a credential payload
 *
 * @param encrypted - Encrypted payload structure
 * @param recipientPrivateKey - Private key of the recipient (hex)
 * @returns Decrypted payload as JSON object
 */
export function decryptPayload(
  encrypted: EncryptedPayload,
  recipientPrivateKey: string
): Record<string, unknown> {
  // Derive shared secret
  const sharedSecret = deriveSharedSecret(recipientPrivateKey, encrypted.ephemeralPublicKey);

  // Derive encryption key
  const ivBytes = getBytes(encrypted.iv);
  const encryptionKey = deriveEncryptionKey(sharedSecret, ivBytes);

  // Parse encrypted data
  const encryptedBytes = getBytes(encrypted.encryptedData);
  const authTag = encryptedBytes.slice(-16);
  const ciphertext = encryptedBytes.slice(0, -16);

  // Decrypt using AES-256-GCM
  const decipher = createDecipheriv("aes-256-gcm", Buffer.from(encryptionKey), Buffer.from(ivBytes));
  decipher.setAuthTag(Buffer.from(authTag));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext)),
    decipher.final(),
  ]);

  return JSON.parse(decrypted.toString("utf8"));
}

// ============================================
// Payload Encoding
// ============================================

/**
 * Encode encrypted payload for on-chain storage
 * Format: ephemeralPublicKey (32 bytes hash) + iv (16 bytes) + ciphertext
 */
export function encodeEncryptedPayload(encrypted: EncryptedPayload): string {
  return hexlify(
    concat([
      getBytes(encrypted.ephemeralPublicKey),
      getBytes(encrypted.iv),
      getBytes(encrypted.encryptedData),
    ])
  );
}

/**
 * Decode encrypted payload from on-chain storage
 */
export function decodeEncryptedPayload(encoded: string): EncryptedPayload {
  const bytes = getBytes(encoded);

  // Ephemeral public key is 32 bytes (keccak hash)
  const ephemeralPublicKey = hexlify(bytes.slice(0, 32));
  const iv = hexlify(bytes.slice(32, 48));
  const encryptedData = hexlify(bytes.slice(48));

  return {
    ephemeralPublicKey,
    iv,
    encryptedData,
  };
}

// ============================================
// Credential Payload Processing
// ============================================

/**
 * Convert a JSON payload object to circuit-compatible field array
 *
 * @param payload - Decrypted JSON payload
 * @param fieldMapping - Optional mapping of field names to indices
 * @param numFields - Number of fields (default: 16)
 * @returns CredentialPayload with field values as bigints
 */
export function payloadToFields(
  payload: Record<string, unknown>,
  fieldMapping?: Record<string, number>,
  numFields: number = 16
): CredentialPayload {
  const fields: bigint[] = new Array(numFields).fill(0n);
  const namedFields: Record<string, number> = fieldMapping || {};

  // Default field mapping for common credential types
  const defaultMapping: Record<string, number> = {
    birthdate: 0,
    birthDate: 0,
    dateOfBirth: 0,
    issuedAt: 1,
    issueDate: 1,
    expiresAt: 2,
    expirationDate: 2,
    value: 3,
    amount: 3,
    status: 4,
    score: 5,
    level: 6,
    type: 7,
  };

  const mapping = { ...defaultMapping, ...fieldMapping };

  for (const [key, value] of Object.entries(payload)) {
    const fieldIndex = mapping[key];
    if (fieldIndex !== undefined && fieldIndex < numFields) {
      fields[fieldIndex] = toBigInt(value);
      namedFields[key] = fieldIndex;
    }
  }

  return { fields, namedFields };
}

/**
 * Convert various types to bigint for circuit inputs
 */
function toBigInt(value: unknown): bigint {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number") {
    return BigInt(Math.floor(value));
  }
  if (typeof value === "string") {
    // Check if it's a hex string
    if (value.startsWith("0x")) {
      return BigInt(value);
    }
    // Check if it's a date string
    const date = Date.parse(value);
    if (!isNaN(date)) {
      return BigInt(Math.floor(date / 1000)); // Convert to Unix timestamp
    }
    // Try parsing as number
    const num = parseFloat(value);
    if (!isNaN(num)) {
      return BigInt(Math.floor(num));
    }
    // Hash string values
    return BigInt(keccak256(toUtf8Bytes(value)));
  }
  if (typeof value === "boolean") {
    return value ? 1n : 0n;
  }
  if (value instanceof Date) {
    return BigInt(Math.floor(value.getTime() / 1000));
  }
  return 0n;
}

/**
 * Create a DecryptedCredential from raw inputs
 */
export function createDecryptedCredential(
  tokenId: bigint,
  claimType: string,
  subject: string,
  issuer: string,
  payload: Record<string, unknown>,
  salt: bigint,
  fieldMapping?: Record<string, number>
): DecryptedCredential {
  const credentialPayload = payloadToFields(payload, fieldMapping);

  return {
    tokenId,
    claimType,
    subject,
    issuer,
    payload: credentialPayload,
    salt,
  };
}

// ============================================
// Hash Utilities
// ============================================

/**
 * Hash a plaintext payload using keccak256
 */
export function hashPayload(payload: Record<string, unknown>): string {
  const payloadStr = JSON.stringify(payload);
  return keccak256(toUtf8Bytes(payloadStr));
}

/**
 * Generate ABI-encoded commitment (for testing without Poseidon)
 * Note: In production, use actual Poseidon hash
 */
export function generateCommitmentKeccak(fields: bigint[], salt: bigint): string {
  const encoded = AbiCoder.defaultAbiCoder().encode(
    ["uint256[]", "uint256"],
    [fields, salt]
  );
  return keccak256(encoded);
}
