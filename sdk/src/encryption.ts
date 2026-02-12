/**
 * @file Encryption Utilities
 * @description ECIES encryption/decryption for credential payloads using
 * secp256k1 ECDH key agreement and HKDF key derivation.
 */

import { createCipheriv, createDecipheriv, randomBytes, hkdfSync } from "crypto";
import { SigningKey, keccak256, getBytes, concat, hexlify, toUtf8Bytes, AbiCoder } from "ethers";
import type {
  EncryptedPayload,
  KeyPair,
  DecryptedCredential,
  CredentialPayload,
} from "./types";

// ============================================
// Constants
// ============================================

/** HKDF info string for domain separation */
const HKDF_INFO = "sovereign-credential-ecies";

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
 * Generate a secp256k1 key pair for ECIES encryption
 */
export function generateKeyPair(): KeyPair {
  const privateKeyBytes = randomBytes(32);
  const privateKey = hexlify(privateKeyBytes);
  const signingKey = new SigningKey(privateKey);
  return {
    privateKey,
    publicKey: signingKey.compressedPublicKey,
  };
}

/**
 * Derive shared secret via secp256k1 ECDH
 *
 * Computes the ECDH shared point and extracts the x-coordinate (32 bytes)
 * as the raw shared secret.
 *
 * @param privateKey - Sender's private key (32 bytes hex)
 * @param publicKey - Recipient's public key (compressed 33 bytes or uncompressed 65 bytes, hex)
 * @returns 32-byte raw shared secret (x-coordinate of shared point)
 */
function deriveSharedSecret(privateKey: string, publicKey: string): Uint8Array {
  const signingKey = new SigningKey(privateKey);
  const sharedPoint = signingKey.computeSharedSecret(publicKey);
  // Shared point is uncompressed (65 bytes: 0x04 || x || y). Extract x-coordinate.
  return getBytes(sharedPoint).slice(1, 33);
}

/**
 * Derive AES-256 encryption key from shared secret using HKDF-SHA256
 *
 * @param sharedSecret - Raw ECDH shared secret (32 bytes)
 * @param salt - HKDF salt (IV is used as salt for domain separation per-message)
 * @returns 32-byte AES-256 encryption key
 */
function deriveEncryptionKey(sharedSecret: Uint8Array, salt: Uint8Array): Uint8Array {
  return new Uint8Array(hkdfSync("sha256", sharedSecret, salt, HKDF_INFO, 32));
}

// ============================================
// Encryption/Decryption
// ============================================

// Maximum payload size (32KB as per SPEC.md Constraint C-05)
const MAX_PAYLOAD_SIZE = 32 * 1024;

/**
 * Encrypt a credential payload using ECIES
 *
 * Flow:
 * 1. Generate ephemeral secp256k1 keypair
 * 2. Compute shared secret via ECDH(ephemeralPriv, recipientPub)
 * 3. Derive AES-256 key via HKDF-SHA256(sharedSecret, IV)
 * 4. Encrypt payload with AES-256-GCM
 *
 * @param payload - The payload object to encrypt
 * @param recipientPublicKey - Recipient's secp256k1 public key (compressed or uncompressed, hex)
 * @param ephemeralPrivateKey - Optional ephemeral private key for deterministic encryption (testing)
 * @returns Encrypted payload structure
 * @throws Error if payload exceeds maximum size
 */
export function encryptPayload(
  payload: Record<string, unknown>,
  recipientPublicKey: string,
  ephemeralPrivateKey?: string
): EncryptedPayload {
  const payloadStr = JSON.stringify(payload);
  const payloadBytes = Buffer.from(payloadStr, "utf8");

  // Validate payload size (SPEC.md Constraint C-05: max 32KB)
  if (payloadBytes.length > MAX_PAYLOAD_SIZE) {
    throw new Error(`Payload size ${payloadBytes.length} exceeds maximum allowed size of ${MAX_PAYLOAD_SIZE} bytes`);
  }

  // Generate ephemeral secp256k1 keypair
  const ephemeralKey = ephemeralPrivateKey || hexlify(randomBytes(32));
  const ephemeralSigningKey = new SigningKey(ephemeralKey);
  const ephemeralPublicKey = ephemeralSigningKey.compressedPublicKey;

  // Generate IV
  const iv = randomBytes(16);

  // Derive shared secret via ECDH
  const sharedSecret = deriveSharedSecret(ephemeralKey, recipientPublicKey);

  // Derive encryption key via HKDF
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
 * Decrypt a credential payload using ECIES
 *
 * Flow:
 * 1. Compute shared secret via ECDH(recipientPriv, ephemeralPub)
 * 2. Derive AES-256 key via HKDF-SHA256(sharedSecret, IV)
 * 3. Decrypt with AES-256-GCM
 *
 * @param encrypted - Encrypted payload structure (from encryptPayload)
 * @param recipientPrivateKey - Recipient's secp256k1 private key (hex)
 * @returns Decrypted payload as JSON object
 * @throws Error if decryption fails or payload is malformed
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
  let decrypted: Buffer;
  try {
    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(encryptionKey), Buffer.from(ivBytes));
    decipher.setAuthTag(Buffer.from(authTag));

    decrypted = Buffer.concat([
      decipher.update(Buffer.from(ciphertext)),
      decipher.final(),
    ]);
  } catch (error) {
    throw new Error(`Decryption failed: ${error instanceof Error ? error.message : "authentication or key mismatch"}`);
  }

  // Parse JSON with error handling
  try {
    return JSON.parse(decrypted.toString("utf8"));
  } catch (error) {
    throw new Error(`Failed to parse decrypted payload as JSON: ${error instanceof Error ? error.message : "invalid JSON"}`);
  }
}

// ============================================
// Payload Encoding
// ============================================

/**
 * Encode encrypted payload for on-chain storage
 * Format: ephemeralPublicKey (33 bytes compressed secp256k1) + iv (16 bytes) + ciphertext
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

  // Ephemeral public key is 33 bytes (compressed secp256k1)
  const ephemeralPublicKey = hexlify(bytes.slice(0, 33));
  const iv = hexlify(bytes.slice(33, 49));
  const encryptedData = hexlify(bytes.slice(49));

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
