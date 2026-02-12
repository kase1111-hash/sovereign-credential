/**
 * @file ECIES encryption helpers for testing
 * @description Utilities for encrypting/decrypting credential payloads
 * using secp256k1 ECDH key agreement and HKDF-SHA256 key derivation.
 */

import { ethers } from "hardhat";
import * as crypto from "crypto";

/** HKDF info string — must match sdk/src/encryption.ts */
const HKDF_INFO = "sovereign-credential-ecies";

// ============================================
// Key Management
// ============================================

/**
 * Generate a new key pair for testing
 */
export function generateKeyPair(): {
  privateKey: string;
  publicKey: string;
  address: string;
} {
  const wallet = ethers.Wallet.createRandom();
  return {
    privateKey: wallet.privateKey,
    publicKey: wallet.signingKey.publicKey,
    address: wallet.address,
  };
}

/**
 * Derive public key from private key
 */
export function derivePublicKey(privateKey: string): string {
  const wallet = new ethers.Wallet(privateKey);
  return wallet.signingKey.publicKey;
}

/**
 * Derive address from public key
 */
export function deriveAddress(publicKey: string): string {
  return ethers.computeAddress(publicKey);
}

// ============================================
// ECIES Implementation
// ============================================

/**
 * Derive ECDH shared secret using secp256k1
 */
function deriveSharedSecret(privateKey: string, publicKey: string): Uint8Array {
  const signingKey = new ethers.SigningKey(privateKey);
  const sharedPoint = signingKey.computeSharedSecret(publicKey);
  // Extract x-coordinate (bytes 1-33) from uncompressed point
  return ethers.getBytes(sharedPoint).slice(1, 33);
}

/**
 * Derive AES-256 encryption key using HKDF-SHA256
 */
function deriveEncryptionKey(sharedSecret: Uint8Array, salt: Uint8Array): Uint8Array {
  return new Uint8Array(crypto.hkdfSync("sha256", sharedSecret, salt, HKDF_INFO, 32));
}

/**
 * Encrypt data using ECIES
 *
 * Uses secp256k1 ECDH + HKDF-SHA256 + AES-256-GCM.
 */
export function encryptPayload(
  payload: string | object,
  recipientPublicKey: string
): {
  encryptedData: string;
  ephemeralPublicKey: string;
  iv: string;
  mac: string;
} {
  // Convert payload to string
  const payloadStr = typeof payload === "string" ? payload : JSON.stringify(payload);
  const payloadBytes = Buffer.from(payloadStr, "utf8");

  // Generate ephemeral secp256k1 key pair
  const ephemeralWallet = ethers.Wallet.createRandom();
  const ephemeralPublicKey = ephemeralWallet.signingKey.compressedPublicKey;

  // Generate IV
  const iv = crypto.randomBytes(16);

  // Derive shared secret via ECDH
  const sharedSecret = deriveSharedSecret(ephemeralWallet.privateKey, recipientPublicKey);

  // Derive encryption key via HKDF
  const encryptionKey = deriveEncryptionKey(sharedSecret, iv);

  // Encrypt using AES-256-GCM
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([
    cipher.update(payloadBytes),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Combine encrypted data and auth tag
  const encryptedWithTag = Buffer.concat([encrypted, authTag]);

  return {
    encryptedData: "0x" + encryptedWithTag.toString("hex"),
    ephemeralPublicKey,
    iv: "0x" + iv.toString("hex"),
    mac: "0x" + authTag.toString("hex"),
  };
}

/**
 * Decrypt data using the recipient's private key
 */
export function decryptPayload(
  encryptedData: string,
  ephemeralPublicKey: string,
  iv: string,
  recipientPrivateKey: string
): string {
  // Derive shared secret via ECDH
  const sharedSecret = deriveSharedSecret(recipientPrivateKey, ephemeralPublicKey);

  // Derive encryption key via HKDF
  const ivBytes = ethers.getBytes(iv);
  const encryptionKey = deriveEncryptionKey(sharedSecret, ivBytes);

  // Parse encrypted data
  const encryptedBytes = ethers.getBytes(encryptedData);
  const authTag = encryptedBytes.slice(-16);
  const ciphertext = encryptedBytes.slice(0, -16);

  // Decrypt using AES-256-GCM
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    encryptionKey,
    Buffer.from(ivBytes)
  );
  decipher.setAuthTag(Buffer.from(authTag));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext)),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}

/**
 * Decrypt and parse JSON payload
 */
export function decryptPayloadToObject<T = Record<string, unknown>>(
  encryptedData: string,
  ephemeralPublicKey: string,
  iv: string,
  recipientPrivateKey: string
): T {
  const decrypted = decryptPayload(
    encryptedData,
    ephemeralPublicKey,
    iv,
    recipientPrivateKey
  );
  return JSON.parse(decrypted) as T;
}

// ============================================
// Payload Encoding/Decoding
// ============================================

/**
 * Encode an encrypted payload for on-chain storage
 * Format: ephemeralPublicKey (33 bytes compressed secp256k1) + iv (16 bytes) + ciphertext
 */
export function encodeEncryptedPayload(encrypted: {
  encryptedData: string;
  ephemeralPublicKey: string;
  iv: string;
}): string {
  return ethers.concat([
    ethers.getBytes(encrypted.ephemeralPublicKey),
    ethers.getBytes(encrypted.iv),
    ethers.getBytes(encrypted.encryptedData),
  ]);
}

/**
 * Decode an encrypted payload from on-chain storage
 */
export function decodeEncryptedPayload(encoded: string): {
  encryptedData: string;
  ephemeralPublicKey: string;
  iv: string;
} {
  const bytes = ethers.getBytes(encoded);

  // Compressed public key is 33 bytes (0x02/0x03 + 32 bytes x)
  const ephemeralPublicKey = ethers.hexlify(bytes.slice(0, 33));
  const iv = ethers.hexlify(bytes.slice(33, 49));
  const encryptedData = ethers.hexlify(bytes.slice(49));

  return {
    ephemeralPublicKey,
    iv,
    encryptedData,
  };
}

// ============================================
// Payload Hashing
// ============================================

/**
 * Hash a plaintext payload for on-chain verification
 */
export function hashPayload(payload: string | object): string {
  const payloadStr = typeof payload === "string" ? payload : JSON.stringify(payload);
  return ethers.keccak256(ethers.toUtf8Bytes(payloadStr));
}

/**
 * Verify that encrypted payload matches the stored hash
 */
export function verifyPayloadHash(
  encryptedData: string,
  ephemeralPublicKey: string,
  iv: string,
  recipientPrivateKey: string,
  expectedHash: string
): boolean {
  try {
    const decrypted = decryptPayload(
      encryptedData,
      ephemeralPublicKey,
      iv,
      recipientPrivateKey
    );
    const actualHash = hashPayload(decrypted);
    return actualHash === expectedHash;
  } catch {
    return false;
  }
}

// ============================================
// Test Helpers
// ============================================

/**
 * Create a full encrypted credential payload for testing
 */
export function createEncryptedCredentialPayload(
  payload: object,
  recipientPublicKey: string
): {
  encryptedPayload: string;
  payloadHash: string;
  ephemeralPublicKey: string;
  iv: string;
} {
  const encrypted = encryptPayload(payload, recipientPublicKey);
  const encodedPayload = encodeEncryptedPayload(encrypted);
  const payloadHash = hashPayload(payload);

  return {
    encryptedPayload: encodedPayload,
    payloadHash,
    ephemeralPublicKey: encrypted.ephemeralPublicKey,
    iv: encrypted.iv,
  };
}

/**
 * Generate dummy encrypted payload for tests that don't need real encryption
 */
export function createDummyEncryptedPayload(length: number = 200): string {
  return "0x" + crypto.randomBytes(length).toString("hex");
}

/**
 * Create a deterministic encrypted payload for snapshot testing
 */
export function createDeterministicPayload(seed: string): string {
  const hash = ethers.keccak256(ethers.toUtf8Bytes(seed));
  return hash + hash.slice(2) + hash.slice(2); // Repeat to make it longer
}

// ============================================
// Commitment Generation
// ============================================

/**
 * Generate a Poseidon-compatible commitment
 * Note: In production, use actual Poseidon hash
 */
export function generateCommitment(value: bigint, salt: string): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "bytes32"],
      [value, salt]
    )
  );
}

/**
 * Generate a random salt for commitments
 */
export function generateSalt(): string {
  return ethers.hexlify(crypto.randomBytes(32));
}

/**
 * Generate commitments for a credential payload
 */
export function generatePayloadCommitments(
  payload: Record<string, unknown>
): {
  commitments: string[];
  salts: string[];
} {
  const commitments: string[] = [];
  const salts: string[] = [];

  // Generate commitments for common fields
  const fieldsToCommit = ["birthdate", "issuedDate", "expirationDate", "value"];

  for (const field of fieldsToCommit) {
    if (field in payload) {
      const salt = generateSalt();
      const value = BigInt(payload[field] as number);
      const commitment = generateCommitment(value, salt);
      commitments.push(commitment);
      salts.push(salt);
    }
  }

  // Ensure at least one commitment
  if (commitments.length === 0) {
    const salt = generateSalt();
    const commitment = generateCommitment(0n, salt);
    commitments.push(commitment);
    salts.push(salt);
  }

  return { commitments, salts };
}

// ============================================
// Key Storage Helpers (for tests)
// ============================================

/**
 * Simple in-memory key store for testing
 */
export class TestKeyStore {
  private keys: Map<string, { privateKey: string; publicKey: string }> = new Map();

  generateKey(address: string): { privateKey: string; publicKey: string } {
    const { privateKey, publicKey } = generateKeyPair();
    this.keys.set(address.toLowerCase(), { privateKey, publicKey });
    return { privateKey, publicKey };
  }

  getPublicKey(address: string): string | undefined {
    return this.keys.get(address.toLowerCase())?.publicKey;
  }

  getPrivateKey(address: string): string | undefined {
    return this.keys.get(address.toLowerCase())?.privateKey;
  }

  hasKey(address: string): boolean {
    return this.keys.has(address.toLowerCase());
  }

  clear(): void {
    this.keys.clear();
  }
}
