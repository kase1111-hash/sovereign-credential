/**
 * @file Signature generation helpers for testing
 * @description Utilities for creating and verifying signatures in tests
 */

import { ethers } from "hardhat";
import { type Signer, type TypedDataDomain } from "ethers";
import { type MintRequest, type Credential } from "../../types";

// ============================================
// Domain Separator
// ============================================

/**
 * EIP-712 domain for Sovereign Credential
 */
export const DOMAIN_NAME = "SovereignCredential";
export const DOMAIN_VERSION = "1";

/**
 * Get the EIP-712 domain for a deployed contract
 */
export function getDomain(
  chainId: bigint,
  verifyingContract: string
): TypedDataDomain {
  return {
    name: DOMAIN_NAME,
    version: DOMAIN_VERSION,
    chainId,
    verifyingContract,
  };
}

/**
 * Get domain for local hardhat network
 */
export async function getLocalDomain(
  verifyingContract: string
): Promise<TypedDataDomain> {
  const network = await ethers.provider.getNetwork();
  return getDomain(network.chainId, verifyingContract);
}

// ============================================
// Type Definitions for EIP-712
// ============================================

/**
 * EIP-712 type definitions for MintRequest
 */
export const MintRequestTypes = {
  MintRequest: [
    { name: "claimType", type: "bytes32" },
    { name: "subject", type: "address" },
    { name: "payloadHash", type: "bytes32" },
    { name: "expiresAt", type: "uint64" },
    { name: "metadataURI", type: "string" },
    { name: "nonce", type: "uint256" },
  ],
};

/**
 * EIP-712 type definitions for Renewal
 */
export const RenewalTypes = {
  Renewal: [
    { name: "tokenId", type: "uint256" },
    { name: "newExpiry", type: "uint64" },
    { name: "nonce", type: "uint256" },
  ],
};

/**
 * EIP-712 type definitions for Revocation
 */
export const RevocationTypes = {
  Revocation: [
    { name: "tokenId", type: "uint256" },
    { name: "reason", type: "string" },
    { name: "nonce", type: "uint256" },
  ],
};

// ============================================
// Signature Generation Functions
// ============================================

/**
 * Sign a mint request using EIP-712 typed data
 */
export async function signMintRequest(
  signer: Signer,
  domain: TypedDataDomain,
  request: MintRequest,
  nonce: bigint = 0n
): Promise<string> {
  const message = {
    claimType: request.claimType,
    subject: request.subject,
    payloadHash: request.payloadHash,
    expiresAt: request.expiresAt,
    metadataURI: request.metadataURI,
    nonce,
  };

  return signer.signTypedData(domain, MintRequestTypes, message);
}

/**
 * Sign a renewal approval using EIP-712 typed data
 */
export async function signRenewal(
  signer: Signer,
  domain: TypedDataDomain,
  tokenId: bigint,
  newExpiry: bigint,
  nonce: bigint = 0n
): Promise<string> {
  const message = {
    tokenId,
    newExpiry,
    nonce,
  };

  return signer.signTypedData(domain, RenewalTypes, message);
}

/**
 * Sign a revocation using EIP-712 typed data
 */
export async function signRevocation(
  signer: Signer,
  domain: TypedDataDomain,
  tokenId: bigint,
  reason: string,
  nonce: bigint = 0n
): Promise<string> {
  const message = {
    tokenId,
    reason,
    nonce,
  };

  return signer.signTypedData(domain, RevocationTypes, message);
}

// ============================================
// Simple Message Signing (Alternative)
// ============================================

/**
 * Hash a mint request for simple ECDSA signing
 */
export function hashMintRequest(request: MintRequest): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "address", "bytes32", "uint64", "string"],
      [
        request.claimType,
        request.subject,
        request.payloadHash,
        request.expiresAt,
        request.metadataURI,
      ]
    )
  );
}

/**
 * Sign a mint request hash with personal_sign
 */
export async function signMintRequestSimple(
  signer: Signer,
  request: MintRequest
): Promise<string> {
  const hash = hashMintRequest(request);
  return signer.signMessage(ethers.getBytes(hash));
}

/**
 * Hash credential data for signing
 */
export function hashCredential(credential: Credential): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "bytes32",
        "address",
        "address",
        "bytes32",
        "uint64",
        "uint64",
        "string",
      ],
      [
        credential.claimType,
        credential.subject,
        credential.issuer,
        credential.payloadHash,
        credential.issuedAt,
        credential.expiresAt,
        credential.metadataURI,
      ]
    )
  );
}

/**
 * Sign credential data
 */
export async function signCredential(
  signer: Signer,
  credential: Credential
): Promise<string> {
  const hash = hashCredential(credential);
  return signer.signMessage(ethers.getBytes(hash));
}

// ============================================
// Signature Verification Helpers
// ============================================

/**
 * Recover signer from a mint request signature
 */
export function recoverMintRequestSigner(
  request: MintRequest,
  signature: string
): string {
  const hash = hashMintRequest(request);
  return ethers.recoverAddress(ethers.hashMessage(ethers.getBytes(hash)), signature);
}

/**
 * Verify that a signature is from the expected signer
 */
export function verifyMintRequestSignature(
  request: MintRequest,
  signature: string,
  expectedSigner: string
): boolean {
  const recoveredSigner = recoverMintRequestSigner(request, signature);
  return recoveredSigner.toLowerCase() === expectedSigner.toLowerCase();
}

/**
 * Recover signer from a credential signature
 */
export function recoverCredentialSigner(
  credential: Credential,
  signature: string
): string {
  const hash = hashCredential(credential);
  return ethers.recoverAddress(ethers.hashMessage(ethers.getBytes(hash)), signature);
}

// ============================================
// Batch Signing Helpers
// ============================================

/**
 * Sign multiple mint requests
 */
export async function signBatchMintRequests(
  signer: Signer,
  requests: MintRequest[]
): Promise<string[]> {
  return Promise.all(
    requests.map((request) => signMintRequestSimple(signer, request))
  );
}

/**
 * Sign with EIP-712 for multiple requests
 */
export async function signBatchMintRequestsTyped(
  signer: Signer,
  domain: TypedDataDomain,
  requests: MintRequest[]
): Promise<string[]> {
  return Promise.all(
    requests.map((request, index) =>
      signMintRequest(signer, domain, request, BigInt(index))
    )
  );
}

// ============================================
// Invalid Signature Generators (for negative tests)
// ============================================

/**
 * Generate an invalid signature (wrong length)
 */
export function generateInvalidSignature(): string {
  return "0x" + "ab".repeat(64); // 64 bytes instead of 65
}

/**
 * Generate a signature with invalid v value
 */
export function generateInvalidVSignature(): string {
  return "0x" + "ab".repeat(64) + "ff"; // Invalid v = 0xff
}

/**
 * Generate a signature from a different message
 */
export async function generateWrongMessageSignature(
  signer: Signer
): Promise<string> {
  return signer.signMessage("wrong message");
}

/**
 * Corrupt a valid signature by flipping bits
 */
export function corruptSignature(signature: string): string {
  const bytes = ethers.getBytes(signature);
  // Flip a bit in the middle of the signature
  bytes[32] = bytes[32] ^ 0x01;
  return ethers.hexlify(bytes);
}

// ============================================
// Delegation Signatures
// ============================================

/**
 * Sign a delegation authorization
 */
export async function signDelegation(
  issuerSigner: Signer,
  delegateAddress: string,
  expiresAt: bigint
): Promise<string> {
  const message = ethers.solidityPackedKeccak256(
    ["string", "address", "uint64"],
    ["DELEGATE:", delegateAddress, expiresAt]
  );
  return issuerSigner.signMessage(ethers.getBytes(message));
}

/**
 * Verify a delegation signature
 */
export function verifyDelegationSignature(
  delegateAddress: string,
  expiresAt: bigint,
  signature: string,
  expectedIssuer: string
): boolean {
  const message = ethers.solidityPackedKeccak256(
    ["string", "address", "uint64"],
    ["DELEGATE:", delegateAddress, expiresAt]
  );
  const recoveredSigner = ethers.recoverAddress(
    ethers.hashMessage(ethers.getBytes(message)),
    signature
  );
  return recoveredSigner.toLowerCase() === expectedIssuer.toLowerCase();
}

// ============================================
// Nonce Management
// ============================================

/**
 * Generate a unique nonce based on timestamp and random value
 */
export function generateNonce(): bigint {
  const timestamp = BigInt(Date.now());
  const random = BigInt(Math.floor(Math.random() * 1000000));
  return timestamp * 1000000n + random;
}

/**
 * Track nonces per signer for tests
 */
export class NonceTracker {
  private nonces: Map<string, bigint> = new Map();

  getNextNonce(signerAddress: string): bigint {
    const current = this.nonces.get(signerAddress.toLowerCase()) ?? 0n;
    this.nonces.set(signerAddress.toLowerCase(), current + 1n);
    return current;
  }

  getCurrentNonce(signerAddress: string): bigint {
    return this.nonces.get(signerAddress.toLowerCase()) ?? 0n;
  }

  reset(): void {
    this.nonces.clear();
  }
}
