/**
 * @file TypeScript type definitions for Sovereign Credential system
 * @description Mirrors Solidity structs from CredentialTypes.sol
 */

// ============================================
// Credential Status (matches CredentialTypes.CredentialStatus)
// ============================================

export enum CredentialStatus {
  PENDING = 0,
  ACTIVE = 1,
  SUSPENDED = 2,
  REVOKED = 3,
  EXPIRED = 4,
  INHERITED = 5,
}

export const CredentialStatusNames: Record<CredentialStatus, string> = {
  [CredentialStatus.PENDING]: "Pending",
  [CredentialStatus.ACTIVE]: "Active",
  [CredentialStatus.SUSPENDED]: "Suspended",
  [CredentialStatus.REVOKED]: "Revoked",
  [CredentialStatus.EXPIRED]: "Expired",
  [CredentialStatus.INHERITED]: "Inherited",
};

// ============================================
// Disclosure Types (matches CredentialTypes.DisclosureType)
// ============================================

export enum DisclosureType {
  AGE_THRESHOLD = 0,
  DATE_RANGE = 1,
  VALUE_RANGE = 2,
  SET_MEMBERSHIP = 3,
  EQUALITY = 4,
  EXISTENCE = 5,
  COMPOUND = 6,
}

export const DisclosureTypeNames: Record<DisclosureType, string> = {
  [DisclosureType.AGE_THRESHOLD]: "Age Threshold",
  [DisclosureType.DATE_RANGE]: "Date Range",
  [DisclosureType.VALUE_RANGE]: "Value Range",
  [DisclosureType.SET_MEMBERSHIP]: "Set Membership",
  [DisclosureType.EQUALITY]: "Equality",
  [DisclosureType.EXISTENCE]: "Existence",
  [DisclosureType.COMPOUND]: "Compound",
};

// ============================================
// Claim Type Categories
// ============================================

export enum ClaimCategory {
  UNKNOWN = 0,
  IDENTITY = 1,
  LICENSE = 2,
  EDUCATION = 3,
  PROPERTY = 4,
  HEALTH = 5,
  EMPLOYMENT = 6,
  FINANCIAL = 7,
  MEMBERSHIP = 8,
  LEGAL = 9,
  ACCESS = 10,
  CUSTOM = 11,
}

// ============================================
// Claim Types (matches ClaimTypes.sol constants)
// ============================================

export const ClaimTypes = {
  // Identity (0x01 - 0x0F)
  IDENTITY_BIRTH: "0x0000000000000000000000000000000000000000000000000000000000000001",
  IDENTITY_CITIZENSHIP: "0x0000000000000000000000000000000000000000000000000000000000000002",
  IDENTITY_RESIDENCE: "0x0000000000000000000000000000000000000000000000000000000000000003",
  IDENTITY_GOVERNMENT_ID: "0x0000000000000000000000000000000000000000000000000000000000000004",
  IDENTITY_TAX_ID: "0x0000000000000000000000000000000000000000000000000000000000000005",

  // License (0x10 - 0x1F)
  LICENSE_PROFESSIONAL: "0x0000000000000000000000000000000000000000000000000000000000000010",
  LICENSE_OPERATOR: "0x0000000000000000000000000000000000000000000000000000000000000011",
  LICENSE_CONTRACTOR: "0x0000000000000000000000000000000000000000000000000000000000000012",
  LICENSE_BUSINESS: "0x0000000000000000000000000000000000000000000000000000000000000013",
  LICENSE_FIREARMS: "0x0000000000000000000000000000000000000000000000000000000000000014",

  // Education (0x20 - 0x2F)
  EDUCATION_DEGREE: "0x0000000000000000000000000000000000000000000000000000000000000020",
  EDUCATION_CERTIFICATION: "0x0000000000000000000000000000000000000000000000000000000000000021",
  EDUCATION_COURSE: "0x0000000000000000000000000000000000000000000000000000000000000022",
  EDUCATION_TRAINING: "0x0000000000000000000000000000000000000000000000000000000000000023",
  EDUCATION_TRANSCRIPT: "0x0000000000000000000000000000000000000000000000000000000000000024",

  // Property (0x30 - 0x3F)
  PROPERTY_DEED: "0x0000000000000000000000000000000000000000000000000000000000000030",
  PROPERTY_TITLE: "0x0000000000000000000000000000000000000000000000000000000000000031",
  PROPERTY_LIEN: "0x0000000000000000000000000000000000000000000000000000000000000032",
  PROPERTY_LEASE: "0x0000000000000000000000000000000000000000000000000000000000000033",
  PROPERTY_INTELLECTUAL: "0x0000000000000000000000000000000000000000000000000000000000000034",

  // Health (0x40 - 0x4F)
  HEALTH_IMMUNIZATION: "0x0000000000000000000000000000000000000000000000000000000000000040",
  HEALTH_INSURANCE: "0x0000000000000000000000000000000000000000000000000000000000000041",
  HEALTH_PRESCRIPTION: "0x0000000000000000000000000000000000000000000000000000000000000042",
  HEALTH_TEST_RESULT: "0x0000000000000000000000000000000000000000000000000000000000000043",
  HEALTH_DISABILITY: "0x0000000000000000000000000000000000000000000000000000000000000044",

  // Employment (0x50 - 0x5F)
  EMPLOYMENT_VERIFICATION: "0x0000000000000000000000000000000000000000000000000000000000000050",
  EMPLOYMENT_INCOME: "0x0000000000000000000000000000000000000000000000000000000000000051",
  EMPLOYMENT_CLEARANCE: "0x0000000000000000000000000000000000000000000000000000000000000052",
  EMPLOYMENT_REFERENCE: "0x0000000000000000000000000000000000000000000000000000000000000053",

  // Financial (0x60 - 0x6F)
  FINANCIAL_ACCOUNT: "0x0000000000000000000000000000000000000000000000000000000000000060",
  FINANCIAL_CREDIT: "0x0000000000000000000000000000000000000000000000000000000000000061",
  FINANCIAL_ACCREDITED: "0x0000000000000000000000000000000000000000000000000000000000000062",
  FINANCIAL_FUNDS: "0x0000000000000000000000000000000000000000000000000000000000000063",

  // Membership (0x70 - 0x7F)
  MEMBERSHIP_ORGANIZATION: "0x0000000000000000000000000000000000000000000000000000000000000070",
  MEMBERSHIP_DAO: "0x0000000000000000000000000000000000000000000000000000000000000071",
  MEMBERSHIP_CLUB: "0x0000000000000000000000000000000000000000000000000000000000000072",
  MEMBERSHIP_ALUMNI: "0x0000000000000000000000000000000000000000000000000000000000000073",

  // Legal (0x80 - 0x8F)
  LEGAL_POA: "0x0000000000000000000000000000000000000000000000000000000000000080",
  LEGAL_NOTARIZED: "0x0000000000000000000000000000000000000000000000000000000000000081",
  LEGAL_COURT_ORDER: "0x0000000000000000000000000000000000000000000000000000000000000082",
  LEGAL_STATUS: "0x0000000000000000000000000000000000000000000000000000000000000083",

  // Access (0x90 - 0x9F)
  AGE_VERIFICATION: "0x0000000000000000000000000000000000000000000000000000000000000090",
  ACCESS_BADGE: "0x0000000000000000000000000000000000000000000000000000000000000091",
  ACCESS_EVENT: "0x0000000000000000000000000000000000000000000000000000000000000092",

  // Custom (0xFF)
  CUSTOM: "0x00000000000000000000000000000000000000000000000000000000000000ff",
} as const;

export type ClaimTypeKey = keyof typeof ClaimTypes;
export type ClaimTypeValue = (typeof ClaimTypes)[ClaimTypeKey];

// ============================================
// Core Structures (mirrors CredentialTypes.sol)
// ============================================

/**
 * Credential struct - mirrors CredentialTypes.Credential
 */
export interface Credential {
  tokenId: bigint;
  claimType: string; // bytes32
  subject: string; // address
  issuer: string; // address
  encryptedPayload: string; // bytes (hex)
  payloadHash: string; // bytes32
  commitments: string[]; // bytes32[]
  issuedAt: bigint; // uint64
  expiresAt: bigint; // uint64 (0 = never)
  status: CredentialStatus;
  metadataURI: string;
}

/**
 * Issuer struct - mirrors CredentialTypes.Issuer
 */
export interface Issuer {
  issuerAddress: string; // address
  authorizedTypes: string[]; // bytes32[]
  jurisdiction: string;
  reputationScore: bigint; // 0-10000 basis points
  totalIssued: bigint;
  totalRevoked: bigint;
  totalDisputed: bigint;
  isActive: boolean;
  delegates: string[]; // address[]
}

/**
 * DisclosureRequest struct - mirrors CredentialTypes.DisclosureRequest
 */
export interface DisclosureRequest {
  credentialId: bigint;
  disclosureType: string; // bytes32
  predicateHash: string; // bytes32
  proof: string; // bytes (hex)
  generatedAt: bigint; // uint64
  validUntil: bigint; // uint64
  verifier: string; // address (0x0 = anyone)
}

/**
 * InheritanceDirective struct - mirrors CredentialTypes.InheritanceDirective
 */
export interface InheritanceDirective {
  credentialId: bigint;
  beneficiaries: string[]; // address[]
  shares: number[]; // uint8[] (must sum to 100)
  requiresFIETrigger: boolean;
  fieIntentHash: string; // bytes32
  conditions: string; // bytes (hex)
}

/**
 * CrossReference struct - mirrors CredentialTypes.CrossReference
 */
export interface CrossReference {
  recordHash: string; // bytes32
  relationship: string;
  prose: string;
}

/**
 * MintRequest struct - mirrors CredentialTypes.MintRequest
 */
export interface MintRequest {
  claimType: string; // bytes32
  subject: string; // address
  encryptedPayload: string; // bytes (hex)
  payloadHash: string; // bytes32
  commitments: string[]; // bytes32[]
  expiresAt: bigint; // uint64
  metadataURI: string;
}

/**
 * RenewalRequest struct - mirrors CredentialTypes.RenewalRequest
 */
export interface RenewalRequest {
  tokenId: bigint;
  requester: string; // address
  requestedAt: bigint; // uint64
  newExpiry: bigint; // uint64
}

// ============================================
// Metadata Types (for IPFS storage)
// ============================================

export interface IssuerMetadata {
  name: string;
  address?: string;
  url?: string;
  logo?: string;
  jurisdiction?: string;
  contact?: {
    email?: string;
    phone?: string;
  };
}

export interface DisplayField {
  name: string;
  path: string;
  format?: "text" | "date" | "datetime" | "number" | "currency" | "list" | "boolean" | "address" | "image";
  private?: boolean;
}

export interface DisclosureSchema {
  description: string;
  fields: string[];
  circuitId?: string;
  publicInputs?: string[];
}

export interface ValidityRules {
  renewable?: boolean;
  gracePeriodDays?: number;
  transferable?: boolean;
  inheritable?: boolean;
  splittable?: boolean;
}

export interface CredentialMetadata {
  name: string;
  description: string;
  image?: string;
  claimType: string;
  claimTypeId?: string;
  version?: string;
  issuer: IssuerMetadata;
  subject?: {
    type?: "person" | "organization" | "asset" | "other";
    identifier?: string;
  };
  displayFields?: DisplayField[];
  disclosureSchemas?: Record<string, DisclosureSchema>;
  payloadSchema?: object;
  validityRules?: ValidityRules;
  natlangchain?: {
    intentType?: "CREDENTIAL_ISSUANCE";
    prose?: string;
    semanticTags?: string[];
    crossReferences?: Array<{
      recordHash: string;
      relationship: "SUPERSEDES" | "AMENDS" | "SUPPORTS" | "REFERENCES" | "REPLACES";
      prose?: string;
    }>;
  };
  localization?: Record<string, {
    name?: string;
    description?: string;
    displayFields?: Record<string, string>;
  }>;
  extensions?: Record<string, unknown>;
}

// ============================================
// Constants (mirrors CredentialTypes.sol)
// ============================================

export const Constants = {
  /** Minimum reputation score to issue credentials (10% = 1000 basis points) */
  MIN_REPUTATION: 1000n,

  /** Maximum reputation score (100% = 10000 basis points) */
  MAX_REPUTATION: 10000n,

  /** Initial reputation score for new issuers (50%) */
  INITIAL_REPUTATION: 5000n,

  /** Grace period for renewal after expiration (90 days in seconds) */
  RENEWAL_GRACE_PERIOD: 90n * 24n * 60n * 60n,

  /** Auto-revoke period for suspended credentials (365 days in seconds) */
  SUSPENSION_AUTO_REVOKE_PERIOD: 365n * 24n * 60n * 60n,

  /** Maximum encrypted payload size (32KB) */
  MAX_PAYLOAD_SIZE: 32n * 1024n,

  /** Zero address */
  ZERO_ADDRESS: "0x0000000000000000000000000000000000000000",

  /** Zero bytes32 */
  ZERO_BYTES32: "0x0000000000000000000000000000000000000000000000000000000000000000",
} as const;

// ============================================
// Type Guards
// ============================================

export function isValidCredentialStatus(status: number): status is CredentialStatus {
  return status >= 0 && status <= 5;
}

export function isValidDisclosureType(type: number): type is DisclosureType {
  return type >= 0 && type <= 6;
}

export function isValidAddress(address: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(address);
}

export function isValidBytes32(bytes32: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(bytes32);
}

// ============================================
// Helper Types
// ============================================

/** Credential with parsed metadata */
export interface CredentialWithMetadata extends Credential {
  metadata: CredentialMetadata;
}

/** Decrypted credential payload (structure varies by claim type) */
export interface DecryptedCredential {
  credential: Credential;
  payload: Record<string, unknown>;
  salt: string;
}

/** ZK Proof for disclosure */
export interface Proof {
  pi_a: [string, string];
  pi_b: [[string, string], [string, string]];
  pi_c: [string, string];
  protocol: "groth16" | "plonk";
  publicSignals: string[];
}
