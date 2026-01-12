/**
 * @file Test fixtures for credential-related tests
 * @description Provides reusable credential data and factory functions
 */

import { ethers } from "hardhat";
import { type Signer } from "ethers";
import {
  ClaimTypes,
  CredentialStatus,
  type Credential,
  type MintRequest,
  type CredentialMetadata,
  Constants,
} from "../../types";

// ============================================
// Sample Encrypted Payloads
// ============================================

/**
 * Sample plaintext payload for a driver's license
 */
export const sampleDriverLicensePayload = {
  firstName: "John",
  lastName: "Doe",
  birthdate: 631152000, // 1990-01-01
  licenseNumber: "DL-123456789",
  class: "C",
  endorsements: ["motorcycle"],
  restrictions: [],
  issuedDate: 1704067200, // 2024-01-01
  expirationDate: 1893456000, // 2030-01-01
  address: {
    street: "123 Main St",
    city: "Portland",
    state: "OR",
    zip: "97201",
  },
};

/**
 * Sample plaintext payload for a university degree
 */
export const sampleDegreePayload = {
  studentName: "Jane Smith",
  birthdate: 662688000, // 1991-01-01
  studentId: "STU-987654321",
  degree: "Bachelor of Science",
  major: "Computer Science",
  minor: "Mathematics",
  graduationDate: 1685577600, // 2023-06-01
  gpa: 3.85,
  honors: "Magna Cum Laude",
  institution: "Stanford University",
};

/**
 * Sample plaintext payload for property deed
 */
export const samplePropertyDeedPayload = {
  propertyId: "PROP-2024-00123",
  parcelNumber: "R123456",
  address: {
    street: "456 Oak Avenue",
    city: "San Francisco",
    state: "CA",
    zip: "94102",
  },
  legalDescription: "Lot 5, Block 12, Subdivision XYZ",
  acres: 0.25,
  purchasePrice: 1500000,
  purchaseDate: 1672531200, // 2023-01-01
  previousOwner: "0x1234567890123456789012345678901234567890",
};

// ============================================
// Fixture Factory Functions
// ============================================

/**
 * Create a basic mint request for testing
 */
export function createMintRequest(overrides: Partial<MintRequest> = {}): MintRequest {
  const now = Math.floor(Date.now() / 1000);
  const oneYearFromNow = now + 365 * 24 * 60 * 60;

  return {
    claimType: ClaimTypes.LICENSE_OPERATOR,
    subject: "0x0000000000000000000000000000000000000001",
    encryptedPayload: "0x" + "ab".repeat(100), // Dummy encrypted data
    payloadHash: ethers.keccak256(ethers.toUtf8Bytes("test-payload")),
    commitments: [
      ethers.keccak256(ethers.toUtf8Bytes("commitment-0")),
      ethers.keccak256(ethers.toUtf8Bytes("commitment-1")),
    ],
    expiresAt: BigInt(oneYearFromNow),
    metadataURI: "ipfs://QmTestMetadataHash123456789",
    ...overrides,
  };
}

/**
 * Create a credential struct for testing
 */
export function createCredential(overrides: Partial<Credential> = {}): Credential {
  const now = Math.floor(Date.now() / 1000);
  const oneYearFromNow = now + 365 * 24 * 60 * 60;

  return {
    tokenId: 1n,
    claimType: ClaimTypes.LICENSE_OPERATOR,
    subject: "0x0000000000000000000000000000000000000001",
    issuer: "0x0000000000000000000000000000000000000002",
    encryptedPayload: "0x" + "ab".repeat(100),
    payloadHash: ethers.keccak256(ethers.toUtf8Bytes("test-payload")),
    commitments: [
      ethers.keccak256(ethers.toUtf8Bytes("commitment-0")),
      ethers.keccak256(ethers.toUtf8Bytes("commitment-1")),
    ],
    issuedAt: BigInt(now),
    expiresAt: BigInt(oneYearFromNow),
    status: CredentialStatus.ACTIVE,
    metadataURI: "ipfs://QmTestMetadataHash123456789",
    ...overrides,
  };
}

/**
 * Create a driver's license mint request
 */
export function createDriverLicenseMintRequest(
  subject: string,
  overrides: Partial<MintRequest> = {}
): MintRequest {
  return createMintRequest({
    claimType: ClaimTypes.LICENSE_OPERATOR,
    subject,
    metadataURI: "ipfs://QmDriverLicenseMetadata",
    ...overrides,
  });
}

/**
 * Create a university degree mint request
 */
export function createDegreeMintRequest(
  subject: string,
  overrides: Partial<MintRequest> = {}
): MintRequest {
  return createMintRequest({
    claimType: ClaimTypes.EDUCATION_DEGREE,
    subject,
    metadataURI: "ipfs://QmDegreeMetadata",
    ...overrides,
  });
}

/**
 * Create a property deed mint request
 */
export function createPropertyDeedMintRequest(
  subject: string,
  overrides: Partial<MintRequest> = {}
): MintRequest {
  return createMintRequest({
    claimType: ClaimTypes.PROPERTY_DEED,
    subject,
    metadataURI: "ipfs://QmPropertyDeedMetadata",
    ...overrides,
  });
}

/**
 * Create an expired credential
 */
export function createExpiredCredential(overrides: Partial<Credential> = {}): Credential {
  const pastTime = Math.floor(Date.now() / 1000) - 365 * 24 * 60 * 60; // 1 year ago

  return createCredential({
    expiresAt: BigInt(pastTime),
    status: CredentialStatus.EXPIRED,
    ...overrides,
  });
}

/**
 * Create a revoked credential
 */
export function createRevokedCredential(overrides: Partial<Credential> = {}): Credential {
  return createCredential({
    status: CredentialStatus.REVOKED,
    ...overrides,
  });
}

/**
 * Create a suspended credential
 */
export function createSuspendedCredential(overrides: Partial<Credential> = {}): Credential {
  return createCredential({
    status: CredentialStatus.SUSPENDED,
    ...overrides,
  });
}

// ============================================
// Metadata Fixtures
// ============================================

/**
 * Create sample credential metadata
 */
export function createCredentialMetadata(
  overrides: Partial<CredentialMetadata> = {}
): CredentialMetadata {
  return {
    name: "Test Credential",
    description: "A test credential for unit testing",
    claimType: "LICENSE_OPERATOR",
    version: "1.0",
    issuer: {
      name: "Test Issuer Authority",
      jurisdiction: "US-OR",
      url: "https://test-issuer.example.com",
    },
    displayFields: [
      { name: "License Class", path: "$.class" },
      { name: "Expiration", path: "$.expirationDate", format: "date" },
    ],
    disclosureSchemas: {
      AGE_THRESHOLD: {
        description: "Prove age above or below threshold",
        fields: ["birthdate"],
        circuitId: "AgeThreshold",
      },
    },
    validityRules: {
      renewable: true,
      gracePeriodDays: 90,
      transferable: false,
      inheritable: false,
    },
    ...overrides,
  };
}

// ============================================
// Batch Fixtures
// ============================================

/**
 * Create multiple mint requests for batch testing
 */
export function createBatchMintRequests(
  subjects: string[],
  claimType: string = ClaimTypes.LICENSE_OPERATOR
): MintRequest[] {
  return subjects.map((subject, index) =>
    createMintRequest({
      claimType,
      subject,
      payloadHash: ethers.keccak256(ethers.toUtf8Bytes(`payload-${index}`)),
      metadataURI: `ipfs://QmBatchMetadata${index}`,
    })
  );
}

/**
 * Create credentials with various statuses for testing state transitions
 */
export function createCredentialsWithAllStatuses(): Credential[] {
  return [
    createCredential({ tokenId: 1n, status: CredentialStatus.PENDING }),
    createCredential({ tokenId: 2n, status: CredentialStatus.ACTIVE }),
    createCredential({ tokenId: 3n, status: CredentialStatus.SUSPENDED }),
    createCredential({ tokenId: 4n, status: CredentialStatus.REVOKED }),
    createCredential({ tokenId: 5n, status: CredentialStatus.EXPIRED }),
    createCredential({ tokenId: 6n, status: CredentialStatus.INHERITED }),
  ];
}

// ============================================
// Commitment Fixtures
// ============================================

/**
 * Create ZK-compatible commitments for testing
 * In production, these would be Poseidon hashes
 */
export function createTestCommitments(payload: Record<string, unknown>): string[] {
  const commitments: string[] = [];

  // Commitment for birthdate (if present)
  if ("birthdate" in payload) {
    const salt = ethers.randomBytes(32);
    commitments.push(ethers.keccak256(ethers.concat([
      ethers.toBeHex(payload.birthdate as number, 32),
      salt,
    ])));
  }

  // Commitment for issuance date (if present)
  if ("issuedDate" in payload) {
    const salt = ethers.randomBytes(32);
    commitments.push(ethers.keccak256(ethers.concat([
      ethers.toBeHex(payload.issuedDate as number, 32),
      salt,
    ])));
  }

  // Commitment for expiration date (if present)
  if ("expirationDate" in payload) {
    const salt = ethers.randomBytes(32);
    commitments.push(ethers.keccak256(ethers.concat([
      ethers.toBeHex(payload.expirationDate as number, 32),
      salt,
    ])));
  }

  // Ensure at least one commitment
  if (commitments.length === 0) {
    commitments.push(ethers.keccak256(ethers.toUtf8Bytes("default-commitment")));
  }

  return commitments;
}

// ============================================
// Hardhat Deployment Fixtures
// ============================================

/**
 * Deploy fixture for ClaimToken tests
 * Usage: const { claimToken, issuerRegistry, owner, issuer, subject } = await loadFixture(deployClaimTokenFixture);
 */
export async function deployClaimTokenFixture() {
  const [owner, issuer, subject, other] = await ethers.getSigners();

  // Deploy IssuerRegistry first
  const IssuerRegistry = await ethers.getContractFactory("IssuerRegistryUpgradeable");
  const issuerRegistry = await IssuerRegistry.deploy();
  await issuerRegistry.waitForDeployment();

  // Deploy ClaimToken
  const ClaimToken = await ethers.getContractFactory("ClaimTokenUpgradeable");
  const claimToken = await ClaimToken.deploy();
  await claimToken.waitForDeployment();

  // Initialize contracts
  await issuerRegistry.initialize();
  await claimToken.initialize(await issuerRegistry.getAddress());

  // Register issuer
  await issuerRegistry.registerIssuer(
    issuer.address,
    "US-OR",
    [ClaimTypes.LICENSE_OPERATOR, ClaimTypes.EDUCATION_DEGREE]
  );

  return {
    claimToken,
    issuerRegistry,
    owner,
    issuer,
    subject,
    other,
  };
}

/**
 * Deploy fixture for full system tests
 */
export async function deployFullSystemFixture() {
  const [owner, issuer, subject, beneficiary, other] = await ethers.getSigners();

  // Deploy all contracts
  const IssuerRegistry = await ethers.getContractFactory("IssuerRegistryUpgradeable");
  const issuerRegistry = await IssuerRegistry.deploy();

  const ClaimToken = await ethers.getContractFactory("ClaimTokenUpgradeable");
  const claimToken = await ClaimToken.deploy();

  const ZKDisclosureEngine = await ethers.getContractFactory("ZKDisclosureEngine");
  const zkEngine = await ZKDisclosureEngine.deploy();

  const LifecycleManager = await ethers.getContractFactory("CredentialLifecycleManagerUpgradeable");
  const lifecycleManager = await LifecycleManager.deploy();

  const FIEBridge = await ethers.getContractFactory("FIEBridge");
  const fieBridge = await FIEBridge.deploy();

  // Wait for deployments
  await Promise.all([
    issuerRegistry.waitForDeployment(),
    claimToken.waitForDeployment(),
    zkEngine.waitForDeployment(),
    lifecycleManager.waitForDeployment(),
    fieBridge.waitForDeployment(),
  ]);

  // Initialize and wire up contracts
  await issuerRegistry.initialize();
  await claimToken.initialize(await issuerRegistry.getAddress());
  await zkEngine.initialize(await claimToken.getAddress());
  await lifecycleManager.initialize(
    await claimToken.getAddress(),
    await issuerRegistry.getAddress()
  );
  await fieBridge.initialize(await lifecycleManager.getAddress());

  // Set cross-references
  await claimToken.setZKEngine(await zkEngine.getAddress());
  await claimToken.setLifecycleManager(await lifecycleManager.getAddress());
  await lifecycleManager.setFIEBridge(await fieBridge.getAddress());

  // Register issuer with multiple claim types
  await issuerRegistry.registerIssuer(issuer.address, "US-OR", [
    ClaimTypes.LICENSE_OPERATOR,
    ClaimTypes.EDUCATION_DEGREE,
    ClaimTypes.PROPERTY_DEED,
    ClaimTypes.HEALTH_IMMUNIZATION,
  ]);

  return {
    issuerRegistry,
    claimToken,
    zkEngine,
    lifecycleManager,
    fieBridge,
    owner,
    issuer,
    subject,
    beneficiary,
    other,
  };
}
