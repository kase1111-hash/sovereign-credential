/**
 * @file Test fixtures for issuer-related tests
 * @description Provides reusable issuer data and factory functions
 */

import { ethers } from "hardhat";
import { type Signer } from "ethers";
import { ClaimTypes, type Issuer, Constants } from "../../types";

// ============================================
// Sample Issuer Data
// ============================================

/**
 * Sample issuer: Oregon DMV
 */
export const oregonDMV = {
  name: "Oregon Department of Motor Vehicles",
  jurisdiction: "US-OR",
  authorizedTypes: [
    ClaimTypes.LICENSE_OPERATOR,
    ClaimTypes.IDENTITY_RESIDENCE,
  ],
  url: "https://www.oregon.gov/odot/dmv",
};

/**
 * Sample issuer: Stanford University
 */
export const stanfordUniversity = {
  name: "Stanford University",
  jurisdiction: "US-CA",
  authorizedTypes: [
    ClaimTypes.EDUCATION_DEGREE,
    ClaimTypes.EDUCATION_CERTIFICATION,
    ClaimTypes.EDUCATION_TRANSCRIPT,
  ],
  url: "https://www.stanford.edu",
};

/**
 * Sample issuer: California Real Estate Board
 */
export const caRealEstateBoard = {
  name: "California Bureau of Real Estate",
  jurisdiction: "US-CA",
  authorizedTypes: [
    ClaimTypes.PROPERTY_DEED,
    ClaimTypes.PROPERTY_TITLE,
    ClaimTypes.PROPERTY_LIEN,
  ],
  url: "https://www.dre.ca.gov",
};

/**
 * Sample issuer: CDC (Health)
 */
export const cdcHealth = {
  name: "Centers for Disease Control and Prevention",
  jurisdiction: "US",
  authorizedTypes: [
    ClaimTypes.HEALTH_IMMUNIZATION,
    ClaimTypes.HEALTH_TEST_RESULT,
  ],
  url: "https://www.cdc.gov",
};

// ============================================
// Issuer Factory Functions
// ============================================

/**
 * Create a basic issuer struct for testing
 */
export function createIssuer(overrides: Partial<Issuer> = {}): Issuer {
  return {
    issuerAddress: "0x0000000000000000000000000000000000000001",
    authorizedTypes: [ClaimTypes.LICENSE_OPERATOR],
    jurisdiction: "US-OR",
    reputationScore: Constants.INITIAL_REPUTATION,
    totalIssued: 0n,
    totalRevoked: 0n,
    totalDisputed: 0n,
    isActive: true,
    delegates: [],
    ...overrides,
  };
}

/**
 * Create an issuer with full authorization for all claim types
 */
export function createFullyAuthorizedIssuer(address: string): Issuer {
  return createIssuer({
    issuerAddress: address,
    authorizedTypes: Object.values(ClaimTypes),
    reputationScore: Constants.MAX_REPUTATION,
  });
}

/**
 * Create an issuer with low reputation (below threshold)
 */
export function createLowReputationIssuer(address: string): Issuer {
  return createIssuer({
    issuerAddress: address,
    reputationScore: Constants.MIN_REPUTATION - 1n,
  });
}

/**
 * Create an inactive issuer
 */
export function createInactiveIssuer(address: string): Issuer {
  return createIssuer({
    issuerAddress: address,
    isActive: false,
  });
}

/**
 * Create an issuer with delegates
 */
export function createIssuerWithDelegates(
  address: string,
  delegates: string[]
): Issuer {
  return createIssuer({
    issuerAddress: address,
    delegates,
  });
}

/**
 * Create an issuer with high activity (many issuances)
 */
export function createHighActivityIssuer(address: string): Issuer {
  return createIssuer({
    issuerAddress: address,
    totalIssued: 10000n,
    totalRevoked: 50n,
    totalDisputed: 10n,
    reputationScore: 9500n, // Very high reputation
  });
}

/**
 * Create an issuer with disputes
 */
export function createDisputedIssuer(address: string): Issuer {
  return createIssuer({
    issuerAddress: address,
    totalIssued: 100n,
    totalRevoked: 20n,
    totalDisputed: 30n,
    reputationScore: 3000n, // Damaged reputation
  });
}

// ============================================
// Jurisdiction Constants
// ============================================

export const Jurisdictions = {
  // United States
  US: "US",
  US_FEDERAL: "US-FED",
  US_CALIFORNIA: "US-CA",
  US_OREGON: "US-OR",
  US_WASHINGTON: "US-WA",
  US_NEW_YORK: "US-NY",
  US_TEXAS: "US-TX",

  // European Union
  EU: "EU",
  EU_GERMANY: "EU-DE",
  EU_FRANCE: "EU-FR",
  EU_NETHERLANDS: "EU-NL",

  // Other
  UK: "UK",
  CANADA: "CA",
  AUSTRALIA: "AU",
  JAPAN: "JP",

  // Global/International
  GLOBAL: "GLOBAL",
  INTERNATIONAL: "INTL",
} as const;

export type Jurisdiction = (typeof Jurisdictions)[keyof typeof Jurisdictions];

// ============================================
// Issuer Categories
// ============================================

/**
 * Create a government issuer (DMV, passport office, etc.)
 */
export function createGovernmentIssuer(
  address: string,
  jurisdiction: Jurisdiction
): Issuer {
  return createIssuer({
    issuerAddress: address,
    jurisdiction,
    authorizedTypes: [
      ClaimTypes.IDENTITY_BIRTH,
      ClaimTypes.IDENTITY_CITIZENSHIP,
      ClaimTypes.IDENTITY_RESIDENCE,
      ClaimTypes.IDENTITY_GOVERNMENT_ID,
      ClaimTypes.LICENSE_OPERATOR,
    ],
    reputationScore: Constants.MAX_REPUTATION, // Government issuers start with max reputation
  });
}

/**
 * Create an educational institution issuer
 */
export function createEducationIssuer(
  address: string,
  jurisdiction: Jurisdiction
): Issuer {
  return createIssuer({
    issuerAddress: address,
    jurisdiction,
    authorizedTypes: [
      ClaimTypes.EDUCATION_DEGREE,
      ClaimTypes.EDUCATION_CERTIFICATION,
      ClaimTypes.EDUCATION_COURSE,
      ClaimTypes.EDUCATION_TRAINING,
      ClaimTypes.EDUCATION_TRANSCRIPT,
    ],
    reputationScore: 8000n, // High but not max
  });
}

/**
 * Create a healthcare issuer
 */
export function createHealthcareIssuer(
  address: string,
  jurisdiction: Jurisdiction
): Issuer {
  return createIssuer({
    issuerAddress: address,
    jurisdiction,
    authorizedTypes: [
      ClaimTypes.HEALTH_IMMUNIZATION,
      ClaimTypes.HEALTH_INSURANCE,
      ClaimTypes.HEALTH_PRESCRIPTION,
      ClaimTypes.HEALTH_TEST_RESULT,
      ClaimTypes.HEALTH_DISABILITY,
    ],
    reputationScore: 8500n,
  });
}

/**
 * Create a financial institution issuer
 */
export function createFinancialIssuer(
  address: string,
  jurisdiction: Jurisdiction
): Issuer {
  return createIssuer({
    issuerAddress: address,
    jurisdiction,
    authorizedTypes: [
      ClaimTypes.FINANCIAL_ACCOUNT,
      ClaimTypes.FINANCIAL_CREDIT,
      ClaimTypes.FINANCIAL_ACCREDITED,
      ClaimTypes.FINANCIAL_FUNDS,
    ],
    reputationScore: 7500n,
  });
}

// ============================================
// Batch Fixtures
// ============================================

/**
 * Create multiple issuers for testing
 */
export function createMultipleIssuers(addresses: string[]): Issuer[] {
  const jurisdictions = Object.values(Jurisdictions);

  return addresses.map((address, index) =>
    createIssuer({
      issuerAddress: address,
      jurisdiction: jurisdictions[index % jurisdictions.length] ?? "US",
      reputationScore: BigInt(5000 + index * 500), // Varying reputations
    })
  );
}

/**
 * Create issuers with all reputation levels for testing thresholds
 */
export function createIssuersWithVaryingReputation(
  addresses: string[]
): Issuer[] {
  const reputations = [0n, 500n, 1000n, 2500n, 5000n, 7500n, 9000n, 10000n];

  return addresses.slice(0, reputations.length).map((address, index) =>
    createIssuer({
      issuerAddress: address,
      reputationScore: reputations[index] ?? 5000n,
    })
  );
}

// ============================================
// Hardhat Deployment Fixtures
// ============================================

/**
 * Deploy fixture for IssuerRegistry tests
 */
export async function deployIssuerRegistryFixture() {
  const [owner, registrar, arbiter, issuer1, issuer2, delegate1, delegate2, other] =
    await ethers.getSigners();

  // Deploy IssuerRegistry
  const IssuerRegistry = await ethers.getContractFactory("IssuerRegistryUpgradeable");
  const issuerRegistry = await IssuerRegistry.deploy();
  await issuerRegistry.waitForDeployment();

  // Initialize
  await issuerRegistry.initialize();

  // Grant roles
  const REGISTRAR_ROLE = await issuerRegistry.REGISTRAR_ROLE();
  const ARBITER_ROLE = await issuerRegistry.ARBITER_ROLE();

  await issuerRegistry.grantRole(REGISTRAR_ROLE, registrar.address);
  await issuerRegistry.grantRole(ARBITER_ROLE, arbiter.address);

  return {
    issuerRegistry,
    owner,
    registrar,
    arbiter,
    issuer1,
    issuer2,
    delegate1,
    delegate2,
    other,
    REGISTRAR_ROLE,
    ARBITER_ROLE,
  };
}

/**
 * Deploy fixture with pre-registered issuers
 */
export async function deployIssuerRegistryWithIssuersFixture() {
  const fixture = await deployIssuerRegistryFixture();
  const { issuerRegistry, registrar, issuer1, issuer2 } = fixture;

  // Register issuers
  await issuerRegistry
    .connect(registrar)
    .registerIssuer(issuer1.address, "US-OR", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.IDENTITY_RESIDENCE,
    ]);

  await issuerRegistry
    .connect(registrar)
    .registerIssuer(issuer2.address, "US-CA", [
      ClaimTypes.EDUCATION_DEGREE,
      ClaimTypes.EDUCATION_CERTIFICATION,
    ]);

  return fixture;
}

// ============================================
// Test Data Generators
// ============================================

/**
 * Generate random issuer data for fuzz testing
 */
export function generateRandomIssuerData(): {
  jurisdiction: Jurisdiction;
  authorizedTypes: string[];
  initialReputation: bigint;
} {
  const jurisdictions = Object.values(Jurisdictions);
  const allClaimTypes = Object.values(ClaimTypes);

  // Random jurisdiction
  const jurisdiction =
    jurisdictions[Math.floor(Math.random() * jurisdictions.length)] ?? "US";

  // Random subset of claim types (1-5 types)
  const numTypes = Math.floor(Math.random() * 5) + 1;
  const shuffled = [...allClaimTypes].sort(() => Math.random() - 0.5);
  const authorizedTypes = shuffled.slice(0, numTypes);

  // Random reputation (1000-10000)
  const initialReputation = BigInt(
    Math.floor(Math.random() * 9000) + 1000
  );

  return {
    jurisdiction,
    authorizedTypes,
    initialReputation,
  };
}
