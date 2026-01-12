/**
 * @file Test fixtures index
 * @description Re-exports all test fixtures for easy importing
 */

// Credential fixtures
export {
  // Sample payloads
  sampleDriverLicensePayload,
  sampleDegreePayload,
  samplePropertyDeedPayload,

  // Factory functions
  createMintRequest,
  createCredential,
  createDriverLicenseMintRequest,
  createDegreeMintRequest,
  createPropertyDeedMintRequest,
  createExpiredCredential,
  createRevokedCredential,
  createSuspendedCredential,

  // Metadata fixtures
  createCredentialMetadata,

  // Batch fixtures
  createBatchMintRequests,
  createCredentialsWithAllStatuses,

  // Commitment fixtures
  createTestCommitments,

  // Deployment fixtures
  deployClaimTokenFixture,
  deployFullSystemFixture,
} from "./credentialFixtures";

// Issuer fixtures
export {
  // Sample issuers
  oregonDMV,
  stanfordUniversity,
  caRealEstateBoard,
  cdcHealth,

  // Factory functions
  createIssuer,
  createFullyAuthorizedIssuer,
  createLowReputationIssuer,
  createInactiveIssuer,
  createIssuerWithDelegates,
  createHighActivityIssuer,
  createDisputedIssuer,

  // Category-specific issuers
  createGovernmentIssuer,
  createEducationIssuer,
  createHealthcareIssuer,
  createFinancialIssuer,

  // Batch fixtures
  createMultipleIssuers,
  createIssuersWithVaryingReputation,

  // Deployment fixtures
  deployIssuerRegistryFixture,
  deployIssuerRegistryWithIssuersFixture,

  // Test data generators
  generateRandomIssuerData,

  // Jurisdictions
  Jurisdictions,
  type Jurisdiction,
} from "./issuerFixtures";
