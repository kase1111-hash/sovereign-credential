/**
 * @file Types index - exports all type definitions
 */

// Core types and interfaces
export {
  // Enums
  CredentialStatus,
  CredentialStatusNames,
  DisclosureType,
  DisclosureTypeNames,
  ClaimCategory,

  // Claim type constants
  ClaimTypes,
  type ClaimTypeKey,
  type ClaimTypeValue,

  // Core structs
  type Credential,
  type Issuer,
  type DisclosureRequest,
  type InheritanceDirective,
  type CrossReference,
  type MintRequest,
  type RenewalRequest,

  // Metadata types
  type IssuerMetadata,
  type DisplayField,
  type DisclosureSchema,
  type ValidityRules,
  type CredentialMetadata,

  // Helper types
  type CredentialWithMetadata,
  type DecryptedCredential,
  type Proof,

  // Constants
  Constants,

  // Type guards
  isValidCredentialStatus,
  isValidDisclosureType,
  isValidAddress,
  isValidBytes32,
} from "./credential";

// Claim type utilities
export {
  // Conversion functions
  claimTypeToNumber,
  numberToClaimType,
  claimTypeToShortHex,

  // Validation functions
  isValidClaimType,
  getCategory,
  getCategoryName,

  // Property check functions
  isIdentityClaim,
  isPropertyClaim,
  requiresAgeProof,
  isNonTransferable,
  isSplittable,

  // Lookup functions
  getClaimTypeName,
  getClaimTypeByName,
  getClaimTypesInCategory,
  getAllClaimTypeKeys,
  getAllClaimTypesWithNames,

  // Metadata helpers
  validateClaimTypeFormat,
  normalizeClaimType,

  // Category ranges
  CategoryRanges,
} from "./claimTypeUtils";
