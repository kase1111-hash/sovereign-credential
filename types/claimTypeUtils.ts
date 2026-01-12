/**
 * @file Claim type utility functions for Sovereign Credential system
 * @description TypeScript helpers that mirror ClaimTypes.sol validation logic
 */

import { ClaimTypes, ClaimCategory, type ClaimTypeKey, type ClaimTypeValue } from "./credential";

// ============================================
// Category Ranges (matches ClaimTypes.sol)
// ============================================

const CategoryRanges = {
  IDENTITY: { min: 0x01, max: 0x0f },
  LICENSE: { min: 0x10, max: 0x1f },
  EDUCATION: { min: 0x20, max: 0x2f },
  PROPERTY: { min: 0x30, max: 0x3f },
  HEALTH: { min: 0x40, max: 0x4f },
  EMPLOYMENT: { min: 0x50, max: 0x5f },
  FINANCIAL: { min: 0x60, max: 0x6f },
  MEMBERSHIP: { min: 0x70, max: 0x7f },
  LEGAL: { min: 0x80, max: 0x8f },
  ACCESS: { min: 0x90, max: 0x9f },
  CUSTOM: { min: 0xf0, max: 0xff },
} as const;

// ============================================
// Claim Type Names (for display)
// ============================================

const ClaimTypeNames: Record<ClaimTypeKey, string> = {
  // Identity
  IDENTITY_BIRTH: "Birth Certificate",
  IDENTITY_CITIZENSHIP: "Citizenship",
  IDENTITY_RESIDENCE: "Proof of Residence",
  IDENTITY_GOVERNMENT_ID: "Government ID",
  IDENTITY_TAX_ID: "Tax ID",

  // License
  LICENSE_PROFESSIONAL: "Professional License",
  LICENSE_OPERATOR: "Operator License",
  LICENSE_CONTRACTOR: "Contractor License",
  LICENSE_BUSINESS: "Business License",
  LICENSE_FIREARMS: "Firearms License",

  // Education
  EDUCATION_DEGREE: "Academic Degree",
  EDUCATION_CERTIFICATION: "Certification",
  EDUCATION_COURSE: "Course Completion",
  EDUCATION_TRAINING: "Training Completion",
  EDUCATION_TRANSCRIPT: "Academic Transcript",

  // Property
  PROPERTY_DEED: "Property Deed",
  PROPERTY_TITLE: "Asset Title",
  PROPERTY_LIEN: "Lien Record",
  PROPERTY_LEASE: "Lease Agreement",
  PROPERTY_INTELLECTUAL: "Intellectual Property",

  // Health
  HEALTH_IMMUNIZATION: "Immunization Record",
  HEALTH_INSURANCE: "Health Insurance",
  HEALTH_PRESCRIPTION: "Prescription",
  HEALTH_TEST_RESULT: "Medical Test Result",
  HEALTH_DISABILITY: "Disability Certification",

  // Employment
  EMPLOYMENT_VERIFICATION: "Employment Verification",
  EMPLOYMENT_INCOME: "Income Verification",
  EMPLOYMENT_CLEARANCE: "Security Clearance",
  EMPLOYMENT_REFERENCE: "Professional Reference",

  // Financial
  FINANCIAL_ACCOUNT: "Bank Account Verification",
  FINANCIAL_CREDIT: "Credit Report",
  FINANCIAL_ACCREDITED: "Accredited Investor",
  FINANCIAL_FUNDS: "Proof of Funds",

  // Membership
  MEMBERSHIP_ORGANIZATION: "Organization Membership",
  MEMBERSHIP_DAO: "DAO Membership",
  MEMBERSHIP_CLUB: "Club Membership",
  MEMBERSHIP_ALUMNI: "Alumni Status",

  // Legal
  LEGAL_POA: "Power of Attorney",
  LEGAL_NOTARIZED: "Notarized Document",
  LEGAL_COURT_ORDER: "Court Order",
  LEGAL_STATUS: "Legal Status",

  // Access
  AGE_VERIFICATION: "Age Verification",
  ACCESS_BADGE: "Access Badge",
  ACCESS_EVENT: "Event Ticket",

  // Custom
  CUSTOM: "Custom Claim",
};

// ============================================
// Conversion Functions
// ============================================

/**
 * Convert a bytes32 hex string to its numeric type ID
 */
export function claimTypeToNumber(claimType: string): number {
  if (!claimType.startsWith("0x")) {
    throw new Error("Claim type must be a hex string starting with 0x");
  }
  return parseInt(claimType, 16);
}

/**
 * Convert a numeric type ID to bytes32 hex string
 */
export function numberToClaimType(typeId: number): string {
  if (typeId < 0 || typeId > 0xff) {
    throw new Error("Type ID must be between 0x00 and 0xFF");
  }
  return "0x" + typeId.toString(16).padStart(64, "0");
}

/**
 * Get the short hex representation (e.g., "0x11" instead of full bytes32)
 */
export function claimTypeToShortHex(claimType: string): string {
  const num = claimTypeToNumber(claimType);
  return "0x" + num.toString(16).padStart(2, "0");
}

// ============================================
// Validation Functions
// ============================================

/**
 * Check if a claim type is valid (within defined ranges)
 * Mirrors ClaimTypes.isValidClaimType()
 */
export function isValidClaimType(claimType: string): boolean {
  try {
    const typeId = claimTypeToNumber(claimType);
    return Object.values(CategoryRanges).some(
      (range) => typeId >= range.min && typeId <= range.max
    );
  } catch {
    return false;
  }
}

/**
 * Get the category for a claim type
 * Mirrors ClaimTypes.getCategory()
 */
export function getCategory(claimType: string): ClaimCategory {
  try {
    const typeId = claimTypeToNumber(claimType);

    if (typeId >= CategoryRanges.IDENTITY.min && typeId <= CategoryRanges.IDENTITY.max) {
      return ClaimCategory.IDENTITY;
    }
    if (typeId >= CategoryRanges.LICENSE.min && typeId <= CategoryRanges.LICENSE.max) {
      return ClaimCategory.LICENSE;
    }
    if (typeId >= CategoryRanges.EDUCATION.min && typeId <= CategoryRanges.EDUCATION.max) {
      return ClaimCategory.EDUCATION;
    }
    if (typeId >= CategoryRanges.PROPERTY.min && typeId <= CategoryRanges.PROPERTY.max) {
      return ClaimCategory.PROPERTY;
    }
    if (typeId >= CategoryRanges.HEALTH.min && typeId <= CategoryRanges.HEALTH.max) {
      return ClaimCategory.HEALTH;
    }
    if (typeId >= CategoryRanges.EMPLOYMENT.min && typeId <= CategoryRanges.EMPLOYMENT.max) {
      return ClaimCategory.EMPLOYMENT;
    }
    if (typeId >= CategoryRanges.FINANCIAL.min && typeId <= CategoryRanges.FINANCIAL.max) {
      return ClaimCategory.FINANCIAL;
    }
    if (typeId >= CategoryRanges.MEMBERSHIP.min && typeId <= CategoryRanges.MEMBERSHIP.max) {
      return ClaimCategory.MEMBERSHIP;
    }
    if (typeId >= CategoryRanges.LEGAL.min && typeId <= CategoryRanges.LEGAL.max) {
      return ClaimCategory.LEGAL;
    }
    if (typeId >= CategoryRanges.ACCESS.min && typeId <= CategoryRanges.ACCESS.max) {
      return ClaimCategory.ACCESS;
    }
    if (typeId >= CategoryRanges.CUSTOM.min && typeId <= CategoryRanges.CUSTOM.max) {
      return ClaimCategory.CUSTOM;
    }

    return ClaimCategory.UNKNOWN;
  } catch {
    return ClaimCategory.UNKNOWN;
  }
}

/**
 * Get the category name as a string
 */
export function getCategoryName(category: ClaimCategory): string {
  const names: Record<ClaimCategory, string> = {
    [ClaimCategory.UNKNOWN]: "Unknown",
    [ClaimCategory.IDENTITY]: "Identity",
    [ClaimCategory.LICENSE]: "License",
    [ClaimCategory.EDUCATION]: "Education",
    [ClaimCategory.PROPERTY]: "Property",
    [ClaimCategory.HEALTH]: "Health",
    [ClaimCategory.EMPLOYMENT]: "Employment",
    [ClaimCategory.FINANCIAL]: "Financial",
    [ClaimCategory.MEMBERSHIP]: "Membership",
    [ClaimCategory.LEGAL]: "Legal",
    [ClaimCategory.ACCESS]: "Access",
    [ClaimCategory.CUSTOM]: "Custom",
  };
  return names[category];
}

// ============================================
// Property Check Functions
// ============================================

/**
 * Check if a claim type is an identity claim
 * Mirrors ClaimTypes.isIdentityClaim()
 */
export function isIdentityClaim(claimType: string): boolean {
  return getCategory(claimType) === ClaimCategory.IDENTITY;
}

/**
 * Check if a claim type is a property claim
 * Mirrors ClaimTypes.isPropertyClaim()
 */
export function isPropertyClaim(claimType: string): boolean {
  return getCategory(claimType) === ClaimCategory.PROPERTY;
}

/**
 * Check if a claim type requires age-related ZK proofs
 * Mirrors ClaimTypes.requiresAgeProof()
 */
export function requiresAgeProof(claimType: string): boolean {
  return (
    claimType === ClaimTypes.IDENTITY_BIRTH ||
    claimType === ClaimTypes.AGE_VERIFICATION ||
    claimType === ClaimTypes.LICENSE_OPERATOR ||
    claimType === ClaimTypes.LICENSE_FIREARMS
  );
}

/**
 * Check if a claim type is typically non-transferable
 * Mirrors ClaimTypes.isNonTransferable()
 */
export function isNonTransferable(claimType: string): boolean {
  const category = getCategory(claimType);
  return (
    category === ClaimCategory.IDENTITY ||
    category === ClaimCategory.EDUCATION ||
    category === ClaimCategory.HEALTH ||
    category === ClaimCategory.EMPLOYMENT
  );
}

/**
 * Check if a claim type is splittable for inheritance
 * Mirrors ClaimTypes.isSplittable()
 */
export function isSplittable(claimType: string): boolean {
  return (
    claimType === ClaimTypes.PROPERTY_DEED ||
    claimType === ClaimTypes.PROPERTY_TITLE ||
    claimType === ClaimTypes.PROPERTY_INTELLECTUAL
  );
}

// ============================================
// Lookup Functions
// ============================================

/**
 * Get the human-readable name for a claim type
 * Mirrors ClaimTypes.getName()
 */
export function getClaimTypeName(claimType: string): string {
  // Find matching key
  const key = (Object.keys(ClaimTypes) as ClaimTypeKey[]).find(
    (k) => ClaimTypes[k] === claimType
  );

  if (key) {
    return ClaimTypeNames[key];
  }

  // Try to identify by category
  const category = getCategory(claimType);
  if (category !== ClaimCategory.UNKNOWN) {
    return `${getCategoryName(category)} Credential`;
  }

  return "Unknown";
}

/**
 * Get claim type by name
 */
export function getClaimTypeByName(name: ClaimTypeKey): ClaimTypeValue {
  return ClaimTypes[name];
}

/**
 * Get all claim types in a category
 */
export function getClaimTypesInCategory(category: ClaimCategory): ClaimTypeValue[] {
  return (Object.keys(ClaimTypes) as ClaimTypeKey[])
    .filter((key) => getCategory(ClaimTypes[key]) === category)
    .map((key) => ClaimTypes[key]);
}

/**
 * Get all available claim type keys
 */
export function getAllClaimTypeKeys(): ClaimTypeKey[] {
  return Object.keys(ClaimTypes) as ClaimTypeKey[];
}

/**
 * Get all claim types with their names
 */
export function getAllClaimTypesWithNames(): Array<{
  key: ClaimTypeKey;
  value: ClaimTypeValue;
  name: string;
  category: ClaimCategory;
}> {
  return getAllClaimTypeKeys().map((key) => ({
    key,
    value: ClaimTypes[key],
    name: ClaimTypeNames[key],
    category: getCategory(ClaimTypes[key]),
  }));
}

// ============================================
// Validation Helpers for Metadata
// ============================================

/**
 * Validate that a claim type string matches the schema pattern
 */
export function validateClaimTypeFormat(claimType: string): boolean {
  // Accept either short hex (0x11) or full bytes32
  const shortHexPattern = /^0x[0-9a-fA-F]{1,2}$/;
  const bytes32Pattern = /^0x[0-9a-fA-F]{64}$/;
  const namePattern = /^[A-Z_]+$/;

  return shortHexPattern.test(claimType) || bytes32Pattern.test(claimType) || namePattern.test(claimType);
}

/**
 * Normalize a claim type to full bytes32 format
 */
export function normalizeClaimType(claimType: string): string {
  // If it's a name, look it up
  if (/^[A-Z_]+$/.test(claimType)) {
    const key = claimType as ClaimTypeKey;
    if (key in ClaimTypes) {
      return ClaimTypes[key];
    }
    throw new Error(`Unknown claim type name: ${claimType}`);
  }

  // If it's short hex, expand it
  if (/^0x[0-9a-fA-F]{1,2}$/.test(claimType)) {
    const num = parseInt(claimType, 16);
    return numberToClaimType(num);
  }

  // If it's already bytes32, return as-is
  if (/^0x[0-9a-fA-F]{64}$/.test(claimType)) {
    return claimType.toLowerCase();
  }

  throw new Error(`Invalid claim type format: ${claimType}`);
}

// ============================================
// Export CategoryRanges for external use
// ============================================

export { CategoryRanges };
