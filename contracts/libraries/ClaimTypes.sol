// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.28;

/**
 * @title ClaimTypes
 * @notice Claim type constants and validation for the Sovereign Credential system
 * @dev Claim type IDs match SPEC.md Section 1.3
 */
library ClaimTypes {
    // ============================================
    // Identity Claims (0x01 - 0x0F)
    // ============================================

    /// @notice Birth certificate / proof of birth
    bytes32 public constant IDENTITY_BIRTH = bytes32(uint256(0x01));

    /// @notice Citizenship or nationality
    bytes32 public constant IDENTITY_CITIZENSHIP = bytes32(uint256(0x02));

    /// @notice Proof of address or residence
    bytes32 public constant IDENTITY_RESIDENCE = bytes32(uint256(0x03));

    /// @notice Government-issued ID (passport, national ID)
    bytes32 public constant IDENTITY_GOVERNMENT_ID = bytes32(uint256(0x04));

    /// @notice Social security or tax ID
    bytes32 public constant IDENTITY_TAX_ID = bytes32(uint256(0x05));

    // ============================================
    // License Claims (0x10 - 0x1F)
    // ============================================

    /// @notice Professional license (medical, legal, etc.)
    bytes32 public constant LICENSE_PROFESSIONAL = bytes32(uint256(0x10));

    /// @notice Operator license (driver, pilot, etc.)
    bytes32 public constant LICENSE_OPERATOR = bytes32(uint256(0x11));

    /// @notice Contractor or trade license
    bytes32 public constant LICENSE_CONTRACTOR = bytes32(uint256(0x12));

    /// @notice Business license
    bytes32 public constant LICENSE_BUSINESS = bytes32(uint256(0x13));

    /// @notice Firearms or weapons license
    bytes32 public constant LICENSE_FIREARMS = bytes32(uint256(0x14));

    // ============================================
    // Education Claims (0x20 - 0x2F)
    // ============================================

    /// @notice Academic degree (bachelor's, master's, PhD)
    bytes32 public constant EDUCATION_DEGREE = bytes32(uint256(0x20));

    /// @notice Professional certification
    bytes32 public constant EDUCATION_CERTIFICATION = bytes32(uint256(0x21));

    /// @notice Course completion
    bytes32 public constant EDUCATION_COURSE = bytes32(uint256(0x22));

    /// @notice Training completion
    bytes32 public constant EDUCATION_TRAINING = bytes32(uint256(0x23));

    /// @notice Academic transcript
    bytes32 public constant EDUCATION_TRANSCRIPT = bytes32(uint256(0x24));

    // ============================================
    // Property Claims (0x30 - 0x3F)
    // ============================================

    /// @notice Real property ownership (deed)
    bytes32 public constant PROPERTY_DEED = bytes32(uint256(0x30));

    /// @notice Vehicle or asset title
    bytes32 public constant PROPERTY_TITLE = bytes32(uint256(0x31));

    /// @notice Lien or encumbrance record
    bytes32 public constant PROPERTY_LIEN = bytes32(uint256(0x32));

    /// @notice Lease agreement
    bytes32 public constant PROPERTY_LEASE = bytes32(uint256(0x33));

    /// @notice Intellectual property registration
    bytes32 public constant PROPERTY_INTELLECTUAL = bytes32(uint256(0x34));

    // ============================================
    // Health Claims (0x40 - 0x4F)
    // ============================================

    /// @notice Vaccination record
    bytes32 public constant HEALTH_IMMUNIZATION = bytes32(uint256(0x40));

    /// @notice Insurance coverage credential
    bytes32 public constant HEALTH_INSURANCE = bytes32(uint256(0x41));

    /// @notice Prescription authorization
    bytes32 public constant HEALTH_PRESCRIPTION = bytes32(uint256(0x42));

    /// @notice Medical test result
    bytes32 public constant HEALTH_TEST_RESULT = bytes32(uint256(0x43));

    /// @notice Disability certification
    bytes32 public constant HEALTH_DISABILITY = bytes32(uint256(0x44));

    // ============================================
    // Employment Claims (0x50 - 0x5F)
    // ============================================

    /// @notice Employment verification
    bytes32 public constant EMPLOYMENT_VERIFICATION = bytes32(uint256(0x50));

    /// @notice Income verification
    bytes32 public constant EMPLOYMENT_INCOME = bytes32(uint256(0x51));

    /// @notice Security clearance
    bytes32 public constant EMPLOYMENT_CLEARANCE = bytes32(uint256(0x52));

    /// @notice Professional reference
    bytes32 public constant EMPLOYMENT_REFERENCE = bytes32(uint256(0x53));

    // ============================================
    // Financial Claims (0x60 - 0x6F)
    // ============================================

    /// @notice Bank account verification
    bytes32 public constant FINANCIAL_ACCOUNT = bytes32(uint256(0x60));

    /// @notice Credit score/report
    bytes32 public constant FINANCIAL_CREDIT = bytes32(uint256(0x61));

    /// @notice Accredited investor status
    bytes32 public constant FINANCIAL_ACCREDITED = bytes32(uint256(0x62));

    /// @notice Proof of funds
    bytes32 public constant FINANCIAL_FUNDS = bytes32(uint256(0x63));

    // ============================================
    // Membership Claims (0x70 - 0x7F)
    // ============================================

    /// @notice Organization membership
    bytes32 public constant MEMBERSHIP_ORGANIZATION = bytes32(uint256(0x70));

    /// @notice DAO membership/voting rights
    bytes32 public constant MEMBERSHIP_DAO = bytes32(uint256(0x71));

    /// @notice Club or association membership
    bytes32 public constant MEMBERSHIP_CLUB = bytes32(uint256(0x72));

    /// @notice Alumni status
    bytes32 public constant MEMBERSHIP_ALUMNI = bytes32(uint256(0x73));

    // ============================================
    // Legal Claims (0x80 - 0x8F)
    // ============================================

    /// @notice Power of attorney
    bytes32 public constant LEGAL_POA = bytes32(uint256(0x80));

    /// @notice Notarized document
    bytes32 public constant LEGAL_NOTARIZED = bytes32(uint256(0x81));

    /// @notice Court order or judgment
    bytes32 public constant LEGAL_COURT_ORDER = bytes32(uint256(0x82));

    /// @notice Legal status (marriage, divorce, etc.)
    bytes32 public constant LEGAL_STATUS = bytes32(uint256(0x83));

    // ============================================
    // Age/Access Claims (0x90 - 0x9F)
    // ============================================

    /// @notice Age verification (over 18, over 21, etc.)
    bytes32 public constant AGE_VERIFICATION = bytes32(uint256(0x90));

    /// @notice Access badge/permission
    bytes32 public constant ACCESS_BADGE = bytes32(uint256(0x91));

    /// @notice Event ticket/admission
    bytes32 public constant ACCESS_EVENT = bytes32(uint256(0x92));

    // ============================================
    // Custom/Reserved (0xF0 - 0xFF)
    // ============================================

    /// @notice Custom claim type (schema in metadata)
    bytes32 public constant CUSTOM = bytes32(uint256(0xFF));

    // ============================================
    // Category Ranges
    // ============================================

    uint256 private constant IDENTITY_MIN = 0x01;
    uint256 private constant IDENTITY_MAX = 0x0F;
    uint256 private constant LICENSE_MIN = 0x10;
    uint256 private constant LICENSE_MAX = 0x1F;
    uint256 private constant EDUCATION_MIN = 0x20;
    uint256 private constant EDUCATION_MAX = 0x2F;
    uint256 private constant PROPERTY_MIN = 0x30;
    uint256 private constant PROPERTY_MAX = 0x3F;
    uint256 private constant HEALTH_MIN = 0x40;
    uint256 private constant HEALTH_MAX = 0x4F;
    uint256 private constant EMPLOYMENT_MIN = 0x50;
    uint256 private constant EMPLOYMENT_MAX = 0x5F;
    uint256 private constant FINANCIAL_MIN = 0x60;
    uint256 private constant FINANCIAL_MAX = 0x6F;
    uint256 private constant MEMBERSHIP_MIN = 0x70;
    uint256 private constant MEMBERSHIP_MAX = 0x7F;
    uint256 private constant LEGAL_MIN = 0x80;
    uint256 private constant LEGAL_MAX = 0x8F;
    uint256 private constant ACCESS_MIN = 0x90;
    uint256 private constant ACCESS_MAX = 0x9F;
    uint256 private constant CUSTOM_MIN = 0xF0;
    uint256 private constant CUSTOM_MAX = 0xFF;

    // ============================================
    // Category Enum
    // ============================================

    enum Category {
        UNKNOWN,
        IDENTITY,
        LICENSE,
        EDUCATION,
        PROPERTY,
        HEALTH,
        EMPLOYMENT,
        FINANCIAL,
        MEMBERSHIP,
        LEGAL,
        ACCESS,
        CUSTOM
    }

    // ============================================
    // Validation Functions
    // ============================================

    /**
     * @notice Check if a claim type is valid (within defined ranges)
     * @param claimType The claim type to validate
     * @return valid True if the claim type is valid
     */
    function isValidClaimType(bytes32 claimType) internal pure returns (bool valid) {
        uint256 typeId = uint256(claimType);

        // Check if within any valid range
        return (typeId >= IDENTITY_MIN && typeId <= IDENTITY_MAX) ||
               (typeId >= LICENSE_MIN && typeId <= LICENSE_MAX) ||
               (typeId >= EDUCATION_MIN && typeId <= EDUCATION_MAX) ||
               (typeId >= PROPERTY_MIN && typeId <= PROPERTY_MAX) ||
               (typeId >= HEALTH_MIN && typeId <= HEALTH_MAX) ||
               (typeId >= EMPLOYMENT_MIN && typeId <= EMPLOYMENT_MAX) ||
               (typeId >= FINANCIAL_MIN && typeId <= FINANCIAL_MAX) ||
               (typeId >= MEMBERSHIP_MIN && typeId <= MEMBERSHIP_MAX) ||
               (typeId >= LEGAL_MIN && typeId <= LEGAL_MAX) ||
               (typeId >= ACCESS_MIN && typeId <= ACCESS_MAX) ||
               (typeId >= CUSTOM_MIN && typeId <= CUSTOM_MAX);
    }

    /**
     * @notice Get the category for a claim type
     * @param claimType The claim type to categorize
     * @return category The category enum value
     */
    function getCategory(bytes32 claimType) internal pure returns (Category category) {
        uint256 typeId = uint256(claimType);

        if (typeId >= IDENTITY_MIN && typeId <= IDENTITY_MAX) {
            return Category.IDENTITY;
        } else if (typeId >= LICENSE_MIN && typeId <= LICENSE_MAX) {
            return Category.LICENSE;
        } else if (typeId >= EDUCATION_MIN && typeId <= EDUCATION_MAX) {
            return Category.EDUCATION;
        } else if (typeId >= PROPERTY_MIN && typeId <= PROPERTY_MAX) {
            return Category.PROPERTY;
        } else if (typeId >= HEALTH_MIN && typeId <= HEALTH_MAX) {
            return Category.HEALTH;
        } else if (typeId >= EMPLOYMENT_MIN && typeId <= EMPLOYMENT_MAX) {
            return Category.EMPLOYMENT;
        } else if (typeId >= FINANCIAL_MIN && typeId <= FINANCIAL_MAX) {
            return Category.FINANCIAL;
        } else if (typeId >= MEMBERSHIP_MIN && typeId <= MEMBERSHIP_MAX) {
            return Category.MEMBERSHIP;
        } else if (typeId >= LEGAL_MIN && typeId <= LEGAL_MAX) {
            return Category.LEGAL;
        } else if (typeId >= ACCESS_MIN && typeId <= ACCESS_MAX) {
            return Category.ACCESS;
        } else if (typeId >= CUSTOM_MIN && typeId <= CUSTOM_MAX) {
            return Category.CUSTOM;
        } else {
            return Category.UNKNOWN;
        }
    }

    /**
     * @notice Check if a claim type is an identity claim
     * @param claimType The claim type to check
     * @return isIdentity True if identity category
     */
    function isIdentityClaim(bytes32 claimType) internal pure returns (bool isIdentity) {
        uint256 typeId = uint256(claimType);
        return typeId >= IDENTITY_MIN && typeId <= IDENTITY_MAX;
    }

    /**
     * @notice Check if a claim type is a property claim (potentially splittable)
     * @param claimType The claim type to check
     * @return isProperty True if property category
     */
    function isPropertyClaim(bytes32 claimType) internal pure returns (bool isProperty) {
        uint256 typeId = uint256(claimType);
        return typeId >= PROPERTY_MIN && typeId <= PROPERTY_MAX;
    }

    /**
     * @notice Check if a claim type requires age-related ZK proofs
     * @param claimType The claim type to check
     * @return requiresAge True if age proofs are relevant
     */
    function requiresAgeProof(bytes32 claimType) internal pure returns (bool requiresAge) {
        return claimType == IDENTITY_BIRTH ||
               claimType == AGE_VERIFICATION ||
               claimType == LICENSE_OPERATOR ||
               claimType == LICENSE_FIREARMS;
    }

    /**
     * @notice Check if a claim type is typically non-transferable
     * @param claimType The claim type to check
     * @return nonTransferable True if credential should not be transferred
     */
    function isNonTransferable(bytes32 claimType) internal pure returns (bool nonTransferable) {
        uint256 typeId = uint256(claimType);

        // Identity claims are bound to the subject
        if (typeId >= IDENTITY_MIN && typeId <= IDENTITY_MAX) {
            return true;
        }

        // Education credentials are bound to the recipient
        if (typeId >= EDUCATION_MIN && typeId <= EDUCATION_MAX) {
            return true;
        }

        // Health records are bound to the patient
        if (typeId >= HEALTH_MIN && typeId <= HEALTH_MAX) {
            return true;
        }

        // Employment records are bound to the employee
        if (typeId >= EMPLOYMENT_MIN && typeId <= EMPLOYMENT_MAX) {
            return true;
        }

        return false;
    }

    /**
     * @notice Check if a claim type is splittable for inheritance
     * @param claimType The claim type to check
     * @return splittable True if credential can be split
     */
    function isSplittable(bytes32 claimType) internal pure returns (bool splittable) {
        // Only property claims are splittable
        return claimType == PROPERTY_DEED ||
               claimType == PROPERTY_TITLE ||
               claimType == PROPERTY_INTELLECTUAL;
    }

    /**
     * @notice Get a human-readable name for a claim type
     * @param claimType The claim type
     * @return name String name of the claim type
     */
    function getName(bytes32 claimType) internal pure returns (string memory name) {
        // Identity
        if (claimType == IDENTITY_BIRTH) return "Birth Certificate";
        if (claimType == IDENTITY_CITIZENSHIP) return "Citizenship";
        if (claimType == IDENTITY_RESIDENCE) return "Proof of Residence";
        if (claimType == IDENTITY_GOVERNMENT_ID) return "Government ID";
        if (claimType == IDENTITY_TAX_ID) return "Tax ID";

        // License
        if (claimType == LICENSE_PROFESSIONAL) return "Professional License";
        if (claimType == LICENSE_OPERATOR) return "Operator License";
        if (claimType == LICENSE_CONTRACTOR) return "Contractor License";
        if (claimType == LICENSE_BUSINESS) return "Business License";
        if (claimType == LICENSE_FIREARMS) return "Firearms License";

        // Education
        if (claimType == EDUCATION_DEGREE) return "Academic Degree";
        if (claimType == EDUCATION_CERTIFICATION) return "Certification";
        if (claimType == EDUCATION_COURSE) return "Course Completion";
        if (claimType == EDUCATION_TRAINING) return "Training Completion";
        if (claimType == EDUCATION_TRANSCRIPT) return "Academic Transcript";

        // Property
        if (claimType == PROPERTY_DEED) return "Property Deed";
        if (claimType == PROPERTY_TITLE) return "Asset Title";
        if (claimType == PROPERTY_LIEN) return "Lien Record";
        if (claimType == PROPERTY_LEASE) return "Lease Agreement";
        if (claimType == PROPERTY_INTELLECTUAL) return "Intellectual Property";

        // Health
        if (claimType == HEALTH_IMMUNIZATION) return "Immunization Record";
        if (claimType == HEALTH_INSURANCE) return "Health Insurance";
        if (claimType == HEALTH_PRESCRIPTION) return "Prescription";
        if (claimType == HEALTH_TEST_RESULT) return "Medical Test Result";
        if (claimType == HEALTH_DISABILITY) return "Disability Certification";

        // Employment
        if (claimType == EMPLOYMENT_VERIFICATION) return "Employment Verification";
        if (claimType == EMPLOYMENT_INCOME) return "Income Verification";
        if (claimType == EMPLOYMENT_CLEARANCE) return "Security Clearance";
        if (claimType == EMPLOYMENT_REFERENCE) return "Professional Reference";

        // Financial
        if (claimType == FINANCIAL_ACCOUNT) return "Bank Account Verification";
        if (claimType == FINANCIAL_CREDIT) return "Credit Report";
        if (claimType == FINANCIAL_ACCREDITED) return "Accredited Investor";
        if (claimType == FINANCIAL_FUNDS) return "Proof of Funds";

        // Membership
        if (claimType == MEMBERSHIP_ORGANIZATION) return "Organization Membership";
        if (claimType == MEMBERSHIP_DAO) return "DAO Membership";
        if (claimType == MEMBERSHIP_CLUB) return "Club Membership";
        if (claimType == MEMBERSHIP_ALUMNI) return "Alumni Status";

        // Legal
        if (claimType == LEGAL_POA) return "Power of Attorney";
        if (claimType == LEGAL_NOTARIZED) return "Notarized Document";
        if (claimType == LEGAL_COURT_ORDER) return "Court Order";
        if (claimType == LEGAL_STATUS) return "Legal Status";

        // Access
        if (claimType == AGE_VERIFICATION) return "Age Verification";
        if (claimType == ACCESS_BADGE) return "Access Badge";
        if (claimType == ACCESS_EVENT) return "Event Ticket";

        // Custom
        if (claimType == CUSTOM) return "Custom Claim";

        return "Unknown";
    }
}
