# Sovereign Credential Issuer Guide

This guide explains how to become a credential issuer and manage credentials in the Sovereign Credential system.

## Overview

As an issuer, you can:
- Issue verifiable credentials as NFTs
- Revoke credentials when necessary
- Approve credential renewals
- Build reputation through responsible issuance

## Getting Started

### Prerequisites

1. **Ethereum Wallet**: A wallet with admin/issuer capabilities
2. **ETH for Gas**: Sufficient ETH for transactions
3. **Authorization**: Must be registered by system administrator

### Becoming an Issuer

Contact the system administrator to register as an issuer:

```bash
# Administrator registers you as an issuer
ISSUER_ADDRESS=0xYourAddress \
JURISDICTION=US-CA \
CLAIM_TYPES=LICENSE.PROFESSIONAL,EDUCATION.DEGREE \
npx hardhat run scripts/setup-issuer.ts --network <network>
```

Registration includes:
- Your issuer address
- Jurisdiction code (e.g., "US-CA", "EU", "GLOBAL")
- Authorized claim types

## Issuing Credentials

### Using Scripts

```bash
# Set environment variables
export SUBJECT_ADDRESS=0xRecipientAddress
export CLAIM_TYPE=LICENSE.PROFESSIONAL
export EXPIRY_DAYS=365

# Mint the credential
npx hardhat run scripts/mint-credential.ts --network <network>
```

### Programmatically

```typescript
import { ethers } from "ethers";

// Connect to contracts
const claimToken = await ethers.getContractAt("ClaimToken", CLAIM_TOKEN_ADDRESS);

// Prepare credential data
const subject = "0x...";  // Recipient address
const claimType = ethers.keccak256(ethers.toUtf8Bytes("LICENSE.PROFESSIONAL"));
const expiresAt = Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60); // 1 year

// Encrypt the credential payload
const credentialData = {
    licenseNumber: "PRO-12345",
    issuedDate: "2024-01-15",
    profession: "Software Engineer"
};
const encryptedPayload = await encryptPayload(credentialData, subject);

// Generate commitment for ZK proofs
const commitment = generatePoseidonHash(credentialData);

// Mint the credential
const tx = await claimToken.mint(
    subject,
    claimType,
    encryptedPayload,
    [commitment],
    expiresAt
);

console.log("Credential minted:", tx.hash);
```

### Credential Data Structure

```typescript
interface CredentialPayload {
    // Required
    type: string;           // Claim type identifier
    issuedAt: string;       // ISO date string

    // Type-specific fields
    licenseNumber?: string;
    dateOfBirth?: string;
    degree?: string;
    institution?: string;
    // ... other fields based on claim type
}
```

## Best Practices

### Data Encryption

Always encrypt sensitive data before minting:

```typescript
import { encrypt } from "@sovereign-credential/sdk";

// Encrypt with subject's public key
const encrypted = await encrypt(credentialData, subjectPublicKey);

// The subject can decrypt with their private key
```

### Commitment Generation

Generate Poseidon hash commitments for ZK proofs:

```typescript
import { poseidonHash } from "@sovereign-credential/sdk";

// Hash each field that may need ZK disclosure
const birthdateCommitment = poseidonHash([birthdate, salt]);
const ageCommitment = poseidonHash([age, salt]);

// Include commitments in mint call
const commitments = [birthdateCommitment, ageCommitment];
```

### Expiry Times

Set appropriate expiry times:
- Professional licenses: 1-5 years
- Educational degrees: No expiry (use far future date)
- Certifications: Per certification validity
- Memberships: Annual

## Managing Credentials

### Revoking Credentials

Revoke a credential when it should no longer be valid:

```typescript
// Revocation is permanent
await claimToken.revoke(tokenId, "License suspended by board");
```

Revocation reasons:
- Fraud detected
- License suspended/revoked
- Subject request
- Error in issuance

### Approving Renewals

When subjects request renewal:

```typescript
// Check pending renewal
const hasRequest = await lifecycleManager.hasPendingRenewal(tokenId);

// Approve with new expiry
if (hasRequest) {
    const newExpiry = Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60);
    await lifecycleManager.approveRenewal(tokenId, newExpiry);
}
```

### Rejecting Renewals

```typescript
await lifecycleManager.rejectRenewal(tokenId, "Continuing education not completed");
```

## Reputation System

Your reputation score affects your ability to issue:

| Score Range | Status | Capabilities |
|-------------|--------|--------------|
| 100-80 | Excellent | Full issuance rights |
| 79-60 | Good | Full issuance rights |
| 59-50 | Fair | Limited issuance |
| Below 50 | Poor | Cannot issue |

### Maintaining Reputation

Reputation improves with:
- Long-term credential validity
- Low revocation rate
- Successful verifications

Reputation decreases with:
- High revocation rate
- Disputed credentials
- Inactive issuance

## Claim Types

### Standard Claim Types

| Type | Description | Typical Issuers |
|------|-------------|-----------------|
| `IDENTITY.BIRTH` | Birth certificate | Government |
| `IDENTITY.NATIONAL_ID` | National ID card | Government |
| `LICENSE.PROFESSIONAL` | Professional license | Licensing boards |
| `LICENSE.OPERATOR` | Driver's license | DMV/Government |
| `EDUCATION.DEGREE` | Academic degree | Universities |
| `EDUCATION.CERTIFICATION` | Professional cert | Certification bodies |
| `MEMBERSHIP.ORGANIZATION` | Membership card | Organizations |

### Custom Claim Types

You can request authorization for custom claim types:

```typescript
// Generate claim type hash
const customType = ethers.keccak256(ethers.toUtf8Bytes("MEDICAL.LICENSE"));

// Request authorization from admin
// Admin grants: issuerRegistry.authorizeType(issuerAddress, customType)
```

## Integration Examples

### Web Application

```typescript
import { SovereignCredentialSDK } from "@sovereign-credential/sdk";

const sdk = new SovereignCredentialSDK({
    provider: window.ethereum,
    contracts: {
        claimToken: CLAIM_TOKEN_ADDRESS,
        issuerRegistry: ISSUER_REGISTRY_ADDRESS,
    }
});

// Issue credential through web UI
async function issueCredential(formData) {
    const result = await sdk.issueCredential({
        subject: formData.recipientAddress,
        claimType: formData.claimType,
        payload: formData.credentialData,
        expiresAt: formData.expiryDate,
    });

    return result.tokenId;
}
```

### Batch Issuance

For issuing many credentials (e.g., graduation):

```typescript
async function batchIssue(graduates: GraduateData[]) {
    const results = [];

    for (const graduate of graduates) {
        const tx = await claimToken.mint(
            graduate.address,
            DEGREE_CLAIM_TYPE,
            encryptPayload(graduate.data),
            [generateCommitment(graduate.data)],
            DEGREE_EXPIRY
        );
        results.push({ graduate, txHash: tx.hash });
    }

    return results;
}
```

## Compliance Considerations

### Data Privacy

- Only store necessary data on-chain
- Encrypt all personal information
- Provide subjects with decryption keys
- Comply with GDPR, CCPA, etc.

### Record Keeping

Maintain off-chain records:
- Issuance decisions
- Identity verification
- Supporting documents

### Audit Trail

All actions are recorded on-chain:
- Issuance events
- Revocations
- Renewals
- Status changes

## Troubleshooting

### "Not authorized for claim type"

```typescript
// Check authorization
const isAuth = await issuerRegistry.isAuthorized(myAddress, claimType);
// Contact admin to add authorization
```

### "Issuer not active"

Your issuer account may be suspended:
- Check with system administrator
- Review reputation score
- Address any compliance issues

### "Insufficient gas"

Minting requires approximately 350,000 gas:
- Ensure sufficient ETH balance
- Check current gas prices

### "Transaction reverted"

Common causes:
- Subject address is zero
- Expiry is in the past
- Claim type not authorized
- Duplicate commitment values

## Security Guidelines

### Key Management

- Use hardware wallets for issuer keys
- Implement multi-signature for critical operations
- Rotate keys periodically

### Access Control

- Limit who can trigger issuance
- Implement approval workflows
- Log all issuance attempts

### Monitoring

- Watch for unusual issuance patterns
- Alert on high-value credentials
- Monitor revocation rates

## Support

- Technical Issues: Create a GitHub issue
- Authorization Requests: Contact system administrator
- Compliance Questions: Review SECURITY.md
