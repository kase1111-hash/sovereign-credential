# Sovereign Credential User Guide

This guide explains how to use Sovereign Credentials as a credential holder.

## What is a Sovereign Credential?

A Sovereign Credential is a verifiable claim about you (like a degree, license, or certification) stored as an NFT on the blockchain. Unlike traditional credentials:

- **You own it**: The credential is in your wallet, not held by an institution
- **It's portable**: Works across any platform that supports the standard
- **It survives**: Even if the issuing institution closes, your credential remains valid
- **Privacy-preserving**: You can prove facts without revealing all your data

## Getting Started

### 1. Set Up a Wallet

You need a compatible Ethereum wallet:
- MetaMask (browser extension)
- Rainbow (mobile)
- Coinbase Wallet
- Any EVM-compatible wallet

### 2. Get Testnet ETH (for testing)

If testing on Sepolia:
1. Visit a faucet: https://sepoliafaucet.com/
2. Enter your wallet address
3. Receive free test ETH

### 3. Receive a Credential

When an issuer mints a credential for you:
1. You'll see a new NFT in your wallet
2. The credential appears in NFT-compatible apps
3. You can view details on block explorers

## Viewing Your Credentials

### Using Block Explorer

1. Go to https://sepolia.etherscan.io (or mainnet etherscan)
2. Search for your wallet address
3. Click "NFTs" tab
4. Find your SovereignCredential (SCRED) tokens

### Using Web3 Apps

Any NFT-compatible dApp can display your credentials. The token metadata includes:
- Claim type (degree, license, etc.)
- Issuer address
- Issue and expiry dates
- Status (active, revoked, etc.)

## Verifying Your Credential

Anyone can verify your credential is valid:

```javascript
// Example verification call
const isValid = await claimToken.verify(tokenId);
```

Verification checks:
- Credential status is ACTIVE or INHERITED
- Not expired
- Issuer is still active
- Issuer was authorized for this claim type

## Selective Disclosure (Zero-Knowledge Proofs)

The most powerful feature: prove facts without revealing everything.

### Example: Proving You're Over 18

Instead of showing your birthdate, generate a ZK proof:

1. Your wallet app generates a proof locally
2. The proof shows "age > 18" without revealing your actual age
3. A verifier checks the proof on-chain

### Available Disclosure Types

| Type | What You Can Prove |
|------|-------------------|
| Age Threshold | "I am over/under X years old" |
| Date Range | "This date is between X and Y" |
| Value Range | "This value is between X and Y" |
| Set Membership | "This value is in the allowed list" |
| Existence | "This credential exists and is valid" |

### Generating Proofs

Use the SDK to generate proofs:

```javascript
import { ProofGenerator } from '@sovereign-credential/sdk';

const generator = new ProofGenerator(credentialData, privateKey);
const proof = await generator.generateAgeThresholdProof(18, true); // over 18
```

## Managing Your Credentials

### Checking Status

Credentials have these statuses:
- **ACTIVE**: Valid and usable
- **REVOKED**: Permanently invalid (issuer revoked)
- **EXPIRED**: Past expiry date
- **SUSPENDED**: Temporarily invalid
- **INHERITED**: Transferred to you via inheritance

### Requesting Renewal

If your credential is expiring:

1. Call `requestRenewal(tokenId)` on CredentialLifecycleManager
2. The original issuer reviews your request
3. If approved, your expiry date is extended

### Setting Up Inheritance

Ensure your credentials transfer to loved ones:

```javascript
// Set inheritance directive
await lifecycleManager.setInheritanceDirective(
    tokenId,
    [beneficiaryAddress],  // Who receives it
    [100],                 // Share percentages
    true,                  // Require FIE trigger (death proof)
    fieIntentHash          // Your FIE intent hash
);
```

## Security Best Practices

### Protect Your Wallet

- Never share your private key or seed phrase
- Use hardware wallets for valuable credentials
- Enable wallet security features

### Verify Before Sharing

- Only share proofs with trusted verifiers
- Each proof can only be used once (replay protection)
- Set expiry times on disclosure requests

### Monitor Your Credentials

- Check status regularly
- Watch for suspicious activity
- Keep issuer contact information

## FAQ

### Can I transfer my credential to someone else?

Generally no - credentials are soulbound to the subject. The exception is inheritance, which requires death verification through FIE.

### What happens if the issuer goes out of business?

Your credential remains valid! The blockchain preserves the issuer's signature and your credential data. Verification still works.

### Can my credential be revoked?

Yes, only by the original issuer. Revocation is permanent and recorded on-chain. You cannot appeal to the smart contract, but may have legal recourse.

### How do I know a credential is fake?

Verification checks:
1. The issuer is registered and authorized
2. The credential was properly minted
3. It hasn't been revoked
4. It hasn't expired

Fake credentials would fail these checks.

### What data is public?

On-chain:
- Token existence
- Claim type
- Subject address
- Issuer address
- Timestamps
- Status

Off-chain (encrypted):
- Actual credential data
- Personal information

### Can I delete my credential?

Credentials cannot be deleted from the blockchain. However:
- You can request the issuer revoke it
- Expired credentials become invalid
- You can remove the NFT from display in your wallet

## Troubleshooting

### "Credential not found"
- Verify the token ID is correct
- Check you're on the right network

### "Verification failed"
- Credential may be expired - check expiry date
- Issuer may be suspended - contact issuer
- Credential may be revoked - contact issuer

### "Proof generation failed"
- Ensure you have the correct private data
- Check the commitment matches on-chain data
- Verify circuit parameters are correct

## Getting Help

- GitHub Issues: https://github.com/[project]/issues
- Documentation: https://docs.sovereigncredential.io
- Discord: https://discord.gg/[invite]
