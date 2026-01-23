# Sovereign Credential

[![Version](https://img.shields.io/badge/Version-0.1.0--alpha-orange.svg)](https://github.com/kase1111-hash/sovereign-credential/releases)
[![License: CC0](https://img.shields.io/badge/License-CC0-blue.svg)](https://creativecommons.org/publicdomain/zero/1.0/)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.28-blue.svg)](https://soliditylang.org/)
[![NatLangChain](https://img.shields.io/badge/Ecosystem-NatLangChain-purple.svg)](https://github.com/kase1111-hash/NatLangChain)

> Custodian-independent verifiable claims as sovereign NFTs

## The Problem with Digital Credentials

Your birth certificate sits in a county records office. Your professional license exists in a state database. Your property deed lives in a title company's system. Every credential you possess depends on some institution existing, being accessible, and vouching for you on demand.

Digital lockers don't solve this—they just move the custodian from a filing cabinet to a server farm. When the locker company folds, or the county office burns down, or you die and your heirs need to prove something about you, the entire system fails. The proof doesn't travel with the asset.

## What Sovereign Credential Does

Sovereign Credential mints verifiable claims as NFTs on NatLangChain. The proof becomes the asset itself—cryptographically secured, globally verifiable, and independent of any custodian's continued existence.

**Custodian-independent verification.** Any system, anywhere, can verify your credential without calling anyone or trusting any intermediary. The proof travels with the claim.

**Composability across trust boundaries.** Your credential becomes a key that unlocks automated processes across systems that don't know you and don't trust each other. Foreign governments, smart contracts, services that won't exist for 20 years—they can all verify without coordination.

**Selective disclosure via zero-knowledge proofs.** Prove you're over 18 without revealing your birthdate. Prove you hold a valid license without exposing your license number. Share exactly what's needed and nothing more.

**Survival and portability.** If the issuing authority dissolves, the credential still exists and still proves what it proves. Your heirs don't need to petition anyone or prove chain of custody. The ledger is the custody chain.

**Programmable ownership.** Credentials can trigger things—automatic inheritance, conditional access, transfer without gatekeeper permission. The claim isn't just a receipt; it's an active agent.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SOVEREIGN CREDENTIAL                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│  │  Claim      │   │  Issuer     │   │  ZK Disclosure      │   │
│  │  Token      │   │  Registry   │   │  Engine             │   │
│  │  (ERC721)   │   │             │   │                     │   │
│  └──────┬──────┘   └──────┬──────┘   └──────────┬──────────┘   │
│         │                 │                      │              │
│         └────────────┬────┴──────────────────────┘              │
│                      │                                          │
│              ┌───────▼───────┐                                  │
│              │  Credential   │                                  │
│              │  Lifecycle    │                                  │
│              │  Manager      │                                  │
│              └───────┬───────┘                                  │
│                      │                                          │
└──────────────────────┼──────────────────────────────────────────┘
                       │
           ┌───────────▼───────────┐
           │     NatLangChain      │
           │   (Intent Records)    │
           └───────────┬───────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
        ▼                             ▼
┌───────────────┐           ┌─────────────────┐
│  Finite       │           │  Other          │
│  Intent       │           │  NatLangChain   │
│  Executor     │           │  Consumers      │
│  (Inheritance)│           │                 │
└───────────────┘           └─────────────────┘
```

## Core Components

### ClaimToken (ERC721)

The NFT representing a verifiable claim. Contains:

- **Claim type**: Birth certificate, professional license, property deed, diploma, etc.
- **Encrypted payload**: The actual credential data, encrypted to the holder's key
- **Issuer signature**: Cryptographic attestation from a registered issuer
- **Disclosure commitments**: ZK-compatible commitments for selective reveal
- **Revocation status**: On-chain revocation check
- **Metadata URI**: IPFS pointer to claim schema and display data

### IssuerRegistry

Manages who can make valid claims of what types:

- **Issuer registration**: Public keys, claim types authorized, jurisdiction
- **Reputation tracking**: Claim validity history, dispute outcomes
- **Revocation authority**: Which issuers can revoke which claim types
- **Delegation**: Issuers can delegate signing authority to sub-entities

### ZKDisclosureEngine

Enables proving facts about credentials without revealing the credentials:

- **Age proofs**: Prove over/under threshold without revealing birthdate
- **Range proofs**: Prove value within range without revealing exact value
- **Set membership**: Prove credential is one of valid types without revealing which
- **Compound proofs**: Combine multiple disclosures in single proof

### CredentialLifecycleManager

Handles credential state transitions:

- **Issuance**: Mint new credential with issuer attestation
- **Transfer**: Move credential between wallets (where applicable)
- **Renewal**: Update expiring credentials with fresh attestation
- **Revocation**: Issuer-initiated invalidation
- **Inheritance**: Integration with FIE for posthumous transfer

## Use Cases

### Identity Documents

Birth certificates, passports, national IDs. Prove citizenship or age to any system without calling the issuing government. Heirs can inherit identity verification without bureaucratic delay.

### Professional Licenses

Medical licenses, bar admissions, contractor certifications. Prove current licensure to any jurisdiction. Automatic expiration handling with renewal hooks.

### Property Rights

Deeds, titles, ownership records. Transfer property via credential transfer. Liens and encumbrances encoded as credential metadata.

### Educational Credentials

Diplomas, certifications, transcripts. Prove degree completion without contacting the university. Micro-credentials for specific skills or courses.

### Health Records

Vaccination records, prescription authorizations, insurance credentials. Prove coverage or immunization status without exposing full medical history.

## Integration with Finite Intent Executor

Sovereign Credential connects to FIE for inheritance scenarios:

1. **Death trigger verification**: FIE validates credential holder's death via oracle/quorum
2. **Beneficiary designation**: Credentials specify inheritance rules in metadata
3. **Automatic transfer**: FIE executes credential transfer to designated heirs
4. **Time-bounded access**: Temporary credential access during estate settlement

This connection is optional—credentials exist independently of FIE and don't sunset with it.

## Smart Contracts

| Contract | Purpose |
|----------|---------|
| **ClaimToken** | ERC721 credential NFT with encrypted payload and ZK commitments |
| **IssuerRegistry** | Authorized issuer management and reputation tracking |
| **ZKDisclosureEngine** | Zero-knowledge proof generation and verification |
| **CredentialLifecycleManager** | Issuance, transfer, renewal, revocation workflows |
| **FIEBridge** | Optional integration with Finite Intent Executor for inheritance |

## Installation

```bash
# Clone repository
git clone https://github.com/kase1111-hash/sovereign-credential.git
cd sovereign-credential

# Install dependencies
npm install

# Compile contracts
npm run compile

# Run tests
npm test

# Deploy to local network
npm run node          # Terminal 1
npm run deploy        # Terminal 2
```

### Prerequisites

- **Node.js 18+**
- **NatLangChain node** (for mainnet deployment)

## Quick Start

### Mint a Credential

```javascript
const { ethers } = require("hardhat");

// Connect to deployed contracts
const claimToken = await ethers.getContractAt("ClaimToken", CLAIM_TOKEN_ADDRESS);
const issuerRegistry = await ethers.getContractAt("IssuerRegistry", REGISTRY_ADDRESS);

// Issuer creates credential
const credential = {
  claimType: "BIRTH_CERTIFICATE",
  subject: holderAddress,
  encryptedPayload: encryptedData,  // Encrypted to holder's public key
  disclosureCommitments: [ageCommitment, citizenshipCommitment],
  expiresAt: 0,  // Never expires
  metadata: "ipfs://Qm..."
};

const signature = await issuer.signMessage(hashCredential(credential));
await claimToken.mint(credential, signature);
```

### Verify a Credential

```javascript
// Anyone can verify
const isValid = await claimToken.verify(tokenId);
const issuer = await claimToken.getIssuer(tokenId);
const isIssuerAuthorized = await issuerRegistry.isAuthorized(issuer, "BIRTH_CERTIFICATE");

// Check revocation
const isRevoked = await claimToken.isRevoked(tokenId);
```

### Generate Zero-Knowledge Disclosure

```javascript
const zkEngine = await ethers.getContractAt("ZKDisclosureEngine", ZK_ADDRESS);

// Prove age > 18 without revealing birthdate
const proof = await zkEngine.generateAgeProof(tokenId, 18, "GREATER_THAN");

// Verifier checks proof
const isValidProof = await zkEngine.verifyAgeProof(proof, tokenId, 18, "GREATER_THAN");
```

## Security Considerations

**Issuer compromise**: If an issuer's keys are compromised, they can mint fraudulent credentials. Mitigation: multi-sig issuer keys, time-locked issuance, reputation staking.

**Encryption key loss**: If a holder loses their decryption key, the credential payload is unrecoverable. Mitigation: social recovery, hardware key backup, FIE integration for inheritance.

**Revocation timing**: On-chain revocation may lag real-world revocation. Mitigation: short-lived credentials with frequent renewal, off-chain revocation lists with on-chain anchors.

**ZK circuit bugs**: Flawed ZK circuits could allow false proofs. Mitigation: formal verification of circuits, multiple independent implementations, bug bounties.

## Roadmap

- [x] Core specification
- [x] ClaimToken contract
- [x] IssuerRegistry contract
- [x] Basic lifecycle management
- [x] ZK disclosure circuits (age, range, set membership)
- [x] FIE bridge integration
- [x] TypeScript SDK
- [x] Deployment scripts
- [x] Comprehensive test suite
- [ ] Frontend credential wallet
- [ ] Issuer onboarding portal
- [ ] Mobile verification app

## Part of the NatLangChain Ecosystem

Sovereign Credential is a consumer of NatLangChain primitives, adding credential-specific semantics to the base intent recording layer.

### NatLangChain Ecosystem

| Repository | Description |
|------------|-------------|
| [NatLangChain](https://github.com/kase1111-hash/NatLangChain) | Prose-first, intent-native blockchain protocol |
| [IntentLog](https://github.com/kase1111-hash/IntentLog) | Git for human reasoning—tracks "why" via prose commits |
| [Finite-Intent-Executor](https://github.com/kase1111-hash/Finite-Intent-Executor) | Bounded posthumous execution of predefined intent |
| [RRA-Module](https://github.com/kase1111-hash/RRA-Module) | Revenant Repo Agent for abandoned repository licensing |
| [mediator-node](https://github.com/kase1111-hash/mediator-node) | LLM mediation for matching and negotiation |
| [ILR-module](https://github.com/kase1111-hash/ILR-module) | IP & Licensing Reconciliation for dispute resolution |

### Agent-OS Ecosystem

| Repository | Description |
|------------|-------------|
| [Agent-OS](https://github.com/kase1111-hash/Agent-OS) | Natural-language native operating system for AI agents |
| [boundary-daemon-](https://github.com/kase1111-hash/boundary-daemon-) | Trust enforcement layer for Agent OS |
| [memory-vault](https://github.com/kase1111-hash/memory-vault) | Sovereign storage for cognitive artifacts |
| [Boundary-SIEM](https://github.com/kase1111-hash/Boundary-SIEM) | Security Information and Event Management for AI |

## License

CC0 1.0 Universal - Public Domain Dedication

---

**Version:** 0.1.0-alpha | **Last Updated:** 2026-01-23
