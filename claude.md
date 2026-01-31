# Sovereign Credential - Claude Context

## Project Overview

Sovereign Credential is a blockchain-based system that mints verifiable claims (birth certificates, licenses, degrees, property deeds) as custodian-independent NFTs on NatLangChain. Cryptographic proofs travel with credentials themselves, eliminating dependency on issuing institutions.

**Version:** 0.1.0-alpha
**License:** CC0-1.0 (Public Domain)
**Node:** >=18.0.0

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SOVEREIGN CREDENTIAL                      │
├─────────────────────────────────────────────────────────────┤
│  ClaimToken (ERC721)     - Credential NFT representation     │
│  IssuerRegistry          - Issuer authorization & reputation │
│  CredentialLifecycleManager - Issuance/renewal/revocation   │
│  ZKDisclosureEngine      - Selective disclosure via ZK proofs│
│  FIEBridge               - Inheritance executor integration  │
└─────────────────────────────────────────────────────────────┘
```

All contracts use **UUPS upgradeable proxy pattern** with OpenZeppelin v5.0.2.

## Tech Stack

| Category | Technologies |
|----------|-------------|
| Smart Contracts | Solidity 0.8.28, OpenZeppelin v5.0.2, Hardhat 2.22.2 |
| ZK Proofs | Circom v2.1.6, snarkjs 0.7.3, Groth16 verifiers |
| TypeScript | TypeScript 5.4.3 (strict mode), ethers.js v6 |
| Testing | Chai, Mocha, Hardhat test framework |
| Code Quality | ESLint, Prettier (with Solidity plugin) |

## Directory Structure

```
sovereign-credential/
├── contracts/           # Solidity smart contracts
│   ├── ClaimToken.sol          # ERC721 credential NFT
│   ├── IssuerRegistry.sol      # Issuer management
│   ├── CredentialLifecycleManager.sol
│   ├── ZKDisclosureEngine.sol
│   ├── FIEBridge.sol
│   ├── libraries/       # Shared types and utilities
│   └── verifiers/       # Groth16 ZK verifiers
├── circuits/            # Circom ZK circuits
├── test/                # Test files
│   ├── fixtures/        # Reusable test data
│   ├── helpers/         # Test utilities
│   ├── integration/     # Integration tests
│   ├── invariants/      # Formal invariant tests
│   └── fuzz/            # Fuzz testing
├── sdk/                 # TypeScript SDK for ZK proof generation
├── scripts/             # Deployment and utility scripts
├── docs/                # Additional documentation
├── schemas/             # JSON schemas for credentials
├── types/               # TypeScript type definitions
└── utils/               # Shared utilities
```

## Common Commands

```bash
# Development
npm run compile          # Compile contracts
npm test                 # Run all tests
npm run test:coverage    # Generate coverage report
npm run test:gas         # Gas usage reporting

# ZK Circuits
npm run circuits:compile # Compile Circom circuits
npm run circuits:setup   # Trusted setup
npm run circuits:test    # Test ZK circuits

# Deployment
npm run node             # Start local Hardhat node
npm run deploy           # Deploy to local network
npm run deploy:testnet   # Deploy to Sepolia
npm run deploy:mainnet   # Deploy to mainnet

# Code Quality
npm run lint             # Run ESLint
npm run lint:fix         # Fix linting issues
npm run format           # Format with Prettier
npm run format:check     # Check formatting
```

## TypeScript Path Aliases

```typescript
@/*           → root directory
@contracts/*  → ./contracts/*
@test/*       → ./test/*
@scripts/*    → ./scripts/*
@sdk/*        → ./sdk/src/*
@types/*      → ./types/*
```

## Code Conventions

### Solidity

- **Solidity 0.8.28** with optimizer enabled (200 runs) and viaIR
- **Custom errors** instead of require strings for gas efficiency
- **NatSpec documentation** on all public/external functions
- **Role-based access control**: DEFAULT_ADMIN_ROLE, REGISTRAR_ROLE, ARBITER_ROLE, UPGRADER_ROLE, LIFECYCLE_MANAGER_ROLE, FIE_BRIDGE_ROLE
- **Events** for all state changes (indexed parameters for filtering)
- **ReentrancyGuard** on sensitive operations

### TypeScript

- **Strict mode** with all strict compiler options enabled
- **Explicit return types** on all functions
- **No unused variables** (prefix with `_` if intentionally unused)
- **noUncheckedIndexedAccess** enabled - always check array/object access

### Claim Types

Claim types are hex values organized by category:
- `0x01-0x0F`: Identity (birth certificate, passport, national ID)
- `0x10-0x1F`: Licenses (medical, legal, contractor)
- `0x20-0x2F`: Education (diploma, transcript, certification)
- `0x30-0x3F`: Property (deed, title, ownership)
- `0x40-0x4F`: Health (vaccination, prescription, insurance)
- `0xFF`: Custom claims

## Testing Patterns

- **Fixture-based approach**: Use `deployFullSystemFixture()` for integration tests
- **Helper functions**: `signMintRequest()`, `generateProof()`, `encryptPayload()`
- **Test timeout**: 60 seconds (for ZK proof tests)
- Tests located in `/test/*.test.ts`

Example test structure:
```typescript
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deployFullSystemFixture } from "./fixtures/deploymentFixtures";

describe("FeatureName", function () {
  it("should do something", async function () {
    const { claimToken, issuerRegistry } = await loadFixture(deployFullSystemFixture);
    // Test implementation
  });
});
```

## Key Contracts

| Contract | Purpose | Key Functions |
|----------|---------|---------------|
| `ClaimToken` | ERC721 credential NFT | `mint()`, `verify()`, `revoke()` |
| `IssuerRegistry` | Issuer management | `registerIssuer()`, `authorizeClaimType()`, `updateReputation()` |
| `CredentialLifecycleManager` | State transitions | `requestRenewal()`, `approveRenewal()`, `setInheritanceDirective()` |
| `ZKDisclosureEngine` | ZK proof verification | `verifyAgeThreshold()`, `verifyDateRange()`, `verifySetMembership()` |
| `FIEBridge` | Inheritance | `initiateTransfer()`, `executeTransfer()` |

## Credential Status Flow

```
PENDING → ACTIVE → SUSPENDED → ACTIVE (resume)
                 ↘ REVOKED
                 ↘ EXPIRED
                 ↘ INHERITED (via FIE)
```

## Environment Variables

Copy `.env.example` to `.env` and configure:
- `PRIVATE_KEY`: Deployer private key
- `SEPOLIA_RPC_URL`: Sepolia testnet RPC
- `MAINNET_RPC_URL`: Ethereum mainnet RPC
- `NATLANGCHAIN_RPC_URL`: NatLangChain RPC
- `ETHERSCAN_API_KEY`: For contract verification

## Security Considerations

- Never commit `.env` or private keys
- All payloads are encrypted to holder's public key
- Multi-sig issuer keys recommended for production
- ZK proofs verified on-chain with replay prevention
- Audit report available in `AUDIT_REPORT.md`

## Related Documentation

- `SPEC.md` - Complete technical specification
- `IMPLEMENTATION_GUIDE.md` - Step-by-step implementation details
- `AUDIT_REPORT.md` - Security audit findings
- `docs/ARCHITECTURE.md` - System architecture
- `docs/SECURITY.md` - Threat model and mitigations
- `docs/API.md` - API reference
- `CONTRIBUTING.md` - Development workflow

## Part of NatLangChain Ecosystem

Sovereign Credential integrates with:
- **NatLangChain**: Prose-first blockchain protocol
- **Finite-Intent-Executor (FIE)**: Posthumous credential inheritance
- **IntentLog**: Intent tracking and reasoning
