# Audit Preparation Document

This document provides auditors with comprehensive information about the Sovereign Credential system to facilitate a thorough security audit.

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Contract Inventory](#contract-inventory)
4. [Interaction Diagrams](#interaction-diagrams)
5. [Access Control Matrix](#access-control-matrix)
6. [Critical Invariants](#critical-invariants)
7. [External Dependencies](#external-dependencies)
8. [Known Issues](#known-issues)
9. [Testing Information](#testing-information)
10. [Deployment Information](#deployment-information)
11. [Audit Scope](#audit-scope)
12. [Areas of Concern](#areas-of-concern)

---

## Project Overview

**Sovereign Credential** is a blockchain-based system for issuing, managing, and verifying custodian-independent verifiable credentials as NFTs.

### Key Features

- ERC-721 based credential tokens
- Zero-knowledge selective disclosure proofs
- Issuer reputation and authorization system
- Credential lifecycle management (renewal, suspension, revocation)
- Posthumous inheritance via FIE (Finite Intent Executor) integration

### Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Smart Contracts | Solidity | 0.8.28 |
| Framework | Hardhat | Latest |
| Upgradability | UUPS (OpenZeppelin) | 5.x |
| ZK Proofs | Circom + snarkjs | 2.1.x |
| Testing | Chai + Mocha | Latest |

---

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     Frontend / SDK                               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                    Smart Contracts                               │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────────┐  │
│  │IssuerRegistry│  │ ClaimToken │  │CredentialLifecycleManager│ │
│  │             │◄─┤  (ERC-721) │──►│                        │  │
│  │             │  │             │  │                        │  │
│  └─────────────┘  └──────┬──────┘  └────────────┬───────────┘  │
│                          │                       │              │
│  ┌──────────────────────▼┐    ┌────────────────▼────────────┐  │
│  │  ZKDisclosureEngine   │    │         FIEBridge           │  │
│  │                       │    │                              │  │
│  │  ┌─────────────────┐  │    │    ┌────────────────────┐   │  │
│  │  │  ZK Verifiers   │  │    │    │  External FIE      │   │  │
│  │  │  (per circuit)  │  │    │    │  (Oracle)          │   │  │
│  │  └─────────────────┘  │    │    └────────────────────┘   │  │
│  └───────────────────────┘    └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Credential Issuance**: Issuer → ClaimToken.mint() → Subject receives NFT
2. **Verification**: Verifier → ZKDisclosureEngine.verifyDisclosure() → Boolean result
3. **Lifecycle**: Subject/Issuer → CredentialLifecycleManager → Status update
4. **Inheritance**: FIE trigger → FIEBridge → CredentialLifecycleManager → Transfer

---

## Contract Inventory

### Core Contracts

| Contract | File | LOC | Description |
|----------|------|-----|-------------|
| `IssuerRegistry` | `contracts/IssuerRegistry.sol` | ~450 | Issuer management and authorization |
| `ClaimToken` | `contracts/ClaimToken.sol` | ~600 | ERC-721 credential token |
| `ZKDisclosureEngine` | `contracts/ZKDisclosureEngine.sol` | ~400 | ZK proof verification |
| `CredentialLifecycleManager` | `contracts/CredentialLifecycleManager.sol` | ~550 | Renewal, inheritance, disputes |
| `FIEBridge` | `contracts/FIEBridge.sol` | ~300 | FIE integration for inheritance |

### Supporting Contracts

| Contract | File | LOC | Description |
|----------|------|-----|-------------|
| `Groth16Verifier` | `contracts/verifiers/Groth16Verifier.sol` | ~250 | ZK proof verification |
| `MockFIE` | `contracts/mocks/MockFIE.sol` | ~100 | Test FIE oracle |
| `MockZKVerifier` | `contracts/mocks/MockZKVerifier.sol` | ~50 | Test ZK verifier |

### Interfaces

| Interface | File | Description |
|-----------|------|-------------|
| `IIssuerRegistry` | `contracts/interfaces/IIssuerRegistry.sol` | Issuer registry interface |
| `IClaimToken` | `contracts/interfaces/IClaimToken.sol` | Claim token interface |
| `IZKDisclosureEngine` | `contracts/interfaces/IZKDisclosureEngine.sol` | ZK engine interface |
| `IVerifier` | `contracts/interfaces/IVerifier.sol` | ZK verifier interface |

---

## Interaction Diagrams

### Credential Minting Flow

```
┌──────┐          ┌─────────────┐    ┌─────────────┐    ┌───────────┐
│Issuer│          │ ClaimToken  │    │IssuerRegistry│    │  Subject  │
└──┬───┘          └──────┬──────┘    └──────┬──────┘    └─────┬─────┘
   │                     │                   │                 │
   │  mint(request, sig) │                   │                 │
   │────────────────────►│                   │                 │
   │                     │ isAuthorized()    │                 │
   │                     │──────────────────►│                 │
   │                     │◄──────────────────│                 │
   │                     │ incrementIssued() │                 │
   │                     │──────────────────►│                 │
   │                     │                   │                 │
   │                     │      Transfer NFT │                 │
   │                     │────────────────────────────────────►│
   │◄────────────────────│                   │                 │
   │     tokenId         │                   │                 │
```

### ZK Disclosure Flow

```
┌────────┐      ┌──────────────────┐    ┌────────────┐    ┌──────────┐
│Verifier│      │ZKDisclosureEngine│    │ ClaimToken │    │ZKVerifier│
└───┬────┘      └────────┬─────────┘    └─────┬──────┘    └────┬─────┘
    │                    │                     │                │
    │ verifyDisclosure() │                     │                │
    │───────────────────►│                     │                │
    │                    │ getCredential()     │                │
    │                    │────────────────────►│                │
    │                    │◄────────────────────│                │
    │                    │ checkNullifier()    │                │
    │                    │─────────────────────────────────────►│
    │                    │ verifyProof()       │                │
    │                    │─────────────────────────────────────►│
    │                    │◄─────────────────────────────────────│
    │◄───────────────────│                     │                │
    │   true/false       │                     │                │
```

### Inheritance Execution Flow

```
┌────────┐    ┌─────────────────────────┐    ┌───────────┐    ┌───────────┐
│  FIE   │    │CredentialLifecycleManager│   │FIEBridge  │    │ClaimToken │
└───┬────┘    └───────────┬─────────────┘    └─────┬─────┘    └─────┬─────┘
    │                     │                        │                │
    │ triggerExecution()  │                        │                │
    │────────────────────────────────────────────►│                │
    │                     │   executeInheritance()│                │
    │                     │◄───────────────────────│                │
    │                     │                        │                │
    │                     │  getInheritanceDirective()              │
    │                     │────────────────────────│                │
    │                     │                        │                │
    │                     │  transfer()            │                │
    │                     │───────────────────────────────────────►│
    │                     │                        │                │
    │                     │  updateStatus()        │                │
    │                     │───────────────────────────────────────►│
    │◄────────────────────│                        │                │
    │    success          │                        │                │
```

---

## Access Control Matrix

### Role Definitions

| Role ID | Constant Name | Purpose |
|---------|---------------|---------|
| 0x00 | `DEFAULT_ADMIN_ROLE` | Grant/revoke other roles |
| 0x01 | `UPGRADER_ROLE` | Upgrade contract implementations |
| 0x02 | `REGISTRAR_ROLE` | Manage issuer registration |
| 0x03 | `ARBITER_ROLE` | Resolve disputes, adjust reputation |
| 0x04 | `CREDENTIAL_CONTRACT_ROLE` | Internal contract calls |
| 0x05 | `FIE_EXECUTION_ROLE` | Execute inheritance |

### Function Access

| Contract | Function | Required Role/Access |
|----------|----------|---------------------|
| **IssuerRegistry** | | |
| | `registerIssuer()` | REGISTRAR_ROLE |
| | `deactivateIssuer()` | REGISTRAR_ROLE |
| | `reactivateIssuer()` | REGISTRAR_ROLE |
| | `authorizeType()` | REGISTRAR_ROLE |
| | `revokeTypeAuthorization()` | REGISTRAR_ROLE |
| | `adjustReputation()` | ARBITER_ROLE |
| | `addDelegate()` | Issuer only |
| | `removeDelegate()` | Issuer only |
| | `incrementIssued()` | CREDENTIAL_CONTRACT_ROLE |
| | `incrementRevoked()` | CREDENTIAL_CONTRACT_ROLE |
| **ClaimToken** | | |
| | `mint()` | Authorized issuer |
| | `mintAsDelegate()` | Authorized delegate |
| | `revoke()` | Original issuer |
| | `suspend()` | Original issuer |
| | `reinstate()` | Original issuer |
| | `setZKEngine()` | DEFAULT_ADMIN_ROLE |
| | `setLifecycleManager()` | DEFAULT_ADMIN_ROLE |
| **ZKDisclosureEngine** | | |
| | `verifyDisclosure()` | Anyone |
| | `registerVerifier()` | DEFAULT_ADMIN_ROLE |
| | `updateVerifier()` | DEFAULT_ADMIN_ROLE |
| **CredentialLifecycleManager** | | |
| | `requestRenewal()` | Token owner |
| | `approveRenewal()` | Original issuer |
| | `denyRenewal()` | Original issuer |
| | `setInheritanceDirective()` | Token owner |
| | `executeInheritance()` | FIE_EXECUTION_ROLE |
| | `fileDispute()` | Anyone |
| | `resolveDispute()` | ARBITER_ROLE |
| | `setFIEBridge()` | DEFAULT_ADMIN_ROLE |
| **FIEBridge** | | |
| | `registerIntent()` | DEFAULT_ADMIN_ROLE |
| | `executeInheritance()` | FIE_EXECUTION_ROLE |
| | `setFIEExecutionAgent()` | DEFAULT_ADMIN_ROLE |

---

## Critical Invariants

These invariants MUST hold at all times. Violation indicates a security issue.

### Safety Invariants

| ID | Invariant | Test File |
|----|-----------|-----------|
| INV-01 | Active credentials must have authorized issuers | `test/invariants/safety.test.ts` |
| INV-02 | Revocation is permanent | `test/invariants/safety.test.ts` |
| INV-03 | Only ACTIVE/INHERITED credentials pass verification | `test/invariants/safety.test.ts` |
| INV-04 | Proofs cannot be replayed (nullifier uniqueness) | `test/invariants/safety.test.ts` |
| INV-05 | Credentials stay with subject unless explicitly transferred | `test/invariants/safety.test.ts` |

### Liveness Invariants

| ID | Invariant | Test File |
|----|-----------|-----------|
| INV-06 | Renewal requests answered within RENEWAL_TIMEOUT | `test/invariants/liveness.test.ts` |
| INV-07 | Inheritance executes within INHERITANCE_TIMEOUT | `test/invariants/liveness.test.ts` |

### Economic Invariants

| ID | Invariant | Test File |
|----|-----------|-----------|
| INV-08 | Issuers below MIN_REPUTATION cannot issue | `test/invariants/liveness.test.ts` |
| INV-09 | totalIssued >= totalRevoked + totalActive | `test/invariants/liveness.test.ts` |

---

## External Dependencies

### OpenZeppelin Contracts (v5.x)

| Contract | Usage |
|----------|-------|
| `ERC721Upgradeable` | NFT base |
| `AccessControlUpgradeable` | Role management |
| `ReentrancyGuardUpgradeable` | Reentrancy protection |
| `UUPSUpgradeable` | Upgrade pattern |
| `PausableUpgradeable` | Emergency pause |
| `ECDSA` | Signature verification |

### Circom Circuits

| Circuit | Source |
|---------|--------|
| `AgeThreshold.circom` | Custom |
| `DateRange.circom` | Custom |
| `ValueRange.circom` | Custom |
| `SetMembership.circom` | Custom |
| `CompoundProof.circom` | Custom |

### External Oracles

| Oracle | Purpose | Trust Level |
|--------|---------|-------------|
| FIE (Finite Intent Executor) | Mortality triggers | High trust required |

---

## Known Issues

### Acknowledged Limitations

1. **Issuer Trust**: Off-chain verification of issuer legitimacy required
2. **FIE Oracle**: System trusts FIE for mortality triggers
3. **Gas Costs**: Large credential payloads increase costs
4. **ZK Setup**: Trusted setup ceremony required for ZK circuits

### Design Decisions

1. **Non-transferable Credentials**: Most credentials cannot be transferred via ERC-721 standard
2. **Revocation Permanence**: Intentional to prevent credential restoration after fraud
3. **Dispute Window**: 30-day period balances finality with dispute resolution

---

## Testing Information

### Test Coverage

```
File                                      |  % Stmts | % Branch | % Funcs | % Lines |
------------------------------------------|----------|----------|---------|---------|
contracts/                                |    95.2  |    91.3  |    96.8 |    94.7 |
  ClaimToken.sol                          |    97.1  |    93.5  |    98.2 |    96.3 |
  IssuerRegistry.sol                      |    94.8  |    89.7  |    95.6 |    93.9 |
  ZKDisclosureEngine.sol                  |    93.4  |    88.2  |    94.1 |    92.8 |
  CredentialLifecycleManager.sol          |    95.6  |    92.1  |    97.3 |    94.9 |
  FIEBridge.sol                           |    95.0  |    91.0  |    96.0 |    94.5 |
```

### Test Categories

| Category | File Count | Test Count | Coverage Focus |
|----------|------------|------------|----------------|
| Unit Tests | 9 | ~450 | Individual functions |
| Integration Tests | 4 | ~120 | Cross-contract flows |
| Invariant Tests | 2 | ~50 | Safety properties |
| Fuzz Tests | 1 | ~30 | Edge cases |

### Running Tests

```bash
# All tests
npm test

# Coverage report
npm run coverage

# Gas report
REPORT_GAS=true npm test

# Specific test file
npx hardhat test test/invariants/safety.test.ts
```

---

## Deployment Information

### Target Networks

| Network | Chain ID | Status |
|---------|----------|--------|
| NatLangChain Mainnet | 1001 | Planned |
| Sepolia Testnet | 11155111 | Testing |
| Local Hardhat | 31337 | Development |

### Deployment Order

1. IssuerRegistry
2. ClaimToken (with IssuerRegistry address)
3. ZKDisclosureEngine (with ClaimToken address)
4. CredentialLifecycleManager (with ClaimToken, IssuerRegistry addresses)
5. FIEBridge (with CredentialLifecycleManager address)
6. ZK Verifiers (deploy and register with ZKDisclosureEngine)
7. Configure cross-references
8. Transfer admin to multisig

### Gas Estimates (Approximate)

| Operation | Gas Used | NFR Requirement |
|-----------|----------|-----------------|
| Credential mint | ~350,000 | < 500,000 |
| ZK proof verification | ~200,000 | < 300,000 |
| Status change | ~50,000 | N/A |
| Inheritance execution | ~300,000 | N/A |

---

## Audit Scope

### In Scope

- All Solidity contracts in `contracts/`
- Contract interactions and data flows
- Access control implementation
- Upgrade mechanism
- State machine transitions

### Out of Scope

- Frontend applications
- Off-chain SDK implementation
- Circom circuit internals (separate audit recommended)
- FIE oracle implementation

### Focus Areas

1. **Access Control**: Role assignments, function modifiers
2. **State Transitions**: Credential status changes
3. **Signature Verification**: EIP-712, replay protection
4. **Upgrade Security**: UUPS implementation, storage layout
5. **Integer Handling**: Overflow/underflow scenarios
6. **External Calls**: Reentrancy, return value handling

---

## Areas of Concern

### High Priority

1. **ZKDisclosureEngine.verifyDisclosure()**: Critical path for proof verification
2. **ClaimToken.mint()**: Signature verification and issuer authorization
3. **FIEBridge.executeInheritance()**: Token transfer and status update
4. **CredentialLifecycleManager.setInheritanceDirective()**: Owner verification

### Medium Priority

1. **IssuerRegistry.adjustReputation()**: Reputation calculation bounds
2. **ClaimToken status transitions**: Valid state machine enforcement
3. **Renewal flow**: Timeout handling and issuer response

### Low Priority

1. **Event emissions**: Completeness and accuracy
2. **View function returns**: Data consistency
3. **Gas optimization opportunities**

---

## Contact Information

| Role | Contact |
|------|---------|
| Project Lead | lead@example.com |
| Technical Contact | tech@example.com |
| Security Contact | security@example.com |

---

*Document Version: 1.0*
*Last Updated: 2026-01-13*
