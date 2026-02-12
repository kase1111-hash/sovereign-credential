# REFOCUS PLAN — Sovereign Credential

**Date:** 2026-02-12
**Based on:** [EVALUATION_REPORT.md](./EVALUATION_REPORT.md)
**Goal:** Move from "well-architected prototype" to "deployable system" by closing the gaps between what the code claims and what it actually delivers.

---

## Current State

**What works:**
- 5 smart contracts with clean separation of concerns and linear dependency graph
- 10 Circom circuits for ZK selective disclosure (age, date, value, set, compound)
- 11,600+ lines of tests (unit, integration, invariant, fuzz)
- UUPS upgradeable proxy pattern correctly implemented
- All 5 audit findings properly resolved (including `batchTransfer` at `CredentialLifecycleManager.sol:840`)
- TypeScript SDK for proof generation and witness building

**What doesn't:**
- Encryption is a placeholder — `sdk/src/encryption.ts:39-42` uses `keccak256(concat(keys))` instead of secp256k1 ECDH
- No CI/CD — zero GitHub Actions workflows
- No deployment evidence — scripts exist but have never been run against a live network
- Inheritance subsystem (~1,400 lines Solidity, ~730 lines tests) is tightly coupled to core contracts AND depends on FIE, a system that doesn't exist in production

---

## Phase 1: Credibility (Week 1-2)

Fix the things that undermine trust in the system before adding anything new.

### 1.1 Replace Placeholder Encryption
**Priority:** Critical
**Files:** `sdk/src/encryption.ts`
**Why:** The project's entire value proposition is cryptographic sovereignty. Using `keccak256(concat(privKey, pubKey))` as a "shared secret" means credential payloads are not encrypted in any meaningful sense. Every TODO in this file acknowledges this.

**Action:**
- Install `@noble/secp256k1` (or `ethereum-cryptography` which bundles it)
- Replace `deriveSharedSecret()` with proper secp256k1 ECDH: `getSharedSecret(privateKey, publicKey)`
- Replace the ephemeral public key derivation at line 91 (`keccak256(getBytes(ephemeralKey))`) with `getPublicKey(ephemeralKey)`
- Add HKDF key derivation instead of `keccak256(concat(sharedSecret, iv))`
- Update tests in `test/helpers/encryption.ts` to use real key pairs
- Remove all 6 WARNING/TODO comments once the implementation is real

**Verification:** Encrypt with one key pair, decrypt with another. Verify that keccak256-derived "secrets" from before can no longer decrypt (breaking change is expected and correct).

### 1.2 Add CI/CD Pipeline
**Priority:** High
**Files:** New `.github/workflows/ci.yml`
**Why:** A smart contract project without automated testing is a liability. Anyone contributing or auditing needs confidence that changes don't break invariants.

**Action:**
Create a single workflow that runs on push and PR:
```
Jobs:
1. compile    — `hardhat compile` (catches Solidity errors)
2. test       — `hardhat test` (runs full suite)
3. coverage   — `hardhat coverage` (tracks coverage percentage)
4. lint       — `eslint . --ext .ts,.tsx` (code quality)
5. format     — `prettier --check` (formatting consistency)
```

Add a badge to `README.md` for build status.

**Verification:** Push a broken test and verify CI fails. Push the fix and verify it passes.

### 1.3 Correct Documentation Drift
**Priority:** Medium
**Files:** `EVALUATION_REPORT.md`, `AUDIT_REPORT.md`, `SPEC.md`

**Action:**
- ~~Correct AUDIT_REPORT.md CLM-002~~ — Already verified as properly FIXED
- Review SPEC.md Section 11 (Implementation Status) against actual code state
- Ensure README.md "Quick Start" commands actually work from a clean clone

---

## Phase 2: Prove It Works (Week 3-4)

Deploy to a real network and demonstrate the core flow end-to-end.

### 2.1 Sepolia Testnet Deployment
**Priority:** High
**Files:** `scripts/deploy-testnet.ts`, new `deployments/sepolia.json`
**Why:** Deployment scripts exist but have never run. Until contracts live on a real network, this is a thought experiment.

**Action:**
- Run `scripts/deploy-testnet.ts` on Sepolia
- Publish deployed contract addresses in a `deployments/sepolia.json` file
- Verify contracts on Etherscan via `hardhat verify`
- Run `scripts/verify-deployment.ts` post-deploy health checks
- Add deployed addresses to README.md

**Verification:** Anyone with a Sepolia wallet can call `verify()` on a minted credential.

### 2.2 End-to-End Demo Script
**Priority:** Medium
**Files:** New `scripts/demo.ts`
**Why:** A single script that demonstrates the core value prop is worth more than documentation.

**Action:**
Create a script that:
1. Registers an issuer
2. Mints a credential (e.g., birth certificate)
3. Verifies the credential on-chain
4. Generates a ZK age-threshold proof (prove age >= 18 without revealing birthdate)
5. Submits and verifies the proof on-chain
6. Prints human-readable output at each step

**Verification:** Run against Sepolia with real transactions.

---

## Phase 3: Decouple Inheritance (Week 5-8)

The inheritance subsystem is the single largest scope risk. It's well-built but tightly coupled to a non-existent external system (FIE). Extract it into an optional module.

### 3.1 Understand the Coupling Boundary

Inheritance touches core contracts in these specific places:

| Contract | Inheritance Code | Core Impact |
|----------|-----------------|-------------|
| `ClaimToken.sol` | `FIE_BRIDGE_ROLE` (line 56), `fieBridge` (line 72), `markInherited()` (565-570), `mintSplit()` (595-649), `setFIEBridge()` (893-901) | `verify()` accepts INHERITED status (line 690); `_update()` allows transfer for INHERITED (line 926) |
| `CredentialLifecycleManager.sol` | Lines 309-886 (~580 lines): directives, execution, splitting, conditions, executor access, disputes | Shares contract with renewal logic (lines 168-308) |
| `FIEBridge.sol` | Entire contract (449 lines) | Standalone — depends on CLM but nothing depends on it |

### 3.2 Extraction Strategy

**Do NOT rip inheritance out of ClaimToken.** The INHERITED status and its 4 reference points (markInherited, mintSplit, verify check, transfer hook) are small and well-isolated. Removing them would break the status enum and require cascade changes across tests and interfaces.

**Instead, extract at the contract boundary:**

1. **Keep in core (`v1.0` scope):**
   - `ClaimToken.sol` — unchanged (INHERITED status stays as a valid credential state)
   - `IssuerRegistry.sol` — unchanged
   - `ZKDisclosureEngine.sol` — unchanged
   - `CredentialLifecycleManager.sol` — **split into two contracts:**
     - `CredentialRenewalManager.sol` — renewal logic only (lines 168-308 + helpers)
     - `InheritanceManager.sol` — everything else currently in CLM (lines 309-886)

2. **Move to optional module (`sovereign-credential-inheritance` or `v1.1` scope):**
   - `InheritanceManager.sol` (extracted from CLM)
   - `FIEBridge.sol` (already standalone)
   - `IFIEBridge.sol`
   - Related test files: `test/inheritance-scenarios.test.ts`, `test/integration/inheritance-e2e.test.ts`

3. **Interface change:**
   - Split `ICredentialLifecycleManager.sol` into `ICredentialRenewalManager.sol` and `IInheritanceManager.sol`
   - `ClaimToken.sol` gets a `setInheritanceManager(address)` function (like `setFIEBridge`) instead of coupling to the monolithic CLM

**Why this split works:**
- `ClaimToken` already uses role-based access — `LIFECYCLE_MANAGER_ROLE` can be granted to either contract
- The INHERITED status in ClaimToken is just a state flag; it doesn't care which contract sets it
- `FIEBridge` already only talks to CLM through the interface, so it naturally follows the extraction
- Renewal and inheritance share zero logic — they only share a contract

### 3.3 Migration Steps

1. Create `CredentialRenewalManager.sol` with renewal functions extracted from CLM
2. Create `InheritanceManager.sol` with inheritance functions extracted from CLM
3. Split the `ICredentialLifecycleManager.sol` interface
4. Update `ClaimToken.sol` to accept either manager via role grants
5. Update deployment scripts to deploy contracts separately
6. Split test files to match new contract boundaries
7. Run full test suite — all existing tests must pass
8. Deploy new contracts to Sepolia alongside existing ones

---

## Phase 4: Harden for Production (Week 9-12)

### 4.1 Simplify Issuer Reputation
**Priority:** Medium
**Files:** `contracts/IssuerRegistry.sol`
**Why:** The reputation system (basis points, thresholds, adjustment with int256) adds complexity for a system that has zero real issuers. Simplify now, add sophistication when there's data.

**Action:**
- Reduce reputation to a simple `active`/`suspended` boolean for v1.0
- Keep the reputation data structures in the interface but make the threshold check trivial
- Defer granular reputation scoring to v1.1 when real issuer behavior exists to calibrate against

### 4.2 Professional Security Audit
**Priority:** High (before mainnet)
**Why:** The existing Claude Code audit is a good internal review but doesn't meet the bar for a system handling identity credentials on mainnet.

**Action:**
- Engage a professional auditor (Trail of Bits, OpenZeppelin, Cyfrin)
- Scope: Core contracts only (ClaimToken, IssuerRegistry, ZKDisclosureEngine, RenewalManager)
- Exclude inheritance module from initial audit scope to reduce cost
- Budget for 2-3 week engagement

### 4.3 Gas Optimization Pass
**Priority:** Low
**Files:** All contracts
**Why:** `EnumerableSet` for indexed queries is convenient but expensive at scale. Before mainnet, benchmark gas costs against NFR-01 (< 500,000 gas for minting) and NFR-02 (< 300,000 gas for ZK verification).

**Action:**
- Run `REPORT_GAS=true hardhat test` and publish results
- If minting exceeds 500k gas, consider replacing EnumerableSet with events-based indexing
- If ZK verification exceeds 300k gas, evaluate proof batching

---

## What NOT To Do

| Temptation | Why Not |
|-----------|---------|
| Build a frontend wallet | No users yet. Prove the protocol works first. |
| Add more ZK disclosure types | 4 types + compound is sufficient for launch |
| Implement CompoundProof3/4 circuits | CompoundProof (2 disclosures) covers 90% of use cases |
| Build NatLangChain integration | NatLangChain doesn't exist in production. Design the interface, don't build the bridge. |
| Add more claim types beyond the 16 defined | The type registry is extensible. 16 types is more than enough for testnet. |
| Over-engineer the issuer onboarding | A simple admin script is sufficient until there are real issuers. |

---

## Success Criteria

**Phase 1 complete when:**
- [x] `sdk/src/encryption.ts` uses real secp256k1 ECDH (no WARNING/TODO comments remain)
- [x] CI passes on every push (compile, test, coverage, lint)
- [x] Documentation matches code state

**Phase 2 complete when:**
- [ ] Contracts deployed and verified on Sepolia
- [x] `scripts/demo.ts` runs the full mint-verify-disclose flow against Sepolia
- [ ] Deployed addresses published in repo

**Phase 3 complete when:**
- [x] `CredentialRenewalManager.sol` and `InheritanceManager.sol` exist as separate contracts
- [x] `FIEBridge` + `InheritanceManager` can be deployed independently of core
- [ ] All existing tests pass against the new contract structure
- [x] Core contracts can be deployed without any inheritance dependencies

**Phase 4 complete when:**
- [ ] Professional audit completed on core contracts — scope documented in `AUDIT_SCOPE.md`
- [x] Gas benchmarks published and within spec targets — `test/gas-benchmark.test.ts`
- [x] Issuer reputation simplified for v1.0 — `MIN_REPUTATION = 0`, gating removed

---

## Timeline Summary

| Phase | Focus | Duration | Gate |
|-------|-------|----------|------|
| 1 | Credibility | Week 1-2 | Encryption real, CI green |
| 2 | Proof of life | Week 3-4 | Sepolia deployment live |
| 3 | Decouple inheritance | Week 5-8 | CLM split, all tests green |
| 4 | Production hardening | Week 9-12 | Audit complete, gas within spec |

**After Phase 4:** The core credential system (mint, verify, disclose) is production-ready for mainnet. The inheritance module ships as an optional v1.1 add-on when FIE exists.
