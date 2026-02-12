# Audit Scope — Sovereign Credential v1.0

**Prepared:** 2026-02-12
**Target:** Professional security audit of core credential contracts
**Recommended firms:** Trail of Bits, OpenZeppelin, Cyfrin

---

## In-Scope Contracts

| Contract | LOC | Description |
|----------|-----|-------------|
| `contracts/ClaimToken.sol` | ~950 | ERC721 credential NFT — mint, verify, status management, soulbound transfer rules |
| `contracts/IssuerRegistry.sol` | ~670 | Issuer registration, type authorization, delegation, reputation tracking |
| `contracts/ZKDisclosureEngine.sol` | ~450 | ZK proof verification, disclosure request management, replay prevention |
| `contracts/CredentialRenewalManager.sol` | ~400 | Renewal workflow (request/approve/deny), batch transfer, grace period |
| `contracts/libraries/CredentialTypes.sol` | ~320 | Shared data structures, constants, enums |
| `contracts/libraries/Errors.sol` | ~230 | Custom error definitions |

**Total in-scope:** ~3,020 LOC Solidity

### Supporting Interfaces (read for context, not primary audit target)

| Interface | Description |
|-----------|-------------|
| `contracts/interfaces/IClaimToken.sol` | ClaimToken interface |
| `contracts/interfaces/IIssuerRegistry.sol` | IssuerRegistry interface |
| `contracts/interfaces/IZKDisclosureEngine.sol` | ZKDisclosureEngine interface |
| `contracts/interfaces/ICredentialRenewalManager.sol` | RenewalManager interface |

---

## Out of Scope

| Contract/Module | Reason |
|----------------|--------|
| `contracts/InheritanceManager.sol` | Optional v1.1 module; depends on FIE (not yet in production) |
| `contracts/FIEBridge.sol` | Optional v1.1 module; bridge to external system |
| `contracts/CredentialLifecycleManager.sol` | Legacy monolithic contract; superseded by RenewalManager + InheritanceManager |
| `contracts/interfaces/IFIEBridge.sol` | Out-of-scope bridge interface |
| `contracts/interfaces/IInheritanceManager.sol` | Out-of-scope inheritance interface |
| `contracts/interfaces/ICredentialLifecycleManager.sol` | Legacy interface |
| `circuits/` | Circom ZK circuits — separate circuit audit recommended |
| `sdk/` | TypeScript SDK — not on-chain |

---

## Architecture Overview

```
                    +-----------------+
                    | IssuerRegistry  |
                    | (UUPS proxy)    |
                    +--------+--------+
                             |
                    isAuthorized(issuer, type)
                             |
                    +--------v--------+
                    |   ClaimToken    |
                    |   (ERC721,      |
                    |    UUPS proxy)  |
                    +--------+--------+
                             |
              +--------------+--------------+
              |                             |
     +--------v--------+          +--------v--------+
     | ZKDisclosure     |          | Credential       |
     | Engine           |          | RenewalManager   |
     | (UUPS proxy)     |          | (UUPS proxy)     |
     +------------------+          +------------------+
```

### Key Design Patterns

1. **UUPS Upgradeable Proxy** — All contracts use OpenZeppelin UUPS with `UPGRADER_ROLE`
2. **Role-Based Access Control** — `DEFAULT_ADMIN_ROLE`, `REGISTRAR_ROLE`, `ARBITER_ROLE`, `LIFECYCLE_MANAGER_ROLE`, `CREDENTIAL_CONTRACT_ROLE`
3. **Soulbound NFTs** — Transfer restricted to issuer, lifecycle manager, or INHERITED status
4. **Signature verification** — ECDSA over `keccak256(abi.encode(...))` with chain ID and contract address binding
5. **Replay prevention** — Signature hash tracking in both ClaimToken and RenewalManager

---

## Known Issues / Design Decisions

### Intentional

| Item | Detail |
|------|--------|
| Reputation gating disabled (v1.0) | `MIN_REPUTATION = 0`. Authorization checks use `isActive` boolean only. Granular reputation scoring deferred to v1.1 when real issuer data exists for calibration. |
| INHERITED status in ClaimToken | The `INHERITED` credential status and 4 associated code paths (`markInherited`, `mintSplit`, verify check, transfer hook) remain in ClaimToken even though the inheritance module is out of scope. These are dormant unless an InheritanceManager is deployed and granted `LIFECYCLE_MANAGER_ROLE`. |
| No on-chain ZK verification | `ZKDisclosureEngine.verifyDisclosure()` accepts proof bytes but actual Groth16 verification happens off-chain via snarkjs. On-chain verification stores proof hashes for replay prevention. |
| 32KB payload limit | `MAX_PAYLOAD_SIZE = 32 * 1024` enforced in ClaimToken mint. Large payloads are expensive but within block gas limits. |

### Areas of Concern (auditor attention requested)

| Area | Concern |
|------|---------|
| Signature malleability | Verify ECDSA signatures in `ClaimToken.mint()` and `CredentialRenewalManager.approveRenewal()` are protected against EIP-2 / compact signature attacks. OpenZeppelin `ECDSA.recover()` handles this, but confirm. |
| Proxy storage collisions | 4 UUPS proxies with independent storage layouts. Verify no storage slot collisions across upgrades. |
| EnumerableSet gas at scale | `_issuersByType`, `_issuerTypes`, `_subjectCredentials` use EnumerableSet. Verify gas stays within bounds as sets grow. Benchmark data in `test/gas-benchmark.test.ts`. |
| Cross-contract reentrancy | ClaimToken calls IssuerRegistry.isAuthorized() during mint and IssuerRegistry.recordIssuance() after mint. Verify no reentrancy vector via callback. |
| Transfer restrictions | Soulbound logic in `ClaimToken._update()` allows transfer only for specific roles/statuses. Verify no bypass via approval mechanics. |
| Expiry handling | `verify()` checks `expiresAt > block.timestamp`. Verify timestamp manipulation resistance and that expired credentials cannot be used in any path. |

---

## Test Coverage

| Suite | File Count | Description |
|-------|-----------|-------------|
| Unit tests | 7 | Individual contract tests |
| Integration tests | 4 | Multi-contract interaction tests |
| Invariant tests | 2 | Safety and liveness property verification |
| Fuzz tests | 1 | Property-based testing for credential operations |
| Gas benchmarks | 1 | NFR-01/NFR-02 gas target verification |

**Run tests:**
```bash
npm test                          # Full suite
npm run test:coverage             # With coverage report
npm run test:gas                  # With gas reporting
npm run test:gas:benchmark        # Gas benchmarks only
```

---

## Deployment Configuration

| Setting | Value |
|---------|-------|
| Solidity version | 0.8.28 |
| Optimizer | Enabled, 200 runs |
| viaIR | true |
| EVM target | Cancun |
| OpenZeppelin | v5.0.2 |
| Proxy pattern | UUPS (ERC1967) |

---

## Deliverables Requested

1. Full security assessment of in-scope contracts
2. Gas optimization recommendations (reference `test/gas-benchmark.test.ts` results)
3. Upgrade safety review (storage layout compatibility)
4. Access control completeness review
5. Formal verification candidates identification (if applicable)
