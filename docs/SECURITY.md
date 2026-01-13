# Security Documentation

This document outlines the security considerations, mitigations, and best practices for the Sovereign Credential system.

## Table of Contents

1. [Security Architecture](#security-architecture)
2. [Access Control](#access-control)
3. [Smart Contract Security](#smart-contract-security)
4. [Zero-Knowledge Security](#zero-knowledge-security)
5. [Cryptographic Security](#cryptographic-security)
6. [Threat Model](#threat-model)
7. [Security Checklist](#security-checklist)
8. [Known Limitations](#known-limitations)
9. [Incident Response](#incident-response)
10. [Contact](#contact)

---

## Security Architecture

### Overview

The Sovereign Credential system implements a defense-in-depth approach with multiple security layers:

1. **Smart Contract Layer**: UUPS upgradeable contracts with role-based access control
2. **Cryptographic Layer**: ECDSA signatures, ZK proofs (Groth16), and Poseidon hashes
3. **Protocol Layer**: Strict state machine transitions and invariant enforcement
4. **External Integration Layer**: FIE Bridge for secure inheritance execution

### Trust Assumptions

| Component | Trust Level | Assumption |
|-----------|-------------|------------|
| Smart Contracts | Verified | Code is audited and correctly deployed |
| Issuers | Semi-trusted | Registered via governance, reputation-tracked |
| FIE (Finite Intent Executor) | Trusted Oracle | External system for mortality triggers |
| ZK Verifiers | Verified | Circuits are correctly compiled and trusted setup performed |
| Subjects | Untrusted | Users must prove claims, cannot forge credentials |

---

## Access Control

### Role Hierarchy

```
DEFAULT_ADMIN_ROLE
    ├── UPGRADER_ROLE
    ├── REGISTRAR_ROLE
    ├── ARBITER_ROLE
    ├── CREDENTIAL_CONTRACT_ROLE
    └── FIE_EXECUTION_ROLE
```

### Role Permissions

| Role | Permissions | Assigned To |
|------|-------------|-------------|
| `DEFAULT_ADMIN_ROLE` | Grant/revoke roles, emergency pause | Multisig wallet |
| `UPGRADER_ROLE` | Upgrade contract implementations | Governance/Timelock |
| `REGISTRAR_ROLE` | Register/deactivate issuers, manage claim types | Registry admin |
| `ARBITER_ROLE` | Adjust reputation, resolve disputes | Arbitration committee |
| `CREDENTIAL_CONTRACT_ROLE` | Update issuer statistics on mint/revoke | ClaimToken contract |
| `FIE_EXECUTION_ROLE` | Execute inheritance triggers | FIEBridge/MockFIE |

### Contract-Specific Access

#### IssuerRegistry
- `registerIssuer()`: REGISTRAR_ROLE
- `deactivateIssuer()`: REGISTRAR_ROLE
- `adjustReputation()`: ARBITER_ROLE
- `authorizeType()`: REGISTRAR_ROLE

#### ClaimToken
- `mint()`: Authorized issuer only
- `revoke()`: Original issuer only
- `suspend()`: Original issuer only
- `reinstate()`: Original issuer only

#### CredentialLifecycleManager
- `setInheritanceDirective()`: Token owner only
- `approveRenewal()`: Original issuer only
- `resolveDispute()`: ARBITER_ROLE

#### FIEBridge
- `registerIntent()`: Admin or owner
- `executeInheritance()`: FIE_EXECUTION_ROLE

---

## Smart Contract Security

### Reentrancy Protection

All external calls are protected using OpenZeppelin's `ReentrancyGuard`:

```solidity
// Example from ClaimToken.sol
function mint(MintRequest calldata request, bytes calldata signature)
    external
    nonReentrant
    returns (uint256)
{
    // Implementation
}
```

**Protected Functions:**
- `mint()`
- `revoke()`
- `suspend()`
- `reinstate()`
- `executeInheritance()`
- `verifyDisclosure()`

### Integer Overflow/Underflow

- Solidity 0.8.28 provides built-in overflow/underflow protection
- All arithmetic operations use checked math by default
- No unchecked blocks are used for financial calculations

### Access Control Implementation

```solidity
// Role-based access using OpenZeppelin AccessControl
modifier onlyIssuer(uint256 tokenId) {
    require(
        credentials[tokenId].issuer == msg.sender,
        "Not credential issuer"
    );
    _;
}

modifier onlyAuthorizedIssuer(bytes32 claimType) {
    require(
        issuerRegistry.isAuthorized(msg.sender, claimType),
        "Not authorized for claim type"
    );
    _;
}
```

### Signature Security

#### Signature Malleability Prevention

EIP-712 typed signatures with domain separation:

```solidity
bytes32 public constant DOMAIN_TYPEHASH = keccak256(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
);

bytes32 public constant MINT_REQUEST_TYPEHASH = keccak256(
    "MintRequest(bytes32 claimType,address subject,bytes32 payloadHash,uint64 expiresAt,string metadataURI)"
);
```

- Uses OpenZeppelin's ECDSA library with `s` value check
- Chain ID included to prevent cross-chain replay
- Contract address included in hash

### Upgrade Security

UUPS (Universal Upgradeable Proxy Standard) pattern:

1. **Timelock**: All upgrades require minimum delay
2. **Authorization**: Only UPGRADER_ROLE can propose upgrades
3. **Storage Layout**: Careful gap management for future variables

```solidity
// Storage gap for upgrade safety
uint256[50] private __gap;
```

---

## Zero-Knowledge Security

### Circuit Security

| Circuit | Purpose | Public Inputs | Private Inputs |
|---------|---------|---------------|----------------|
| AgeThreshold | Prove age above/below threshold | threshold, currentTime, result | birthdate, salt |
| DateRange | Prove date within range | rangeStart, rangeEnd, result | actualDate, salt |
| ValueRange | Prove value within range | minValue, maxValue, result | actualValue, salt |
| SetMembership | Prove value in allowed set | merkleRoot, result | value, salt, merkleProof |
| CompoundProof | Combine multiple disclosures | sub-proof results | all sub-proof private inputs |

### Proof Replay Prevention

```solidity
mapping(bytes32 => bool) public usedNullifiers;

function verifyDisclosure(DisclosureRequest calldata request)
    external
    returns (bool)
{
    require(!usedNullifiers[request.nullifier], "Nullifier already used");
    usedNullifiers[request.nullifier] = true;
    // Verify proof...
}
```

### Commitment Verification

- All disclosed values must match stored commitments
- Commitments use Poseidon hash for ZK-friendliness
- Salt prevents rainbow table attacks

---

## Cryptographic Security

### Hash Functions

| Usage | Algorithm | Rationale |
|-------|-----------|-----------|
| General hashing | Keccak-256 | EVM native, widely audited |
| ZK commitments | Poseidon | ZK-SNARK friendly, efficient in circuits |
| Merkle trees | Keccak-256 | Gas efficient for on-chain verification |

### Encryption

- Payload encryption: AES-256-GCM (off-chain)
- Key exchange: ECIES with secp256k1
- Only hashes stored on-chain

### Signature Schemes

- ECDSA with secp256k1 (Ethereum standard)
- EIP-712 for structured data signing
- EIP-191 for personal message signing

---

## Threat Model

### Threat Categories

#### T1: Unauthorized Credential Issuance
- **Risk**: Malicious actor mints fake credentials
- **Mitigation**: Issuer registration, reputation system, type authorization
- **Detection**: On-chain audit trail, issuer monitoring

#### T2: Credential Forgery
- **Risk**: Attacker creates credential without issuer
- **Mitigation**: ECDSA signature verification, chain ID binding
- **Detection**: Invalid signature rejected by contract

#### T3: Proof Replay Attack
- **Risk**: Same ZK proof used multiple times
- **Mitigation**: Nullifier tracking, per-proof unique identifier
- **Detection**: NullifierAlreadyUsed error

#### T4: Unauthorized Status Change
- **Risk**: Non-issuer revokes/suspends credential
- **Mitigation**: Issuer-only access control
- **Detection**: Transaction revert

#### T5: Inheritance Hijacking
- **Risk**: Attacker redirects inheritance
- **Mitigation**: FIE intent hash verification, owner-only directive setting
- **Detection**: Hash mismatch rejected

#### T6: Front-Running
- **Risk**: MEV extraction on credential operations
- **Mitigation**: Commit-reveal for sensitive operations where applicable
- **Severity**: Low (most operations are issuer-controlled)

#### T7: Oracle Manipulation
- **Risk**: False FIE trigger (fake death notification)
- **Mitigation**: External FIE security, dispute mechanism
- **Recovery**: 30-day dispute window for inheritance

### Risk Matrix

| Threat | Likelihood | Impact | Risk Level |
|--------|------------|--------|------------|
| T1 | Low | High | Medium |
| T2 | Very Low | Critical | Medium |
| T3 | Low | Medium | Low |
| T4 | Very Low | High | Low |
| T5 | Low | High | Medium |
| T6 | Medium | Low | Low |
| T7 | Low | High | Medium |

---

## Security Checklist

### Pre-Deployment

- [x] All contracts compile without warnings
- [x] 95%+ test coverage achieved
- [x] All invariant tests pass
- [x] Gas costs within NFR limits
- [x] Reentrancy guards on all external functions
- [x] Access control verified on all privileged functions
- [x] Upgrade mechanism tested
- [x] No unused state variables
- [x] Events emitted for all state changes

### Deployment

- [ ] Deploy to testnet first
- [ ] Verify all contract source code on block explorer
- [ ] Transfer admin to multisig
- [ ] Configure timelock for upgrades
- [ ] Register initial trusted issuers
- [ ] Test all critical paths on testnet

### Post-Deployment

- [ ] Monitor for unusual activity
- [ ] Set up alerting for critical events
- [ ] Regular security reviews
- [ ] Bug bounty program active
- [ ] Incident response plan documented

---

## Known Limitations

### Design Limitations

1. **Issuer Trust**: System relies on off-chain verification of issuer legitimacy
2. **FIE Dependency**: Inheritance requires external FIE oracle accuracy
3. **Gas Costs**: Large payloads increase storage costs
4. **ZK Overhead**: Proof verification adds computational cost

### Implementation Notes

1. **Credential Privacy**: Payload is encrypted but existence is public
2. **Transfer Restrictions**: Most credentials are non-transferable by design
3. **Upgrade Window**: UUPS upgrades have timelock but are possible
4. **Revocation Permanence**: Revoked credentials cannot be reinstated

### Not Covered

1. **Private transaction submission**: Use Flashbots or similar for MEV protection
2. **Legal compliance**: Jurisdiction-specific requirements are external
3. **Key management**: User wallet security is out of scope

---

## Incident Response

### Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| P0 - Critical | Active exploit, funds at risk | Immediate |
| P1 - High | Exploitable vulnerability found | < 4 hours |
| P2 - Medium | Potential vulnerability | < 24 hours |
| P3 - Low | Minor issue, no immediate risk | < 1 week |

### Response Procedures

#### P0/P1 - Emergency Pause
1. Execute pause function via multisig
2. Notify security team and community
3. Assess damage and vector
4. Deploy fix via emergency upgrade if needed
5. Post-mortem report within 7 days

#### P2/P3 - Standard Process
1. Document issue in security tracker
2. Develop and test fix
3. Schedule upgrade through timelock
4. Deploy and verify

### Contact

For security issues, contact: security@example.com

**Bug Bounty**: See bug-bounty.md for reward structure

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-13 | Initial security documentation |

---

*This document should be reviewed and updated with each major release.*
