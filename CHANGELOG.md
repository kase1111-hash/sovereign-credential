# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha] - 2026-01-23

### Added

#### Smart Contracts
- **ClaimToken (ERC721)**: Core credential NFT contract with encrypted payload support
- **IssuerRegistry**: Authorized issuer management with claim type permissions and delegation
- **ZKDisclosureEngine**: Zero-knowledge proof verification for selective disclosure
- **CredentialLifecycleManager**: Full credential lifecycle (issuance, transfer, renewal, revocation)
- **FIEBridge**: Integration with Finite Intent Executor for inheritance scenarios

#### Zero-Knowledge Circuits
- **AgeThreshold**: Prove age comparisons without revealing birthdate
- **DateRange**: Prove dates fall within ranges
- **ValueRange**: Prove numeric values within bounds
- **SetMembership**: Prove membership in credential sets
- **CompoundProof**: Combine multiple proofs into single verification

#### SDK
- TypeScript SDK for contract interaction
- Credential creation and verification utilities
- ZK proof generation helpers
- Merkle tree implementation for efficient proofs

#### Testing
- Comprehensive unit tests for all contracts
- Integration tests for multi-contract workflows
- Invariant tests for protocol properties
- Fuzz testing for edge cases
- Test fixtures and helpers

#### Deployment
- Local development deployment scripts
- Sepolia testnet deployment configuration
- Mainnet deployment scripts with verification
- Deployment verification utilities

#### Documentation
- Technical specification (SPEC.md)
- 20-step implementation guide
- Architecture documentation
- API reference
- Deployment guide
- Security documentation and threat models
- Audit preparation guide
- User and issuer guides

### Security
- Reentrancy protection on all state-changing functions
- Access control via OpenZeppelin libraries
- Signature verification for credential issuance
- Revocation status checks integrated throughout

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 0.1.0-alpha | 2026-01-23 | Initial alpha release with core functionality |

[Unreleased]: https://github.com/kase1111-hash/sovereign-credential/compare/v0.1.0-alpha...HEAD
[0.1.0-alpha]: https://github.com/kase1111-hash/sovereign-credential/releases/tag/v0.1.0-alpha
