# Sovereign Credential Deployment Guide

This guide covers deploying the Sovereign Credential system to various networks.

## Prerequisites

### Software Requirements

- Node.js 18+
- npm or yarn
- Git

### Environment Setup

1. Clone the repository:
```bash
git clone https://github.com/[org]/sovereign-credential
cd sovereign-credential
```

2. Install dependencies:
```bash
npm install
```

3. Compile contracts:
```bash
npx hardhat compile
```

4. Run tests:
```bash
npx hardhat test
```

### Environment Variables

Create a `.env` file:

```bash
# Private key for deployment (without 0x prefix)
PRIVATE_KEY=your_private_key_here

# RPC endpoints
SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/YOUR_KEY
MAINNET_RPC_URL=https://mainnet.infura.io/v3/YOUR_KEY
NATLANGCHAIN_RPC_URL=https://rpc.natlangchain.io

# Block explorer API keys
ETHERSCAN_API_KEY=your_etherscan_key

# Optional: For mainnet
MULTISIG_ADDRESS=0x...
FIE_EXECUTION_AGENT=0x...
MAX_GAS_PRICE=50  # in gwei
```

## Deployment Options

### Local Development

Deploy to local Hardhat network:

```bash
# Start local node (in separate terminal)
npx hardhat node

# Deploy
npx hardhat run scripts/deploy.ts --network localhost
```

### Testnet (Sepolia)

```bash
# Ensure you have testnet ETH
# Get from: https://sepoliafaucet.com/

# Deploy with testnet script
npx hardhat run scripts/deploy-testnet.ts --network sepolia
```

### Mainnet

```bash
# IMPORTANT: Review all safety checks first
# Set required environment variables

export MULTISIG_ADDRESS=0x...  # Your Gnosis Safe
export FIE_EXECUTION_AGENT=0x...  # Authorized FIE agent

# Deploy with mainnet script
npx hardhat run scripts/deploy-mainnet.ts --network mainnet
```

## Deployment Scripts

### Main Deployment (`deploy.ts`)

Deploys all contracts with default configuration:
- IssuerRegistry
- ClaimToken
- CredentialLifecycleManager
- ZKDisclosureEngine
- FIEBridge
- All ZK verifiers

```bash
npx hardhat run scripts/deploy.ts --network <network>
```

### Testnet Deployment (`deploy-testnet.ts`)

Additional testnet features:
- Automatic test issuer registration
- Contract verification on block explorer
- Balance checks with faucet links
- Detailed progress output

```bash
npx hardhat run scripts/deploy-testnet.ts --network sepolia
```

### Mainnet Deployment (`deploy-mainnet.ts`)

Production safety features:
- Required environment variables check
- Gas price limits
- Confirmation prompts
- Admin transfer to multisig
- Backup deployment records

```bash
npx hardhat run scripts/deploy-mainnet.ts --network mainnet
```

## Post-Deployment Steps

### 1. Verify Deployment

```bash
npx hardhat run scripts/verify-deployment.ts --network <network>
```

This checks:
- All contracts deployed
- Proxy implementations correct
- Cross-references configured
- Roles assigned properly
- ZK verifiers registered

### 2. Verify on Block Explorer

For Sepolia/Mainnet, contracts should auto-verify. If not:

```bash
npx hardhat verify --network <network> <contract_address>
```

### 3. Register Issuers

```bash
ISSUER_ADDRESS=0x... \
JURISDICTION=US-CA \
npx hardhat run scripts/setup-issuer.ts --network <network>
```

### 4. Test Minting

```bash
SUBJECT_ADDRESS=0x... \
CLAIM_TYPE=IDENTITY.BIRTH \
npx hardhat run scripts/mint-credential.ts --network <network>
```

### 5. Verify Credential

```bash
TOKEN_ID=1 npx hardhat run scripts/verify-credential.ts --network <network>
```

## Deployment Artifacts

After deployment, artifacts are saved in `deployments/`:

```
deployments/
├── sepolia-latest.json          # Latest testnet deployment
├── sepolia-1704067200.json      # Timestamped backup
├── mainnet-latest.json          # Latest mainnet deployment
├── mainnet-1704067200.json      # Timestamped backup
├── upgrades/                    # Upgrade records
│   └── sepolia-ClaimToken-1704153600.json
├── mints/                       # Mint records
│   └── sepolia-1-1704240000.json
└── backups/                     # Mainnet backups
    └── mainnet-1704067200.json
```

### Deployment JSON Structure

```json
{
  "networkName": "sepolia",
  "chainId": 11155111,
  "timestamp": 1704067200,
  "contracts": {
    "issuerRegistry": {
      "proxy": "0x...",
      "implementation": "0x..."
    },
    "claimToken": {
      "proxy": "0x...",
      "implementation": "0x..."
    },
    "credentialLifecycleManager": {
      "proxy": "0x...",
      "implementation": "0x..."
    },
    "zkDisclosureEngine": {
      "proxy": "0x...",
      "implementation": "0x..."
    },
    "fieBridge": {
      "proxy": "0x...",
      "implementation": "0x..."
    },
    "verifiers": {
      "dateRange": "0x...",
      "valueRange": "0x...",
      "setMembership": "0x...",
      "compoundProof": "0x..."
    }
  },
  "roles": {
    "admin": "0x...",
    "upgrader": "0x..."
  }
}
```

## Upgrades

### Preparing an Upgrade

1. Make contract changes
2. Ensure storage compatibility:
```bash
npx hardhat run scripts/check-upgrade-safety.ts
```

3. Deploy new implementation:
```bash
UPGRADE_CONTRACT=ClaimToken \
PROXY_ADDRESS=0x... \
npx hardhat run scripts/upgrade.ts --network <network>
```

### Upgrade Safety

The upgrade script:
- Validates upgrade compatibility
- Checks caller has UPGRADER_ROLE
- Records old/new implementation
- Updates deployment files

### Mainnet Upgrades

For mainnet, upgrades should go through multisig:

1. Prepare upgrade transaction data
2. Submit to Gnosis Safe
3. Collect required signatures
4. Execute upgrade

## Network Configuration

### Hardhat Config Networks

```typescript
// hardhat.config.ts
networks: {
  hardhat: {
    chainId: 31337,
  },
  localhost: {
    url: "http://127.0.0.1:8545",
    chainId: 31337,
  },
  sepolia: {
    url: process.env.SEPOLIA_RPC_URL,
    accounts: [process.env.PRIVATE_KEY],
    chainId: 11155111,
  },
  mainnet: {
    url: process.env.MAINNET_RPC_URL,
    accounts: [process.env.PRIVATE_KEY],
    chainId: 1,
  },
  natlangchain: {
    url: process.env.NATLANGCHAIN_RPC_URL,
    accounts: [process.env.PRIVATE_KEY],
    chainId: parseInt(process.env.NATLANGCHAIN_CHAIN_ID || "0"),
  },
}
```

### Adding New Networks

1. Add network config to `hardhat.config.ts`
2. Add RPC URL to `.env`
3. Update `NETWORK_CONFIGS` in deploy scripts

## Gas Optimization

### Estimated Deployment Costs

| Contract | Gas | Est. Cost (30 gwei) |
|----------|-----|---------------------|
| IssuerRegistry | ~2.5M | ~0.075 ETH |
| ClaimToken | ~4M | ~0.12 ETH |
| CredentialLifecycleManager | ~3M | ~0.09 ETH |
| ZKDisclosureEngine | ~2.5M | ~0.075 ETH |
| FIEBridge | ~2M | ~0.06 ETH |
| Verifiers (4x) | ~4M | ~0.12 ETH |
| Configuration | ~0.5M | ~0.015 ETH |
| **Total** | **~18.5M** | **~0.555 ETH** |

### Reducing Costs

- Deploy during low gas periods
- Use `MAX_GAS_PRICE` limit
- Consider L2 deployment for testing

## Troubleshooting

### "Insufficient funds"

```
Error: sender doesn't have enough funds to send tx
```

Solution: Add more ETH to deployer wallet

### "Nonce too low"

```
Error: nonce has already been used
```

Solution: Wait for pending transactions or reset nonce

### "Gas estimation failed"

```
Error: cannot estimate gas; transaction may fail
```

Solutions:
- Check constructor arguments
- Verify dependencies deployed
- Review contract for errors

### "Verification failed"

```
Error: Contract verification failed
```

Solutions:
- Wait 1-2 minutes after deployment
- Check constructor arguments match
- Verify correct compiler settings

### "Upgrade validation failed"

```
Error: New storage layout is incompatible
```

Solutions:
- Check storage layout changes
- Use storage gaps
- Consider migration strategy

## Security Checklist

Before mainnet deployment:

- [ ] All tests pass
- [ ] Security audit completed
- [ ] Gas costs reviewed
- [ ] Multisig configured
- [ ] FIE agent authorized
- [ ] Testnet deployment verified
- [ ] Admin keys secured
- [ ] Monitoring configured
- [ ] Incident response plan ready
- [ ] Documentation updated

## Monitoring

### Post-Deployment Monitoring

1. Set up event listeners for critical events
2. Configure alerts for:
   - Large credential mints
   - Issuer suspensions
   - Unusual verification patterns
   - Upgrade events

### Tools

- Tenderly for transaction monitoring
- OpenZeppelin Defender for admin operations
- The Graph for indexing
- Custom dashboard for metrics

## Support

- Documentation: `/docs` folder
- Issues: GitHub Issues
- Security: See `SECURITY.md`
