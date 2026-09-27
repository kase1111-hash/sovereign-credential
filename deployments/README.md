# Deployments

This directory stores deployment artifacts for each network.

## File naming convention

- `<network>-<timestamp>.json` — Snapshot at deploy time
- `<network>-latest.json` — Most recent deployment for a given network

## Contracts deployed

The core v1.0 deployment creates 4 contracts (all UUPS proxies):

1. **IssuerRegistry** — Issuer registration, type authorization, delegation
2. **ClaimToken** — ERC721 credential NFT with soulbound transfer rules
3. **CredentialRenewalManager** — Renewal workflow, batch transfer, grace periods
4. **ZKDisclosureEngine** — ZK proof verification and replay prevention

The optional inheritance module (InheritanceManager + FIEBridge) is **not** deployed in v1.0.

## How to deploy

### Local (Hardhat)

```bash
# Terminal 1: start a local node
npm run node

# Terminal 2: run the full demo (deploys + exercises all core operations)
npm run demo:local
```

Or deploy without the demo:
```bash
npx hardhat run scripts/deploy.ts --network localhost
```

### Sepolia Testnet

```bash
# Set environment variables
export PRIVATE_KEY="0x..."            # Deployer wallet (needs >= 0.1 ETH)
export SEPOLIA_RPC_URL="https://..."  # e.g. Alchemy or Infura
export ETHERSCAN_API_KEY="..."        # For contract verification

# Deploy
npx hardhat run scripts/deploy-testnet.ts --network sepolia
```

### After deployment

```bash
# Verify the deployment is healthy
npx hardhat run scripts/verify-deployment.ts --network <network>

# Run the end-to-end demo against the deployed contracts
npx hardhat run scripts/demo.ts --network <network>
```

## Current deployments

No live deployments yet. Deploy to Sepolia to create the first one.
