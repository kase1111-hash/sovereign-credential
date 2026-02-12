# Deployments

This directory stores deployment artifacts for each network.

## File naming convention

- `<network>-<timestamp>.json` — Snapshot at deploy time
- `<network>-latest.json` — Most recent deployment for a given network

## How to deploy

### Local (Hardhat)

```bash
# Terminal 1: start a local node
npx hardhat node

# Terminal 2: deploy
npx hardhat run scripts/deploy.ts --network localhost
```

### Sepolia Testnet

```bash
# Set environment variables
export PRIVATE_KEY="0x..."          # Deployer wallet (needs >= 0.1 ETH)
export SEPOLIA_RPC_URL="https://..."  # e.g. Alchemy or Infura
export ETHERSCAN_API_KEY="..."       # For contract verification

# Deploy
npx hardhat run scripts/deploy-testnet.ts --network sepolia
```

### After deployment

```bash
# Verify the deployment is healthy
npx hardhat run scripts/verify-deployment.ts --network <network>

# Run the end-to-end demo
npx hardhat run scripts/demo.ts --network <network>
```

## Current deployments

No live deployments yet. Deploy to Sepolia to create the first one.
