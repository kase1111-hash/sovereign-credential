/**
 * @file deploy.ts
 * @description Main deployment script for Sovereign Credential contracts
 * @dev Deploys all contracts using UUPS proxy pattern
 */

import { ethers, upgrades, network } from "hardhat";
import { type Contract } from "ethers";
import * as fs from "fs";
import * as path from "path";

// Deployment configuration
interface DeploymentConfig {
  networkName: string;
  chainId: number;
  multisigAddress?: string;
  verifyContracts: boolean;
}

// Deployment result
interface DeploymentResult {
  networkName: string;
  chainId: number;
  timestamp: number;
  contracts: {
    issuerRegistry: {
      proxy: string;
      implementation: string;
    };
    claimToken: {
      proxy: string;
      implementation: string;
    };
    credentialLifecycleManager: {
      proxy: string;
      implementation: string;
    };
  };
  roles: {
    admin: string;
    upgrader: string;
  };
}

// Network-specific configurations
const NETWORK_CONFIGS: Record<string, Partial<DeploymentConfig>> = {
  hardhat: {
    verifyContracts: false,
  },
  localhost: {
    verifyContracts: false,
  },
  sepolia: {
    verifyContracts: true,
  },
  mainnet: {
    verifyContracts: true,
  },
};

async function main() {
  console.log("🚀 Starting Sovereign Credential Deployment\n");

  // Get deployment config
  const networkName = network.name;
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const config: DeploymentConfig = {
    networkName,
    chainId: Number(chainId),
    verifyContracts: NETWORK_CONFIGS[networkName]?.verifyContracts ?? false,
    ...NETWORK_CONFIGS[networkName],
  };

  console.log(`📡 Network: ${networkName} (chainId: ${chainId})`);

  // Get deployer
  const [deployer] = await ethers.getSigners();
  console.log(`👤 Deployer: ${deployer.address}`);
  console.log(`💰 Balance: ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))} ETH\n`);

  // Deploy contracts
  const result = await deployContracts(deployer.address, config);

  // Save deployment result
  await saveDeploymentResult(result);

  // Print summary
  printDeploymentSummary(result);

  console.log("\n✅ Deployment complete!");
}

async function deployContracts(
  deployerAddress: string,
  config: DeploymentConfig
): Promise<DeploymentResult> {
  const timestamp = Math.floor(Date.now() / 1000);

  // 1. Deploy IssuerRegistry
  console.log("📦 Deploying IssuerRegistry...");
  const IssuerRegistry = await ethers.getContractFactory("IssuerRegistry");
  const issuerRegistry = await upgrades.deployProxy(IssuerRegistry, [], {
    initializer: "initialize",
    kind: "uups",
  });
  await issuerRegistry.waitForDeployment();

  const issuerRegistryAddress = await issuerRegistry.getAddress();
  const issuerRegistryImplAddress = await upgrades.erc1967.getImplementationAddress(
    issuerRegistryAddress
  );
  console.log(`   Proxy: ${issuerRegistryAddress}`);
  console.log(`   Implementation: ${issuerRegistryImplAddress}`);

  // 2. Deploy ClaimToken
  console.log("\n📦 Deploying ClaimToken...");
  const ClaimToken = await ethers.getContractFactory("ClaimToken");
  const claimToken = await upgrades.deployProxy(
    ClaimToken,
    [issuerRegistryAddress],
    {
      initializer: "initialize",
      kind: "uups",
    }
  );
  await claimToken.waitForDeployment();

  const claimTokenAddress = await claimToken.getAddress();
  const claimTokenImplAddress = await upgrades.erc1967.getImplementationAddress(
    claimTokenAddress
  );
  console.log(`   Proxy: ${claimTokenAddress}`);
  console.log(`   Implementation: ${claimTokenImplAddress}`);

  // 3. Deploy CredentialLifecycleManager
  console.log("\n📦 Deploying CredentialLifecycleManager...");
  const CredentialLifecycleManager = await ethers.getContractFactory(
    "CredentialLifecycleManager"
  );
  const lifecycleManager = await upgrades.deployProxy(
    CredentialLifecycleManager,
    [claimTokenAddress, issuerRegistryAddress],
    {
      initializer: "initialize",
      kind: "uups",
    }
  );
  await lifecycleManager.waitForDeployment();

  const lifecycleManagerAddress = await lifecycleManager.getAddress();
  const lifecycleManagerImplAddress = await upgrades.erc1967.getImplementationAddress(
    lifecycleManagerAddress
  );
  console.log(`   Proxy: ${lifecycleManagerAddress}`);
  console.log(`   Implementation: ${lifecycleManagerImplAddress}`);

  // 4. Configure cross-references
  console.log("\n🔗 Configuring cross-references...");

  // Grant CREDENTIAL_CONTRACT_ROLE to ClaimToken in IssuerRegistry
  const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
  await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, claimTokenAddress);
  console.log("   ✓ Granted CREDENTIAL_CONTRACT_ROLE to ClaimToken");

  // Set LifecycleManager in ClaimToken
  await claimToken.setLifecycleManager(lifecycleManagerAddress);
  console.log("   ✓ Set LifecycleManager in ClaimToken");

  return {
    networkName: config.networkName,
    chainId: config.chainId,
    timestamp,
    contracts: {
      issuerRegistry: {
        proxy: issuerRegistryAddress,
        implementation: issuerRegistryImplAddress,
      },
      claimToken: {
        proxy: claimTokenAddress,
        implementation: claimTokenImplAddress,
      },
      credentialLifecycleManager: {
        proxy: lifecycleManagerAddress,
        implementation: lifecycleManagerImplAddress,
      },
    },
    roles: {
      admin: deployerAddress,
      upgrader: deployerAddress,
    },
  };
}

async function saveDeploymentResult(result: DeploymentResult): Promise<void> {
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const filename = `${result.networkName}-${result.timestamp}.json`;
  const filepath = path.join(deploymentsDir, filename);

  fs.writeFileSync(filepath, JSON.stringify(result, null, 2));
  console.log(`\n💾 Deployment saved to: ${filepath}`);

  // Also save as latest deployment for this network
  const latestFilename = `${result.networkName}-latest.json`;
  const latestFilepath = path.join(deploymentsDir, latestFilename);
  fs.writeFileSync(latestFilepath, JSON.stringify(result, null, 2));
}

function printDeploymentSummary(result: DeploymentResult): void {
  console.log("\n" + "=".repeat(60));
  console.log("DEPLOYMENT SUMMARY");
  console.log("=".repeat(60));
  console.log(`Network: ${result.networkName} (${result.chainId})`);
  console.log(`Timestamp: ${new Date(result.timestamp * 1000).toISOString()}`);
  console.log("\nContract Addresses:");
  console.log(`  IssuerRegistry (Proxy): ${result.contracts.issuerRegistry.proxy}`);
  console.log(`  ClaimToken (Proxy): ${result.contracts.claimToken.proxy}`);
  console.log(`  LifecycleManager (Proxy): ${result.contracts.credentialLifecycleManager.proxy}`);
  console.log("\nRoles:");
  console.log(`  Admin: ${result.roles.admin}`);
  console.log(`  Upgrader: ${result.roles.upgrader}`);
  console.log("=".repeat(60));
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Deployment failed:", error);
    process.exit(1);
  });
