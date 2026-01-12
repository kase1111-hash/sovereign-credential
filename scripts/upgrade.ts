/**
 * @file upgrade.ts
 * @description Upgrade script for Sovereign Credential contracts
 * @dev Upgrades contracts using UUPS proxy pattern with safety checks
 *
 * Usage:
 *   npx hardhat run scripts/upgrade.ts --network <network>
 *
 * Environment variables:
 *   UPGRADE_CONTRACT: Contract to upgrade (IssuerRegistry, ClaimToken, CredentialLifecycleManager)
 *   PROXY_ADDRESS: Address of the proxy to upgrade
 */

import { ethers, upgrades, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

// Contract names that can be upgraded
type UpgradeableContract =
  | "IssuerRegistry"
  | "ClaimToken"
  | "CredentialLifecycleManager";

interface UpgradeConfig {
  contractName: UpgradeableContract;
  proxyAddress: string;
}

interface UpgradeResult {
  networkName: string;
  chainId: number;
  timestamp: number;
  contractName: string;
  proxyAddress: string;
  oldImplementation: string;
  newImplementation: string;
  upgrader: string;
}

async function main() {
  console.log("🔄 Starting Sovereign Credential Upgrade\n");

  // Get upgrade config from environment
  const config = getUpgradeConfig();
  if (!config) {
    console.log("Usage: UPGRADE_CONTRACT=<ContractName> PROXY_ADDRESS=<address> npx hardhat run scripts/upgrade.ts --network <network>");
    console.log("\nAlternatively, use interactive mode by running without environment variables.");
    await interactiveUpgrade();
    return;
  }

  // Execute upgrade
  const result = await executeUpgrade(config);

  // Save upgrade result
  await saveUpgradeResult(result);

  // Print summary
  printUpgradeSummary(result);

  console.log("\n✅ Upgrade complete!");
}

function getUpgradeConfig(): UpgradeConfig | null {
  const contractName = process.env.UPGRADE_CONTRACT as UpgradeableContract;
  const proxyAddress = process.env.PROXY_ADDRESS;

  if (!contractName || !proxyAddress) {
    return null;
  }

  const validContracts: UpgradeableContract[] = [
    "IssuerRegistry",
    "ClaimToken",
    "CredentialLifecycleManager",
  ];

  if (!validContracts.includes(contractName)) {
    throw new Error(
      `Invalid contract name: ${contractName}. Valid options: ${validContracts.join(", ")}`
    );
  }

  if (!ethers.isAddress(proxyAddress)) {
    throw new Error(`Invalid proxy address: ${proxyAddress}`);
  }

  return { contractName, proxyAddress };
}

async function interactiveUpgrade(): Promise<void> {
  // Load latest deployment for current network
  const networkName = network.name;
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  const latestFilepath = path.join(deploymentsDir, `${networkName}-latest.json`);

  if (!fs.existsSync(latestFilepath)) {
    console.error(`❌ No deployment found for network: ${networkName}`);
    console.log(`Run 'npx hardhat run scripts/deploy.ts --network ${networkName}' first.`);
    return;
  }

  const deployment = JSON.parse(fs.readFileSync(latestFilepath, "utf-8"));
  console.log(`📋 Found deployment for ${networkName}:`);
  console.log(`   IssuerRegistry: ${deployment.contracts.issuerRegistry.proxy}`);
  console.log(`   ClaimToken: ${deployment.contracts.claimToken.proxy}`);
  console.log(`   LifecycleManager: ${deployment.contracts.credentialLifecycleManager.proxy}`);
  console.log("\nTo upgrade a contract, set environment variables:");
  console.log(`   UPGRADE_CONTRACT=<ContractName> PROXY_ADDRESS=<address> npx hardhat run scripts/upgrade.ts --network ${networkName}`);
}

async function executeUpgrade(config: UpgradeConfig): Promise<UpgradeResult> {
  const networkName = network.name;
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const timestamp = Math.floor(Date.now() / 1000);

  console.log(`📡 Network: ${networkName} (chainId: ${chainId})`);

  // Get upgrader
  const [upgrader] = await ethers.getSigners();
  console.log(`👤 Upgrader: ${upgrader.address}`);

  // Get current implementation
  const oldImplementation = await upgrades.erc1967.getImplementationAddress(
    config.proxyAddress
  );
  console.log(`\n📦 Upgrading ${config.contractName}...`);
  console.log(`   Proxy: ${config.proxyAddress}`);
  console.log(`   Current Implementation: ${oldImplementation}`);

  // Verify upgrader has UPGRADER_ROLE
  const ContractFactory = await ethers.getContractFactory(config.contractName);
  const proxy = ContractFactory.attach(config.proxyAddress);

  const UPGRADER_ROLE = await proxy.UPGRADER_ROLE();
  const hasRole = await proxy.hasRole(UPGRADER_ROLE, upgrader.address);

  if (!hasRole) {
    throw new Error(
      `Account ${upgrader.address} does not have UPGRADER_ROLE on ${config.contractName}`
    );
  }
  console.log("   ✓ Upgrader has UPGRADER_ROLE");

  // Perform upgrade
  console.log("\n🔄 Performing upgrade...");
  const NewContractFactory = await ethers.getContractFactory(config.contractName);

  // Validate upgrade compatibility
  await upgrades.validateUpgrade(config.proxyAddress, NewContractFactory, {
    kind: "uups",
  });
  console.log("   ✓ Upgrade validation passed");

  // Execute upgrade
  const upgraded = await upgrades.upgradeProxy(config.proxyAddress, NewContractFactory, {
    kind: "uups",
  });
  await upgraded.waitForDeployment();

  // Get new implementation
  const newImplementation = await upgrades.erc1967.getImplementationAddress(
    config.proxyAddress
  );
  console.log(`   ✓ New Implementation: ${newImplementation}`);

  return {
    networkName,
    chainId,
    timestamp,
    contractName: config.contractName,
    proxyAddress: config.proxyAddress,
    oldImplementation,
    newImplementation,
    upgrader: upgrader.address,
  };
}

async function saveUpgradeResult(result: UpgradeResult): Promise<void> {
  const upgradesDir = path.join(__dirname, "..", "deployments", "upgrades");
  if (!fs.existsSync(upgradesDir)) {
    fs.mkdirSync(upgradesDir, { recursive: true });
  }

  const filename = `${result.networkName}-${result.contractName}-${result.timestamp}.json`;
  const filepath = path.join(upgradesDir, filename);

  fs.writeFileSync(filepath, JSON.stringify(result, null, 2));
  console.log(`\n💾 Upgrade record saved to: ${filepath}`);

  // Update latest deployment with new implementation
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  const latestFilepath = path.join(deploymentsDir, `${result.networkName}-latest.json`);

  if (fs.existsSync(latestFilepath)) {
    const deployment = JSON.parse(fs.readFileSync(latestFilepath, "utf-8"));

    // Update the correct contract implementation
    const contractKey = getContractKey(result.contractName);
    if (deployment.contracts[contractKey]) {
      deployment.contracts[contractKey].implementation = result.newImplementation;
      fs.writeFileSync(latestFilepath, JSON.stringify(deployment, null, 2));
      console.log(`   Updated latest deployment record`);
    }
  }
}

function getContractKey(contractName: string): string {
  const mapping: Record<string, string> = {
    IssuerRegistry: "issuerRegistry",
    ClaimToken: "claimToken",
    CredentialLifecycleManager: "credentialLifecycleManager",
  };
  return mapping[contractName] || contractName.toLowerCase();
}

function printUpgradeSummary(result: UpgradeResult): void {
  console.log("\n" + "=".repeat(60));
  console.log("UPGRADE SUMMARY");
  console.log("=".repeat(60));
  console.log(`Network: ${result.networkName} (${result.chainId})`);
  console.log(`Contract: ${result.contractName}`);
  console.log(`Timestamp: ${new Date(result.timestamp * 1000).toISOString()}`);
  console.log(`\nAddresses:`);
  console.log(`  Proxy: ${result.proxyAddress}`);
  console.log(`  Old Implementation: ${result.oldImplementation}`);
  console.log(`  New Implementation: ${result.newImplementation}`);
  console.log(`\nUpgrader: ${result.upgrader}`);
  console.log("=".repeat(60));
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Upgrade failed:", error);
    process.exit(1);
  });
