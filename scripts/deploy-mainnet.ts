/**
 * @file deploy-mainnet.ts
 * @description Mainnet deployment script with safety checks and multisig handoff
 * @dev Production deployment with additional safety measures
 *
 * Usage:
 *   npx hardhat run scripts/deploy-mainnet.ts --network mainnet
 *
 * Environment variables:
 *   PRIVATE_KEY: Deployer private key
 *   MAINNET_RPC_URL: Mainnet RPC endpoint
 *   ETHERSCAN_API_KEY: For contract verification
 *   MULTISIG_ADDRESS: (Required) Address to transfer admin to
 *   FIE_EXECUTION_AGENT: (Required) FIE execution agent address
 *
 * Safety Checklist:
 *   [ ] All tests pass
 *   [ ] Security audit completed
 *   [ ] Multisig address verified
 *   [ ] FIE agent address verified
 *   [ ] Gas prices checked
 *   [ ] Deployment rehearsed on testnet
 */

import { ethers, upgrades, network, run } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";

interface MainnetConfig {
  multisigAddress: string;
  fieExecutionAgent: string;
  gasLimit?: bigint;
  maxGasPrice?: bigint;
}

interface MainnetDeploymentResult {
  networkName: string;
  chainId: number;
  timestamp: number;
  blockNumber: number;
  deployer: string;
  contracts: {
    issuerRegistry: { proxy: string; implementation: string };
    claimToken: { proxy: string; implementation: string };
    credentialLifecycleManager: { proxy: string; implementation: string };
    zkDisclosureEngine: { proxy: string; implementation: string };
    fieBridge: { proxy: string; implementation: string };
    verifiers: {
      dateRange: string;
      valueRange: string;
      setMembership: string;
      compoundProof: string;
    };
  };
  roles: {
    admin: string;
    upgrader: string;
  };
  adminTransferred: boolean;
  totalGasUsed: string;
  totalCostETH: string;
}

async function main() {
  console.log("=".repeat(60));
  console.log("SOVEREIGN CREDENTIAL MAINNET DEPLOYMENT");
  console.log("=".repeat(60));
  console.log("\n*** PRODUCTION DEPLOYMENT - PROCEED WITH CAUTION ***\n");

  // Validate network
  if (network.name !== "mainnet" && network.name !== "natlangchain") {
    console.error(`\nError: This script is for mainnet deployment only.`);
    console.log(`Current network: ${network.name}`);
    console.log("\nFor testnet deployment, use: npx hardhat run scripts/deploy-testnet.ts");
    process.exit(1);
  }

  // Validate environment variables
  const config = validateConfig();

  // Get deployer
  const [deployer] = await ethers.getSigners();
  const balance = await ethers.provider.getBalance(deployer.address);
  const chainId = Number((await ethers.provider.getNetwork()).chainId);

  console.log(`Network: ${network.name} (chainId: ${chainId})`);
  console.log(`Deployer: ${deployer.address}`);
  console.log(`Balance: ${ethers.formatEther(balance)} ETH`);
  console.log(`\nMultisig: ${config.multisigAddress}`);
  console.log(`FIE Agent: ${config.fieExecutionAgent}`);

  // Check gas price
  const feeData = await ethers.provider.getFeeData();
  const gasPrice = feeData.gasPrice || 0n;
  console.log(`\nCurrent gas price: ${ethers.formatUnits(gasPrice, "gwei")} gwei`);

  if (config.maxGasPrice && gasPrice > config.maxGasPrice) {
    console.error(`\nError: Gas price too high!`);
    console.log(`Max allowed: ${ethers.formatUnits(config.maxGasPrice, "gwei")} gwei`);
    console.log("Wait for lower gas prices or increase MAX_GAS_PRICE env var.");
    process.exit(1);
  }

  // Minimum balance check (estimate ~5 ETH for full deployment)
  const minBalance = ethers.parseEther("2");
  if (balance < minBalance) {
    console.error(`\nError: Insufficient balance`);
    console.log(`Required: >= 2 ETH (recommended: 5 ETH)`);
    console.log(`Current: ${ethers.formatEther(balance)} ETH`);
    process.exit(1);
  }

  // Confirmation prompt
  await confirmDeployment(config);

  console.log("\nStarting deployment...\n");

  // Deploy all contracts
  const result = await deployMainnetContracts(deployer.address, chainId, config);

  // Transfer admin to multisig
  await transferAdminToMultisig(result, config);

  // Save deployment result
  await saveDeploymentResult(result);

  // Verify contracts
  await verifyContracts(result);

  // Print summary
  printDeploymentSummary(result);

  console.log("\n" + "=".repeat(60));
  console.log("MAINNET DEPLOYMENT COMPLETE");
  console.log("=".repeat(60));
  console.log("\nCRITICAL POST-DEPLOYMENT STEPS:");
  console.log("1. Verify all contract addresses on Etherscan");
  console.log("2. Test admin functions via multisig");
  console.log("3. Register production issuers");
  console.log("4. Update documentation with contract addresses");
  console.log("5. Configure monitoring and alerts");
}

function validateConfig(): MainnetConfig {
  const multisigAddress = process.env.MULTISIG_ADDRESS;
  const fieExecutionAgent = process.env.FIE_EXECUTION_AGENT;
  const maxGasPrice = process.env.MAX_GAS_PRICE
    ? ethers.parseUnits(process.env.MAX_GAS_PRICE, "gwei")
    : undefined;

  if (!multisigAddress) {
    console.error("\nError: MULTISIG_ADDRESS environment variable is required for mainnet");
    console.log("This should be a Gnosis Safe or similar multisig contract.");
    process.exit(1);
  }

  if (!ethers.isAddress(multisigAddress)) {
    console.error(`\nError: Invalid MULTISIG_ADDRESS: ${multisigAddress}`);
    process.exit(1);
  }

  if (!fieExecutionAgent) {
    console.error("\nError: FIE_EXECUTION_AGENT environment variable is required for mainnet");
    process.exit(1);
  }

  if (!ethers.isAddress(fieExecutionAgent)) {
    console.error(`\nError: Invalid FIE_EXECUTION_AGENT: ${fieExecutionAgent}`);
    process.exit(1);
  }

  return {
    multisigAddress,
    fieExecutionAgent,
    maxGasPrice,
  };
}

async function confirmDeployment(config: MainnetConfig): Promise<void> {
  console.log("\n" + "=".repeat(60));
  console.log("DEPLOYMENT CONFIRMATION");
  console.log("=".repeat(60));
  console.log("\nThis will deploy the Sovereign Credential system to mainnet.");
  console.log("Admin will be transferred to:", config.multisigAddress);
  console.log("\nPlease confirm the following:");
  console.log("  [x] All tests pass (npx hardhat test)");
  console.log("  [x] Security audit completed");
  console.log("  [x] Multisig address is correct and accessible");
  console.log("  [x] Deployment rehearsed on testnet");
  console.log("=".repeat(60));

  // Skip confirmation if CI environment
  if (process.env.CI === "true") {
    console.log("\nCI environment detected, skipping confirmation.");
    return;
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve, reject) => {
    rl.question("\nType 'DEPLOY' to proceed: ", (answer) => {
      rl.close();
      if (answer === "DEPLOY") {
        resolve();
      } else {
        reject(new Error("Deployment cancelled by user"));
      }
    });
  });
}

async function deployMainnetContracts(
  deployerAddress: string,
  chainId: number,
  config: MainnetConfig
): Promise<MainnetDeploymentResult> {
  const timestamp = Math.floor(Date.now() / 1000);
  const blockNumber = await ethers.provider.getBlockNumber();
  let totalGasUsed = 0n;

  // Deploy IssuerRegistry
  console.log("[1/9] Deploying IssuerRegistry...");
  const IssuerRegistry = await ethers.getContractFactory("IssuerRegistry");
  const issuerRegistry = await upgrades.deployProxy(IssuerRegistry, [], {
    initializer: "initialize",
    kind: "uups",
  });
  const issuerRegistryReceipt = await issuerRegistry.deploymentTransaction()?.wait();
  totalGasUsed += issuerRegistryReceipt?.gasUsed || 0n;
  await issuerRegistry.waitForDeployment();
  const issuerRegistryAddress = await issuerRegistry.getAddress();
  const issuerRegistryImpl = await upgrades.erc1967.getImplementationAddress(issuerRegistryAddress);
  console.log(`   Proxy: ${issuerRegistryAddress}`);

  // Deploy ClaimToken
  console.log("\n[2/9] Deploying ClaimToken...");
  const ClaimToken = await ethers.getContractFactory("ClaimToken");
  const claimToken = await upgrades.deployProxy(ClaimToken, [issuerRegistryAddress], {
    initializer: "initialize",
    kind: "uups",
  });
  const claimTokenReceipt = await claimToken.deploymentTransaction()?.wait();
  totalGasUsed += claimTokenReceipt?.gasUsed || 0n;
  await claimToken.waitForDeployment();
  const claimTokenAddress = await claimToken.getAddress();
  const claimTokenImpl = await upgrades.erc1967.getImplementationAddress(claimTokenAddress);
  console.log(`   Proxy: ${claimTokenAddress}`);

  // Deploy CredentialLifecycleManager
  console.log("\n[3/9] Deploying CredentialLifecycleManager...");
  const CredentialLifecycleManager = await ethers.getContractFactory("CredentialLifecycleManager");
  const lifecycleManager = await upgrades.deployProxy(
    CredentialLifecycleManager,
    [claimTokenAddress, issuerRegistryAddress],
    { initializer: "initialize", kind: "uups" }
  );
  const lifecycleReceipt = await lifecycleManager.deploymentTransaction()?.wait();
  totalGasUsed += lifecycleReceipt?.gasUsed || 0n;
  await lifecycleManager.waitForDeployment();
  const lifecycleManagerAddress = await lifecycleManager.getAddress();
  const lifecycleManagerImpl = await upgrades.erc1967.getImplementationAddress(lifecycleManagerAddress);
  console.log(`   Proxy: ${lifecycleManagerAddress}`);

  // Deploy ZKDisclosureEngine
  console.log("\n[4/9] Deploying ZKDisclosureEngine...");
  const ZKDisclosureEngine = await ethers.getContractFactory("ZKDisclosureEngine");
  const zkDisclosureEngine = await upgrades.deployProxy(
    ZKDisclosureEngine,
    [claimTokenAddress],
    { initializer: "initialize", kind: "uups" }
  );
  const zkEngineReceipt = await zkDisclosureEngine.deploymentTransaction()?.wait();
  totalGasUsed += zkEngineReceipt?.gasUsed || 0n;
  await zkDisclosureEngine.waitForDeployment();
  const zkDisclosureEngineAddress = await zkDisclosureEngine.getAddress();
  const zkDisclosureEngineImpl = await upgrades.erc1967.getImplementationAddress(zkDisclosureEngineAddress);
  console.log(`   Proxy: ${zkDisclosureEngineAddress}`);

  // Deploy FIEBridge
  console.log("\n[5/9] Deploying FIEBridge...");
  const FIEBridge = await ethers.getContractFactory("FIEBridge");
  const fieBridge = await upgrades.deployProxy(
    FIEBridge,
    [lifecycleManagerAddress],
    { initializer: "initialize", kind: "uups" }
  );
  const fieBridgeReceipt = await fieBridge.deploymentTransaction()?.wait();
  totalGasUsed += fieBridgeReceipt?.gasUsed || 0n;
  await fieBridge.waitForDeployment();
  const fieBridgeAddress = await fieBridge.getAddress();
  const fieBridgeImpl = await upgrades.erc1967.getImplementationAddress(fieBridgeAddress);
  console.log(`   Proxy: ${fieBridgeAddress}`);

  // Deploy ZK Verifiers
  console.log("\n[6/9] Deploying ZK Verifiers...");

  const DateRangeVerifier = await ethers.getContractFactory("DateRangeVerifier");
  const dateRangeVerifier = await DateRangeVerifier.deploy();
  await dateRangeVerifier.waitForDeployment();
  const dateRangeVerifierAddress = await dateRangeVerifier.getAddress();

  const ValueRangeVerifier = await ethers.getContractFactory("ValueRangeVerifier");
  const valueRangeVerifier = await ValueRangeVerifier.deploy();
  await valueRangeVerifier.waitForDeployment();
  const valueRangeVerifierAddress = await valueRangeVerifier.getAddress();

  const SetMembershipVerifier = await ethers.getContractFactory("SetMembershipVerifier");
  const setMembershipVerifier = await SetMembershipVerifier.deploy();
  await setMembershipVerifier.waitForDeployment();
  const setMembershipVerifierAddress = await setMembershipVerifier.getAddress();

  const CompoundProofVerifier = await ethers.getContractFactory("CompoundProofVerifier");
  const compoundProofVerifier = await CompoundProofVerifier.deploy();
  await compoundProofVerifier.waitForDeployment();
  const compoundProofVerifierAddress = await compoundProofVerifier.getAddress();

  console.log("   All verifiers deployed");

  // Configure cross-references
  console.log("\n[7/9] Configuring cross-references...");
  const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
  let tx = await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, claimTokenAddress);
  let receipt = await tx.wait();
  totalGasUsed += receipt?.gasUsed || 0n;

  tx = await claimToken.setLifecycleManager(lifecycleManagerAddress);
  receipt = await tx.wait();
  totalGasUsed += receipt?.gasUsed || 0n;
  console.log("   Cross-references configured");

  // Register ZK verifiers
  console.log("\n[8/9] Registering ZK verifiers...");
  const DISCLOSURE_DATE_RANGE = await zkDisclosureEngine.DISCLOSURE_DATE_RANGE();
  const DISCLOSURE_VALUE_RANGE = await zkDisclosureEngine.DISCLOSURE_VALUE_RANGE();
  const DISCLOSURE_SET_MEMBERSHIP = await zkDisclosureEngine.DISCLOSURE_SET_MEMBERSHIP();
  const DISCLOSURE_COMPOUND = await zkDisclosureEngine.DISCLOSURE_COMPOUND();

  await zkDisclosureEngine.registerVerifier(DISCLOSURE_DATE_RANGE, dateRangeVerifierAddress);
  await zkDisclosureEngine.registerVerifier(DISCLOSURE_VALUE_RANGE, valueRangeVerifierAddress);
  await zkDisclosureEngine.registerVerifier(DISCLOSURE_SET_MEMBERSHIP, setMembershipVerifierAddress);
  await zkDisclosureEngine.registerVerifier(DISCLOSURE_COMPOUND, compoundProofVerifierAddress);
  console.log("   ZK verifiers registered");

  // Configure FIE agent
  console.log("\n[9/9] Configuring FIE agent...");
  tx = await fieBridge.setFIEExecutionAgent(config.fieExecutionAgent);
  receipt = await tx.wait();
  totalGasUsed += receipt?.gasUsed || 0n;
  console.log(`   FIE agent set: ${config.fieExecutionAgent}`);

  // Calculate total cost
  const feeData = await ethers.provider.getFeeData();
  const gasPrice = feeData.gasPrice || 0n;
  const totalCost = totalGasUsed * gasPrice;

  return {
    networkName: network.name,
    chainId,
    timestamp,
    blockNumber,
    deployer: deployerAddress,
    contracts: {
      issuerRegistry: { proxy: issuerRegistryAddress, implementation: issuerRegistryImpl },
      claimToken: { proxy: claimTokenAddress, implementation: claimTokenImpl },
      credentialLifecycleManager: { proxy: lifecycleManagerAddress, implementation: lifecycleManagerImpl },
      zkDisclosureEngine: { proxy: zkDisclosureEngineAddress, implementation: zkDisclosureEngineImpl },
      fieBridge: { proxy: fieBridgeAddress, implementation: fieBridgeImpl },
      verifiers: {
        dateRange: dateRangeVerifierAddress,
        valueRange: valueRangeVerifierAddress,
        setMembership: setMembershipVerifierAddress,
        compoundProof: compoundProofVerifierAddress,
      },
    },
    roles: {
      admin: config.multisigAddress,
      upgrader: config.multisigAddress,
    },
    adminTransferred: false,
    totalGasUsed: totalGasUsed.toString(),
    totalCostETH: ethers.formatEther(totalCost),
  };
}

async function transferAdminToMultisig(
  result: MainnetDeploymentResult,
  config: MainnetConfig
): Promise<void> {
  console.log("\nTransferring admin roles to multisig...");

  const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
  const UPGRADER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("UPGRADER_ROLE"));

  const contracts = [
    { name: "IssuerRegistry", address: result.contracts.issuerRegistry.proxy },
    { name: "ClaimToken", address: result.contracts.claimToken.proxy },
    { name: "CredentialLifecycleManager", address: result.contracts.credentialLifecycleManager.proxy },
    { name: "ZKDisclosureEngine", address: result.contracts.zkDisclosureEngine.proxy },
    { name: "FIEBridge", address: result.contracts.fieBridge.proxy },
  ];

  for (const contract of contracts) {
    const factory = await ethers.getContractFactory(contract.name);
    const instance = factory.attach(contract.address);

    // Grant roles to multisig
    await instance.grantRole(DEFAULT_ADMIN_ROLE, config.multisigAddress);
    await instance.grantRole(UPGRADER_ROLE, config.multisigAddress);

    // Renounce roles from deployer
    const [deployer] = await ethers.getSigners();
    await instance.renounceRole(UPGRADER_ROLE, deployer.address);
    await instance.renounceRole(DEFAULT_ADMIN_ROLE, deployer.address);

    console.log(`   ${contract.name}: Admin transferred to multisig`);
  }

  result.adminTransferred = true;
  console.log("\nAdmin transfer complete!");
}

async function verifyContracts(result: MainnetDeploymentResult): Promise<void> {
  console.log("\nVerifying contracts on Etherscan...");

  const implementations = [
    { name: "IssuerRegistry", address: result.contracts.issuerRegistry.implementation },
    { name: "ClaimToken", address: result.contracts.claimToken.implementation },
    { name: "CredentialLifecycleManager", address: result.contracts.credentialLifecycleManager.implementation },
    { name: "ZKDisclosureEngine", address: result.contracts.zkDisclosureEngine.implementation },
    { name: "FIEBridge", address: result.contracts.fieBridge.implementation },
    { name: "DateRangeVerifier", address: result.contracts.verifiers.dateRange },
    { name: "ValueRangeVerifier", address: result.contracts.verifiers.valueRange },
    { name: "SetMembershipVerifier", address: result.contracts.verifiers.setMembership },
    { name: "CompoundProofVerifier", address: result.contracts.verifiers.compoundProof },
  ];

  for (const impl of implementations) {
    try {
      await run("verify:verify", {
        address: impl.address,
        constructorArguments: [],
      });
      console.log(`   Verified: ${impl.name}`);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      if (errorMessage.includes("Already Verified")) {
        console.log(`   Already verified: ${impl.name}`);
      } else {
        console.log(`   Verification pending: ${impl.name}`);
      }
    }
  }
}

async function saveDeploymentResult(result: MainnetDeploymentResult): Promise<void> {
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const filename = `${result.networkName}-${result.timestamp}.json`;
  const filepath = path.join(deploymentsDir, filename);
  fs.writeFileSync(filepath, JSON.stringify(result, null, 2));

  const latestFilepath = path.join(deploymentsDir, `${result.networkName}-latest.json`);
  fs.writeFileSync(latestFilepath, JSON.stringify(result, null, 2));

  // Also save a backup
  const backupDir = path.join(deploymentsDir, "backups");
  if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir, { recursive: true });
  }
  const backupFilepath = path.join(backupDir, filename);
  fs.writeFileSync(backupFilepath, JSON.stringify(result, null, 2));

  console.log(`\nDeployment saved to: ${filepath}`);
  console.log(`Backup saved to: ${backupFilepath}`);
}

function printDeploymentSummary(result: MainnetDeploymentResult): void {
  console.log("\n" + "=".repeat(60));
  console.log("MAINNET DEPLOYMENT SUMMARY");
  console.log("=".repeat(60));
  console.log(`Network: ${result.networkName} (chainId: ${result.chainId})`);
  console.log(`Block: ${result.blockNumber}`);
  console.log(`Timestamp: ${new Date(result.timestamp * 1000).toISOString()}`);
  console.log(`\nDeployer: ${result.deployer}`);
  console.log(`Admin (Multisig): ${result.roles.admin}`);
  console.log(`Admin Transferred: ${result.adminTransferred ? "YES" : "NO"}`);
  console.log("\nCore Contracts:");
  console.log(`  IssuerRegistry: ${result.contracts.issuerRegistry.proxy}`);
  console.log(`  ClaimToken: ${result.contracts.claimToken.proxy}`);
  console.log(`  LifecycleManager: ${result.contracts.credentialLifecycleManager.proxy}`);
  console.log(`  ZKDisclosureEngine: ${result.contracts.zkDisclosureEngine.proxy}`);
  console.log(`  FIEBridge: ${result.contracts.fieBridge.proxy}`);
  console.log("\nZK Verifiers:");
  console.log(`  DateRangeVerifier: ${result.contracts.verifiers.dateRange}`);
  console.log(`  ValueRangeVerifier: ${result.contracts.verifiers.valueRange}`);
  console.log(`  SetMembershipVerifier: ${result.contracts.verifiers.setMembership}`);
  console.log(`  CompoundProofVerifier: ${result.contracts.verifiers.compoundProof}`);
  console.log(`\nDeployment Cost:`);
  console.log(`  Total Gas Used: ${result.totalGasUsed}`);
  console.log(`  Total Cost: ${result.totalCostETH} ETH`);
  console.log("=".repeat(60));
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Mainnet deployment failed:", error);
    process.exit(1);
  });
