/**
 * @file deploy-testnet.ts
 * @description Testnet-specific deployment script with additional setup for testing
 * @dev Extends base deployment with testnet-specific configurations
 *
 * Usage:
 *   npx hardhat run scripts/deploy-testnet.ts --network sepolia
 *
 * Environment variables:
 *   PRIVATE_KEY: Deployer private key
 *   SEPOLIA_RPC_URL: Sepolia RPC endpoint
 *   ETHERSCAN_API_KEY: For contract verification
 */

import { ethers, upgrades, network, run } from "hardhat";
import * as fs from "fs";
import * as path from "path";

// Supported testnets
const SUPPORTED_TESTNETS = ["sepolia", "holesky", "localhost", "hardhat"];

interface TestnetDeploymentResult {
  networkName: string;
  chainId: number;
  timestamp: number;
  blockNumber: number;
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
  testAccounts: {
    issuer: string;
    subject: string;
  };
}

async function main() {
  console.log("=".repeat(60));
  console.log("SOVEREIGN CREDENTIAL TESTNET DEPLOYMENT");
  console.log("=".repeat(60));

  // Validate network
  if (!SUPPORTED_TESTNETS.includes(network.name)) {
    console.error(`\nError: Unsupported network '${network.name}'`);
    console.log(`Supported testnets: ${SUPPORTED_TESTNETS.join(", ")}`);
    console.log("\nUsage: npx hardhat run scripts/deploy-testnet.ts --network sepolia");
    process.exit(1);
  }

  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  console.log(`\nNetwork: ${network.name} (chainId: ${chainId})`);

  // Get signers
  const signers = await ethers.getSigners();
  const deployer = signers[0];

  console.log(`Deployer: ${deployer.address}`);
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`Balance: ${ethers.formatEther(balance)} ETH`);

  // Check minimum balance
  const minBalance = ethers.parseEther("0.1");
  if (balance < minBalance) {
    console.error("\nError: Insufficient balance for deployment");
    console.log(`Required: >= 0.1 ETH`);
    console.log(`Current: ${ethers.formatEther(balance)} ETH`);
    console.log("\nGet testnet ETH from a faucet:");
    console.log("  Sepolia: https://sepoliafaucet.com/");
    console.log("  Sepolia: https://www.alchemy.com/faucets/ethereum-sepolia");
    process.exit(1);
  }

  // Deploy all contracts
  const result = await deployTestnetContracts(deployer.address, chainId);

  // Register test issuer
  await registerTestIssuer(result);

  // Save deployment result
  await saveDeploymentResult(result);

  // Verify contracts on block explorer (if not local network)
  if (network.name !== "localhost" && network.name !== "hardhat") {
    await verifyContracts(result);
  }

  // Print summary
  printDeploymentSummary(result);

  console.log("\n" + "=".repeat(60));
  console.log("TESTNET DEPLOYMENT COMPLETE");
  console.log("=".repeat(60));
  console.log("\nNext steps:");
  console.log("1. Run verification: npx hardhat run scripts/verify-deployment.ts --network " + network.name);
  console.log("2. Register issuers: ISSUER_ADDRESS=0x... npx hardhat run scripts/setup-issuer.ts --network " + network.name);
  console.log("3. Mint a test credential: npx hardhat run scripts/mint-credential.ts --network " + network.name);
}

async function deployTestnetContracts(
  deployerAddress: string,
  chainId: number
): Promise<TestnetDeploymentResult> {
  const timestamp = Math.floor(Date.now() / 1000);
  const blockNumber = await ethers.provider.getBlockNumber();

  // Deploy IssuerRegistry
  console.log("\n[1/9] Deploying IssuerRegistry...");
  const IssuerRegistry = await ethers.getContractFactory("IssuerRegistry");
  const issuerRegistry = await upgrades.deployProxy(IssuerRegistry, [], {
    initializer: "initialize",
    kind: "uups",
  });
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
  await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, claimTokenAddress);
  await claimToken.setLifecycleManager(lifecycleManagerAddress);
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

  // Get test accounts
  console.log("\n[9/9] Setting up test accounts...");
  const signers = await ethers.getSigners();
  const testIssuer = signers.length > 1 ? signers[1].address : deployerAddress;
  const testSubject = signers.length > 2 ? signers[2].address : deployerAddress;
  console.log(`   Test Issuer: ${testIssuer}`);
  console.log(`   Test Subject: ${testSubject}`);

  return {
    networkName: network.name,
    chainId,
    timestamp,
    blockNumber,
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
      admin: deployerAddress,
      upgrader: deployerAddress,
    },
    testAccounts: {
      issuer: testIssuer,
      subject: testSubject,
    },
  };
}

async function registerTestIssuer(result: TestnetDeploymentResult): Promise<void> {
  console.log("\nRegistering test issuer...");

  const IssuerRegistry = await ethers.getContractFactory("IssuerRegistry");
  const issuerRegistry = IssuerRegistry.attach(result.contracts.issuerRegistry.proxy);

  // Check if test issuer is already registered
  const issuerInfo = await issuerRegistry.getIssuer(result.testAccounts.issuer);
  if (issuerInfo.issuerAddress !== ethers.ZeroAddress) {
    console.log("   Test issuer already registered");
    return;
  }

  // Define claim types for testing
  const claimTypes = [
    ethers.keccak256(ethers.toUtf8Bytes("IDENTITY.BIRTH")),
    ethers.keccak256(ethers.toUtf8Bytes("LICENSE.PROFESSIONAL")),
    ethers.keccak256(ethers.toUtf8Bytes("EDUCATION.DEGREE")),
  ];

  // Register test issuer
  await issuerRegistry.registerIssuer(
    result.testAccounts.issuer,
    "TESTNET",
    claimTypes
  );
  console.log(`   Test issuer registered: ${result.testAccounts.issuer}`);
}

async function verifyContracts(result: TestnetDeploymentResult): Promise<void> {
  console.log("\nVerifying contracts on block explorer...");
  console.log("(This may take a few minutes)");

  const contracts = [
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

  for (const contract of contracts) {
    try {
      await run("verify:verify", {
        address: contract.address,
        constructorArguments: [],
      });
      console.log(`   Verified: ${contract.name}`);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      if (errorMessage.includes("Already Verified")) {
        console.log(`   Already verified: ${contract.name}`);
      } else {
        console.log(`   Failed to verify ${contract.name}: ${errorMessage}`);
      }
    }
  }
}

async function saveDeploymentResult(result: TestnetDeploymentResult): Promise<void> {
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir, { recursive: true });
  }

  const filename = `${result.networkName}-${result.timestamp}.json`;
  const filepath = path.join(deploymentsDir, filename);
  fs.writeFileSync(filepath, JSON.stringify(result, null, 2));

  const latestFilepath = path.join(deploymentsDir, `${result.networkName}-latest.json`);
  fs.writeFileSync(latestFilepath, JSON.stringify(result, null, 2));

  console.log(`\nDeployment saved to: ${filepath}`);
}

function printDeploymentSummary(result: TestnetDeploymentResult): void {
  console.log("\n" + "=".repeat(60));
  console.log("TESTNET DEPLOYMENT SUMMARY");
  console.log("=".repeat(60));
  console.log(`Network: ${result.networkName} (chainId: ${result.chainId})`);
  console.log(`Block: ${result.blockNumber}`);
  console.log(`Timestamp: ${new Date(result.timestamp * 1000).toISOString()}`);
  console.log("\nCore Contracts:");
  console.log(`  IssuerRegistry: ${result.contracts.issuerRegistry.proxy}`);
  console.log(`  ClaimToken: ${result.contracts.claimToken.proxy}`);
  console.log(`  LifecycleManager: ${result.contracts.credentialLifecycleManager.proxy}`);
  console.log(`  ZKDisclosureEngine: ${result.contracts.zkDisclosureEngine.proxy}`);
  console.log(`  FIEBridge: ${result.contracts.fieBridge.proxy}`);
  console.log("\nTest Accounts:");
  console.log(`  Admin: ${result.roles.admin}`);
  console.log(`  Test Issuer: ${result.testAccounts.issuer}`);
  console.log(`  Test Subject: ${result.testAccounts.subject}`);
  console.log("=".repeat(60));
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Testnet deployment failed:", error);
    process.exit(1);
  });
