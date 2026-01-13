/**
 * @file deploy.ts
 * @description Main deployment script for Sovereign Credential contracts
 * @dev Deploys all contracts using UUPS proxy pattern
 *
 * Usage:
 *   npx hardhat run scripts/deploy.ts --network <network>
 *
 * Environment variables:
 *   FIE_EXECUTION_AGENT: Address of the FIE execution agent (optional)
 */

import { ethers, upgrades, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

// Deployment configuration
interface DeploymentConfig {
  networkName: string;
  chainId: number;
  multisigAddress?: string;
  fieExecutionAgent?: string;
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
    zkDisclosureEngine: {
      proxy: string;
      implementation: string;
    };
    fieBridge: {
      proxy: string;
      implementation: string;
    };
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
  natlangchain: {
    verifyContracts: false,
  },
};

async function main() {
  console.log("=".repeat(60));
  console.log("SOVEREIGN CREDENTIAL DEPLOYMENT");
  console.log("=".repeat(60));

  // Get deployment config
  const networkName = network.name;
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const config: DeploymentConfig = {
    networkName,
    chainId: Number(chainId),
    verifyContracts: NETWORK_CONFIGS[networkName]?.verifyContracts ?? false,
    fieExecutionAgent: process.env.FIE_EXECUTION_AGENT,
    ...NETWORK_CONFIGS[networkName],
  };

  console.log(`\nNetwork: ${networkName} (chainId: ${chainId})`);

  // Get deployer
  const [deployer] = await ethers.getSigners();
  console.log(`Deployer: ${deployer.address}`);
  console.log(
    `Balance: ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))} ETH\n`
  );

  // Deploy contracts
  const result = await deployContracts(deployer.address, config);

  // Save deployment result
  await saveDeploymentResult(result);

  // Print summary
  printDeploymentSummary(result);

  console.log("\n" + "=".repeat(60));
  console.log("DEPLOYMENT COMPLETE");
  console.log("=".repeat(60));
}

async function deployContracts(
  deployerAddress: string,
  config: DeploymentConfig
): Promise<DeploymentResult> {
  const timestamp = Math.floor(Date.now() / 1000);

  // =========================================
  // 1. Deploy IssuerRegistry
  // =========================================
  console.log("\n[1/9] Deploying IssuerRegistry...");
  const IssuerRegistry = await ethers.getContractFactory("IssuerRegistry");
  const issuerRegistry = await upgrades.deployProxy(IssuerRegistry, [], {
    initializer: "initialize",
    kind: "uups",
  });
  await issuerRegistry.waitForDeployment();

  const issuerRegistryAddress = await issuerRegistry.getAddress();
  const issuerRegistryImplAddress =
    await upgrades.erc1967.getImplementationAddress(issuerRegistryAddress);
  console.log(`   Proxy: ${issuerRegistryAddress}`);
  console.log(`   Implementation: ${issuerRegistryImplAddress}`);

  // =========================================
  // 2. Deploy ClaimToken
  // =========================================
  console.log("\n[2/9] Deploying ClaimToken...");
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
  const claimTokenImplAddress =
    await upgrades.erc1967.getImplementationAddress(claimTokenAddress);
  console.log(`   Proxy: ${claimTokenAddress}`);
  console.log(`   Implementation: ${claimTokenImplAddress}`);

  // =========================================
  // 3. Deploy CredentialLifecycleManager
  // =========================================
  console.log("\n[3/9] Deploying CredentialLifecycleManager...");
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
  const lifecycleManagerImplAddress =
    await upgrades.erc1967.getImplementationAddress(lifecycleManagerAddress);
  console.log(`   Proxy: ${lifecycleManagerAddress}`);
  console.log(`   Implementation: ${lifecycleManagerImplAddress}`);

  // =========================================
  // 4. Deploy ZKDisclosureEngine
  // =========================================
  console.log("\n[4/9] Deploying ZKDisclosureEngine...");
  const ZKDisclosureEngine = await ethers.getContractFactory(
    "ZKDisclosureEngine"
  );
  const zkDisclosureEngine = await upgrades.deployProxy(
    ZKDisclosureEngine,
    [claimTokenAddress],
    {
      initializer: "initialize",
      kind: "uups",
    }
  );
  await zkDisclosureEngine.waitForDeployment();

  const zkDisclosureEngineAddress = await zkDisclosureEngine.getAddress();
  const zkDisclosureEngineImplAddress =
    await upgrades.erc1967.getImplementationAddress(zkDisclosureEngineAddress);
  console.log(`   Proxy: ${zkDisclosureEngineAddress}`);
  console.log(`   Implementation: ${zkDisclosureEngineImplAddress}`);

  // =========================================
  // 5. Deploy FIEBridge
  // =========================================
  console.log("\n[5/9] Deploying FIEBridge...");
  const FIEBridge = await ethers.getContractFactory("FIEBridge");
  const fieBridge = await upgrades.deployProxy(
    FIEBridge,
    [lifecycleManagerAddress],
    {
      initializer: "initialize",
      kind: "uups",
    }
  );
  await fieBridge.waitForDeployment();

  const fieBridgeAddress = await fieBridge.getAddress();
  const fieBridgeImplAddress =
    await upgrades.erc1967.getImplementationAddress(fieBridgeAddress);
  console.log(`   Proxy: ${fieBridgeAddress}`);
  console.log(`   Implementation: ${fieBridgeImplAddress}`);

  // =========================================
  // 6. Deploy ZK Verifiers
  // =========================================
  console.log("\n[6/9] Deploying ZK Verifiers...");

  const DateRangeVerifier = await ethers.getContractFactory(
    "DateRangeVerifier"
  );
  const dateRangeVerifier = await DateRangeVerifier.deploy();
  await dateRangeVerifier.waitForDeployment();
  const dateRangeVerifierAddress = await dateRangeVerifier.getAddress();
  console.log(`   DateRangeVerifier: ${dateRangeVerifierAddress}`);

  const ValueRangeVerifier = await ethers.getContractFactory(
    "ValueRangeVerifier"
  );
  const valueRangeVerifier = await ValueRangeVerifier.deploy();
  await valueRangeVerifier.waitForDeployment();
  const valueRangeVerifierAddress = await valueRangeVerifier.getAddress();
  console.log(`   ValueRangeVerifier: ${valueRangeVerifierAddress}`);

  const SetMembershipVerifier = await ethers.getContractFactory(
    "SetMembershipVerifier"
  );
  const setMembershipVerifier = await SetMembershipVerifier.deploy();
  await setMembershipVerifier.waitForDeployment();
  const setMembershipVerifierAddress = await setMembershipVerifier.getAddress();
  console.log(`   SetMembershipVerifier: ${setMembershipVerifierAddress}`);

  const CompoundProofVerifier = await ethers.getContractFactory(
    "CompoundProofVerifier"
  );
  const compoundProofVerifier = await CompoundProofVerifier.deploy();
  await compoundProofVerifier.waitForDeployment();
  const compoundProofVerifierAddress = await compoundProofVerifier.getAddress();
  console.log(`   CompoundProofVerifier: ${compoundProofVerifierAddress}`);

  // =========================================
  // 7. Configure Cross-References
  // =========================================
  console.log("\n[7/9] Configuring cross-references...");

  // Grant CREDENTIAL_CONTRACT_ROLE to ClaimToken in IssuerRegistry
  const CREDENTIAL_CONTRACT_ROLE =
    await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
  await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, claimTokenAddress);
  console.log("   Granted CREDENTIAL_CONTRACT_ROLE to ClaimToken");

  // Set LifecycleManager in ClaimToken
  await claimToken.setLifecycleManager(lifecycleManagerAddress);
  console.log("   Set LifecycleManager in ClaimToken");

  // =========================================
  // 8. Register ZK Verifiers
  // =========================================
  console.log("\n[8/9] Registering ZK verifiers...");

  const DISCLOSURE_DATE_RANGE = await zkDisclosureEngine.DISCLOSURE_DATE_RANGE();
  const DISCLOSURE_VALUE_RANGE =
    await zkDisclosureEngine.DISCLOSURE_VALUE_RANGE();
  const DISCLOSURE_SET_MEMBERSHIP =
    await zkDisclosureEngine.DISCLOSURE_SET_MEMBERSHIP();
  const DISCLOSURE_COMPOUND = await zkDisclosureEngine.DISCLOSURE_COMPOUND();

  await zkDisclosureEngine.registerVerifier(
    DISCLOSURE_DATE_RANGE,
    dateRangeVerifierAddress
  );
  console.log("   Registered DateRangeVerifier");

  await zkDisclosureEngine.registerVerifier(
    DISCLOSURE_VALUE_RANGE,
    valueRangeVerifierAddress
  );
  console.log("   Registered ValueRangeVerifier");

  await zkDisclosureEngine.registerVerifier(
    DISCLOSURE_SET_MEMBERSHIP,
    setMembershipVerifierAddress
  );
  console.log("   Registered SetMembershipVerifier");

  await zkDisclosureEngine.registerVerifier(
    DISCLOSURE_COMPOUND,
    compoundProofVerifierAddress
  );
  console.log("   Registered CompoundProofVerifier");

  // =========================================
  // 9. Configure FIE Agent (if provided)
  // =========================================
  console.log("\n[9/9] Final configuration...");

  if (config.fieExecutionAgent) {
    await fieBridge.setFIEExecutionAgent(config.fieExecutionAgent);
    console.log(`   Set FIE Execution Agent: ${config.fieExecutionAgent}`);
  } else {
    console.log("   FIE Execution Agent not configured (set FIE_EXECUTION_AGENT env var)");
  }

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
      zkDisclosureEngine: {
        proxy: zkDisclosureEngineAddress,
        implementation: zkDisclosureEngineImplAddress,
      },
      fieBridge: {
        proxy: fieBridgeAddress,
        implementation: fieBridgeImplAddress,
      },
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
  console.log(`\nDeployment saved to: ${filepath}`);

  // Also save as latest deployment for this network
  const latestFilename = `${result.networkName}-latest.json`;
  const latestFilepath = path.join(deploymentsDir, latestFilename);
  fs.writeFileSync(latestFilepath, JSON.stringify(result, null, 2));
}

function printDeploymentSummary(result: DeploymentResult): void {
  console.log("\n" + "=".repeat(60));
  console.log("DEPLOYMENT SUMMARY");
  console.log("=".repeat(60));
  console.log(`Network: ${result.networkName} (chainId: ${result.chainId})`);
  console.log(`Timestamp: ${new Date(result.timestamp * 1000).toISOString()}`);
  console.log("\nCore Contracts:");
  console.log(
    `  IssuerRegistry (Proxy): ${result.contracts.issuerRegistry.proxy}`
  );
  console.log(`  ClaimToken (Proxy): ${result.contracts.claimToken.proxy}`);
  console.log(
    `  LifecycleManager (Proxy): ${result.contracts.credentialLifecycleManager.proxy}`
  );
  console.log(
    `  ZKDisclosureEngine (Proxy): ${result.contracts.zkDisclosureEngine.proxy}`
  );
  console.log(`  FIEBridge (Proxy): ${result.contracts.fieBridge.proxy}`);
  console.log("\nZK Verifiers:");
  console.log(`  DateRangeVerifier: ${result.contracts.verifiers.dateRange}`);
  console.log(`  ValueRangeVerifier: ${result.contracts.verifiers.valueRange}`);
  console.log(
    `  SetMembershipVerifier: ${result.contracts.verifiers.setMembership}`
  );
  console.log(
    `  CompoundProofVerifier: ${result.contracts.verifiers.compoundProof}`
  );
  console.log("\nRoles:");
  console.log(`  Admin: ${result.roles.admin}`);
  console.log(`  Upgrader: ${result.roles.upgrader}`);
  console.log("=".repeat(60));
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });
