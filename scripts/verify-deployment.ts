/**
 * @file verify-deployment.ts
 * @description Verification script to validate Sovereign Credential deployment
 * @dev Checks all contracts are properly deployed and configured
 */

import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

interface DeploymentData {
  networkName: string;
  chainId: number;
  contracts: {
    issuerRegistry: { proxy: string; implementation: string };
    claimToken: { proxy: string; implementation: string };
    credentialLifecycleManager: { proxy: string; implementation: string };
  };
  roles: {
    admin: string;
    upgrader: string;
  };
}

interface VerificationResult {
  passed: boolean;
  checks: {
    name: string;
    passed: boolean;
    message: string;
  }[];
}

async function main() {
  console.log("🔍 Verifying Sovereign Credential Deployment\n");

  // Load deployment
  const deployment = loadDeployment();
  if (!deployment) {
    console.error("❌ No deployment found for current network");
    process.exit(1);
  }

  console.log(`📡 Network: ${network.name}`);
  console.log(`📋 Deployment timestamp: ${new Date(deployment.chainId * 1000).toISOString()}\n`);

  // Run verification checks
  const result = await runVerificationChecks(deployment);

  // Print results
  printVerificationResults(result);

  if (result.passed) {
    console.log("\n✅ All verification checks passed!");
    process.exit(0);
  } else {
    console.log("\n❌ Some verification checks failed!");
    process.exit(1);
  }
}

function loadDeployment(): DeploymentData | null {
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  const latestFilepath = path.join(deploymentsDir, `${network.name}-latest.json`);

  if (!fs.existsSync(latestFilepath)) {
    return null;
  }

  return JSON.parse(fs.readFileSync(latestFilepath, "utf-8"));
}

async function runVerificationChecks(
  deployment: DeploymentData
): Promise<VerificationResult> {
  const checks: VerificationResult["checks"] = [];

  // 1. Verify contracts exist at addresses
  console.log("📦 Checking contract deployments...");

  const issuerRegistryExists = await verifyContractExists(
    deployment.contracts.issuerRegistry.proxy,
    "IssuerRegistry"
  );
  checks.push(issuerRegistryExists);

  const claimTokenExists = await verifyContractExists(
    deployment.contracts.claimToken.proxy,
    "ClaimToken"
  );
  checks.push(claimTokenExists);

  const lifecycleManagerExists = await verifyContractExists(
    deployment.contracts.credentialLifecycleManager.proxy,
    "CredentialLifecycleManager"
  );
  checks.push(lifecycleManagerExists);

  // 2. Verify proxy implementations
  console.log("\n🔗 Checking proxy implementations...");

  const issuerRegistryImpl = await verifyProxyImplementation(
    deployment.contracts.issuerRegistry.proxy,
    deployment.contracts.issuerRegistry.implementation,
    "IssuerRegistry"
  );
  checks.push(issuerRegistryImpl);

  const claimTokenImpl = await verifyProxyImplementation(
    deployment.contracts.claimToken.proxy,
    deployment.contracts.claimToken.implementation,
    "ClaimToken"
  );
  checks.push(claimTokenImpl);

  const lifecycleManagerImpl = await verifyProxyImplementation(
    deployment.contracts.credentialLifecycleManager.proxy,
    deployment.contracts.credentialLifecycleManager.implementation,
    "CredentialLifecycleManager"
  );
  checks.push(lifecycleManagerImpl);

  // 3. Verify cross-references
  console.log("\n🔄 Checking cross-references...");

  const claimTokenIssuerRegistry = await verifyClaimTokenIssuerRegistry(
    deployment.contracts.claimToken.proxy,
    deployment.contracts.issuerRegistry.proxy
  );
  checks.push(claimTokenIssuerRegistry);

  const lifecycleManagerClaimToken = await verifyLifecycleManagerClaimToken(
    deployment.contracts.credentialLifecycleManager.proxy,
    deployment.contracts.claimToken.proxy
  );
  checks.push(lifecycleManagerClaimToken);

  const lifecycleManagerIssuerRegistry = await verifyLifecycleManagerIssuerRegistry(
    deployment.contracts.credentialLifecycleManager.proxy,
    deployment.contracts.issuerRegistry.proxy
  );
  checks.push(lifecycleManagerIssuerRegistry);

  // 4. Verify roles
  console.log("\n👥 Checking roles...");

  const adminRole = await verifyAdminRole(
    deployment.contracts.issuerRegistry.proxy,
    deployment.roles.admin
  );
  checks.push(adminRole);

  const credentialContractRole = await verifyCredentialContractRole(
    deployment.contracts.issuerRegistry.proxy,
    deployment.contracts.claimToken.proxy
  );
  checks.push(credentialContractRole);

  const lifecycleManagerRole = await verifyLifecycleManagerRole(
    deployment.contracts.claimToken.proxy,
    deployment.contracts.credentialLifecycleManager.proxy
  );
  checks.push(lifecycleManagerRole);

  // 5. Verify contract functionality
  console.log("\n⚙️ Checking contract functionality...");

  const claimTokenName = await verifyClaimTokenMetadata(
    deployment.contracts.claimToken.proxy
  );
  checks.push(claimTokenName);

  const passed = checks.every((check) => check.passed);

  return { passed, checks };
}

async function verifyContractExists(
  address: string,
  name: string
): Promise<VerificationResult["checks"][0]> {
  try {
    const code = await ethers.provider.getCode(address);
    const exists = code !== "0x";
    return {
      name: `${name} exists at ${address}`,
      passed: exists,
      message: exists ? "Contract exists" : "No code at address",
    };
  } catch (error) {
    return {
      name: `${name} exists at ${address}`,
      passed: false,
      message: `Error: ${error}`,
    };
  }
}

async function verifyProxyImplementation(
  proxyAddress: string,
  expectedImpl: string,
  name: string
): Promise<VerificationResult["checks"][0]> {
  try {
    // EIP-1967 implementation slot
    const implSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
    const implBytes = await ethers.provider.getStorage(proxyAddress, implSlot);
    const actualImpl = ethers.getAddress("0x" + implBytes.slice(-40));

    const matches = actualImpl.toLowerCase() === expectedImpl.toLowerCase();
    return {
      name: `${name} proxy implementation`,
      passed: matches,
      message: matches
        ? `Implementation: ${actualImpl}`
        : `Expected ${expectedImpl}, got ${actualImpl}`,
    };
  } catch (error) {
    return {
      name: `${name} proxy implementation`,
      passed: false,
      message: `Error: ${error}`,
    };
  }
}

async function verifyClaimTokenIssuerRegistry(
  claimTokenAddress: string,
  expectedRegistry: string
): Promise<VerificationResult["checks"][0]> {
  try {
    const ClaimToken = await ethers.getContractFactory("ClaimToken");
    const claimToken = ClaimToken.attach(claimTokenAddress);
    const actualRegistry = await claimToken.issuerRegistry();

    const matches = actualRegistry.toLowerCase() === expectedRegistry.toLowerCase();
    return {
      name: "ClaimToken.issuerRegistry",
      passed: matches,
      message: matches
        ? `Correct: ${actualRegistry}`
        : `Expected ${expectedRegistry}, got ${actualRegistry}`,
    };
  } catch (error) {
    return {
      name: "ClaimToken.issuerRegistry",
      passed: false,
      message: `Error: ${error}`,
    };
  }
}

async function verifyLifecycleManagerClaimToken(
  lifecycleManagerAddress: string,
  expectedClaimToken: string
): Promise<VerificationResult["checks"][0]> {
  try {
    const LifecycleManager = await ethers.getContractFactory(
      "CredentialLifecycleManager"
    );
    const lifecycleManager = LifecycleManager.attach(lifecycleManagerAddress);
    const actualClaimToken = await lifecycleManager.claimToken();

    const matches = actualClaimToken.toLowerCase() === expectedClaimToken.toLowerCase();
    return {
      name: "LifecycleManager.claimToken",
      passed: matches,
      message: matches
        ? `Correct: ${actualClaimToken}`
        : `Expected ${expectedClaimToken}, got ${actualClaimToken}`,
    };
  } catch (error) {
    return {
      name: "LifecycleManager.claimToken",
      passed: false,
      message: `Error: ${error}`,
    };
  }
}

async function verifyLifecycleManagerIssuerRegistry(
  lifecycleManagerAddress: string,
  expectedRegistry: string
): Promise<VerificationResult["checks"][0]> {
  try {
    const LifecycleManager = await ethers.getContractFactory(
      "CredentialLifecycleManager"
    );
    const lifecycleManager = LifecycleManager.attach(lifecycleManagerAddress);
    const actualRegistry = await lifecycleManager.issuerRegistry();

    const matches = actualRegistry.toLowerCase() === expectedRegistry.toLowerCase();
    return {
      name: "LifecycleManager.issuerRegistry",
      passed: matches,
      message: matches
        ? `Correct: ${actualRegistry}`
        : `Expected ${expectedRegistry}, got ${actualRegistry}`,
    };
  } catch (error) {
    return {
      name: "LifecycleManager.issuerRegistry",
      passed: false,
      message: `Error: ${error}`,
    };
  }
}

async function verifyAdminRole(
  issuerRegistryAddress: string,
  expectedAdmin: string
): Promise<VerificationResult["checks"][0]> {
  try {
    const IssuerRegistry = await ethers.getContractFactory("IssuerRegistry");
    const issuerRegistry = IssuerRegistry.attach(issuerRegistryAddress);

    const DEFAULT_ADMIN_ROLE = await issuerRegistry.DEFAULT_ADMIN_ROLE();
    const hasRole = await issuerRegistry.hasRole(DEFAULT_ADMIN_ROLE, expectedAdmin);

    return {
      name: "Admin has DEFAULT_ADMIN_ROLE",
      passed: hasRole,
      message: hasRole ? `Admin ${expectedAdmin} has role` : `Admin missing role`,
    };
  } catch (error) {
    return {
      name: "Admin has DEFAULT_ADMIN_ROLE",
      passed: false,
      message: `Error: ${error}`,
    };
  }
}

async function verifyCredentialContractRole(
  issuerRegistryAddress: string,
  claimTokenAddress: string
): Promise<VerificationResult["checks"][0]> {
  try {
    const IssuerRegistry = await ethers.getContractFactory("IssuerRegistry");
    const issuerRegistry = IssuerRegistry.attach(issuerRegistryAddress);

    const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
    const hasRole = await issuerRegistry.hasRole(CREDENTIAL_CONTRACT_ROLE, claimTokenAddress);

    return {
      name: "ClaimToken has CREDENTIAL_CONTRACT_ROLE",
      passed: hasRole,
      message: hasRole ? "Role granted correctly" : "Role not granted",
    };
  } catch (error) {
    return {
      name: "ClaimToken has CREDENTIAL_CONTRACT_ROLE",
      passed: false,
      message: `Error: ${error}`,
    };
  }
}

async function verifyLifecycleManagerRole(
  claimTokenAddress: string,
  lifecycleManagerAddress: string
): Promise<VerificationResult["checks"][0]> {
  try {
    const ClaimToken = await ethers.getContractFactory("ClaimToken");
    const claimToken = ClaimToken.attach(claimTokenAddress);

    const LIFECYCLE_MANAGER_ROLE = await claimToken.LIFECYCLE_MANAGER_ROLE();
    const hasRole = await claimToken.hasRole(LIFECYCLE_MANAGER_ROLE, lifecycleManagerAddress);

    return {
      name: "LifecycleManager has LIFECYCLE_MANAGER_ROLE",
      passed: hasRole,
      message: hasRole ? "Role granted correctly" : "Role not granted",
    };
  } catch (error) {
    return {
      name: "LifecycleManager has LIFECYCLE_MANAGER_ROLE",
      passed: false,
      message: `Error: ${error}`,
    };
  }
}

async function verifyClaimTokenMetadata(
  claimTokenAddress: string
): Promise<VerificationResult["checks"][0]> {
  try {
    const ClaimToken = await ethers.getContractFactory("ClaimToken");
    const claimToken = ClaimToken.attach(claimTokenAddress);

    const name = await claimToken.name();
    const symbol = await claimToken.symbol();

    const correct = name === "SovereignCredential" && symbol === "SCRED";

    return {
      name: "ClaimToken metadata",
      passed: correct,
      message: correct
        ? `Name: ${name}, Symbol: ${symbol}`
        : `Expected SovereignCredential/SCRED, got ${name}/${symbol}`,
    };
  } catch (error) {
    return {
      name: "ClaimToken metadata",
      passed: false,
      message: `Error: ${error}`,
    };
  }
}

function printVerificationResults(result: VerificationResult): void {
  console.log("\n" + "=".repeat(60));
  console.log("VERIFICATION RESULTS");
  console.log("=".repeat(60));

  for (const check of result.checks) {
    const icon = check.passed ? "✅" : "❌";
    console.log(`${icon} ${check.name}`);
    console.log(`   ${check.message}`);
  }

  console.log("=".repeat(60));
  console.log(`Total: ${result.checks.filter((c) => c.passed).length}/${result.checks.length} checks passed`);
}

main().catch((error) => {
  console.error("❌ Verification failed:", error);
  process.exit(1);
});
