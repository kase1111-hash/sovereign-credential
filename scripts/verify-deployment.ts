/**
 * @file verify-deployment.ts
 * @description Verification script to validate Sovereign Credential deployment
 * @dev Checks all contracts are properly deployed and configured
 *
 * Usage:
 *   npx hardhat run scripts/verify-deployment.ts --network <network>
 */

import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

interface DeploymentData {
  networkName: string;
  chainId: number;
  timestamp: number;
  contracts: {
    issuerRegistry: { proxy: string; implementation: string };
    claimToken: { proxy: string; implementation: string };
    credentialLifecycleManager: { proxy: string; implementation: string };
    zkDisclosureEngine?: { proxy: string; implementation: string };
    fieBridge?: { proxy: string; implementation: string };
    verifiers?: {
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

interface VerificationCheck {
  name: string;
  passed: boolean;
  message: string;
  critical: boolean;
}

interface VerificationResult {
  passed: boolean;
  checks: VerificationCheck[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    critical: number;
  };
}

async function main() {
  console.log("=".repeat(60));
  console.log("SOVEREIGN CREDENTIAL DEPLOYMENT VERIFICATION");
  console.log("=".repeat(60));

  // Load deployment
  const deployment = loadDeployment();
  if (!deployment) {
    console.error(`\nError: No deployment found for network: ${network.name}`);
    console.log(`Run 'npx hardhat run scripts/deploy.ts --network ${network.name}' first.`);
    process.exit(1);
  }

  console.log(`\nNetwork: ${network.name}`);
  console.log(`Deployment timestamp: ${new Date(deployment.timestamp * 1000).toISOString()}`);

  // Run verification checks
  const result = await runVerificationChecks(deployment);

  // Print results
  printVerificationResults(result);

  // Exit with appropriate code
  if (result.passed) {
    console.log("\nVERIFICATION PASSED");
    process.exit(0);
  } else {
    console.log("\nVERIFICATION FAILED");
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

async function runVerificationChecks(deployment: DeploymentData): Promise<VerificationResult> {
  const checks: VerificationCheck[] = [];

  // =========================================
  // Contract Existence Checks
  // =========================================
  console.log("\n[1/6] Checking contract deployments...");

  checks.push(await verifyContractExists(deployment.contracts.issuerRegistry.proxy, "IssuerRegistry"));
  checks.push(await verifyContractExists(deployment.contracts.claimToken.proxy, "ClaimToken"));
  checks.push(await verifyContractExists(deployment.contracts.credentialLifecycleManager.proxy, "CredentialLifecycleManager"));

  if (deployment.contracts.zkDisclosureEngine) {
    checks.push(await verifyContractExists(deployment.contracts.zkDisclosureEngine.proxy, "ZKDisclosureEngine"));
  }

  if (deployment.contracts.fieBridge) {
    checks.push(await verifyContractExists(deployment.contracts.fieBridge.proxy, "FIEBridge"));
  }

  // =========================================
  // Proxy Implementation Checks
  // =========================================
  console.log("\n[2/6] Checking proxy implementations...");

  checks.push(await verifyProxyImplementation(
    deployment.contracts.issuerRegistry.proxy,
    deployment.contracts.issuerRegistry.implementation,
    "IssuerRegistry"
  ));
  checks.push(await verifyProxyImplementation(
    deployment.contracts.claimToken.proxy,
    deployment.contracts.claimToken.implementation,
    "ClaimToken"
  ));
  checks.push(await verifyProxyImplementation(
    deployment.contracts.credentialLifecycleManager.proxy,
    deployment.contracts.credentialLifecycleManager.implementation,
    "CredentialLifecycleManager"
  ));

  if (deployment.contracts.zkDisclosureEngine) {
    checks.push(await verifyProxyImplementation(
      deployment.contracts.zkDisclosureEngine.proxy,
      deployment.contracts.zkDisclosureEngine.implementation,
      "ZKDisclosureEngine"
    ));
  }

  if (deployment.contracts.fieBridge) {
    checks.push(await verifyProxyImplementation(
      deployment.contracts.fieBridge.proxy,
      deployment.contracts.fieBridge.implementation,
      "FIEBridge"
    ));
  }

  // =========================================
  // Cross-Reference Checks
  // =========================================
  console.log("\n[3/6] Checking cross-references...");

  checks.push(await verifyClaimTokenIssuerRegistry(
    deployment.contracts.claimToken.proxy,
    deployment.contracts.issuerRegistry.proxy
  ));

  checks.push(await verifyLifecycleManagerReferences(
    deployment.contracts.credentialLifecycleManager.proxy,
    deployment.contracts.claimToken.proxy,
    deployment.contracts.issuerRegistry.proxy
  ));

  if (deployment.contracts.zkDisclosureEngine) {
    checks.push(await verifyZKEngineClaimToken(
      deployment.contracts.zkDisclosureEngine.proxy,
      deployment.contracts.claimToken.proxy
    ));
  }

  if (deployment.contracts.fieBridge) {
    checks.push(await verifyFIEBridgeLifecycleManager(
      deployment.contracts.fieBridge.proxy,
      deployment.contracts.credentialLifecycleManager.proxy
    ));
  }

  // =========================================
  // Role Checks
  // =========================================
  console.log("\n[4/6] Checking roles...");

  checks.push(await verifyAdminRole(
    deployment.contracts.issuerRegistry.proxy,
    deployment.roles.admin
  ));

  checks.push(await verifyCredentialContractRole(
    deployment.contracts.issuerRegistry.proxy,
    deployment.contracts.claimToken.proxy
  ));

  checks.push(await verifyLifecycleManagerRole(
    deployment.contracts.claimToken.proxy,
    deployment.contracts.credentialLifecycleManager.proxy
  ));

  // =========================================
  // ZK Verifier Checks
  // =========================================
  if (deployment.contracts.zkDisclosureEngine && deployment.contracts.verifiers) {
    console.log("\n[5/6] Checking ZK verifiers...");

    checks.push(await verifyZKVerifierRegistered(
      deployment.contracts.zkDisclosureEngine.proxy,
      "DATE_RANGE",
      deployment.contracts.verifiers.dateRange
    ));

    checks.push(await verifyZKVerifierRegistered(
      deployment.contracts.zkDisclosureEngine.proxy,
      "VALUE_RANGE",
      deployment.contracts.verifiers.valueRange
    ));

    checks.push(await verifyZKVerifierRegistered(
      deployment.contracts.zkDisclosureEngine.proxy,
      "SET_MEMBERSHIP",
      deployment.contracts.verifiers.setMembership
    ));

    checks.push(await verifyZKVerifierRegistered(
      deployment.contracts.zkDisclosureEngine.proxy,
      "COMPOUND",
      deployment.contracts.verifiers.compoundProof
    ));
  } else {
    console.log("\n[5/6] Skipping ZK verifier checks (not deployed)...");
  }

  // =========================================
  // Functionality Checks
  // =========================================
  console.log("\n[6/6] Checking contract functionality...");

  checks.push(await verifyClaimTokenMetadata(deployment.contracts.claimToken.proxy));

  // Calculate summary
  const summary = {
    total: checks.length,
    passed: checks.filter((c) => c.passed).length,
    failed: checks.filter((c) => !c.passed).length,
    critical: checks.filter((c) => !c.passed && c.critical).length,
  };

  // Overall pass only if no critical failures
  const passed = summary.critical === 0;

  return { passed, checks, summary };
}

async function verifyContractExists(address: string, name: string): Promise<VerificationCheck> {
  try {
    const code = await ethers.provider.getCode(address);
    const exists = code !== "0x";
    return {
      name: `${name} deployed`,
      passed: exists,
      message: exists ? `Contract at ${address}` : "No code at address",
      critical: true,
    };
  } catch (error) {
    return {
      name: `${name} deployed`,
      passed: false,
      message: `Error: ${error}`,
      critical: true,
    };
  }
}

async function verifyProxyImplementation(
  proxyAddress: string,
  expectedImpl: string,
  name: string
): Promise<VerificationCheck> {
  try {
    // EIP-1967 implementation slot
    const implSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
    const implBytes = await ethers.provider.getStorage(proxyAddress, implSlot);
    const actualImpl = ethers.getAddress("0x" + implBytes.slice(-40));

    const matches = actualImpl.toLowerCase() === expectedImpl.toLowerCase();
    return {
      name: `${name} implementation`,
      passed: matches,
      message: matches ? `Implementation: ${actualImpl}` : `Expected ${expectedImpl}, got ${actualImpl}`,
      critical: true,
    };
  } catch (error) {
    return {
      name: `${name} implementation`,
      passed: false,
      message: `Error: ${error}`,
      critical: true,
    };
  }
}

async function verifyClaimTokenIssuerRegistry(
  claimTokenAddress: string,
  expectedRegistry: string
): Promise<VerificationCheck> {
  try {
    const ClaimToken = await ethers.getContractFactory("ClaimToken");
    const claimToken = ClaimToken.attach(claimTokenAddress);
    const actualRegistry = await claimToken.issuerRegistry();

    const matches = actualRegistry.toLowerCase() === expectedRegistry.toLowerCase();
    return {
      name: "ClaimToken.issuerRegistry",
      passed: matches,
      message: matches ? `Correct: ${actualRegistry}` : `Expected ${expectedRegistry}`,
      critical: true,
    };
  } catch (error) {
    return {
      name: "ClaimToken.issuerRegistry",
      passed: false,
      message: `Error: ${error}`,
      critical: true,
    };
  }
}

async function verifyLifecycleManagerReferences(
  lifecycleManagerAddress: string,
  expectedClaimToken: string,
  expectedRegistry: string
): Promise<VerificationCheck> {
  try {
    const LifecycleManager = await ethers.getContractFactory("CredentialLifecycleManager");
    const lifecycleManager = LifecycleManager.attach(lifecycleManagerAddress);

    const actualClaimToken = await lifecycleManager.claimToken();
    const actualRegistry = await lifecycleManager.issuerRegistry();

    const claimTokenMatches = actualClaimToken.toLowerCase() === expectedClaimToken.toLowerCase();
    const registryMatches = actualRegistry.toLowerCase() === expectedRegistry.toLowerCase();

    const passed = claimTokenMatches && registryMatches;
    return {
      name: "LifecycleManager references",
      passed,
      message: passed ? "All references correct" : `ClaimToken: ${claimTokenMatches}, Registry: ${registryMatches}`,
      critical: true,
    };
  } catch (error) {
    return {
      name: "LifecycleManager references",
      passed: false,
      message: `Error: ${error}`,
      critical: true,
    };
  }
}

async function verifyZKEngineClaimToken(
  zkEngineAddress: string,
  expectedClaimToken: string
): Promise<VerificationCheck> {
  try {
    const ZKEngine = await ethers.getContractFactory("ZKDisclosureEngine");
    const zkEngine = ZKEngine.attach(zkEngineAddress);
    const actualClaimToken = await zkEngine.claimToken();

    const matches = actualClaimToken.toLowerCase() === expectedClaimToken.toLowerCase();
    return {
      name: "ZKDisclosureEngine.claimToken",
      passed: matches,
      message: matches ? `Correct: ${actualClaimToken}` : `Expected ${expectedClaimToken}`,
      critical: true,
    };
  } catch (error) {
    return {
      name: "ZKDisclosureEngine.claimToken",
      passed: false,
      message: `Error: ${error}`,
      critical: true,
    };
  }
}

async function verifyFIEBridgeLifecycleManager(
  fieBridgeAddress: string,
  expectedLifecycleManager: string
): Promise<VerificationCheck> {
  try {
    const FIEBridge = await ethers.getContractFactory("FIEBridge");
    const fieBridge = FIEBridge.attach(fieBridgeAddress);
    const actualLifecycleManager = await fieBridge.lifecycleManager();

    const matches = actualLifecycleManager.toLowerCase() === expectedLifecycleManager.toLowerCase();
    return {
      name: "FIEBridge.lifecycleManager",
      passed: matches,
      message: matches ? `Correct: ${actualLifecycleManager}` : `Expected ${expectedLifecycleManager}`,
      critical: true,
    };
  } catch (error) {
    return {
      name: "FIEBridge.lifecycleManager",
      passed: false,
      message: `Error: ${error}`,
      critical: true,
    };
  }
}

async function verifyAdminRole(
  issuerRegistryAddress: string,
  expectedAdmin: string
): Promise<VerificationCheck> {
  try {
    const IssuerRegistry = await ethers.getContractFactory("IssuerRegistry");
    const issuerRegistry = IssuerRegistry.attach(issuerRegistryAddress);

    const DEFAULT_ADMIN_ROLE = await issuerRegistry.DEFAULT_ADMIN_ROLE();
    const hasRole = await issuerRegistry.hasRole(DEFAULT_ADMIN_ROLE, expectedAdmin);

    return {
      name: "Admin role granted",
      passed: hasRole,
      message: hasRole ? `Admin: ${expectedAdmin}` : "Admin role not granted",
      critical: true,
    };
  } catch (error) {
    return {
      name: "Admin role granted",
      passed: false,
      message: `Error: ${error}`,
      critical: true,
    };
  }
}

async function verifyCredentialContractRole(
  issuerRegistryAddress: string,
  claimTokenAddress: string
): Promise<VerificationCheck> {
  try {
    const IssuerRegistry = await ethers.getContractFactory("IssuerRegistry");
    const issuerRegistry = IssuerRegistry.attach(issuerRegistryAddress);

    const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
    const hasRole = await issuerRegistry.hasRole(CREDENTIAL_CONTRACT_ROLE, claimTokenAddress);

    return {
      name: "ClaimToken has CREDENTIAL_CONTRACT_ROLE",
      passed: hasRole,
      message: hasRole ? "Role granted" : "Role not granted",
      critical: true,
    };
  } catch (error) {
    return {
      name: "ClaimToken has CREDENTIAL_CONTRACT_ROLE",
      passed: false,
      message: `Error: ${error}`,
      critical: true,
    };
  }
}

async function verifyLifecycleManagerRole(
  claimTokenAddress: string,
  lifecycleManagerAddress: string
): Promise<VerificationCheck> {
  try {
    const ClaimToken = await ethers.getContractFactory("ClaimToken");
    const claimToken = ClaimToken.attach(claimTokenAddress);

    const LIFECYCLE_MANAGER_ROLE = await claimToken.LIFECYCLE_MANAGER_ROLE();
    const hasRole = await claimToken.hasRole(LIFECYCLE_MANAGER_ROLE, lifecycleManagerAddress);

    return {
      name: "LifecycleManager has LIFECYCLE_MANAGER_ROLE",
      passed: hasRole,
      message: hasRole ? "Role granted" : "Role not granted",
      critical: true,
    };
  } catch (error) {
    return {
      name: "LifecycleManager has LIFECYCLE_MANAGER_ROLE",
      passed: false,
      message: `Error: ${error}`,
      critical: true,
    };
  }
}

async function verifyZKVerifierRegistered(
  zkEngineAddress: string,
  disclosureTypeName: string,
  expectedVerifier: string
): Promise<VerificationCheck> {
  try {
    const ZKEngine = await ethers.getContractFactory("ZKDisclosureEngine");
    const zkEngine = ZKEngine.attach(zkEngineAddress);

    const disclosureType = ethers.keccak256(ethers.toUtf8Bytes(disclosureTypeName));
    const registeredVerifier = await zkEngine.verifiers(disclosureType);

    const matches = registeredVerifier.toLowerCase() === expectedVerifier.toLowerCase();
    return {
      name: `${disclosureTypeName} verifier registered`,
      passed: matches,
      message: matches ? `Verifier: ${registeredVerifier}` : `Expected ${expectedVerifier}, got ${registeredVerifier}`,
      critical: false,
    };
  } catch (error) {
    return {
      name: `${disclosureTypeName} verifier registered`,
      passed: false,
      message: `Error: ${error}`,
      critical: false,
    };
  }
}

async function verifyClaimTokenMetadata(claimTokenAddress: string): Promise<VerificationCheck> {
  try {
    const ClaimToken = await ethers.getContractFactory("ClaimToken");
    const claimToken = ClaimToken.attach(claimTokenAddress);

    const name = await claimToken.name();
    const symbol = await claimToken.symbol();

    const correct = name === "SovereignCredential" && symbol === "SCRED";

    return {
      name: "ClaimToken metadata",
      passed: correct,
      message: correct ? `Name: ${name}, Symbol: ${symbol}` : `Expected SovereignCredential/SCRED, got ${name}/${symbol}`,
      critical: false,
    };
  } catch (error) {
    return {
      name: "ClaimToken metadata",
      passed: false,
      message: `Error: ${error}`,
      critical: false,
    };
  }
}

function printVerificationResults(result: VerificationResult): void {
  console.log("\n" + "=".repeat(60));
  console.log("VERIFICATION RESULTS");
  console.log("=".repeat(60));

  // Group by status
  const passed = result.checks.filter((c) => c.passed);
  const failed = result.checks.filter((c) => !c.passed);

  console.log("\nPassed Checks:");
  for (const check of passed) {
    console.log(`  [PASS] ${check.name}`);
    console.log(`         ${check.message}`);
  }

  if (failed.length > 0) {
    console.log("\nFailed Checks:");
    for (const check of failed) {
      const label = check.critical ? "[FAIL*]" : "[FAIL] ";
      console.log(`  ${label} ${check.name}`);
      console.log(`         ${check.message}`);
    }
  }

  console.log("\n" + "-".repeat(60));
  console.log("SUMMARY");
  console.log("-".repeat(60));
  console.log(`Total Checks: ${result.summary.total}`);
  console.log(`Passed: ${result.summary.passed}`);
  console.log(`Failed: ${result.summary.failed}`);
  if (result.summary.critical > 0) {
    console.log(`Critical Failures: ${result.summary.critical}`);
  }
  console.log("=".repeat(60));
}

main().catch((error) => {
  console.error("Verification failed:", error);
  process.exit(1);
});
