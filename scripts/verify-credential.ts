/**
 * @file verify-credential.ts
 * @description Script to verify a credential's status and validity
 *
 * Usage:
 *   TOKEN_ID=1 npx hardhat run scripts/verify-credential.ts --network <network>
 *
 * Environment variables:
 *   TOKEN_ID: ID of the credential token to verify
 */

import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

interface DeploymentData {
  contracts: {
    issuerRegistry: { proxy: string };
    claimToken: { proxy: string };
    zkDisclosureEngine: { proxy: string };
  };
}

// Credential status enum
const CredentialStatus = {
  0: "ACTIVE",
  1: "REVOKED",
  2: "EXPIRED",
  3: "SUSPENDED",
  4: "INHERITED",
};

async function main() {
  console.log("=".repeat(60));
  console.log("VERIFY CREDENTIAL");
  console.log("=".repeat(60));

  // Get token ID from environment
  const tokenIdStr = process.env.TOKEN_ID;
  if (!tokenIdStr) {
    console.log("\nUsage: TOKEN_ID=<id> npx hardhat run scripts/verify-credential.ts --network <network>");
    console.log("\nEnvironment variables:");
    console.log("  TOKEN_ID: ID of the credential token to verify (required)");
    process.exit(1);
  }

  const tokenId = BigInt(tokenIdStr);
  console.log(`\nNetwork: ${network.name}`);
  console.log(`Token ID: ${tokenId.toString()}`);

  // Load deployment
  const deployment = loadDeployment();
  if (!deployment) {
    console.error("\nError: No deployment found for current network");
    process.exit(1);
  }

  // Get contracts
  const ClaimToken = await ethers.getContractFactory("ClaimToken");
  const claimToken = ClaimToken.attach(deployment.contracts.claimToken.proxy);

  const IssuerRegistry = await ethers.getContractFactory("IssuerRegistry");
  const issuerRegistry = IssuerRegistry.attach(deployment.contracts.issuerRegistry.proxy);

  // Check if token exists
  try {
    const owner = await claimToken.ownerOf(tokenId);
    console.log(`\nOwner: ${owner}`);
  } catch {
    console.error(`\nError: Token ID ${tokenId.toString()} does not exist`);
    process.exit(1);
  }

  // Get credential details
  console.log("\n" + "-".repeat(40));
  console.log("CREDENTIAL DETAILS");
  console.log("-".repeat(40));

  const credential = await claimToken.getCredential(tokenId);

  console.log(`Subject: ${credential.subject}`);
  console.log(`Issuer: ${credential.issuer}`);
  console.log(`Claim Type: ${credential.claimType}`);
  console.log(`Status: ${CredentialStatus[credential.status as keyof typeof CredentialStatus] || "UNKNOWN"}`);
  console.log(`Issued At: ${formatTimestamp(credential.issuedAt)}`);
  console.log(`Expires At: ${formatTimestamp(credential.expiresAt)}`);

  if (credential.commitments.length > 0) {
    console.log(`Commitments: ${credential.commitments.length} commitment(s)`);
    for (let i = 0; i < credential.commitments.length; i++) {
      console.log(`  [${i}]: ${credential.commitments[i]}`);
    }
  }

  // Verify issuer status
  console.log("\n" + "-".repeat(40));
  console.log("ISSUER VERIFICATION");
  console.log("-".repeat(40));

  const issuerInfo = await issuerRegistry.getIssuer(credential.issuer);
  console.log(`Issuer Address: ${issuerInfo.issuerAddress}`);
  console.log(`Jurisdiction: ${issuerInfo.jurisdiction}`);
  console.log(`Is Active: ${issuerInfo.isActive}`);
  console.log(`Reputation Score: ${issuerInfo.reputationScore.toString()}`);
  console.log(`Registration Time: ${formatTimestamp(issuerInfo.registrationTime)}`);

  // Check if issuer is authorized for this claim type
  const isAuthorized = await issuerRegistry.isAuthorized(
    credential.issuer,
    credential.claimType
  );
  console.log(`Authorized for Claim Type: ${isAuthorized}`);

  // Perform verification
  console.log("\n" + "-".repeat(40));
  console.log("VERIFICATION RESULT");
  console.log("-".repeat(40));

  const isValid = await claimToken.verify(tokenId);
  console.log(`\nCREDENTIAL IS ${isValid ? "VALID" : "INVALID"}`);

  // Detailed verification checks
  const checks: { name: string; passed: boolean; reason: string }[] = [];

  // Check 1: Status is ACTIVE or INHERITED
  const statusOk = credential.status === 0 || credential.status === 4;
  checks.push({
    name: "Status Check",
    passed: statusOk,
    reason: statusOk ? "Status is ACTIVE or INHERITED" : `Status is ${CredentialStatus[credential.status as keyof typeof CredentialStatus]}`,
  });

  // Check 2: Not expired
  const now = Math.floor(Date.now() / 1000);
  const notExpired = Number(credential.expiresAt) > now;
  checks.push({
    name: "Expiry Check",
    passed: notExpired,
    reason: notExpired ? "Credential has not expired" : "Credential has expired",
  });

  // Check 3: Issuer is active
  checks.push({
    name: "Issuer Active",
    passed: issuerInfo.isActive,
    reason: issuerInfo.isActive ? "Issuer is active" : "Issuer is not active",
  });

  // Check 4: Issuer is authorized
  checks.push({
    name: "Issuer Authorized",
    passed: isAuthorized,
    reason: isAuthorized ? "Issuer is authorized for claim type" : "Issuer is not authorized for claim type",
  });

  // Check 5: Issuer reputation
  const hasReputation = Number(issuerInfo.reputationScore) >= 50;
  checks.push({
    name: "Issuer Reputation",
    passed: hasReputation,
    reason: hasReputation ? `Reputation score: ${issuerInfo.reputationScore}` : "Reputation score below threshold",
  });

  // Print check results
  console.log("\nVerification Checks:");
  for (const check of checks) {
    const icon = check.passed ? "[PASS]" : "[FAIL]";
    console.log(`  ${icon} ${check.name}: ${check.reason}`);
  }

  // ZK Disclosure Engine check
  if (deployment.contracts.zkDisclosureEngine) {
    console.log("\n" + "-".repeat(40));
    console.log("ZK DISCLOSURE ENGINE");
    console.log("-".repeat(40));

    const ZKDisclosureEngine = await ethers.getContractFactory("ZKDisclosureEngine");
    const zkEngine = ZKDisclosureEngine.attach(deployment.contracts.zkDisclosureEngine.proxy);

    // List available verifiers
    const disclosureTypes = [
      { name: "AGE_THRESHOLD", key: await zkEngine.DISCLOSURE_AGE_THRESHOLD() },
      { name: "DATE_RANGE", key: await zkEngine.DISCLOSURE_DATE_RANGE() },
      { name: "VALUE_RANGE", key: await zkEngine.DISCLOSURE_VALUE_RANGE() },
      { name: "SET_MEMBERSHIP", key: await zkEngine.DISCLOSURE_SET_MEMBERSHIP() },
      { name: "COMPOUND", key: await zkEngine.DISCLOSURE_COMPOUND() },
    ];

    console.log("Available ZK Verifiers:");
    for (const dt of disclosureTypes) {
      const verifier = await zkEngine.verifiers(dt.key);
      const status = verifier !== ethers.ZeroAddress ? verifier : "Not registered";
      console.log(`  ${dt.name}: ${status}`);
    }
  }

  // Summary
  console.log("\n" + "=".repeat(60));
  if (isValid) {
    console.log("RESULT: CREDENTIAL VERIFIED SUCCESSFULLY");
  } else {
    console.log("RESULT: CREDENTIAL VERIFICATION FAILED");
    console.log("\nReasons for failure:");
    for (const check of checks.filter((c) => !c.passed)) {
      console.log(`  - ${check.name}: ${check.reason}`);
    }
  }
  console.log("=".repeat(60));
}

function loadDeployment(): DeploymentData | null {
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  const latestFilepath = path.join(deploymentsDir, `${network.name}-latest.json`);

  if (!fs.existsSync(latestFilepath)) {
    return null;
  }

  return JSON.parse(fs.readFileSync(latestFilepath, "utf-8"));
}

function formatTimestamp(timestamp: bigint): string {
  const ts = Number(timestamp);
  if (ts === 0) return "Not set";
  return new Date(ts * 1000).toISOString();
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Verification failed:", error);
    process.exit(1);
  });
