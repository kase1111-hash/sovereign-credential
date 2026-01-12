/**
 * @file setup-issuer.ts
 * @description Script to register a new issuer with the system
 *
 * Usage:
 *   ISSUER_ADDRESS=<address> JURISDICTION=<code> npx hardhat run scripts/setup-issuer.ts --network <network>
 */

import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import { ClaimTypes } from "../types";

interface SetupConfig {
  issuerAddress: string;
  jurisdiction: string;
  claimTypes: string[];
}

async function main() {
  console.log("🏛️ Setting Up New Issuer\n");

  // Get configuration
  const config = getConfig();
  console.log(`📡 Network: ${network.name}`);
  console.log(`👤 Issuer: ${config.issuerAddress}`);
  console.log(`🌍 Jurisdiction: ${config.jurisdiction}`);
  console.log(`📋 Claim Types: ${config.claimTypes.length} types\n`);

  // Load deployment
  const deployment = loadDeployment();
  if (!deployment) {
    console.error("❌ No deployment found for current network");
    process.exit(1);
  }

  // Get signer (must have REGISTRAR_ROLE)
  const [registrar] = await ethers.getSigners();
  console.log(`🔐 Registrar: ${registrar.address}`);

  // Get IssuerRegistry contract
  const IssuerRegistry = await ethers.getContractFactory("IssuerRegistry");
  const issuerRegistry = IssuerRegistry.attach(deployment.contracts.issuerRegistry.proxy);

  // Check if registrar has REGISTRAR_ROLE
  const REGISTRAR_ROLE = await issuerRegistry.REGISTRAR_ROLE();
  const hasRole = await issuerRegistry.hasRole(REGISTRAR_ROLE, registrar.address);

  if (!hasRole) {
    // Check if registrar is admin (admin can also register)
    const DEFAULT_ADMIN_ROLE = await issuerRegistry.DEFAULT_ADMIN_ROLE();
    const isAdmin = await issuerRegistry.hasRole(DEFAULT_ADMIN_ROLE, registrar.address);

    if (!isAdmin) {
      console.error(`❌ Account ${registrar.address} does not have REGISTRAR_ROLE or admin`);
      process.exit(1);
    }
  }

  // Check if issuer already registered
  const existingIssuer = await issuerRegistry.getIssuer(config.issuerAddress);
  if (existingIssuer.issuerAddress !== ethers.ZeroAddress) {
    console.log(`⚠️ Issuer ${config.issuerAddress} is already registered`);

    // Add any new claim types
    for (const claimType of config.claimTypes) {
      const isAuthorized = await issuerRegistry.isAuthorized(config.issuerAddress, claimType);
      if (!isAuthorized) {
        console.log(`   Adding claim type authorization: ${claimType}`);
        await issuerRegistry.authorizeType(config.issuerAddress, claimType);
      }
    }
    console.log("✅ Issuer configuration updated");
    return;
  }

  // Register issuer
  console.log("\n📝 Registering issuer...");
  const tx = await issuerRegistry.registerIssuer(
    config.issuerAddress,
    config.jurisdiction,
    config.claimTypes
  );
  await tx.wait();

  console.log(`   Transaction: ${tx.hash}`);

  // Verify registration
  const issuer = await issuerRegistry.getIssuer(config.issuerAddress);
  console.log("\n✅ Issuer registered successfully!");
  console.log(`   Address: ${issuer.issuerAddress}`);
  console.log(`   Jurisdiction: ${issuer.jurisdiction}`);
  console.log(`   Reputation: ${issuer.reputationScore.toString()}`);
  console.log(`   Active: ${issuer.isActive}`);
}

function getConfig(): SetupConfig {
  const issuerAddress = process.env.ISSUER_ADDRESS;
  const jurisdiction = process.env.JURISDICTION || "GLOBAL";

  if (!issuerAddress) {
    console.log("Usage: ISSUER_ADDRESS=<address> [JURISDICTION=<code>] npx hardhat run scripts/setup-issuer.ts --network <network>");
    console.log("\nEnvironment variables:");
    console.log("  ISSUER_ADDRESS: Address of the issuer to register (required)");
    console.log("  JURISDICTION: Jurisdiction code, e.g., 'US-CA', 'EU', 'GLOBAL' (default: GLOBAL)");
    console.log("  CLAIM_TYPES: Comma-separated list of claim type IDs (default: common types)");
    process.exit(1);
  }

  if (!ethers.isAddress(issuerAddress)) {
    console.error(`❌ Invalid issuer address: ${issuerAddress}`);
    process.exit(1);
  }

  // Parse claim types or use defaults
  let claimTypes: string[];
  if (process.env.CLAIM_TYPES) {
    claimTypes = process.env.CLAIM_TYPES.split(",").map((t) => t.trim());
  } else {
    // Default common claim types
    claimTypes = [
      ClaimTypes.IDENTITY_BIRTH,
      ClaimTypes.LICENSE_PROFESSIONAL,
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.EDUCATION_DEGREE,
      ClaimTypes.EDUCATION_CERTIFICATION,
    ];
  }

  return {
    issuerAddress,
    jurisdiction,
    claimTypes,
  };
}

function loadDeployment() {
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  const latestFilepath = path.join(deploymentsDir, `${network.name}-latest.json`);

  if (!fs.existsSync(latestFilepath)) {
    return null;
  }

  return JSON.parse(fs.readFileSync(latestFilepath, "utf-8"));
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Setup failed:", error);
    process.exit(1);
  });
