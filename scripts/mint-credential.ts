/**
 * @file mint-credential.ts
 * @description Script to mint a credential NFT
 *
 * Usage:
 *   npx hardhat run scripts/mint-credential.ts --network <network>
 *
 * Environment variables:
 *   SUBJECT_ADDRESS: Address to receive the credential
 *   CLAIM_TYPE: Type of claim (e.g., "IDENTITY.BIRTH", "LICENSE.PROFESSIONAL")
 *   EXPIRY_DAYS: Days until expiry (default: 365)
 */

import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

interface MintConfig {
  subjectAddress: string;
  claimType: string;
  expiryDays: number;
  payload?: string;
}

interface DeploymentData {
  contracts: {
    issuerRegistry: { proxy: string };
    claimToken: { proxy: string };
  };
}

// Common claim types
const CLAIM_TYPES: Record<string, string> = {
  "IDENTITY.BIRTH": ethers.keccak256(ethers.toUtf8Bytes("IDENTITY.BIRTH")),
  "LICENSE.PROFESSIONAL": ethers.keccak256(ethers.toUtf8Bytes("LICENSE.PROFESSIONAL")),
  "LICENSE.OPERATOR": ethers.keccak256(ethers.toUtf8Bytes("LICENSE.OPERATOR")),
  "EDUCATION.DEGREE": ethers.keccak256(ethers.toUtf8Bytes("EDUCATION.DEGREE")),
  "EDUCATION.CERTIFICATION": ethers.keccak256(ethers.toUtf8Bytes("EDUCATION.CERTIFICATION")),
  "MEMBERSHIP.ORGANIZATION": ethers.keccak256(ethers.toUtf8Bytes("MEMBERSHIP.ORGANIZATION")),
};

async function main() {
  console.log("=".repeat(60));
  console.log("MINT CREDENTIAL");
  console.log("=".repeat(60));

  // Get configuration
  const config = getConfig();
  console.log(`\nNetwork: ${network.name}`);
  console.log(`Subject: ${config.subjectAddress}`);
  console.log(`Claim Type: ${config.claimType}`);
  console.log(`Expiry: ${config.expiryDays} days`);

  // Load deployment
  const deployment = loadDeployment();
  if (!deployment) {
    console.error("\nError: No deployment found for current network");
    console.log(`Run 'npx hardhat run scripts/deploy.ts --network ${network.name}' first.`);
    process.exit(1);
  }

  // Get signer (must be an authorized issuer)
  const [issuer] = await ethers.getSigners();
  console.log(`\nIssuer: ${issuer.address}`);

  // Get contracts
  const IssuerRegistry = await ethers.getContractFactory("IssuerRegistry");
  const issuerRegistry = IssuerRegistry.attach(deployment.contracts.issuerRegistry.proxy);

  const ClaimToken = await ethers.getContractFactory("ClaimToken");
  const claimToken = ClaimToken.attach(deployment.contracts.claimToken.proxy);

  // Check if issuer is authorized
  const claimTypeHash = CLAIM_TYPES[config.claimType] || ethers.keccak256(ethers.toUtf8Bytes(config.claimType));
  const isAuthorized = await issuerRegistry.isAuthorized(issuer.address, claimTypeHash);

  if (!isAuthorized) {
    console.error("\nError: Issuer is not authorized for this claim type");
    console.log(`Issuer: ${issuer.address}`);
    console.log(`Claim Type: ${config.claimType}`);
    console.log("\nRegister the issuer first using scripts/setup-issuer.ts");
    process.exit(1);
  }

  console.log("\nMinting credential...");

  // Prepare credential data
  const expiryTimestamp = Math.floor(Date.now() / 1000) + config.expiryDays * 24 * 60 * 60;

  // Generate a sample encrypted payload (in production, this would be actual encrypted data)
  const samplePayload = config.payload || generateSamplePayload(config.claimType);
  const encryptedPayload = ethers.toUtf8Bytes(samplePayload);

  // Generate commitment (in production, this would be a Poseidon hash)
  const commitment = ethers.keccak256(
    ethers.solidityPacked(
      ["address", "bytes32", "bytes"],
      [config.subjectAddress, claimTypeHash, encryptedPayload]
    )
  );

  // Mint the credential
  const tx = await claimToken.mint(
    config.subjectAddress,
    claimTypeHash,
    encryptedPayload,
    [commitment], // commitments array
    expiryTimestamp
  );

  console.log(`Transaction hash: ${tx.hash}`);
  const receipt = await tx.wait();

  // Extract token ID from event
  let tokenId: bigint | undefined;
  if (receipt && receipt.logs) {
    for (const log of receipt.logs) {
      try {
        const parsed = claimToken.interface.parseLog({
          topics: log.topics as string[],
          data: log.data,
        });
        if (parsed && parsed.name === "CredentialMinted") {
          tokenId = parsed.args.tokenId;
          break;
        }
      } catch {
        // Skip logs that don't match
      }
    }
  }

  if (tokenId !== undefined) {
    console.log(`\nCredential minted successfully!`);
    console.log(`Token ID: ${tokenId.toString()}`);

    // Get credential details
    const credential = await claimToken.getCredential(tokenId);
    console.log("\nCredential Details:");
    console.log(`  Subject: ${credential.subject}`);
    console.log(`  Issuer: ${credential.issuer}`);
    console.log(`  Claim Type: ${config.claimType}`);
    console.log(`  Status: ${getStatusName(credential.status)}`);
    console.log(`  Issued At: ${new Date(Number(credential.issuedAt) * 1000).toISOString()}`);
    console.log(`  Expires At: ${new Date(Number(credential.expiresAt) * 1000).toISOString()}`);

    // Save mint result
    saveMintResult({
      network: network.name,
      tokenId: tokenId.toString(),
      subject: config.subjectAddress,
      issuer: issuer.address,
      claimType: config.claimType,
      expiresAt: expiryTimestamp,
      txHash: tx.hash,
      timestamp: Math.floor(Date.now() / 1000),
    });
  } else {
    console.log("\nTransaction completed but token ID not found in events.");
    console.log("Check the transaction on block explorer.");
  }

  console.log("\n" + "=".repeat(60));
  console.log("MINT COMPLETE");
  console.log("=".repeat(60));
}

function getConfig(): MintConfig {
  const subjectAddress = process.env.SUBJECT_ADDRESS;
  const claimType = process.env.CLAIM_TYPE || "IDENTITY.BIRTH";
  const expiryDays = parseInt(process.env.EXPIRY_DAYS || "365", 10);
  const payload = process.env.PAYLOAD;

  if (!subjectAddress) {
    console.log("\nUsage: SUBJECT_ADDRESS=0x... CLAIM_TYPE=<type> npx hardhat run scripts/mint-credential.ts --network <network>");
    console.log("\nEnvironment variables:");
    console.log("  SUBJECT_ADDRESS: Address to receive the credential (required)");
    console.log("  CLAIM_TYPE: Type of claim (default: IDENTITY.BIRTH)");
    console.log("  EXPIRY_DAYS: Days until expiry (default: 365)");
    console.log("  PAYLOAD: Custom payload data (optional)");
    console.log("\nAvailable claim types:");
    for (const type of Object.keys(CLAIM_TYPES)) {
      console.log(`  - ${type}`);
    }
    process.exit(1);
  }

  if (!ethers.isAddress(subjectAddress)) {
    console.error(`\nError: Invalid subject address: ${subjectAddress}`);
    process.exit(1);
  }

  return {
    subjectAddress,
    claimType,
    expiryDays,
    payload,
  };
}

function loadDeployment(): DeploymentData | null {
  const deploymentsDir = path.join(__dirname, "..", "deployments");
  const latestFilepath = path.join(deploymentsDir, `${network.name}-latest.json`);

  if (!fs.existsSync(latestFilepath)) {
    return null;
  }

  return JSON.parse(fs.readFileSync(latestFilepath, "utf-8"));
}

function generateSamplePayload(claimType: string): string {
  const timestamp = new Date().toISOString();

  switch (claimType) {
    case "IDENTITY.BIRTH":
      return JSON.stringify({
        type: "birth_certificate",
        dateOfBirth: "1990-01-15",
        placeOfBirth: "Sample City",
        issuedAt: timestamp,
      });
    case "LICENSE.PROFESSIONAL":
      return JSON.stringify({
        type: "professional_license",
        licenseNumber: "PL-" + Math.random().toString(36).substring(7).toUpperCase(),
        profession: "Software Engineer",
        issuedAt: timestamp,
      });
    case "EDUCATION.DEGREE":
      return JSON.stringify({
        type: "degree",
        institution: "Sample University",
        degree: "Bachelor of Science",
        major: "Computer Science",
        graduationDate: "2012-05-15",
        issuedAt: timestamp,
      });
    default:
      return JSON.stringify({
        type: claimType.toLowerCase(),
        issuedAt: timestamp,
        data: "Sample credential data",
      });
  }
}

function getStatusName(status: number): string {
  const statuses = ["ACTIVE", "REVOKED", "EXPIRED", "SUSPENDED", "INHERITED"];
  return statuses[status] || "UNKNOWN";
}

function saveMintResult(result: Record<string, unknown>): void {
  const mintsDir = path.join(__dirname, "..", "deployments", "mints");
  if (!fs.existsSync(mintsDir)) {
    fs.mkdirSync(mintsDir, { recursive: true });
  }

  const filename = `${result.network}-${result.tokenId}-${result.timestamp}.json`;
  const filepath = path.join(mintsDir, filename);
  fs.writeFileSync(filepath, JSON.stringify(result, null, 2));
  console.log(`\nMint record saved to: ${filepath}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Minting failed:", error);
    process.exit(1);
  });
