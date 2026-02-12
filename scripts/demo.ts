/**
 * @file demo.ts
 * @description End-to-end demo of the Sovereign Credential system.
 *
 * Deploys all contracts, registers an issuer, mints a credential,
 * verifies it, and demonstrates the verification lifecycle — all in
 * a single script with human-readable output at each step.
 *
 * Usage:
 *   npx hardhat run scripts/demo.ts                      # ephemeral Hardhat network
 *   npx hardhat run scripts/demo.ts --network localhost   # persistent local node
 *   npx hardhat run scripts/demo.ts --network sepolia     # testnet (reads deployments/sepolia-latest.json)
 */

import { ethers, upgrades, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

// ============================================
// Helpers
// ============================================

const STATUS_NAMES: Record<number, string> = {
  0: "PENDING",
  1: "ACTIVE",
  2: "SUSPENDED",
  3: "REVOKED",
  4: "EXPIRED",
  5: "INHERITED",
};

function hr(label?: string) {
  if (label) {
    console.log(`\n${"=".repeat(60)}`);
    console.log(`  ${label}`);
    console.log(`${"=".repeat(60)}`);
  } else {
    console.log("-".repeat(60));
  }
}

function step(n: number, label: string) {
  console.log(`\n[${"Step " + n}] ${label}`);
  console.log("-".repeat(60));
}

// ============================================
// Main
// ============================================

async function main() {
  hr("SOVEREIGN CREDENTIAL — END-TO-END DEMO");

  const signers = await ethers.getSigners();
  const deployer = signers[0]!;
  const issuerSigner = signers[1] ?? deployer;
  const holderSigner = signers[2] ?? deployer;
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  console.log(`Network:  ${network.name} (chainId ${chainId})`);
  console.log(`Deployer: ${deployer.address}`);
  console.log(`Issuer:   ${issuerSigner.address}`);
  console.log(`Holder:   ${holderSigner.address}`);

  // ------------------------------------------------------------------
  // Step 1: Deploy contracts (or load existing deployment)
  // ------------------------------------------------------------------
  step(1, "Deploy contracts");

  let issuerRegistryAddr: string;
  let claimTokenAddr: string;
  let zkEngineAddr: string;

  const existing = loadDeployment();
  if (existing) {
    console.log("Using existing deployment from deployments/ directory");
    issuerRegistryAddr = existing.contracts.issuerRegistry.proxy;
    claimTokenAddr = existing.contracts.claimToken.proxy;
    zkEngineAddr = existing.contracts.zkDisclosureEngine.proxy;
    console.log(`  IssuerRegistry:    ${issuerRegistryAddr}`);
    console.log(`  ClaimToken:        ${claimTokenAddr}`);
    console.log(`  ZKDisclosureEngine: ${zkEngineAddr}`);
  } else {
    console.log("No existing deployment found — deploying fresh contracts...");

    // IssuerRegistry
    const IR = await ethers.getContractFactory("IssuerRegistry");
    const ir = await upgrades.deployProxy(IR, [], { initializer: "initialize", kind: "uups" });
    await ir.waitForDeployment();
    issuerRegistryAddr = await ir.getAddress();
    console.log(`  IssuerRegistry:    ${issuerRegistryAddr}`);

    // ClaimToken
    const CT = await ethers.getContractFactory("ClaimToken");
    const ct = await upgrades.deployProxy(CT, [issuerRegistryAddr], { initializer: "initialize", kind: "uups" });
    await ct.waitForDeployment();
    claimTokenAddr = await ct.getAddress();
    console.log(`  ClaimToken:        ${claimTokenAddr}`);

    // CredentialLifecycleManager
    const CLM = await ethers.getContractFactory("CredentialLifecycleManager");
    const clm = await upgrades.deployProxy(CLM, [claimTokenAddr, issuerRegistryAddr], { initializer: "initialize", kind: "uups" });
    await clm.waitForDeployment();
    const clmAddr = await clm.getAddress();
    console.log(`  LifecycleManager:  ${clmAddr}`);

    // ZKDisclosureEngine
    const ZK = await ethers.getContractFactory("ZKDisclosureEngine");
    const zk = await upgrades.deployProxy(ZK, [claimTokenAddr], { initializer: "initialize", kind: "uups" });
    await zk.waitForDeployment();
    zkEngineAddr = await zk.getAddress();
    console.log(`  ZKDisclosureEngine: ${zkEngineAddr}`);

    // Cross-references
    const CREDENTIAL_CONTRACT_ROLE = await ir.CREDENTIAL_CONTRACT_ROLE();
    await ir.grantRole(CREDENTIAL_CONTRACT_ROLE, claimTokenAddr);
    await ct.setLifecycleManager(clmAddr);
    console.log("  Cross-references configured");
  }

  // Attach to contracts
  const issuerRegistry = (await ethers.getContractFactory("IssuerRegistry")).attach(issuerRegistryAddr);
  const claimToken = (await ethers.getContractFactory("ClaimToken")).attach(claimTokenAddr);

  // ------------------------------------------------------------------
  // Step 2: Register issuer
  // ------------------------------------------------------------------
  step(2, "Register issuer");

  const CLAIM_TYPE_BIRTH = ethers.keccak256(ethers.toUtf8Bytes("IDENTITY.BIRTH"));
  const CLAIM_TYPE_LICENSE = ethers.keccak256(ethers.toUtf8Bytes("LICENSE.PROFESSIONAL"));

  // Check if already registered
  const issuerInfo = await issuerRegistry.getIssuer(issuerSigner.address);
  if (issuerInfo.issuerAddress === ethers.ZeroAddress) {
    const tx = await issuerRegistry.registerIssuer(
      issuerSigner.address,
      "US-OR",
      [CLAIM_TYPE_BIRTH, CLAIM_TYPE_LICENSE]
    );
    await tx.wait();
    console.log(`  Registered: ${issuerSigner.address}`);
    console.log(`  Jurisdiction: US-OR`);
    console.log(`  Authorized types: IDENTITY.BIRTH, LICENSE.PROFESSIONAL`);
  } else {
    console.log(`  Issuer already registered: ${issuerSigner.address}`);
  }

  // Verify authorization
  const isAuth = await issuerRegistry.isAuthorized(issuerSigner.address, CLAIM_TYPE_BIRTH);
  console.log(`  Authorized for IDENTITY.BIRTH: ${isAuth}`);

  // ------------------------------------------------------------------
  // Step 3: Mint a birth certificate credential
  // ------------------------------------------------------------------
  step(3, "Mint credential (birth certificate)");

  const nowTs = (await ethers.provider.getBlock("latest"))!.timestamp;
  const expiresAt = BigInt(nowTs) + BigInt(365 * 24 * 60 * 60); // 1 year

  // Credential payload (would be encrypted in production)
  const payloadStr = JSON.stringify({
    type: "birth_certificate",
    dateOfBirth: "1990-06-15",
    placeOfBirth: "Portland, OR",
    fullName: "Alice Johnson",
  });
  const encryptedPayload = ethers.toUtf8Bytes(payloadStr);
  const payloadHash = ethers.keccak256(ethers.toUtf8Bytes(payloadStr));

  // ZK commitments
  const ageCommitment = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["string", "uint256"],
      ["birthdate", 645494400] // 1990-06-15 Unix timestamp
    )
  );

  const mintRequest = {
    claimType: CLAIM_TYPE_BIRTH,
    subject: holderSigner.address,
    encryptedPayload,
    payloadHash,
    commitments: [ageCommitment],
    expiresAt,
    metadataURI: "ipfs://QmDemoMetadata",
  };

  // Issuer signs the mint request
  const messageHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "address", "bytes32", "uint64", "string", "uint256", "address"],
      [
        mintRequest.claimType,
        mintRequest.subject,
        mintRequest.payloadHash,
        mintRequest.expiresAt,
        mintRequest.metadataURI,
        chainId,
        claimTokenAddr,
      ]
    )
  );
  const signature = await issuerSigner.signMessage(ethers.getBytes(messageHash));

  console.log(`  Subject:    ${holderSigner.address}`);
  console.log(`  Claim type: IDENTITY.BIRTH`);
  console.log(`  Expires:    ${new Date(Number(expiresAt) * 1000).toISOString()}`);

  // Mint
  const mintTx = await claimToken.mint(mintRequest, signature);
  const receipt = await mintTx.wait();

  // Extract token ID from CredentialMinted event
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
        // skip
      }
    }
  }

  if (tokenId === undefined) {
    console.error("  ERROR: Could not extract tokenId from mint transaction");
    process.exit(1);
  }
  console.log(`  Minted!  Token ID: ${tokenId}`);
  console.log(`  Tx hash: ${mintTx.hash}`);

  // ------------------------------------------------------------------
  // Step 4: Verify credential on-chain
  // ------------------------------------------------------------------
  step(4, "Verify credential on-chain");

  const credential = await claimToken.getCredential(tokenId);
  const isValid = await claimToken.verify(tokenId);

  console.log(`  Token ID:   ${tokenId}`);
  console.log(`  Subject:    ${credential.subject}`);
  console.log(`  Issuer:     ${credential.issuer}`);
  console.log(`  Status:     ${STATUS_NAMES[credential.status] || "UNKNOWN"}`);
  console.log(`  Issued at:  ${new Date(Number(credential.issuedAt) * 1000).toISOString()}`);
  console.log(`  Expires at: ${new Date(Number(credential.expiresAt) * 1000).toISOString()}`);
  console.log(`  Commitments: ${credential.commitments.length}`);
  console.log(`  Metadata:   ${credential.metadataURI}`);
  console.log(`  `);
  console.log(`  verify() result: ${isValid ? "VALID" : "INVALID"}`);

  // ------------------------------------------------------------------
  // Step 5: Query by subject
  // ------------------------------------------------------------------
  step(5, "Query credentials by subject");

  const subjectCredentials = await claimToken.getCredentialsBySubject(holderSigner.address);
  console.log(`  Holder ${holderSigner.address} owns ${subjectCredentials.length} credential(s):`);
  for (const tid of subjectCredentials) {
    console.log(`    - Token ID ${tid}`);
  }

  // ------------------------------------------------------------------
  // Step 6: Demonstrate suspension and reinstatement
  // ------------------------------------------------------------------
  step(6, "Suspend and reinstate credential");

  // Suspend
  const suspendTx = await claimToken.connect(issuerSigner).suspend(tokenId, "Routine audit");
  await suspendTx.wait();
  const afterSuspend = await claimToken.getCredential(tokenId);
  const validAfterSuspend = await claimToken.verify(tokenId);
  console.log(`  After suspend:`);
  console.log(`    Status:   ${STATUS_NAMES[afterSuspend.status]}`);
  console.log(`    verify(): ${validAfterSuspend}`);

  // Reinstate
  const reinstateTx = await claimToken.connect(issuerSigner).reinstate(tokenId);
  await reinstateTx.wait();
  const afterReinstate = await claimToken.getCredential(tokenId);
  const validAfterReinstate = await claimToken.verify(tokenId);
  console.log(`  After reinstate:`);
  console.log(`    Status:   ${STATUS_NAMES[afterReinstate.status]}`);
  console.log(`    verify(): ${validAfterReinstate}`);

  // ------------------------------------------------------------------
  // Step 7: Demonstrate revocation (permanent)
  // ------------------------------------------------------------------
  step(7, "Revoke credential (permanent)");

  const revokeTx = await claimToken.connect(issuerSigner).revoke(tokenId, "Fraudulent documentation");
  await revokeTx.wait();
  const afterRevoke = await claimToken.getCredential(tokenId);
  const validAfterRevoke = await claimToken.verify(tokenId);
  console.log(`  After revoke:`);
  console.log(`    Status:   ${STATUS_NAMES[afterRevoke.status]}`);
  console.log(`    verify(): ${validAfterRevoke}`);
  console.log(`    Revocation is permanent — credential can never be reactivated.`);

  // ------------------------------------------------------------------
  // Summary
  // ------------------------------------------------------------------
  hr("DEMO COMPLETE");
  console.log(`
  What this demonstrated:
    1. Deployed 4 UUPS-upgradeable contracts on ${network.name}
    2. Registered an authorized issuer with jurisdiction and claim types
    3. Minted a birth certificate credential (ERC721) with:
       - Issuer signature verification
       - Encrypted payload storage
       - ZK-compatible commitments
    4. Verified the credential on-chain (status + expiry + issuer authorization)
    5. Queried credentials by subject address
    6. Suspended and reinstated a credential (temporary state change)
    7. Permanently revoked a credential (irreversible)

  What this did NOT demonstrate (requires ZK circuit artifacts):
    - Zero-knowledge age threshold proof
    - Selective disclosure via ZKDisclosureEngine
    - Inheritance via FIEBridge

  To run ZK proofs, first compile circuits:
    npm run circuits:compile && npm run circuits:setup
  `);
}

function loadDeployment(): { contracts: { issuerRegistry: { proxy: string }; claimToken: { proxy: string }; zkDisclosureEngine: { proxy: string } } } | null {
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
    console.error("Demo failed:", error);
    process.exit(1);
  });
