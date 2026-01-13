/**
 * @file Full lifecycle integration tests
 * @description End-to-end tests covering the complete credential lifecycle:
 *              Mint → Verify → Renew → Revoke/Inherit
 * @dev Tests Step 19 requirements from IMPLEMENTATION_GUIDE.md
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { type SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import {
  type ClaimToken,
  type IssuerRegistry,
  type CredentialLifecycleManager,
  type FIEBridge,
  type ZKDisclosureEngine,
  type MockFIE,
  type MockZKVerifier,
} from "../../typechain-types";
import { ClaimTypes, CredentialStatus, Constants } from "../../types";

describe("Full Lifecycle Integration", function () {
  // ============================================
  // Constants
  // ============================================

  const ONE_YEAR = 365 * 24 * 60 * 60;
  const ONE_DAY = 24 * 60 * 60;
  const GRACE_PERIOD = 90 * ONE_DAY;

  // ============================================
  // Fixtures
  // ============================================

  async function deployFullSystemFixture() {
    const [owner, issuer, subject, beneficiary, verifierSigner, other] =
      await ethers.getSigners();

    // Deploy IssuerRegistry
    const IssuerRegistryFactory = await ethers.getContractFactory("IssuerRegistry");
    const issuerRegistry = (await upgrades.deployProxy(IssuerRegistryFactory, [], {
      initializer: "initialize",
    })) as unknown as IssuerRegistry;
    await issuerRegistry.waitForDeployment();

    // Deploy ClaimToken
    const ClaimTokenFactory = await ethers.getContractFactory("ClaimToken");
    const claimToken = (await upgrades.deployProxy(
      ClaimTokenFactory,
      [await issuerRegistry.getAddress()],
      { initializer: "initialize" }
    )) as unknown as ClaimToken;
    await claimToken.waitForDeployment();

    // Deploy ZKDisclosureEngine
    const ZKEngineFactory = await ethers.getContractFactory("ZKDisclosureEngine");
    const zkEngine = (await upgrades.deployProxy(
      ZKEngineFactory,
      [await claimToken.getAddress()],
      { initializer: "initialize" }
    )) as unknown as ZKDisclosureEngine;
    await zkEngine.waitForDeployment();

    // Deploy CredentialLifecycleManager
    const LifecycleManagerFactory = await ethers.getContractFactory("CredentialLifecycleManager");
    const lifecycleManager = (await upgrades.deployProxy(
      LifecycleManagerFactory,
      [await claimToken.getAddress(), await issuerRegistry.getAddress()],
      { initializer: "initialize" }
    )) as unknown as CredentialLifecycleManager;
    await lifecycleManager.waitForDeployment();

    // Deploy FIEBridge
    const FIEBridgeFactory = await ethers.getContractFactory("FIEBridge");
    const fieBridge = (await upgrades.deployProxy(
      FIEBridgeFactory,
      [await lifecycleManager.getAddress()],
      { initializer: "initialize" }
    )) as unknown as FIEBridge;
    await fieBridge.waitForDeployment();

    // Deploy MockFIE
    const MockFIEFactory = await ethers.getContractFactory("MockFIE");
    const mockFIE = (await MockFIEFactory.deploy()) as MockFIE;
    await mockFIE.waitForDeployment();

    // Deploy MockZKVerifier
    const MockVerifierFactory = await ethers.getContractFactory("MockZKVerifier");
    const mockVerifier = (await MockVerifierFactory.deploy()) as MockZKVerifier;
    await mockVerifier.waitForDeployment();

    // Grant roles
    const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
    await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, await claimToken.getAddress());

    // Set ZK engine in ClaimToken
    await claimToken.setZKEngine(await zkEngine.getAddress());

    // Set lifecycle manager in ClaimToken
    await claimToken.setLifecycleManager(await lifecycleManager.getAddress());

    // Set FIE Bridge in CredentialLifecycleManager
    await lifecycleManager.setFIEBridge(await fieBridge.getAddress());

    // Configure MockFIE to use FIEBridge
    await mockFIE.setFIEBridge(await fieBridge.getAddress());

    // Set MockFIE as the FIE execution agent
    await fieBridge.setFIEExecutionAgent(await mockFIE.getAddress());

    // Register issuer with multiple claim types
    await issuerRegistry.registerIssuer(issuer.address, "US-CA", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.PROPERTY_DEED,
      ClaimTypes.EDUCATION_DEGREE,
      ClaimTypes.IDENTITY_BIRTH,
      ClaimTypes.HEALTH_IMMUNIZATION,
    ]);

    return {
      claimToken,
      issuerRegistry,
      zkEngine,
      lifecycleManager,
      fieBridge,
      mockFIE,
      mockVerifier,
      owner,
      issuer,
      subject,
      beneficiary,
      verifierSigner,
      other,
    };
  }

  // ============================================
  // Helper Functions
  // ============================================

  async function createMintRequest(
    claimType: string,
    subject: string,
    expiresAt?: bigint
  ) {
    const now = await time.latest();
    const oneYearFromNow = BigInt(now) + BigInt(ONE_YEAR);

    return {
      claimType,
      subject,
      encryptedPayload: "0x" + "ab".repeat(100),
      payloadHash: ethers.keccak256(ethers.toUtf8Bytes("test-payload-" + Math.random())),
      commitments: [
        ethers.keccak256(ethers.toUtf8Bytes("commitment-0-" + Math.random())),
        ethers.keccak256(ethers.toUtf8Bytes("commitment-1-" + Math.random())),
      ],
      expiresAt: expiresAt ?? oneYearFromNow,
      metadataURI: "ipfs://QmTestMetadata",
    };
  }

  async function signMintRequest(
    signer: SignerWithAddress,
    request: Awaited<ReturnType<typeof createMintRequest>>,
    claimTokenAddress: string
  ): Promise<string> {
    const chainId = (await ethers.provider.getNetwork()).chainId;

    const messageHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "address", "bytes32", "uint64", "string", "uint256", "address"],
        [
          request.claimType,
          request.subject,
          request.payloadHash,
          request.expiresAt,
          request.metadataURI,
          chainId,
          claimTokenAddress,
        ]
      )
    );

    return signer.signMessage(ethers.getBytes(messageHash));
  }

  async function mintCredential(
    fixture: Awaited<ReturnType<typeof deployFullSystemFixture>>,
    claimType: string = ClaimTypes.LICENSE_OPERATOR,
    subjectAddress?: string,
    expiresAt?: bigint
  ): Promise<bigint> {
    const { claimToken, issuer, subject } = fixture;
    const targetSubject = subjectAddress ?? subject.address;
    const request = await createMintRequest(claimType, targetSubject, expiresAt);
    const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

    const tx = await claimToken.connect(issuer).mint(request, signature);
    const receipt = await tx.wait();

    const transferEvent = receipt?.logs.find((log) => {
      try {
        const parsed = claimToken.interface.parseLog({
          topics: log.topics as string[],
          data: log.data,
        });
        return parsed?.name === "Transfer";
      } catch {
        return false;
      }
    });

    if (!transferEvent) {
      throw new Error("Transfer event not found");
    }

    const parsed = claimToken.interface.parseLog({
      topics: transferEvent.topics as string[],
      data: transferEvent.data,
    });

    return parsed?.args.tokenId;
  }

  async function createInheritanceDirective(
    beneficiaries: string[],
    fieIntentHash: string,
    requiresFIETrigger: boolean = true,
    shares: number[] = []
  ) {
    const effectiveShares = shares.length > 0
      ? shares
      : beneficiaries.map(() => Math.floor(10000 / beneficiaries.length));

    return {
      beneficiaries,
      shares: effectiveShares,
      fieIntentHash,
      requiresFIETrigger,
      conditionType: 0, // None
      conditionData: "0x",
      executorAddress: ethers.ZeroAddress,
      executorAccessDuration: 0n,
    };
  }

  // ============================================
  // Test Suites
  // ============================================

  describe("Complete Credential Lifecycle", function () {
    it("should complete full lifecycle: mint → verify → renew → expire", async function () {
      const fixture = await loadFixture(deployFullSystemFixture);
      const { claimToken, lifecycleManager, issuer, subject } = fixture;

      // Step 1: Mint credential with 30-day expiration
      const now = await time.latest();
      const thirtyDays = BigInt(now) + BigInt(30 * ONE_DAY);
      const tokenId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR, undefined, thirtyDays);

      // Verify initial state
      expect(await claimToken.ownerOf(tokenId)).to.equal(subject.address);
      const credential = await claimToken.getCredential(tokenId);
      expect(credential.status).to.equal(CredentialStatus.ACTIVE);

      // Step 2: Verify credential is valid
      expect(await claimToken.isValid(tokenId)).to.be.true;
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);

      // Step 3: Request renewal before expiration
      await time.increase(20 * ONE_DAY); // Move forward 20 days

      const renewalRequest = {
        tokenId,
        newExpiresAt: BigInt(await time.latest()) + BigInt(ONE_YEAR),
        newEncryptedPayload: "0x" + "cd".repeat(100),
        newPayloadHash: ethers.keccak256(ethers.toUtf8Bytes("renewed-payload")),
        reason: "Standard renewal",
      };

      await lifecycleManager.connect(subject).requestRenewal(
        renewalRequest.tokenId,
        renewalRequest.newExpiresAt,
        renewalRequest.reason
      );

      // Step 4: Issuer approves renewal
      await lifecycleManager.connect(issuer).approveRenewal(
        tokenId,
        renewalRequest.newExpiresAt,
        renewalRequest.newEncryptedPayload,
        renewalRequest.newPayloadHash
      );

      // Verify renewal succeeded
      const renewedCredential = await claimToken.getCredential(tokenId);
      expect(renewedCredential.status).to.equal(CredentialStatus.ACTIVE);
      expect(renewedCredential.expiresAt).to.equal(renewalRequest.newExpiresAt);

      // Step 5: Time travel past new expiration
      await time.increase(ONE_YEAR + ONE_DAY);

      // Credential should now be expired
      expect(await claimToken.isValid(tokenId)).to.be.false;
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.EXPIRED);
    });

    it("should complete lifecycle with revocation: mint → use → revoke", async function () {
      const fixture = await loadFixture(deployFullSystemFixture);
      const { claimToken, issuer, subject } = fixture;

      // Step 1: Mint credential
      const tokenId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR);

      // Verify active
      expect(await claimToken.isValid(tokenId)).to.be.true;

      // Step 2: Issuer revokes credential (e.g., license suspended for violations)
      const revokeReason = ethers.keccak256(ethers.toUtf8Bytes("FRAUD_DETECTED"));
      await claimToken.connect(issuer).revoke(tokenId, revokeReason);

      // Verify revoked
      expect(await claimToken.isValid(tokenId)).to.be.false;
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.REVOKED);

      // Step 3: Attempt to use revoked credential should fail
      // Note: In practice, verification services would check this
      const credential = await claimToken.getCredential(tokenId);
      expect(credential.status).to.equal(CredentialStatus.REVOKED);
    });

    it("should complete lifecycle with suspension and reinstatement", async function () {
      const fixture = await loadFixture(deployFullSystemFixture);
      const { claimToken, issuer, subject } = fixture;

      // Step 1: Mint credential
      const tokenId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR);
      expect(await claimToken.isValid(tokenId)).to.be.true;

      // Step 2: Issuer suspends credential
      const suspendReason = ethers.keccak256(ethers.toUtf8Bytes("PENDING_INVESTIGATION"));
      await claimToken.connect(issuer).suspend(tokenId, suspendReason);

      expect(await claimToken.isValid(tokenId)).to.be.false;
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.SUSPENDED);

      // Step 3: Investigation clears, issuer reinstates
      await claimToken.connect(issuer).reinstate(tokenId);

      expect(await claimToken.isValid(tokenId)).to.be.true;
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);
    });

    it("should handle credential inheritance via FIE trigger", async function () {
      const fixture = await loadFixture(deployFullSystemFixture);
      const { claimToken, lifecycleManager, fieBridge, mockFIE, subject, beneficiary, owner } = fixture;

      // Step 1: Mint property deed credential
      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);
      expect(await claimToken.ownerOf(tokenId)).to.equal(subject.address);

      // Step 2: Set up inheritance directive
      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_" + Math.random()));
      const directive = await createInheritanceDirective([beneficiary.address], fieIntentHash);

      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      // Verify directive is set
      const storedDirective = await lifecycleManager.getInheritanceDirective(tokenId);
      expect(storedDirective.beneficiaries[0]).to.equal(beneficiary.address);

      // Step 3: Register the FIE intent
      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);

      // Step 4: Trigger FIE execution (simulates death notification)
      await mockFIE.triggerExecution(fieIntentHash);

      // Step 5: Verify inheritance completed
      expect(await claimToken.ownerOf(tokenId)).to.equal(beneficiary.address);
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.INHERITED);
    });
  });

  describe("Multi-Credential Management", function () {
    it("should handle multiple credentials for same subject", async function () {
      const fixture = await loadFixture(deployFullSystemFixture);
      const { claimToken, subject } = fixture;

      // Mint multiple credentials
      const licenseId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR);
      const degreeId = await mintCredential(fixture, ClaimTypes.EDUCATION_DEGREE);
      const propertyId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      // All should be owned by subject
      expect(await claimToken.ownerOf(licenseId)).to.equal(subject.address);
      expect(await claimToken.ownerOf(degreeId)).to.equal(subject.address);
      expect(await claimToken.ownerOf(propertyId)).to.equal(subject.address);

      // Query subject's credentials
      const balance = await claimToken.balanceOf(subject.address);
      expect(balance).to.equal(3n);

      // All should be valid
      expect(await claimToken.isValid(licenseId)).to.be.true;
      expect(await claimToken.isValid(degreeId)).to.be.true;
      expect(await claimToken.isValid(propertyId)).to.be.true;
    });

    it("should handle selective operations on specific credentials", async function () {
      const fixture = await loadFixture(deployFullSystemFixture);
      const { claimToken, issuer } = fixture;

      // Mint multiple credentials
      const licenseId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR);
      const degreeId = await mintCredential(fixture, ClaimTypes.EDUCATION_DEGREE);

      // Revoke only the license
      const revokeReason = ethers.keccak256(ethers.toUtf8Bytes("LICENSE_VIOLATION"));
      await claimToken.connect(issuer).revoke(licenseId, revokeReason);

      // License revoked, degree still active
      expect(await claimToken.isValid(licenseId)).to.be.false;
      expect(await claimToken.isValid(degreeId)).to.be.true;
      expect(await claimToken.getStatus(licenseId)).to.equal(CredentialStatus.REVOKED);
      expect(await claimToken.getStatus(degreeId)).to.equal(CredentialStatus.ACTIVE);
    });
  });

  describe("Cross-Component Integration", function () {
    it("should maintain state consistency across all components", async function () {
      const fixture = await loadFixture(deployFullSystemFixture);
      const { claimToken, issuerRegistry, lifecycleManager, issuer, subject } = fixture;

      // Mint credential
      const tokenId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR);

      // Check ClaimToken state
      const credential = await claimToken.getCredential(tokenId);
      expect(credential.issuer).to.equal(issuer.address);
      expect(credential.subject).to.equal(subject.address);
      expect(credential.status).to.equal(CredentialStatus.ACTIVE);

      // Check IssuerRegistry state
      expect(await issuerRegistry.isAuthorized(issuer.address, ClaimTypes.LICENSE_OPERATOR)).to.be.true;
      const issuerStats = await issuerRegistry.getIssuerStats(issuer.address);
      expect(issuerStats.totalIssued).to.be.gte(1n);

      // Set inheritance directive via LifecycleManager
      const directive = await createInheritanceDirective(
        [fixture.beneficiary.address],
        ethers.keccak256(ethers.toUtf8Bytes("INTENT"))
      );
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      // Verify LifecycleManager state
      const storedDirective = await lifecycleManager.getInheritanceDirective(tokenId);
      expect(storedDirective.beneficiaries.length).to.equal(1);
    });

    it("should handle gas costs within NFR limits", async function () {
      const fixture = await loadFixture(deployFullSystemFixture);
      const { claimToken, issuer, subject } = fixture;

      // Measure mint gas cost (NFR-01: < 500k gas)
      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      const tx = await claimToken.connect(issuer).mint(request, signature);
      const receipt = await tx.wait();

      // Gas should be under 500k for minting
      expect(receipt?.gasUsed).to.be.lt(500000n);
    });
  });

  describe("Edge Cases and Error Handling", function () {
    it("should prevent renewal after revocation", async function () {
      const fixture = await loadFixture(deployFullSystemFixture);
      const { claimToken, lifecycleManager, issuer, subject } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR);

      // Revoke the credential
      await claimToken.connect(issuer).revoke(tokenId, ethers.keccak256(ethers.toUtf8Bytes("REVOKED")));

      // Attempt renewal should fail
      const newExpiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
      await expect(
        lifecycleManager.connect(subject).requestRenewal(tokenId, newExpiry, "Trying to renew")
      ).to.be.reverted;
    });

    it("should prevent unauthorized status changes", async function () {
      const fixture = await loadFixture(deployFullSystemFixture);
      const { claimToken, other } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR);

      // Non-issuer trying to revoke should fail
      await expect(
        claimToken.connect(other).revoke(tokenId, ethers.keccak256(ethers.toUtf8Bytes("REASON")))
      ).to.be.reverted;

      // Non-issuer trying to suspend should fail
      await expect(
        claimToken.connect(other).suspend(tokenId, ethers.keccak256(ethers.toUtf8Bytes("REASON")))
      ).to.be.reverted;
    });

    it("should handle expired credential operations correctly", async function () {
      const fixture = await loadFixture(deployFullSystemFixture);
      const { claimToken, subject } = fixture;

      // Mint credential with very short expiration
      const now = await time.latest();
      const shortExpiry = BigInt(now) + BigInt(ONE_DAY);
      const tokenId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR, undefined, shortExpiry);

      // Verify active
      expect(await claimToken.isValid(tokenId)).to.be.true;

      // Fast forward past expiration
      await time.increase(ONE_DAY + 1);

      // Credential should be expired
      expect(await claimToken.isValid(tokenId)).to.be.false;
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.EXPIRED);

      // Ownership unchanged
      expect(await claimToken.ownerOf(tokenId)).to.equal(subject.address);
    });
  });

  describe("Sequential Status Transitions", function () {
    it("should track correct status history: ACTIVE → SUSPENDED → ACTIVE → EXPIRED", async function () {
      const fixture = await loadFixture(deployFullSystemFixture);
      const { claimToken, issuer } = fixture;

      const now = await time.latest();
      const shortExpiry = BigInt(now) + BigInt(7 * ONE_DAY);
      const tokenId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR, undefined, shortExpiry);

      // Initial: ACTIVE
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);

      // Suspend
      await claimToken.connect(issuer).suspend(tokenId, ethers.keccak256(ethers.toUtf8Bytes("TEMP")));
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.SUSPENDED);

      // Reinstate
      await claimToken.connect(issuer).reinstate(tokenId);
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);

      // Wait for expiration
      await time.increase(8 * ONE_DAY);
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.EXPIRED);
    });

    it("should enforce terminal states: REVOKED cannot transition", async function () {
      const fixture = await loadFixture(deployFullSystemFixture);
      const { claimToken, issuer } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR);

      // Revoke
      await claimToken.connect(issuer).revoke(tokenId, ethers.keccak256(ethers.toUtf8Bytes("TERMINAL")));
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.REVOKED);

      // Cannot reinstate
      await expect(claimToken.connect(issuer).reinstate(tokenId)).to.be.reverted;

      // Cannot suspend (already in terminal state)
      await expect(
        claimToken.connect(issuer).suspend(tokenId, ethers.keccak256(ethers.toUtf8Bytes("TRY")))
      ).to.be.reverted;
    });
  });
});
