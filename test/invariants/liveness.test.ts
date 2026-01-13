/**
 * @file Liveness and Economic Invariants Tests
 * @description Tests verifying the liveness invariants from SPEC.md Section 10.2
 *              and economic invariants from Section 10.3
 *
 * Liveness Invariants:
 * INV-06: Renewal requests must be answered within RENEWAL_TIMEOUT
 * INV-07: Inheritance executes within INHERITANCE_TIMEOUT
 *
 * Economic Invariants:
 * INV-08: Issuers below reputation threshold cannot issue
 * INV-09: Credential accounting is consistent (totalIssued >= totalRevoked + totalActive)
 *
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
  type MockFIE,
} from "../../typechain-types";
import { ClaimTypes, CredentialStatus, Constants } from "../../types";

describe("Liveness & Economic Invariants (SPEC Sections 10.2 & 10.3)", function () {
  // ============================================
  // Constants
  // ============================================

  const ONE_YEAR = 365 * 24 * 60 * 60;
  const ONE_DAY = 24 * 60 * 60;
  const RENEWAL_TIMEOUT = 30 * ONE_DAY; // 30 days
  const INHERITANCE_TIMEOUT = 7 * ONE_DAY; // 7 days
  const MIN_REPUTATION = 1000n;
  const INITIAL_REPUTATION = 5000n;
  const MAX_REPUTATION = 10000n;

  // ============================================
  // Fixtures
  // ============================================

  async function deployLivenessTestFixture() {
    const [owner, registrar, arbiter, issuer1, issuer2, subject, beneficiary, other] =
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

    // Grant roles
    const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
    const REGISTRAR_ROLE = await issuerRegistry.REGISTRAR_ROLE();
    const ARBITER_ROLE = await issuerRegistry.ARBITER_ROLE();

    await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, await claimToken.getAddress());
    await issuerRegistry.grantRole(REGISTRAR_ROLE, registrar.address);
    await issuerRegistry.grantRole(ARBITER_ROLE, arbiter.address);

    // Wire up contracts
    await claimToken.setLifecycleManager(await lifecycleManager.getAddress());
    await lifecycleManager.setFIEBridge(await fieBridge.getAddress());
    await mockFIE.setFIEBridge(await fieBridge.getAddress());
    await fieBridge.setFIEExecutionAgent(await mockFIE.getAddress());

    // Register issuers
    await issuerRegistry.connect(registrar).registerIssuer(issuer1.address, "US-CA", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.PROPERTY_DEED,
    ]);
    await issuerRegistry.connect(registrar).registerIssuer(issuer2.address, "US-OR", [
      ClaimTypes.EDUCATION_DEGREE,
    ]);

    return {
      claimToken,
      issuerRegistry,
      lifecycleManager,
      fieBridge,
      mockFIE,
      owner,
      registrar,
      arbiter,
      issuer1,
      issuer2,
      subject,
      beneficiary,
      other,
    };
  }

  // ============================================
  // Helper Functions
  // ============================================

  async function createMintRequest(claimType: string, subject: string, expiresAt?: bigint) {
    const now = await time.latest();
    const oneYearFromNow = BigInt(now) + BigInt(ONE_YEAR);

    return {
      claimType,
      subject,
      encryptedPayload: "0x" + "ab".repeat(100),
      payloadHash: ethers.keccak256(ethers.toUtf8Bytes("payload-" + Math.random())),
      commitments: [ethers.keccak256(ethers.toUtf8Bytes("commit-" + Math.random()))],
      expiresAt: expiresAt ?? oneYearFromNow,
      metadataURI: "ipfs://QmTest",
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
        [request.claimType, request.subject, request.payloadHash, request.expiresAt, request.metadataURI, chainId, claimTokenAddress]
      )
    );
    return signer.signMessage(ethers.getBytes(messageHash));
  }

  async function mintCredential(
    fixture: Awaited<ReturnType<typeof deployLivenessTestFixture>>,
    issuer: SignerWithAddress,
    claimType: string,
    subject: SignerWithAddress,
    expiresAt?: bigint
  ): Promise<bigint> {
    const { claimToken } = fixture;
    const request = await createMintRequest(claimType, subject.address, expiresAt);
    const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

    const tx = await claimToken.connect(issuer).mint(request, signature);
    const receipt = await tx.wait();

    const transferEvent = receipt?.logs.find((log) => {
      try {
        const parsed = claimToken.interface.parseLog({ topics: log.topics as string[], data: log.data });
        return parsed?.name === "Transfer";
      } catch {
        return false;
      }
    });

    const parsed = claimToken.interface.parseLog({
      topics: transferEvent!.topics as string[],
      data: transferEvent!.data,
    });

    return parsed?.args.tokenId;
  }

  // ============================================
  // INV-06: Renewal requests must be answered within RENEWAL_TIMEOUT
  // ∀ renewal request r: ∃ response within RENEWAL_TIMEOUT
  // ============================================

  describe("INV-06: Renewal requests must be answered within timeout", function () {
    it("should track renewal request timestamp", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { claimToken, lifecycleManager, issuer1, subject } = fixture;

      // Mint credential with short expiration
      const shortExpiry = BigInt(await time.latest()) + BigInt(60 * ONE_DAY);
      const tokenId = await mintCredential(fixture, issuer1, ClaimTypes.LICENSE_OPERATOR, subject, shortExpiry);

      // Request renewal
      const newExpiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
      await lifecycleManager.connect(subject).requestRenewal(tokenId, newExpiry, "Renewal request");

      // Get renewal request info
      const renewalInfo = await lifecycleManager.getRenewalRequest(tokenId);
      expect(renewalInfo.requestedAt).to.be.gt(0n);
      expect(renewalInfo.pending).to.be.true;
    });

    it("should allow renewal approval within timeout", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { claimToken, lifecycleManager, issuer1, subject } = fixture;

      const shortExpiry = BigInt(await time.latest()) + BigInt(60 * ONE_DAY);
      const tokenId = await mintCredential(fixture, issuer1, ClaimTypes.LICENSE_OPERATOR, subject, shortExpiry);

      const newExpiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
      await lifecycleManager.connect(subject).requestRenewal(tokenId, newExpiry, "Standard renewal");

      // Fast forward within timeout
      await time.increase(RENEWAL_TIMEOUT / 2);

      // Approve renewal
      const newPayload = "0x" + "cd".repeat(100);
      const newPayloadHash = ethers.keccak256(ethers.toUtf8Bytes("renewed"));

      await expect(
        lifecycleManager.connect(issuer1).approveRenewal(tokenId, newExpiry, newPayload, newPayloadHash)
      ).to.not.be.reverted;

      // Verify renewal completed
      const credential = await claimToken.getCredential(tokenId);
      expect(credential.expiresAt).to.equal(newExpiry);
    });

    it("should handle timeout expiration for unanswered requests", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { lifecycleManager, issuer1, subject } = fixture;

      const shortExpiry = BigInt(await time.latest()) + BigInt(60 * ONE_DAY);
      const tokenId = await mintCredential(fixture, issuer1, ClaimTypes.LICENSE_OPERATOR, subject, shortExpiry);

      const newExpiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
      await lifecycleManager.connect(subject).requestRenewal(tokenId, newExpiry, "May timeout");

      // Fast forward past timeout
      await time.increase(RENEWAL_TIMEOUT + ONE_DAY);

      // Check if request can be escalated or auto-resolved
      const renewalInfo = await lifecycleManager.getRenewalRequest(tokenId);

      // The system should provide a mechanism for handling timeouts
      // This test documents the expected behavior
      if (renewalInfo.pending) {
        // If still pending after timeout, subject should be able to escalate
        await expect(
          lifecycleManager.connect(subject).escalateRenewal(tokenId)
        ).to.not.be.reverted;
      }
    });

    it("should allow denial of renewal request", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { lifecycleManager, issuer1, subject } = fixture;

      const shortExpiry = BigInt(await time.latest()) + BigInt(60 * ONE_DAY);
      const tokenId = await mintCredential(fixture, issuer1, ClaimTypes.LICENSE_OPERATOR, subject, shortExpiry);

      const newExpiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
      await lifecycleManager.connect(subject).requestRenewal(tokenId, newExpiry, "May be denied");

      // Issuer denies renewal
      await lifecycleManager.connect(issuer1).denyRenewal(tokenId, "Requirements not met");

      // Verify denial
      const renewalInfo = await lifecycleManager.getRenewalRequest(tokenId);
      expect(renewalInfo.pending).to.be.false;
    });
  });

  // ============================================
  // INV-07: Inheritance executes within INHERITANCE_TIMEOUT
  // ∀ FIE trigger t: processedWithin(t, INHERITANCE_TIMEOUT)
  // ============================================

  describe("INV-07: Inheritance executes within bounded time", function () {
    it("should execute inheritance immediately upon FIE trigger", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { claimToken, lifecycleManager, fieBridge, mockFIE, issuer1, subject, beneficiary, owner } = fixture;

      const tokenId = await mintCredential(fixture, issuer1, ClaimTypes.PROPERTY_DEED, subject);

      // Set up inheritance
      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INV07_IMMEDIATE"));
      const directive = {
        beneficiaries: [beneficiary.address],
        shares: [10000],
        fieIntentHash,
        requiresFIETrigger: true,
        conditionType: 0,
        conditionData: "0x",
        executorAddress: ethers.ZeroAddress,
        executorAccessDuration: 0n,
      };

      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);
      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);

      const triggerTimestamp = await time.latest();

      // Trigger FIE
      await mockFIE.triggerExecution(fieIntentHash);

      const executionTimestamp = await time.latest();

      // Execution should be immediate (within same block or next)
      expect(executionTimestamp - triggerTimestamp).to.be.lte(1);

      // Verify ownership transferred
      expect(await claimToken.ownerOf(tokenId)).to.equal(beneficiary.address);
    });

    it("should track execution timing for audit purposes", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { lifecycleManager, fieBridge, mockFIE, issuer1, subject, beneficiary, owner } = fixture;

      const tokenId = await mintCredential(fixture, issuer1, ClaimTypes.PROPERTY_DEED, subject);

      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INV07_TIMING"));
      const directive = {
        beneficiaries: [beneficiary.address],
        shares: [10000],
        fieIntentHash,
        requiresFIETrigger: true,
        conditionType: 0,
        conditionData: "0x",
        executorAddress: ethers.ZeroAddress,
        executorAccessDuration: 0n,
      };

      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);
      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);

      // Record trigger time
      const triggerTime = await time.latest();
      await mockFIE.triggerExecution(fieIntentHash);

      // Get execution record
      const intentInfo = await fieBridge.getIntent(fieIntentHash);
      expect(intentInfo.executed).to.be.true;
      expect(intentInfo.executedAt).to.be.gte(triggerTime);

      // Verify execution was within INHERITANCE_TIMEOUT
      const executionDelay = Number(intentInfo.executedAt) - triggerTime;
      expect(executionDelay).to.be.lt(INHERITANCE_TIMEOUT);
    });

    it("should handle multiple inheritance triggers efficiently", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { claimToken, lifecycleManager, fieBridge, mockFIE, issuer1, subject, beneficiary, owner } = fixture;

      // Create multiple credentials with inheritance directives
      const tokenIds: bigint[] = [];
      const intentHashes: string[] = [];

      for (let i = 0; i < 3; i++) {
        const tokenId = await mintCredential(fixture, issuer1, ClaimTypes.PROPERTY_DEED, subject);
        const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes(`FIE_MULTI_${i}`));

        const directive = {
          beneficiaries: [beneficiary.address],
          shares: [10000],
          fieIntentHash,
          requiresFIETrigger: true,
          conditionType: 0,
          conditionData: "0x",
          executorAddress: ethers.ZeroAddress,
          executorAccessDuration: 0n,
        };

        await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);
        await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);

        tokenIds.push(tokenId);
        intentHashes.push(fieIntentHash);
      }

      // Trigger all in sequence
      const startTime = await time.latest();

      for (const hash of intentHashes) {
        await mockFIE.triggerExecution(hash);
      }

      const endTime = await time.latest();

      // All should complete within timeout
      expect(endTime - startTime).to.be.lt(INHERITANCE_TIMEOUT);

      // All should be transferred
      for (const tokenId of tokenIds) {
        expect(await claimToken.ownerOf(tokenId)).to.equal(beneficiary.address);
      }
    });
  });

  // ============================================
  // INV-08: Issuers below reputation threshold cannot issue
  // ∀ issuer i: i.reputationScore >= MIN_REPUTATION → i.canIssue
  // ============================================

  describe("INV-08: Issuers below reputation threshold cannot issue", function () {
    it("should allow issuers above MIN_REPUTATION to issue", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { issuerRegistry, issuer1, subject } = fixture;

      // Verify initial reputation is above minimum
      const reputation = await issuerRegistry.getReputation(issuer1.address);
      expect(reputation).to.be.gte(MIN_REPUTATION);

      // Issuer can mint
      const tokenId = await mintCredential(fixture, issuer1, ClaimTypes.LICENSE_OPERATOR, subject);
      expect(tokenId).to.be.gt(0n);
    });

    it("should prevent issuers below MIN_REPUTATION from issuing", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { claimToken, issuerRegistry, arbiter, issuer1, subject } = fixture;

      // Reduce reputation below minimum
      const currentRep = await issuerRegistry.getReputation(issuer1.address);
      const reduction = Number(currentRep) - Number(MIN_REPUTATION) + 100; // Go below MIN
      await issuerRegistry.connect(arbiter).adjustReputation(issuer1.address, -reduction);

      // Verify reputation is below minimum
      const newRep = await issuerRegistry.getReputation(issuer1.address);
      expect(newRep).to.be.lt(MIN_REPUTATION);

      // Issuer should not be able to mint
      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(issuer1, request, await claimToken.getAddress());

      await expect(claimToken.connect(issuer1).mint(request, signature)).to.be.reverted;
    });

    it("should restore issuance capability when reputation returns above threshold", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { claimToken, issuerRegistry, arbiter, issuer1, subject } = fixture;

      // Reduce reputation below minimum
      const currentRep = await issuerRegistry.getReputation(issuer1.address);
      const reduction = Number(currentRep) - Number(MIN_REPUTATION) + 100;
      await issuerRegistry.connect(arbiter).adjustReputation(issuer1.address, -reduction);

      // Cannot issue
      const request1 = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature1 = await signMintRequest(issuer1, request1, await claimToken.getAddress());
      await expect(claimToken.connect(issuer1).mint(request1, signature1)).to.be.reverted;

      // Restore reputation above minimum
      await issuerRegistry.connect(arbiter).adjustReputation(issuer1.address, 500);

      // Should be able to issue again
      const request2 = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature2 = await signMintRequest(issuer1, request2, await claimToken.getAddress());
      await expect(claimToken.connect(issuer1).mint(request2, signature2)).to.not.be.reverted;
    });

    it("should enforce MIN_REPUTATION boundary exactly", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { claimToken, issuerRegistry, arbiter, issuer1, subject } = fixture;

      // Set reputation to exactly MIN_REPUTATION
      const currentRep = await issuerRegistry.getReputation(issuer1.address);
      const adjustment = Number(MIN_REPUTATION) - Number(currentRep);
      await issuerRegistry.connect(arbiter).adjustReputation(issuer1.address, adjustment);

      // Should be able to issue at exactly MIN_REPUTATION
      const tokenId = await mintCredential(fixture, issuer1, ClaimTypes.LICENSE_OPERATOR, subject);
      expect(tokenId).to.be.gt(0n);

      // Reduce by 1 below minimum
      await issuerRegistry.connect(arbiter).adjustReputation(issuer1.address, -1);

      // Should not be able to issue
      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(issuer1, request, await claimToken.getAddress());
      await expect(claimToken.connect(issuer1).mint(request, signature)).to.be.reverted;
    });
  });

  // ============================================
  // INV-09: Credential accounting is consistent
  // totalIssued(i) >= totalRevoked(i) + totalActive(i)
  // ============================================

  describe("INV-09: Credential accounting is consistent", function () {
    it("should track totalIssued accurately", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { issuerRegistry, issuer1, subject } = fixture;

      const initialStats = await issuerRegistry.getIssuerStats(issuer1.address);
      const initialIssued = initialStats.totalIssued;

      // Mint 5 credentials
      for (let i = 0; i < 5; i++) {
        await mintCredential(fixture, issuer1, ClaimTypes.LICENSE_OPERATOR, subject);
      }

      const finalStats = await issuerRegistry.getIssuerStats(issuer1.address);
      expect(finalStats.totalIssued).to.equal(initialIssued + 5n);
    });

    it("should track totalRevoked accurately", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { claimToken, issuerRegistry, issuer1, subject } = fixture;

      // Mint credentials
      const tokenIds: bigint[] = [];
      for (let i = 0; i < 5; i++) {
        tokenIds.push(await mintCredential(fixture, issuer1, ClaimTypes.LICENSE_OPERATOR, subject));
      }

      // Revoke 3
      for (let i = 0; i < 3; i++) {
        await claimToken.connect(issuer1).revoke(tokenIds[i], ethers.keccak256(ethers.toUtf8Bytes(`REVOKE_${i}`)));
      }

      const stats = await issuerRegistry.getIssuerStats(issuer1.address);
      expect(stats.totalRevoked).to.equal(3n);
    });

    it("should maintain accounting consistency: totalIssued >= totalRevoked + totalActive", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { claimToken, issuerRegistry, issuer1, subject } = fixture;

      // Mint 10 credentials
      const tokenIds: bigint[] = [];
      for (let i = 0; i < 10; i++) {
        tokenIds.push(await mintCredential(fixture, issuer1, ClaimTypes.LICENSE_OPERATOR, subject));
      }

      // Revoke 3
      for (let i = 0; i < 3; i++) {
        await claimToken.connect(issuer1).revoke(tokenIds[i], ethers.keccak256(ethers.toUtf8Bytes(`R${i}`)));
      }

      // Suspend 2
      for (let i = 3; i < 5; i++) {
        await claimToken.connect(issuer1).suspend(tokenIds[i], ethers.keccak256(ethers.toUtf8Bytes(`S${i}`)));
      }

      const stats = await issuerRegistry.getIssuerStats(issuer1.address);

      // INV-09: totalIssued >= totalRevoked + totalActive
      // Note: suspended credentials are not "active" but also not "revoked"
      // totalActive = totalIssued - totalRevoked - totalSuspended - totalExpired
      expect(stats.totalIssued).to.be.gte(stats.totalRevoked + stats.totalActive);
    });

    it("should handle mixed operations correctly", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { claimToken, issuerRegistry, issuer1, subject } = fixture;

      const tokenIds: bigint[] = [];

      // Mint 6 credentials
      for (let i = 0; i < 6; i++) {
        tokenIds.push(await mintCredential(fixture, issuer1, ClaimTypes.LICENSE_OPERATOR, subject));
      }

      // Suspend then reinstate (should not affect accounting)
      await claimToken.connect(issuer1).suspend(tokenIds[0], ethers.keccak256(ethers.toUtf8Bytes("TEMP")));
      await claimToken.connect(issuer1).reinstate(tokenIds[0]);

      // Revoke 2
      await claimToken.connect(issuer1).revoke(tokenIds[1], ethers.keccak256(ethers.toUtf8Bytes("R1")));
      await claimToken.connect(issuer1).revoke(tokenIds[2], ethers.keccak256(ethers.toUtf8Bytes("R2")));

      const stats = await issuerRegistry.getIssuerStats(issuer1.address);

      // Verify consistency
      expect(stats.totalIssued).to.equal(6n);
      expect(stats.totalRevoked).to.equal(2n);
      // Active should be 4 (6 issued - 2 revoked)
      expect(stats.totalIssued).to.be.gte(stats.totalRevoked + stats.totalActive);
    });

    it("should track statistics across multiple issuers independently", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { issuerRegistry, issuer1, issuer2, subject } = fixture;

      // issuer1 mints 5
      for (let i = 0; i < 5; i++) {
        await mintCredential(fixture, issuer1, ClaimTypes.LICENSE_OPERATOR, subject);
      }

      // issuer2 mints 3
      for (let i = 0; i < 3; i++) {
        await mintCredential(fixture, issuer2, ClaimTypes.EDUCATION_DEGREE, subject);
      }

      const stats1 = await issuerRegistry.getIssuerStats(issuer1.address);
      const stats2 = await issuerRegistry.getIssuerStats(issuer2.address);

      expect(stats1.totalIssued).to.equal(5n);
      expect(stats2.totalIssued).to.equal(3n);

      // Each issuer's accounting is independent and consistent
      expect(stats1.totalIssued).to.be.gte(stats1.totalRevoked + stats1.totalActive);
      expect(stats2.totalIssued).to.be.gte(stats2.totalRevoked + stats2.totalActive);
    });

    it("should verify global credential count matches sum of issuer counts", async function () {
      const fixture = await loadFixture(deployLivenessTestFixture);
      const { claimToken, issuerRegistry, issuer1, issuer2, subject } = fixture;

      // Mint credentials from both issuers
      for (let i = 0; i < 4; i++) {
        await mintCredential(fixture, issuer1, ClaimTypes.LICENSE_OPERATOR, subject);
      }
      for (let i = 0; i < 3; i++) {
        await mintCredential(fixture, issuer2, ClaimTypes.EDUCATION_DEGREE, subject);
      }

      const stats1 = await issuerRegistry.getIssuerStats(issuer1.address);
      const stats2 = await issuerRegistry.getIssuerStats(issuer2.address);
      const totalCredentials = await claimToken.totalCredentials();

      // Global total should equal sum of issuer totals
      expect(totalCredentials).to.equal(stats1.totalIssued + stats2.totalIssued);
    });
  });
});
