/**
 * @file Inheritance scenarios integration tests
 * @description Comprehensive tests for partial inheritance, conditional inheritance,
 *              time-bounded executor access, and dispute handling
 * @dev Tests Step 18 requirements from IMPLEMENTATION_GUIDE.md
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
} from "../typechain-types";
import { ClaimTypes, CredentialStatus, Constants } from "../types";

describe("Inheritance Scenarios", function () {
  // ============================================
  // Fixtures
  // ============================================

  async function deployContractsFixture() {
    const [owner, issuer, subject, beneficiary1, beneficiary2, beneficiary3, executor, disputant, other] =
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
    const LifecycleManagerFactory = await ethers.getContractFactory(
      "CredentialLifecycleManager"
    );
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
    await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, await claimToken.getAddress());

    // Set lifecycle manager in ClaimToken
    await claimToken.setLifecycleManager(await lifecycleManager.getAddress());

    // Set FIE Bridge in CredentialLifecycleManager
    await lifecycleManager.setFIEBridge(await fieBridge.getAddress());

    // Configure MockFIE to use FIEBridge
    await mockFIE.setFIEBridge(await fieBridge.getAddress());

    // Set MockFIE as the FIE execution agent
    await fieBridge.setFIEExecutionAgent(await mockFIE.getAddress());

    // Register issuer with splittable claim types
    await issuerRegistry.registerIssuer(issuer.address, "US-CA", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.PROPERTY_DEED,
      ClaimTypes.PROPERTY_TITLE,
      ClaimTypes.EDUCATION_DEGREE,
    ]);

    return {
      claimToken,
      issuerRegistry,
      lifecycleManager,
      fieBridge,
      mockFIE,
      owner,
      issuer,
      subject,
      beneficiary1,
      beneficiary2,
      beneficiary3,
      executor,
      disputant,
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
    const oneYearFromNow = BigInt(now) + BigInt(365 * 24 * 60 * 60);

    return {
      claimType,
      subject,
      encryptedPayload: "0x" + "ab".repeat(100),
      payloadHash: ethers.keccak256(ethers.toUtf8Bytes("test-payload-" + Math.random())),
      commitments: [
        ethers.keccak256(ethers.toUtf8Bytes("commitment-0")),
        ethers.keccak256(ethers.toUtf8Bytes("commitment-1")),
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
    fixture: Awaited<ReturnType<typeof deployContractsFixture>>,
    claimType: string = ClaimTypes.PROPERTY_DEED,
    expiresAt?: bigint
  ): Promise<bigint> {
    const { claimToken, issuer, subject } = fixture;
    const request = await createMintRequest(claimType, subject.address, expiresAt);
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
    return {
      credentialId: 0n,
      beneficiaries,
      shares,
      requiresFIETrigger,
      fieIntentHash,
      conditions: "0x",
    };
  }

  // ============================================
  // Test Suite: Credential Splitting (50/50)
  // ============================================

  describe("Credential Splitting - 50/50 Split", function () {
    it("should split property deed 50/50 between two beneficiaries", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, claimToken, subject, beneficiary1, beneficiary2 } = fixture;

      // Mint a splittable credential (property deed)
      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      // Verify original ownership
      expect(await claimToken.ownerOf(tokenId)).to.equal(subject.address);

      // Split credential via admin
      const tx = await lifecycleManager.splitCredential(
        tokenId,
        [beneficiary1.address, beneficiary2.address],
        [50, 50]
      );

      const receipt = await tx.wait();

      // Check for CredentialSplit event
      const splitEvent = receipt?.logs.find((log) => {
        try {
          const parsed = lifecycleManager.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "CredentialSplit";
        } catch {
          return false;
        }
      });

      expect(splitEvent).to.not.be.undefined;

      // Parse event to get new token IDs
      const parsed = lifecycleManager.interface.parseLog({
        topics: splitEvent!.topics as string[],
        data: splitEvent!.data,
      });

      const newTokenIds = parsed?.args.newTokenIds;
      expect(newTokenIds.length).to.equal(2);

      // Verify new ownership
      expect(await claimToken.ownerOf(newTokenIds[0])).to.equal(beneficiary1.address);
      expect(await claimToken.ownerOf(newTokenIds[1])).to.equal(beneficiary2.address);

      // Verify split metadata
      const metadata1 = await claimToken.getSplitMetadata(newTokenIds[0]);
      expect(metadata1.sharePercentage).to.equal(50);
      expect(metadata1.splitIndex).to.equal(0);
      expect(metadata1.totalSplits).to.equal(2);

      const metadata2 = await claimToken.getSplitMetadata(newTokenIds[1]);
      expect(metadata2.sharePercentage).to.equal(50);
      expect(metadata2.splitIndex).to.equal(1);
      expect(metadata2.totalSplits).to.equal(2);

      // Verify original is burned (should revert)
      await expect(claimToken.ownerOf(tokenId)).to.be.reverted;
    });
  });

  // ============================================
  // Test Suite: Three-Way Split (40/35/25)
  // ============================================

  describe("Credential Splitting - Three Beneficiaries (40/35/25)", function () {
    it("should split credential among three beneficiaries with unequal shares", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, claimToken, beneficiary1, beneficiary2, beneficiary3 } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      const tx = await lifecycleManager.splitCredential(
        tokenId,
        [beneficiary1.address, beneficiary2.address, beneficiary3.address],
        [40, 35, 25]
      );

      const receipt = await tx.wait();

      const splitEvent = receipt?.logs.find((log) => {
        try {
          const parsed = lifecycleManager.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "CredentialSplit";
        } catch {
          return false;
        }
      });

      const parsed = lifecycleManager.interface.parseLog({
        topics: splitEvent!.topics as string[],
        data: splitEvent!.data,
      });

      const newTokenIds = parsed?.args.newTokenIds;
      expect(newTokenIds.length).to.equal(3);

      // Verify share percentages
      expect((await claimToken.getSplitMetadata(newTokenIds[0])).sharePercentage).to.equal(40);
      expect((await claimToken.getSplitMetadata(newTokenIds[1])).sharePercentage).to.equal(35);
      expect((await claimToken.getSplitMetadata(newTokenIds[2])).sharePercentage).to.equal(25);
    });

    it("should revert if shares don't sum to 100", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, beneficiary1, beneficiary2 } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      await expect(
        lifecycleManager.splitCredential(
          tokenId,
          [beneficiary1.address, beneficiary2.address],
          [40, 40] // Sums to 80, not 100
        )
      ).to.be.revertedWithCustomError(lifecycleManager, "InvalidShares");
    });

    it("should revert splitting non-splittable credential type", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, beneficiary1, beneficiary2 } = fixture;

      // License is not splittable
      const tokenId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR);

      await expect(
        lifecycleManager.splitCredential(
          tokenId,
          [beneficiary1.address, beneficiary2.address],
          [50, 50]
        )
      ).to.be.revertedWithCustomError(lifecycleManager, "NotSplittable");
    });
  });

  // ============================================
  // Test Suite: Conditional Inheritance
  // ============================================

  describe("Conditional Inheritance", function () {
    it("should set DATE_AFTER condition for inheritance", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, subject } = fixture;

      const tokenId = await mintCredential(fixture);

      // Set a date condition (must be after a specific timestamp)
      const futureDate = BigInt(await time.latest()) + BigInt(365 * 24 * 60 * 60); // 1 year from now

      const dateCondition = {
        conditionType: ethers.keccak256(ethers.toUtf8Bytes("DATE_AFTER")),
        params: ethers.AbiCoder.defaultAbiCoder().encode(["uint64"], [futureDate]),
        oracleAddress: ethers.ZeroAddress,
      };

      await lifecycleManager.connect(subject).setInheritanceConditions(tokenId, [dateCondition]);

      const conditions = await lifecycleManager.getInheritanceConditions(tokenId);
      expect(conditions.length).to.equal(1);
      expect(conditions[0].conditionType).to.equal(dateCondition.conditionType);
    });

    it("should evaluate DATE_AFTER condition correctly", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, subject, beneficiary1 } = fixture;

      const tokenId = await mintCredential(fixture);

      // Set a condition that is already met (in the past)
      const pastDate = BigInt(await time.latest()) - BigInt(100);

      const dateCondition = {
        conditionType: ethers.keccak256(ethers.toUtf8Bytes("DATE_AFTER")),
        params: ethers.AbiCoder.defaultAbiCoder().encode(["uint64"], [pastDate]),
        oracleAddress: ethers.ZeroAddress,
      };

      await lifecycleManager.connect(subject).setInheritanceConditions(tokenId, [dateCondition]);

      // Should evaluate to true (date is in the past)
      expect(await lifecycleManager.evaluateConditions(tokenId, beneficiary1.address)).to.be.true;
    });

    it("should evaluate DATE_AFTER condition as false when date not reached", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, subject, beneficiary1 } = fixture;

      const tokenId = await mintCredential(fixture);

      // Set a condition in the future
      const futureDate = BigInt(await time.latest()) + BigInt(365 * 24 * 60 * 60);

      const dateCondition = {
        conditionType: ethers.keccak256(ethers.toUtf8Bytes("DATE_AFTER")),
        params: ethers.AbiCoder.defaultAbiCoder().encode(["uint64"], [futureDate]),
        oracleAddress: ethers.ZeroAddress,
      };

      await lifecycleManager.connect(subject).setInheritanceConditions(tokenId, [dateCondition]);

      // Should evaluate to false (date not reached)
      expect(await lifecycleManager.evaluateConditions(tokenId, beneficiary1.address)).to.be.false;
    });

    it("should reject invalid condition type", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, subject } = fixture;

      const tokenId = await mintCredential(fixture);

      const invalidCondition = {
        conditionType: ethers.keccak256(ethers.toUtf8Bytes("INVALID_TYPE")),
        params: "0x00",
        oracleAddress: ethers.ZeroAddress,
      };

      await expect(
        lifecycleManager.connect(subject).setInheritanceConditions(tokenId, [invalidCondition])
      ).to.be.revertedWithCustomError(lifecycleManager, "InvalidConditionParams");
    });
  });

  // ============================================
  // Test Suite: Time-Bounded Executor Access
  // ============================================

  describe("Time-Bounded Executor Access", function () {
    it("should grant executor access with default duration", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, executor } = fixture;

      const tokenId = await mintCredential(fixture);

      // Grant executor access (VIEW + TRANSFER permissions = 3)
      const permissions = 3; // PERMISSION_VIEW | PERMISSION_TRANSFER
      await lifecycleManager.grantExecutorAccess(tokenId, executor.address, 0, permissions);

      const access = await lifecycleManager.getExecutorAccess(tokenId);
      expect(access.executor).to.equal(executor.address);
      expect(access.permissions).to.equal(permissions);

      // Default duration is 90 days
      const expectedExpiry = BigInt(await time.latest()) + BigInt(90 * 24 * 60 * 60);
      expect(access.expiresAt).to.be.closeTo(expectedExpiry, 10);
    });

    it("should grant executor access with custom duration", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, executor } = fixture;

      const tokenId = await mintCredential(fixture);

      const customDuration = 30 * 24 * 60 * 60; // 30 days
      await lifecycleManager.grantExecutorAccess(tokenId, executor.address, customDuration, 7);

      const access = await lifecycleManager.getExecutorAccess(tokenId);
      const expectedExpiry = BigInt(await time.latest()) + BigInt(customDuration);
      expect(access.expiresAt).to.be.closeTo(expectedExpiry, 10);
    });

    it("should verify executor has valid access", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, executor } = fixture;

      const tokenId = await mintCredential(fixture);

      await lifecycleManager.grantExecutorAccess(tokenId, executor.address, 0, 7); // Full permissions

      // Check individual permissions
      expect(await lifecycleManager.hasExecutorAccess(tokenId, executor.address, 1)).to.be.true; // VIEW
      expect(await lifecycleManager.hasExecutorAccess(tokenId, executor.address, 2)).to.be.true; // TRANSFER
      expect(await lifecycleManager.hasExecutorAccess(tokenId, executor.address, 4)).to.be.true; // MANAGE_INHERITANCE
    });

    it("should deny access after expiration", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, executor } = fixture;

      const tokenId = await mintCredential(fixture);

      // Grant short duration access
      const shortDuration = 100; // 100 seconds
      await lifecycleManager.grantExecutorAccess(tokenId, executor.address, shortDuration, 7);

      expect(await lifecycleManager.hasExecutorAccess(tokenId, executor.address, 1)).to.be.true;

      // Fast forward past expiration
      await time.increase(shortDuration + 1);

      expect(await lifecycleManager.hasExecutorAccess(tokenId, executor.address, 1)).to.be.false;
    });

    it("should reject duration exceeding maximum", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, executor } = fixture;

      const tokenId = await mintCredential(fixture);

      // Try to grant access for more than 365 days
      const excessiveDuration = 400 * 24 * 60 * 60; // 400 days

      await expect(
        lifecycleManager.grantExecutorAccess(tokenId, executor.address, excessiveDuration, 7)
      ).to.be.revertedWithCustomError(lifecycleManager, "ExecutorPeriodExceedsMax");
    });

    it("should revoke executor access", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, executor, owner } = fixture;

      const tokenId = await mintCredential(fixture);

      await lifecycleManager.grantExecutorAccess(tokenId, executor.address, 0, 7);
      expect(await lifecycleManager.hasExecutorAccess(tokenId, executor.address, 1)).to.be.true;

      await lifecycleManager.connect(owner).revokeExecutorAccess(tokenId);
      expect(await lifecycleManager.hasExecutorAccess(tokenId, executor.address, 1)).to.be.false;
    });
  });

  // ============================================
  // Test Suite: Dispute Handling
  // ============================================

  describe("Dispute Handling", function () {
    it("should file a dispute against inheritance", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, disputant } = fixture;

      const tokenId = await mintCredential(fixture);

      const reason = ethers.toUtf8Bytes("I am the rightful heir");

      const tx = await lifecycleManager.connect(disputant).fileDispute(tokenId, reason);
      const receipt = await tx.wait();

      const disputeEvent = receipt?.logs.find((log) => {
        try {
          const parsed = lifecycleManager.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "DisputeFiled";
        } catch {
          return false;
        }
      });

      expect(disputeEvent).to.not.be.undefined;

      const parsed = lifecycleManager.interface.parseLog({
        topics: disputeEvent!.topics as string[],
        data: disputeEvent!.data,
      });

      const disputeId = parsed?.args.disputeId;

      // Verify dispute was created
      const dispute = await lifecycleManager.getDispute(disputeId);
      expect(dispute.disputant).to.equal(disputant.address);
      expect(dispute.tokenId).to.equal(tokenId);
      expect(dispute.resolution).to.equal(0); // DISPUTE_PENDING
    });

    it("should freeze inheritance during active dispute", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, disputant, beneficiary1, beneficiary2 } = fixture;

      const tokenId = await mintCredential(fixture);

      // File dispute
      await lifecycleManager.connect(disputant).fileDispute(tokenId, "0x");

      // Try to split - should be frozen
      await expect(
        lifecycleManager.splitCredential(
          tokenId,
          [beneficiary1.address, beneficiary2.address],
          [50, 50]
        )
      ).to.be.revertedWithCustomError(lifecycleManager, "InheritanceFrozen");
    });

    it("should resolve dispute as upheld", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, owner, disputant } = fixture;

      const tokenId = await mintCredential(fixture);

      const tx = await lifecycleManager.connect(disputant).fileDispute(tokenId, "0x");
      const receipt = await tx.wait();

      const disputeEvent = receipt?.logs.find((log) => {
        try {
          const parsed = lifecycleManager.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "DisputeFiled";
        } catch {
          return false;
        }
      });

      const parsed = lifecycleManager.interface.parseLog({
        topics: disputeEvent!.topics as string[],
        data: disputeEvent!.data,
      });

      const disputeId = parsed?.args.disputeId;

      // Resolve as upheld (1)
      await lifecycleManager.connect(owner).resolveDispute(disputeId, 1);

      const dispute = await lifecycleManager.getDispute(disputeId);
      expect(dispute.resolution).to.equal(1); // DISPUTE_UPHELD
      expect(dispute.resolvedAt).to.be.gt(0);
    });

    it("should resolve dispute as rejected and allow inheritance", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, owner, disputant, beneficiary1, beneficiary2 } = fixture;

      const tokenId = await mintCredential(fixture);

      // File dispute
      const tx = await lifecycleManager.connect(disputant).fileDispute(tokenId, "0x");
      const receipt = await tx.wait();

      const disputeEvent = receipt?.logs.find((log) => {
        try {
          const parsed = lifecycleManager.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "DisputeFiled";
        } catch {
          return false;
        }
      });

      const parsed = lifecycleManager.interface.parseLog({
        topics: disputeEvent!.topics as string[],
        data: disputeEvent!.data,
      });

      const disputeId = parsed?.args.disputeId;

      // Resolve as rejected (2)
      await lifecycleManager.connect(owner).resolveDispute(disputeId, 2);

      // Now splitting should work
      await expect(
        lifecycleManager.splitCredential(
          tokenId,
          [beneficiary1.address, beneficiary2.address],
          [50, 50]
        )
      ).to.not.be.reverted;
    });

    it("should prevent duplicate dispute filing", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, disputant, other } = fixture;

      const tokenId = await mintCredential(fixture);

      await lifecycleManager.connect(disputant).fileDispute(tokenId, "0x");

      // Another party tries to file dispute
      await expect(
        lifecycleManager.connect(other).fileDispute(tokenId, "0x")
      ).to.be.revertedWithCustomError(lifecycleManager, "DisputeAlreadyFiled");
    });

    it("should check active dispute status", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, disputant } = fixture;

      const tokenId = await mintCredential(fixture);

      // Initially no dispute
      let [hasDispute, disputeId] = await lifecycleManager.hasActiveDispute(tokenId);
      expect(hasDispute).to.be.false;
      expect(disputeId).to.equal(0);

      // File dispute
      await lifecycleManager.connect(disputant).fileDispute(tokenId, "0x");

      [hasDispute, disputeId] = await lifecycleManager.hasActiveDispute(tokenId);
      expect(hasDispute).to.be.true;
      expect(disputeId).to.be.gt(0);
    });

    it("should prevent resolving non-existent dispute", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, owner } = fixture;

      await expect(
        lifecycleManager.connect(owner).resolveDispute(9999, 1)
      ).to.be.revertedWithCustomError(lifecycleManager, "DisputeNotFound");
    });

    it("should prevent double resolution of dispute", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, owner, disputant } = fixture;

      const tokenId = await mintCredential(fixture);

      const tx = await lifecycleManager.connect(disputant).fileDispute(tokenId, "0x");
      const receipt = await tx.wait();

      const disputeEvent = receipt?.logs.find((log) => {
        try {
          const parsed = lifecycleManager.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "DisputeFiled";
        } catch {
          return false;
        }
      });

      const parsed = lifecycleManager.interface.parseLog({
        topics: disputeEvent!.topics as string[],
        data: disputeEvent!.data,
      });

      const disputeId = parsed?.args.disputeId;

      // Resolve once
      await lifecycleManager.connect(owner).resolveDispute(disputeId, 1);

      // Try to resolve again
      await expect(
        lifecycleManager.connect(owner).resolveDispute(disputeId, 2)
      ).to.be.revertedWithCustomError(lifecycleManager, "DisputeAlreadyResolved");
    });
  });

  // ============================================
  // Test Suite: Split Credential Properties
  // ============================================

  describe("Split Credential Properties", function () {
    it("should mark split credentials as inherited status", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, claimToken, beneficiary1, beneficiary2 } = fixture;

      const tokenId = await mintCredential(fixture);

      const tx = await lifecycleManager.splitCredential(
        tokenId,
        [beneficiary1.address, beneficiary2.address],
        [50, 50]
      );

      const receipt = await tx.wait();
      const splitEvent = receipt?.logs.find((log) => {
        try {
          const parsed = lifecycleManager.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "CredentialSplit";
        } catch {
          return false;
        }
      });

      const parsed = lifecycleManager.interface.parseLog({
        topics: splitEvent!.topics as string[],
        data: splitEvent!.data,
      });

      const newTokenIds = parsed?.args.newTokenIds;

      // Check status is INHERITED (5)
      const status1 = await claimToken.getStatus(newTokenIds[0]);
      const status2 = await claimToken.getStatus(newTokenIds[1]);

      expect(status1).to.equal(5); // INHERITED
      expect(status2).to.equal(5); // INHERITED
    });

    it("should track original token ID in split metadata", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, claimToken, beneficiary1, beneficiary2 } = fixture;

      const tokenId = await mintCredential(fixture);

      const tx = await lifecycleManager.splitCredential(
        tokenId,
        [beneficiary1.address, beneficiary2.address],
        [50, 50]
      );

      const receipt = await tx.wait();
      const splitEvent = receipt?.logs.find((log) => {
        try {
          const parsed = lifecycleManager.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "CredentialSplit";
        } catch {
          return false;
        }
      });

      const parsed = lifecycleManager.interface.parseLog({
        topics: splitEvent!.topics as string[],
        data: splitEvent!.data,
      });

      const newTokenIds = parsed?.args.newTokenIds;

      // Both should reference original
      const metadata1 = await claimToken.getSplitMetadata(newTokenIds[0]);
      const metadata2 = await claimToken.getSplitMetadata(newTokenIds[1]);

      expect(metadata1.originalTokenId).to.equal(tokenId);
      expect(metadata2.originalTokenId).to.equal(tokenId);
    });

    it("should identify split credentials correctly", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, claimToken, beneficiary1, beneficiary2 } = fixture;

      const tokenId1 = await mintCredential(fixture); // Will be split
      const tokenId2 = await mintCredential(fixture); // Will remain whole

      // Split first credential
      const tx = await lifecycleManager.splitCredential(
        tokenId1,
        [beneficiary1.address, beneficiary2.address],
        [50, 50]
      );

      const receipt = await tx.wait();
      const splitEvent = receipt?.logs.find((log) => {
        try {
          const parsed = lifecycleManager.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "CredentialSplit";
        } catch {
          return false;
        }
      });

      const parsed = lifecycleManager.interface.parseLog({
        topics: splitEvent!.topics as string[],
        data: splitEvent!.data,
      });

      const newTokenIds = parsed?.args.newTokenIds;

      // Split credentials should be identified as split
      expect(await claimToken.isSplitCredential(newTokenIds[0])).to.be.true;
      expect(await claimToken.isSplitCredential(newTokenIds[1])).to.be.true;

      // Whole credential should not be identified as split
      expect(await claimToken.isSplitCredential(tokenId2)).to.be.false;
    });

    it("should prevent re-splitting an already split credential", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, beneficiary1, beneficiary2, beneficiary3 } = fixture;

      const tokenId = await mintCredential(fixture);

      // First split
      const tx = await lifecycleManager.splitCredential(
        tokenId,
        [beneficiary1.address, beneficiary2.address],
        [50, 50]
      );

      const receipt = await tx.wait();
      const splitEvent = receipt?.logs.find((log) => {
        try {
          const parsed = lifecycleManager.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "CredentialSplit";
        } catch {
          return false;
        }
      });

      const parsed = lifecycleManager.interface.parseLog({
        topics: splitEvent!.topics as string[],
        data: splitEvent!.data,
      });

      const newTokenIds = parsed?.args.newTokenIds;

      // Try to split a split credential
      await expect(
        lifecycleManager.splitCredential(
          newTokenIds[0],
          [beneficiary1.address, beneficiary3.address],
          [50, 50]
        )
      ).to.be.revertedWithCustomError(lifecycleManager, "CannotSplitCredential");
    });
  });
});
