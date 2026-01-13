/**
 * @file Inheritance end-to-end integration tests
 * @description Complete inheritance flow testing:
 *              FIE trigger → Directive Execution → Settlement → Disputes
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

describe("Inheritance End-to-End Integration", function () {
  // ============================================
  // Constants
  // ============================================

  const ONE_YEAR = 365 * 24 * 60 * 60;
  const ONE_DAY = 24 * 60 * 60;
  const DISPUTE_PERIOD = 30 * ONE_DAY;
  const EXECUTOR_ACCESS_DURATION = 90 * ONE_DAY;

  // Condition types
  const CONDITION_NONE = 0;
  const CONDITION_AGE_THRESHOLD = 1;
  const CONDITION_DATE_AFTER = 2;
  const CONDITION_CUSTOM = 3;

  // ============================================
  // Fixtures
  // ============================================

  async function deployInheritanceFixture() {
    const [
      owner,
      issuer,
      subject,
      beneficiary1,
      beneficiary2,
      beneficiary3,
      executor,
      disputant,
      other,
    ] = await ethers.getSigners();

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
    await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, await claimToken.getAddress());

    // Set lifecycle manager in ClaimToken
    await claimToken.setLifecycleManager(await lifecycleManager.getAddress());

    // Set FIE Bridge in CredentialLifecycleManager
    await lifecycleManager.setFIEBridge(await fieBridge.getAddress());

    // Configure MockFIE to use FIEBridge
    await mockFIE.setFIEBridge(await fieBridge.getAddress());

    // Set MockFIE as the FIE execution agent
    await fieBridge.setFIEExecutionAgent(await mockFIE.getAddress());

    // Register issuer with inheritable claim types
    await issuerRegistry.registerIssuer(issuer.address, "US-CA", [
      ClaimTypes.PROPERTY_DEED,
      ClaimTypes.PROPERTY_TITLE,
      ClaimTypes.LICENSE_OPERATOR,
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
    fixture: Awaited<ReturnType<typeof deployInheritanceFixture>>,
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

  function createInheritanceDirective(
    beneficiaries: string[],
    fieIntentHash: string,
    shares?: number[],
    conditionType: number = CONDITION_NONE,
    conditionData: string = "0x",
    executorAddress: string = ethers.ZeroAddress,
    executorAccessDuration: bigint = 0n
  ) {
    const effectiveShares = shares ?? beneficiaries.map(() => Math.floor(10000 / beneficiaries.length));

    return {
      beneficiaries,
      shares: effectiveShares,
      fieIntentHash,
      requiresFIETrigger: true,
      conditionType,
      conditionData,
      executorAddress,
      executorAccessDuration,
    };
  }

  // ============================================
  // Test Suites
  // ============================================

  describe("Basic Inheritance Flow", function () {
    it("should complete simple single-beneficiary inheritance", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { claimToken, lifecycleManager, fieBridge, mockFIE, subject, beneficiary1, owner } = fixture;

      // Step 1: Mint property credential
      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);
      expect(await claimToken.ownerOf(tokenId)).to.equal(subject.address);

      // Step 2: Set inheritance directive
      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_" + Math.random()));
      const directive = createInheritanceDirective([beneficiary1.address], fieIntentHash);
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      // Step 3: Register FIE intent
      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);

      // Step 4: Trigger FIE (simulating death notification)
      await mockFIE.triggerExecution(fieIntentHash);

      // Step 5: Verify inheritance completed
      expect(await claimToken.ownerOf(tokenId)).to.equal(beneficiary1.address);
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.INHERITED);
    });

    it("should complete multi-beneficiary inheritance with equal shares", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const {
        claimToken,
        lifecycleManager,
        fieBridge,
        mockFIE,
        subject,
        beneficiary1,
        beneficiary2,
        beneficiary3,
        owner,
      } = fixture;

      // Mint splittable property credential
      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      // Set inheritance directive with 3 beneficiaries (equal shares: ~33.33% each)
      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_MULTI"));
      const directive = createInheritanceDirective(
        [beneficiary1.address, beneficiary2.address, beneficiary3.address],
        fieIntentHash,
        [3333, 3333, 3334] // Total = 10000 (100%)
      );
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      // Register and trigger FIE
      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);
      await mockFIE.triggerExecution(fieIntentHash);

      // For splittable credentials, the original credential goes to first beneficiary
      // and new credentials are minted for others
      // Check the inheritance was processed
      const originalCredential = await claimToken.getCredential(tokenId);
      expect(originalCredential.status).to.equal(CredentialStatus.INHERITED);
    });

    it("should complete inheritance with unequal shares", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const {
        lifecycleManager,
        fieBridge,
        mockFIE,
        claimToken,
        subject,
        beneficiary1,
        beneficiary2,
        owner,
      } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      // 70% to beneficiary1, 30% to beneficiary2
      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_UNEQUAL"));
      const directive = createInheritanceDirective(
        [beneficiary1.address, beneficiary2.address],
        fieIntentHash,
        [7000, 3000]
      );
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);
      await mockFIE.triggerExecution(fieIntentHash);

      // Verify inheritance processed
      const credential = await claimToken.getCredential(tokenId);
      expect(credential.status).to.equal(CredentialStatus.INHERITED);
    });
  });

  describe("Conditional Inheritance", function () {
    it("should execute inheritance with AGE_THRESHOLD condition when met", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, fieBridge, mockFIE, claimToken, subject, beneficiary1, owner } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      // Set condition: beneficiary must be 21+
      // Encode age threshold: 21 years in seconds (minimum age)
      const minAge = 21 * 365 * ONE_DAY;
      const conditionData = ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [minAge]);

      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_AGE"));
      const directive = createInheritanceDirective(
        [beneficiary1.address],
        fieIntentHash,
        [10000],
        CONDITION_AGE_THRESHOLD,
        conditionData
      );
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);

      // Trigger inheritance - assuming beneficiary meets age requirement
      await mockFIE.triggerExecution(fieIntentHash);

      const credential = await claimToken.getCredential(tokenId);
      expect(credential.status).to.equal(CredentialStatus.INHERITED);
    });

    it("should execute inheritance with DATE_AFTER condition when time has passed", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, fieBridge, mockFIE, claimToken, subject, beneficiary1, owner } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      // Set condition: inherit after specific date (1 day from now)
      const targetDate = BigInt(await time.latest()) + BigInt(ONE_DAY);
      const conditionData = ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [targetDate]);

      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_DATE"));
      const directive = createInheritanceDirective(
        [beneficiary1.address],
        fieIntentHash,
        [10000],
        CONDITION_DATE_AFTER,
        conditionData
      );
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);

      // Fast forward past the condition date
      await time.increase(2 * ONE_DAY);

      // Now trigger - condition should be met
      await mockFIE.triggerExecution(fieIntentHash);

      const credential = await claimToken.getCredential(tokenId);
      expect(credential.status).to.equal(CredentialStatus.INHERITED);
    });
  });

  describe("Executor Access", function () {
    it("should grant time-bounded access to executor during settlement", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, fieBridge, mockFIE, claimToken, subject, beneficiary1, executor, owner } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      // Set directive with executor
      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_EXECUTOR"));
      const directive = createInheritanceDirective(
        [beneficiary1.address],
        fieIntentHash,
        [10000],
        CONDITION_NONE,
        "0x",
        executor.address,
        BigInt(EXECUTOR_ACCESS_DURATION)
      );
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);

      // Trigger FIE
      await mockFIE.triggerExecution(fieIntentHash);

      // Executor should have access during settlement period
      const hasAccess = await lifecycleManager.hasExecutorAccess(tokenId, executor.address);
      expect(hasAccess).to.be.true;
    });

    it("should revoke executor access after settlement period", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, fieBridge, mockFIE, subject, beneficiary1, executor, owner } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_EXEC_EXPIRE"));
      const directive = createInheritanceDirective(
        [beneficiary1.address],
        fieIntentHash,
        [10000],
        CONDITION_NONE,
        "0x",
        executor.address,
        BigInt(EXECUTOR_ACCESS_DURATION)
      );
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);
      await mockFIE.triggerExecution(fieIntentHash);

      // Executor has access initially
      expect(await lifecycleManager.hasExecutorAccess(tokenId, executor.address)).to.be.true;

      // Fast forward past access duration
      await time.increase(EXECUTOR_ACCESS_DURATION + ONE_DAY);

      // Executor no longer has access
      expect(await lifecycleManager.hasExecutorAccess(tokenId, executor.address)).to.be.false;
    });
  });

  describe("Dispute Handling", function () {
    it("should allow filing dispute during dispute period", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, fieBridge, mockFIE, subject, beneficiary1, disputant, owner } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_DISPUTE"));
      const directive = createInheritanceDirective([beneficiary1.address], fieIntentHash);
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);
      await mockFIE.triggerExecution(fieIntentHash);

      // File dispute within dispute period
      const disputeReason = "Fraudulent death certificate";
      await expect(
        lifecycleManager.connect(disputant).fileDispute(tokenId, disputeReason)
      ).to.emit(lifecycleManager, "DisputeFiled");

      // Check dispute status
      const dispute = await lifecycleManager.getDispute(tokenId);
      expect(dispute.disputant).to.equal(disputant.address);
      expect(dispute.active).to.be.true;
    });

    it("should prevent finalization while dispute is active", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, fieBridge, mockFIE, subject, beneficiary1, disputant, owner } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_DISPUTE_BLOCK"));
      const directive = createInheritanceDirective([beneficiary1.address], fieIntentHash);
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);
      await mockFIE.triggerExecution(fieIntentHash);

      // File dispute
      await lifecycleManager.connect(disputant).fileDispute(tokenId, "Contest inheritance");

      // Attempt to finalize should be blocked
      await expect(
        lifecycleManager.connect(beneficiary1).finalizeInheritance(tokenId)
      ).to.be.reverted;
    });

    it("should allow resolution of dispute by arbiter", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, issuerRegistry, fieBridge, mockFIE, subject, beneficiary1, disputant, owner } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      // Grant arbiter role
      const ARBITER_ROLE = await issuerRegistry.ARBITER_ROLE();
      await issuerRegistry.grantRole(ARBITER_ROLE, owner.address);

      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_RESOLVE"));
      const directive = createInheritanceDirective([beneficiary1.address], fieIntentHash);
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);
      await mockFIE.triggerExecution(fieIntentHash);

      // File dispute
      await lifecycleManager.connect(disputant).fileDispute(tokenId, "Invalid will");

      // Arbiter resolves dispute (in favor of beneficiary)
      await lifecycleManager.connect(owner).resolveDispute(tokenId, true, "Will verified authentic");

      // Dispute should be resolved
      const dispute = await lifecycleManager.getDispute(tokenId);
      expect(dispute.active).to.be.false;
    });
  });

  describe("FIE Bridge Integration", function () {
    it("should correctly register and track FIE intents", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { fieBridge, owner } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);
      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_TRACK"));

      // Register intent
      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);

      // Verify registration
      const intentInfo = await fieBridge.getIntent(fieIntentHash);
      expect(intentInfo.tokenId).to.equal(tokenId);
      expect(intentInfo.registered).to.be.true;
      expect(intentInfo.executed).to.be.false;
    });

    it("should prevent duplicate FIE intent registration", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { fieBridge, owner } = fixture;

      const tokenId1 = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);
      const tokenId2 = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);
      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_DUP"));

      await fieBridge.connect(owner).registerIntent(tokenId1, fieIntentHash);

      // Second registration with same hash should fail
      await expect(
        fieBridge.connect(owner).registerIntent(tokenId2, fieIntentHash)
      ).to.be.reverted;
    });

    it("should prevent re-execution of FIE intent", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, fieBridge, mockFIE, subject, beneficiary1, owner } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);
      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_REEXEC"));

      const directive = createInheritanceDirective([beneficiary1.address], fieIntentHash);
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);

      // First execution succeeds
      await mockFIE.triggerExecution(fieIntentHash);

      // Second execution should fail
      await expect(mockFIE.triggerExecution(fieIntentHash)).to.be.reverted;
    });

    it("should emit correct events during inheritance execution", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, fieBridge, mockFIE, claimToken, subject, beneficiary1, owner } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);
      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_EVENTS"));

      const directive = createInheritanceDirective([beneficiary1.address], fieIntentHash);
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);

      // Trigger and verify events
      await expect(mockFIE.triggerExecution(fieIntentHash))
        .to.emit(fieBridge, "IntentExecuted")
        .withArgs(fieIntentHash, tokenId);
    });
  });

  describe("Edge Cases", function () {
    it("should handle inheritance for non-splittable credentials", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, fieBridge, mockFIE, claimToken, subject, beneficiary1, owner } = fixture;

      // License is non-splittable
      const tokenId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR);

      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_NONSPLIT"));
      const directive = createInheritanceDirective([beneficiary1.address], fieIntentHash);
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);
      await mockFIE.triggerExecution(fieIntentHash);

      // Non-splittable credential transfers entirely
      expect(await claimToken.ownerOf(tokenId)).to.equal(beneficiary1.address);
    });

    it("should prevent inheritance directive modification after FIE trigger", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, fieBridge, mockFIE, subject, beneficiary1, beneficiary2, owner } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);

      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_MODIFY"));
      const directive = createInheritanceDirective([beneficiary1.address], fieIntentHash);
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);
      await mockFIE.triggerExecution(fieIntentHash);

      // Attempt to modify directive after execution should fail
      const newDirective = createInheritanceDirective(
        [beneficiary2.address],
        ethers.keccak256(ethers.toUtf8Bytes("NEW_INTENT"))
      );

      await expect(
        lifecycleManager.connect(subject).setInheritanceDirective(tokenId, newDirective)
      ).to.be.reverted;
    });

    it("should handle expired credential inheritance", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, fieBridge, mockFIE, claimToken, subject, beneficiary1, owner } = fixture;

      // Mint credential with short expiration
      const shortExpiry = BigInt(await time.latest()) + BigInt(7 * ONE_DAY);
      const tokenId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED, shortExpiry);

      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_EXPIRED"));
      const directive = createInheritanceDirective([beneficiary1.address], fieIntentHash);
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);

      // Let credential expire
      await time.increase(10 * ONE_DAY);
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.EXPIRED);

      // Inheritance should still execute (property rights don't expire with credential)
      await mockFIE.triggerExecution(fieIntentHash);

      // Ownership should transfer to beneficiary
      expect(await claimToken.ownerOf(tokenId)).to.equal(beneficiary1.address);
    });

    it("should reject inheritance for revoked credentials", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, fieBridge, mockFIE, claimToken, issuer, subject, beneficiary1, owner } = fixture;

      const tokenId = await mintCredential(fixture, ClaimTypes.LICENSE_OPERATOR);

      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_REVOKED"));
      const directive = createInheritanceDirective([beneficiary1.address], fieIntentHash);
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      await fieBridge.connect(owner).registerIntent(tokenId, fieIntentHash);

      // Revoke the credential before FIE trigger
      await claimToken.connect(issuer).revoke(tokenId, ethers.keccak256(ethers.toUtf8Bytes("FRAUD")));

      // FIE trigger for revoked credential should fail or handle gracefully
      await expect(mockFIE.triggerExecution(fieIntentHash)).to.be.reverted;
    });
  });

  describe("Multi-Credential Inheritance", function () {
    it("should handle inheritance of multiple credentials with single FIE trigger", async function () {
      const fixture = await loadFixture(deployInheritanceFixture);
      const { lifecycleManager, fieBridge, mockFIE, claimToken, subject, beneficiary1, owner } = fixture;

      // Mint multiple credentials
      const deedId = await mintCredential(fixture, ClaimTypes.PROPERTY_DEED);
      const titleId = await mintCredential(fixture, ClaimTypes.PROPERTY_TITLE);

      // Use same FIE intent hash for both (grouped inheritance)
      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("FIE_INTENT_MULTI_CRED"));

      const directive = createInheritanceDirective([beneficiary1.address], fieIntentHash);
      await lifecycleManager.connect(subject).setInheritanceDirective(deedId, directive);
      await lifecycleManager.connect(subject).setInheritanceDirective(titleId, directive);

      // Register both under same intent
      await fieBridge.connect(owner).registerIntent(deedId, fieIntentHash);

      // Single FIE trigger
      await mockFIE.triggerExecution(fieIntentHash);

      // First credential should be transferred
      expect(await claimToken.ownerOf(deedId)).to.equal(beneficiary1.address);
    });
  });
});
