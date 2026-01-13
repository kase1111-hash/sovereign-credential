/**
 * @file FIEBridge integration tests
 * @description Comprehensive tests for the FIEBridge contract
 * @dev Tests Step 17 requirements from IMPLEMENTATION_GUIDE.md
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

describe("FIEBridge", function () {
  // ============================================
  // Fixtures
  // ============================================

  async function deployContractsFixture() {
    const [owner, issuer, subject, beneficiary1, beneficiary2, fieAgent, other] =
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

    // Register issuer with claim types
    await issuerRegistry.registerIssuer(issuer.address, "US-CA", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.PROPERTY_DEED,
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
      fieAgent,
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
    claimType: string = ClaimTypes.LICENSE_OPERATOR,
    expiresAt?: bigint
  ): Promise<bigint> {
    const { claimToken, issuer, subject } = fixture;
    const request = await createMintRequest(claimType, subject.address, expiresAt);
    const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

    const tx = await claimToken.connect(issuer).mint(request, signature);
    const receipt = await tx.wait();

    // Get token ID from event
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
      credentialId: 0n, // Will be set by contract
      beneficiaries,
      shares,
      requiresFIETrigger,
      fieIntentHash,
      conditions: "0x",
    };
  }

  // ============================================
  // Test Suite: Deployment & Initialization
  // ============================================

  describe("Deployment", function () {
    it("should deploy with correct lifecycle manager", async function () {
      const { fieBridge, lifecycleManager } = await loadFixture(deployContractsFixture);
      expect(await fieBridge.getLifecycleManager()).to.equal(
        await lifecycleManager.getAddress()
      );
    });

    it("should set owner as admin", async function () {
      const { fieBridge, owner } = await loadFixture(deployContractsFixture);
      const adminRole = await fieBridge.DEFAULT_ADMIN_ROLE();
      expect(await fieBridge.hasRole(adminRole, owner.address)).to.be.true;
    });

    it("should not be paused initially", async function () {
      const { fieBridge } = await loadFixture(deployContractsFixture);
      expect(await fieBridge.isPaused()).to.be.false;
    });

    it("should revert initialization with zero address", async function () {
      const FIEBridgeFactory = await ethers.getContractFactory("FIEBridge");
      await expect(
        upgrades.deployProxy(FIEBridgeFactory, [ethers.ZeroAddress], {
          initializer: "initialize",
        })
      ).to.be.revertedWithCustomError(FIEBridgeFactory, "ZeroAddress");
    });
  });

  // ============================================
  // Test Suite: FIE Agent Management
  // ============================================

  describe("FIE Agent Management", function () {
    it("should set FIE execution agent successfully", async function () {
      const { fieBridge, fieAgent, owner } = await loadFixture(deployContractsFixture);

      await expect(fieBridge.connect(owner).setFIEExecutionAgent(fieAgent.address))
        .to.emit(fieBridge, "FIEAgentUpdated")
        .withArgs(fieAgent.address);

      expect(await fieBridge.getFIEExecutionAgent()).to.equal(fieAgent.address);
    });

    it("should revert when non-admin sets FIE agent", async function () {
      const { fieBridge, other, fieAgent } = await loadFixture(deployContractsFixture);

      await expect(
        fieBridge.connect(other).setFIEExecutionAgent(fieAgent.address)
      ).to.be.reverted;
    });

    it("should revert when setting zero address as FIE agent", async function () {
      const { fieBridge, owner } = await loadFixture(deployContractsFixture);

      await expect(
        fieBridge.connect(owner).setFIEExecutionAgent(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(fieBridge, "ZeroAddress");
    });

    it("should allow updating FIE agent", async function () {
      const { fieBridge, fieAgent, other, owner } = await loadFixture(
        deployContractsFixture
      );

      await fieBridge.connect(owner).setFIEExecutionAgent(fieAgent.address);
      await fieBridge.connect(owner).setFIEExecutionAgent(other.address);

      expect(await fieBridge.getFIEExecutionAgent()).to.equal(other.address);
    });
  });

  // ============================================
  // Test Suite: Trigger Notification
  // ============================================

  describe("Trigger Notification", function () {
    it("should emit FIETriggerReceived on valid notification", async function () {
      const { fieBridge, mockFIE, subject } = await loadFixture(deployContractsFixture);

      // Create intent through MockFIE
      const tx = await mockFIE.createIntent(subject.address);
      const receipt = await tx.wait();

      // Get intent hash from event
      const event = receipt?.logs.find((log) => {
        try {
          const parsed = mockFIE.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "IntentCreated";
        } catch {
          return false;
        }
      });

      const parsed = mockFIE.interface.parseLog({
        topics: event!.topics as string[],
        data: event!.data,
      });
      const intentHash = parsed?.args.intentHash;

      // Simulate death trigger - this calls notifyTrigger on the bridge
      await expect(mockFIE.simulateDeathTrigger(intentHash))
        .to.emit(fieBridge, "FIETriggerReceived")
        .withArgs(intentHash, subject.address);
    });

    it("should revert trigger notification from non-FIE caller", async function () {
      const { fieBridge, other, subject } = await loadFixture(deployContractsFixture);

      const intentHash = ethers.keccak256(ethers.toUtf8Bytes("test-intent"));

      await expect(
        fieBridge.connect(other).notifyTrigger(intentHash, subject.address)
      ).to.be.revertedWithCustomError(fieBridge, "NotFIEAgent");
    });

    it("should revert on duplicate trigger notification", async function () {
      const { fieBridge, mockFIE, lifecycleManager, subject, beneficiary1 } =
        await loadFixture(deployContractsFixture);
      const fixture = await loadFixture(deployContractsFixture);

      // Mint credential
      const tokenId = await mintCredential(fixture);

      // Create intent through MockFIE
      const salt = ethers.keccak256(ethers.toUtf8Bytes("test-salt"));
      const createTx = await fixture.mockFIE.createDeterministicIntent(
        fixture.subject.address,
        salt
      );
      const createReceipt = await createTx.wait();

      const event = createReceipt?.logs.find((log) => {
        try {
          const parsed = fixture.mockFIE.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "IntentCreated";
        } catch {
          return false;
        }
      });

      const parsed = fixture.mockFIE.interface.parseLog({
        topics: event!.topics as string[],
        data: event!.data,
      });
      const intentHash = parsed?.args.intentHash;

      // Set inheritance directive with FIE trigger
      const directive = await createInheritanceDirective(
        [fixture.beneficiary1.address],
        intentHash,
        true
      );
      await fixture.lifecycleManager
        .connect(fixture.subject)
        .setInheritanceDirective(tokenId, directive);

      // Register credential for FIE in the bridge
      await fixture.fieBridge.registerCredentialForFIE(
        tokenId,
        fixture.subject.address,
        intentHash
      );

      // First trigger should succeed
      await fixture.mockFIE.simulateDeathTrigger(intentHash);

      // Reset trigger in mock for retry
      await fixture.mockFIE.resetTrigger(intentHash);

      // Second trigger should fail (already processed)
      await expect(
        fixture.mockFIE.simulateDeathTrigger(intentHash)
      ).to.be.revertedWithCustomError(fixture.fieBridge, "InheritanceAlreadyExecuted");
    });
  });

  // ============================================
  // Test Suite: Inheritance Execution
  // ============================================

  describe("Inheritance Execution", function () {
    it("should execute inheritance via FIE trigger", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, fieBridge, mockFIE, subject, beneficiary1 } = fixture;

      // Mint credential
      const tokenId = await mintCredential(fixture);

      // Create intent
      const salt = ethers.keccak256(ethers.toUtf8Bytes("inheritance-test"));
      const createTx = await mockFIE.createDeterministicIntent(subject.address, salt);
      const createReceipt = await createTx.wait();

      const event = createReceipt?.logs.find((log) => {
        try {
          const parsed = mockFIE.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "IntentCreated";
        } catch {
          return false;
        }
      });

      const parsed = mockFIE.interface.parseLog({
        topics: event!.topics as string[],
        data: event!.data,
      });
      const intentHash = parsed?.args.intentHash;

      // Set inheritance directive
      const directive = await createInheritanceDirective(
        [beneficiary1.address],
        intentHash,
        true
      );
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      // Register credential for FIE
      await fieBridge.registerCredentialForFIE(tokenId, subject.address, intentHash);

      // Execute inheritance via mock FIE
      await expect(mockFIE.simulateDeathTriggerWithCredential(intentHash, tokenId))
        .to.emit(fieBridge, "CredentialInheritanceExecuted")
        .withArgs(tokenId, intentHash, beneficiary1.address);

      // Verify trigger is marked as processed
      expect(await fieBridge.isTriggerProcessed(intentHash)).to.be.true;
    });

    it("should revert inheritance for non-FIE-required directive", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, fieBridge, mockFIE, subject, beneficiary1 } = fixture;

      // Mint credential
      const tokenId = await mintCredential(fixture);

      // Create intent
      const salt = ethers.keccak256(ethers.toUtf8Bytes("no-fie-test"));
      const createTx = await mockFIE.createDeterministicIntent(subject.address, salt);
      const createReceipt = await createTx.wait();

      const event = createReceipt?.logs.find((log) => {
        try {
          const parsed = mockFIE.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "IntentCreated";
        } catch {
          return false;
        }
      });

      const parsed = mockFIE.interface.parseLog({
        topics: event!.topics as string[],
        data: event!.data,
      });
      const intentHash = parsed?.args.intentHash;

      // Set inheritance directive WITHOUT FIE trigger requirement
      const directive = await createInheritanceDirective(
        [beneficiary1.address],
        intentHash,
        false // requiresFIETrigger = false
      );
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      // Attempt execution should fail
      await expect(
        mockFIE.simulateDeathTriggerWithCredential(intentHash, tokenId)
      ).to.be.revertedWithCustomError(fieBridge, "OperationNotAllowed");
    });

    it("should revert inheritance with mismatched intent hash", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, fieBridge, mockFIE, subject, beneficiary1 } = fixture;

      // Mint credential
      const tokenId = await mintCredential(fixture);

      // Create two different intents
      const salt1 = ethers.keccak256(ethers.toUtf8Bytes("intent-1"));
      const salt2 = ethers.keccak256(ethers.toUtf8Bytes("intent-2"));

      await mockFIE.createDeterministicIntent(subject.address, salt1);
      const createTx2 = await mockFIE.createDeterministicIntent(subject.address, salt2);
      const createReceipt2 = await createTx2.wait();

      // Get second intent hash
      const event = createReceipt2?.logs.find((log) => {
        try {
          const parsed = mockFIE.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "IntentCreated";
        } catch {
          return false;
        }
      });

      const parsed = mockFIE.interface.parseLog({
        topics: event!.topics as string[],
        data: event!.data,
      });
      const intentHash2 = parsed?.args.intentHash;

      // Create a different intent hash for directive
      const differentIntentHash = ethers.keccak256(ethers.toUtf8Bytes("different-intent"));

      // Set inheritance directive with different intent hash
      const directive = await createInheritanceDirective(
        [beneficiary1.address],
        differentIntentHash,
        true
      );
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      // Attempt execution with wrong intent should fail
      await expect(
        mockFIE.simulateDeathTriggerWithCredential(intentHash2, tokenId)
      ).to.be.revertedWithCustomError(fieBridge, "FIETriggerInvalid");
    });

    it("should revert when no inheritance directive exists", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { mockFIE, subject } = fixture;

      // Mint credential but don't set inheritance directive
      const tokenId = await mintCredential(fixture);

      // Create intent
      const salt = ethers.keccak256(ethers.toUtf8Bytes("no-directive-test"));
      const createTx = await mockFIE.createDeterministicIntent(subject.address, salt);
      const createReceipt = await createTx.wait();

      const event = createReceipt?.logs.find((log) => {
        try {
          const parsed = mockFIE.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "IntentCreated";
        } catch {
          return false;
        }
      });

      const parsed = mockFIE.interface.parseLog({
        topics: event!.topics as string[],
        data: event!.data,
      });
      const intentHash = parsed?.args.intentHash;

      // Attempt execution should fail
      await expect(
        mockFIE.simulateDeathTriggerWithCredential(intentHash, tokenId)
      ).to.be.revertedWithCustomError(fixture.fieBridge, "InheritanceNotSet");
    });
  });

  // ============================================
  // Test Suite: Double-Execution Prevention
  // ============================================

  describe("Double-Execution Prevention", function () {
    it("should prevent double execution of same intent", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, fieBridge, mockFIE, subject, beneficiary1 } = fixture;

      // Mint credential
      const tokenId = await mintCredential(fixture);

      // Create intent
      const salt = ethers.keccak256(ethers.toUtf8Bytes("double-exec-test"));
      const createTx = await mockFIE.createDeterministicIntent(subject.address, salt);
      const createReceipt = await createTx.wait();

      const event = createReceipt?.logs.find((log) => {
        try {
          const parsed = mockFIE.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "IntentCreated";
        } catch {
          return false;
        }
      });

      const parsed = mockFIE.interface.parseLog({
        topics: event!.topics as string[],
        data: event!.data,
      });
      const intentHash = parsed?.args.intentHash;

      // Set inheritance directive
      const directive = await createInheritanceDirective(
        [beneficiary1.address],
        intentHash,
        true
      );
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      // First execution should succeed
      await mockFIE.simulateDeathTriggerWithCredential(intentHash, tokenId);

      // Verify processed
      expect(await fieBridge.isTriggerProcessed(intentHash)).to.be.true;

      // Reset mock trigger state (simulates a malicious retry)
      await mockFIE.resetTrigger(intentHash);

      // Second execution should fail
      await expect(
        mockFIE.simulateDeathTriggerWithCredential(intentHash, tokenId)
      ).to.be.revertedWithCustomError(fieBridge, "InheritanceAlreadyExecuted");
    });

    it("should track processed triggers correctly", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { fieBridge, mockFIE, subject } = fixture;

      // Create intent
      const salt = ethers.keccak256(ethers.toUtf8Bytes("track-test"));
      const createTx = await mockFIE.createDeterministicIntent(subject.address, salt);
      const createReceipt = await createTx.wait();

      const event = createReceipt?.logs.find((log) => {
        try {
          const parsed = mockFIE.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "IntentCreated";
        } catch {
          return false;
        }
      });

      const parsed = mockFIE.interface.parseLog({
        topics: event!.topics as string[],
        data: event!.data,
      });
      const intentHash = parsed?.args.intentHash;

      // Initially not processed
      expect(await fieBridge.isTriggerProcessed(intentHash)).to.be.false;
    });
  });

  // ============================================
  // Test Suite: Batch Inheritance
  // ============================================

  describe("Batch Inheritance", function () {
    it("should execute batch inheritance for multiple credentials", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { lifecycleManager, fieBridge, mockFIE, subject, beneficiary1 } = fixture;

      // Mint multiple credentials
      const tokenId1 = await mintCredential(fixture);
      const tokenId2 = await mintCredential(fixture);

      // Create intent
      const salt = ethers.keccak256(ethers.toUtf8Bytes("batch-test"));
      const createTx = await mockFIE.createDeterministicIntent(subject.address, salt);
      const createReceipt = await createTx.wait();

      const event = createReceipt?.logs.find((log) => {
        try {
          const parsed = mockFIE.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "IntentCreated";
        } catch {
          return false;
        }
      });

      const parsed = mockFIE.interface.parseLog({
        topics: event!.topics as string[],
        data: event!.data,
      });
      const intentHash = parsed?.args.intentHash;

      // Set inheritance directives for both
      const directive = await createInheritanceDirective(
        [beneficiary1.address],
        intentHash,
        true
      );

      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId1, directive);
      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId2, directive);

      // Execute batch inheritance
      await expect(mockFIE.simulateBatchInheritance(intentHash, [tokenId1, tokenId2]))
        .to.emit(fieBridge, "CredentialInheritanceExecuted")
        .withArgs(tokenId1, intentHash, beneficiary1.address)
        .and.to.emit(fieBridge, "CredentialInheritanceExecuted")
        .withArgs(tokenId2, intentHash, beneficiary1.address);

      // Verify trigger is processed
      expect(await fieBridge.isTriggerProcessed(intentHash)).to.be.true;
    });

    it("should revert batch with empty array", async function () {
      const { mockFIE, subject } = await loadFixture(deployContractsFixture);

      // Create intent
      const salt = ethers.keccak256(ethers.toUtf8Bytes("empty-batch-test"));
      const createTx = await mockFIE.createDeterministicIntent(subject.address, salt);
      const createReceipt = await createTx.wait();

      const event = createReceipt?.logs.find((log) => {
        try {
          const parsed = mockFIE.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "IntentCreated";
        } catch {
          return false;
        }
      });

      const parsed = mockFIE.interface.parseLog({
        topics: event!.topics as string[],
        data: event!.data,
      });
      const intentHash = parsed?.args.intentHash;

      await expect(
        mockFIE.simulateBatchInheritance(intentHash, [])
      ).to.be.revertedWithCustomError(
        await ethers.getContractFactory("FIEBridge"),
        "EmptyArray"
      );
    });
  });

  // ============================================
  // Test Suite: FIE Proof Verification
  // ============================================

  describe("FIE Proof Verification", function () {
    it("should verify valid FIE proof", async function () {
      const { fieBridge, subject } = await loadFixture(deployContractsFixture);

      const intentHash = ethers.keccak256(ethers.toUtf8Bytes("proof-test"));
      const timestamp = (await time.latest()) - 100; // Recent timestamp

      const proof = ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "address", "uint256", "bytes32"],
        [intentHash, subject.address, timestamp, ethers.ZeroHash]
      );

      expect(await fieBridge.verifyFIEProof(proof)).to.be.true;
    });

    it("should reject proof with zero intent hash", async function () {
      const { fieBridge, subject } = await loadFixture(deployContractsFixture);

      const timestamp = await time.latest();

      const proof = ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "address", "uint256", "bytes32"],
        [ethers.ZeroHash, subject.address, timestamp, ethers.ZeroHash]
      );

      expect(await fieBridge.verifyFIEProof(proof)).to.be.false;
    });

    it("should reject proof with zero subject", async function () {
      const { fieBridge } = await loadFixture(deployContractsFixture);

      const intentHash = ethers.keccak256(ethers.toUtf8Bytes("proof-test"));
      const timestamp = await time.latest();

      const proof = ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "address", "uint256", "bytes32"],
        [intentHash, ethers.ZeroAddress, timestamp, ethers.ZeroHash]
      );

      expect(await fieBridge.verifyFIEProof(proof)).to.be.false;
    });

    it("should reject proof with future timestamp", async function () {
      const { fieBridge, subject } = await loadFixture(deployContractsFixture);

      const intentHash = ethers.keccak256(ethers.toUtf8Bytes("proof-test"));
      const futureTimestamp = (await time.latest()) + 3600; // 1 hour in future

      const proof = ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "address", "uint256", "bytes32"],
        [intentHash, subject.address, futureTimestamp, ethers.ZeroHash]
      );

      expect(await fieBridge.verifyFIEProof(proof)).to.be.false;
    });

    it("should reject proof with too old timestamp", async function () {
      const { fieBridge, subject } = await loadFixture(deployContractsFixture);

      const intentHash = ethers.keccak256(ethers.toUtf8Bytes("proof-test"));
      const oldTimestamp = (await time.latest()) - 2 * 24 * 60 * 60; // 2 days ago

      const proof = ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "address", "uint256", "bytes32"],
        [intentHash, subject.address, oldTimestamp, ethers.ZeroHash]
      );

      expect(await fieBridge.verifyFIEProof(proof)).to.be.false;
    });

    it("should reject proof with insufficient length", async function () {
      const { fieBridge } = await loadFixture(deployContractsFixture);

      const shortProof = "0x" + "00".repeat(32); // Only 32 bytes

      expect(await fieBridge.verifyFIEProof(shortProof)).to.be.false;
    });
  });

  // ============================================
  // Test Suite: Administrative Functions
  // ============================================

  describe("Administrative Functions", function () {
    it("should allow admin to pause and unpause", async function () {
      const { fieBridge, owner } = await loadFixture(deployContractsFixture);

      await fieBridge.connect(owner).setPaused(true);
      expect(await fieBridge.isPaused()).to.be.true;

      await fieBridge.connect(owner).setPaused(false);
      expect(await fieBridge.isPaused()).to.be.false;
    });

    it("should block operations when paused", async function () {
      const { fieBridge, mockFIE, owner, subject } = await loadFixture(
        deployContractsFixture
      );

      // Pause the bridge
      await fieBridge.connect(owner).setPaused(true);

      // Create intent
      const salt = ethers.keccak256(ethers.toUtf8Bytes("paused-test"));
      const createTx = await mockFIE.createDeterministicIntent(subject.address, salt);
      const createReceipt = await createTx.wait();

      const event = createReceipt?.logs.find((log) => {
        try {
          const parsed = mockFIE.interface.parseLog({
            topics: log.topics as string[],
            data: log.data,
          });
          return parsed?.name === "IntentCreated";
        } catch {
          return false;
        }
      });

      const parsed = mockFIE.interface.parseLog({
        topics: event!.topics as string[],
        data: event!.data,
      });
      const intentHash = parsed?.args.intentHash;

      // Attempt trigger should fail due to pause
      await expect(
        mockFIE.simulateDeathTrigger(intentHash)
      ).to.be.revertedWithCustomError(fieBridge, "EnforcedPause");
    });

    it("should allow admin to update lifecycle manager", async function () {
      const { fieBridge, owner, other } = await loadFixture(deployContractsFixture);

      await fieBridge.connect(owner).setLifecycleManager(other.address);
      expect(await fieBridge.getLifecycleManager()).to.equal(other.address);
    });

    it("should revert setting zero lifecycle manager", async function () {
      const { fieBridge, owner } = await loadFixture(deployContractsFixture);

      await expect(
        fieBridge.connect(owner).setLifecycleManager(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(fieBridge, "ZeroAddress");
    });

    it("should prevent non-admin from pausing", async function () {
      const { fieBridge, other } = await loadFixture(deployContractsFixture);

      await expect(fieBridge.connect(other).setPaused(true)).to.be.reverted;
    });
  });

  // ============================================
  // Test Suite: Credential Registration
  // ============================================

  describe("Credential Registration", function () {
    it("should register credential for FIE tracking", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { fieBridge, subject } = fixture;

      const tokenId = await mintCredential(fixture);
      const intentHash = ethers.keccak256(ethers.toUtf8Bytes("register-test"));

      await fieBridge.registerCredentialForFIE(tokenId, subject.address, intentHash);

      expect(await fieBridge.getLinkedIntentHash(tokenId)).to.equal(intentHash);

      const credentials = await fieBridge.getCredentialsWithFIEInheritance(subject.address);
      expect(credentials).to.include(tokenId);
    });

    it("should unregister credential from FIE tracking", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { fieBridge, subject } = fixture;

      const tokenId = await mintCredential(fixture);
      const intentHash = ethers.keccak256(ethers.toUtf8Bytes("unregister-test"));

      await fieBridge.registerCredentialForFIE(tokenId, subject.address, intentHash);
      await fieBridge.unregisterCredentialForFIE(tokenId, subject.address);

      expect(await fieBridge.getLinkedIntentHash(tokenId)).to.equal(ethers.ZeroHash);

      const credentials = await fieBridge.getCredentialsWithFIEInheritance(subject.address);
      expect(credentials).to.not.include(tokenId);
    });

    it("should revert registration with zero address", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { fieBridge } = fixture;

      const tokenId = await mintCredential(fixture);
      const intentHash = ethers.keccak256(ethers.toUtf8Bytes("zero-address-test"));

      await expect(
        fieBridge.registerCredentialForFIE(tokenId, ethers.ZeroAddress, intentHash)
      ).to.be.revertedWithCustomError(fieBridge, "ZeroAddress");
    });

    it("should revert registration with zero intent hash", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { fieBridge, subject } = fixture;

      const tokenId = await mintCredential(fixture);

      await expect(
        fieBridge.registerCredentialForFIE(tokenId, subject.address, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(fieBridge, "FIETriggerInvalid");
    });

    it("should prevent non-admin from registering", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { fieBridge, subject, other } = fixture;

      const tokenId = await mintCredential(fixture);
      const intentHash = ethers.keccak256(ethers.toUtf8Bytes("non-admin-test"));

      await expect(
        fieBridge
          .connect(other)
          .registerCredentialForFIE(tokenId, subject.address, intentHash)
      ).to.be.reverted;
    });
  });

  // ============================================
  // Test Suite: Query Functions
  // ============================================

  describe("Query Functions", function () {
    it("should return empty array for subject with no FIE credentials", async function () {
      const { fieBridge, other } = await loadFixture(deployContractsFixture);

      const credentials = await fieBridge.getCredentialsWithFIEInheritance(other.address);
      expect(credentials).to.be.empty;
    });

    it("should return zero hash for unlinked credential", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { fieBridge } = fixture;

      const tokenId = await mintCredential(fixture);

      expect(await fieBridge.getLinkedIntentHash(tokenId)).to.equal(ethers.ZeroHash);
    });

    it("should return multiple credentials for subject", async function () {
      const fixture = await loadFixture(deployContractsFixture);
      const { fieBridge, subject } = fixture;

      const tokenId1 = await mintCredential(fixture);
      const tokenId2 = await mintCredential(fixture);
      const intentHash = ethers.keccak256(ethers.toUtf8Bytes("multi-cred-test"));

      await fieBridge.registerCredentialForFIE(tokenId1, subject.address, intentHash);
      await fieBridge.registerCredentialForFIE(tokenId2, subject.address, intentHash);

      const credentials = await fieBridge.getCredentialsWithFIEInheritance(subject.address);
      expect(credentials.length).to.equal(2);
      expect(credentials).to.include(tokenId1);
      expect(credentials).to.include(tokenId2);
    });
  });
});
