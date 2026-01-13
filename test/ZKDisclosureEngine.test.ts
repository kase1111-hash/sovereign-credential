/**
 * @file ZKDisclosureEngine unit and integration tests
 * @description Comprehensive tests for the ZK proof verification engine
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { type SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import {
  type ZKDisclosureEngine,
  type ClaimToken,
  type IssuerRegistry,
  type MockZKVerifier,
} from "../typechain-types";
import { ClaimTypes, CredentialStatus } from "../types";

describe("ZKDisclosureEngine", function () {
  // ============================================
  // Fixtures
  // ============================================

  async function deployZKEngineFixture() {
    const [owner, issuer, subject, verifierAdmin, other] = await ethers.getSigners();

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

    // Grant CREDENTIAL_CONTRACT_ROLE to ClaimToken
    const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
    await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, await claimToken.getAddress());

    // Deploy ZKDisclosureEngine
    const ZKDisclosureEngineFactory = await ethers.getContractFactory("ZKDisclosureEngine");
    const zkEngine = (await ZKDisclosureEngineFactory.deploy(
      owner.address,
      await claimToken.getAddress()
    )) as unknown as ZKDisclosureEngine;
    await zkEngine.waitForDeployment();

    // Set ZK engine on ClaimToken
    await claimToken.setZKEngine(await zkEngine.getAddress());

    // Deploy MockZKVerifier
    const MockZKVerifierFactory = await ethers.getContractFactory("MockZKVerifier");
    const mockVerifier = (await MockZKVerifierFactory.deploy()) as unknown as MockZKVerifier;
    await mockVerifier.waitForDeployment();

    // Grant verifier admin role
    const VERIFIER_ADMIN_ROLE = await zkEngine.VERIFIER_ADMIN_ROLE();
    await zkEngine.grantRole(VERIFIER_ADMIN_ROLE, verifierAdmin.address);

    // Register issuer
    await issuerRegistry.registerIssuer(issuer.address, "US-OR", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.IDENTITY_BIRTH,
      ClaimTypes.PROPERTY_DEED,
    ]);

    return {
      zkEngine,
      claimToken,
      issuerRegistry,
      mockVerifier,
      owner,
      issuer,
      subject,
      verifierAdmin,
      other,
    };
  }

  // ============================================
  // Helper Functions
  // ============================================

  async function createMintRequest(claimType: string, subject: string, expiresAt?: bigint) {
    const now = await time.latest();
    const oneYearFromNow = BigInt(now) + BigInt(365 * 24 * 60 * 60);

    return {
      claimType,
      subject,
      encryptedPayload: "0x" + "ab".repeat(100),
      payloadHash: ethers.keccak256(ethers.toUtf8Bytes("test-payload")),
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
    claimToken: ClaimToken,
    issuer: SignerWithAddress,
    subject: SignerWithAddress,
    claimType: string = ClaimTypes.LICENSE_OPERATOR
  ): Promise<bigint> {
    const request = await createMintRequest(claimType, subject.address);
    const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
    await claimToken.mint(request, signature);
    return 1n;
  }

  function createMockProof(): string {
    // Create a mock Groth16 proof (pA, pB, pC encoded)
    const pA: [bigint, bigint] = [1n, 2n];
    const pB: [[bigint, bigint], [bigint, bigint]] = [
      [3n, 4n],
      [5n, 6n],
    ];
    const pC: [bigint, bigint] = [7n, 8n];

    return ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256[2]", "uint256[2][2]", "uint256[2]"],
      [pA, pB, pC]
    );
  }

  // ============================================
  // Deployment Tests
  // ============================================

  describe("Deployment", function () {
    it("should deploy with correct admin roles", async function () {
      const { zkEngine, owner } = await loadFixture(deployZKEngineFixture);

      const DEFAULT_ADMIN_ROLE = await zkEngine.DEFAULT_ADMIN_ROLE();
      const VERIFIER_ADMIN_ROLE = await zkEngine.VERIFIER_ADMIN_ROLE();

      expect(await zkEngine.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.be.true;
      expect(await zkEngine.hasRole(VERIFIER_ADMIN_ROLE, owner.address)).to.be.true;
    });

    it("should set ClaimToken address correctly", async function () {
      const { zkEngine, claimToken } = await loadFixture(deployZKEngineFixture);

      expect(await zkEngine.getClaimToken()).to.equal(await claimToken.getAddress());
    });

    it("should reject deployment with zero admin address", async function () {
      const { claimToken } = await loadFixture(deployZKEngineFixture);
      const ZKDisclosureEngineFactory = await ethers.getContractFactory("ZKDisclosureEngine");

      await expect(
        ZKDisclosureEngineFactory.deploy(ethers.ZeroAddress, await claimToken.getAddress())
      ).to.be.revertedWithCustomError(ZKDisclosureEngineFactory, "ZeroAddress");
    });

    it("should allow deployment with zero ClaimToken address", async function () {
      const [owner] = await ethers.getSigners();
      const ZKDisclosureEngineFactory = await ethers.getContractFactory("ZKDisclosureEngine");

      const zkEngine = await ZKDisclosureEngineFactory.deploy(owner.address, ethers.ZeroAddress);
      await zkEngine.waitForDeployment();

      expect(await zkEngine.getClaimToken()).to.equal(ethers.ZeroAddress);
    });
  });

  // ============================================
  // Verifier Management Tests
  // ============================================

  describe("Verifier Management", function () {
    it("should register a verifier successfully", async function () {
      const { zkEngine, mockVerifier, verifierAdmin } = await loadFixture(deployZKEngineFixture);

      const disclosureType = await zkEngine.DISCLOSURE_AGE_THRESHOLD();

      await expect(
        zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress())
      )
        .to.emit(zkEngine, "VerifierRegistered")
        .withArgs(disclosureType, await mockVerifier.getAddress());

      expect(await zkEngine.getVerifier(disclosureType)).to.equal(await mockVerifier.getAddress());
    });

    it("should reject verifier registration without admin role", async function () {
      const { zkEngine, mockVerifier, other } = await loadFixture(deployZKEngineFixture);

      const disclosureType = await zkEngine.DISCLOSURE_AGE_THRESHOLD();

      await expect(
        zkEngine.connect(other).registerVerifier(disclosureType, await mockVerifier.getAddress())
      ).to.be.reverted;
    });

    it("should reject registration with zero address verifier", async function () {
      const { zkEngine, verifierAdmin } = await loadFixture(deployZKEngineFixture);

      const disclosureType = await zkEngine.DISCLOSURE_AGE_THRESHOLD();

      await expect(
        zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(zkEngine, "ZeroAddress");
    });

    it("should remove a verifier successfully", async function () {
      const { zkEngine, mockVerifier, verifierAdmin } = await loadFixture(deployZKEngineFixture);

      const disclosureType = await zkEngine.DISCLOSURE_AGE_THRESHOLD();

      // First register
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      // Then remove
      await expect(zkEngine.connect(verifierAdmin).removeVerifier(disclosureType))
        .to.emit(zkEngine, "VerifierRegistered")
        .withArgs(disclosureType, ethers.ZeroAddress);

      expect(await zkEngine.getVerifier(disclosureType)).to.equal(ethers.ZeroAddress);
    });

    it("should reject removal of non-registered verifier", async function () {
      const { zkEngine, verifierAdmin } = await loadFixture(deployZKEngineFixture);

      const disclosureType = await zkEngine.DISCLOSURE_AGE_THRESHOLD();

      await expect(
        zkEngine.connect(verifierAdmin).removeVerifier(disclosureType)
      ).to.be.revertedWithCustomError(zkEngine, "VerifierNotRegistered");
    });

    it("should update ClaimToken address", async function () {
      const { zkEngine, owner, other } = await loadFixture(deployZKEngineFixture);

      await zkEngine.connect(owner).setClaimToken(other.address);
      expect(await zkEngine.getClaimToken()).to.equal(other.address);
    });

    it("should reject setting zero ClaimToken address", async function () {
      const { zkEngine, owner } = await loadFixture(deployZKEngineFixture);

      await expect(
        zkEngine.connect(owner).setClaimToken(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(zkEngine, "ZeroAddress");
    });
  });

  // ============================================
  // Age Threshold Verification Tests
  // ============================================

  describe("Age Threshold Verification", function () {
    async function setupAgeVerificationFixture() {
      const fixture = await deployZKEngineFixture();
      const { zkEngine, claimToken, mockVerifier, issuer, subject, verifierAdmin } = fixture;

      // Register verifier
      const disclosureType = await zkEngine.DISCLOSURE_AGE_THRESHOLD();
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      // Mint credential
      await mintCredential(claimToken, issuer, subject, ClaimTypes.IDENTITY_BIRTH);

      return { ...fixture, tokenId: 1n };
    }

    it("should verify valid age threshold proof", async function () {
      const { zkEngine, mockVerifier, tokenId } = await loadFixture(setupAgeVerificationFixture);

      // Ensure mock verifier accepts proofs
      await mockVerifier.setAcceptAll(true);

      const proof = createMockProof();
      const threshold = 18;
      const greaterThan = true;

      await expect(zkEngine.verifyAgeThreshold(tokenId, threshold, greaterThan, proof))
        .to.emit(zkEngine, "ProofVerified");
    });

    it("should reject invalid age threshold proof", async function () {
      const { zkEngine, mockVerifier, tokenId } = await loadFixture(setupAgeVerificationFixture);

      // Set mock verifier to reject proofs
      await mockVerifier.setAcceptAll(false);

      const proof = createMockProof();
      const threshold = 18;
      const greaterThan = true;

      const result = await zkEngine.verifyAgeThreshold.staticCall(tokenId, threshold, greaterThan, proof);
      expect(result).to.be.false;
    });

    it("should reject proof for revoked credential", async function () {
      const { zkEngine, claimToken, issuer, tokenId } = await loadFixture(setupAgeVerificationFixture);

      // Revoke the credential
      await claimToken.connect(issuer).revoke(tokenId, "Test revocation");

      const proof = createMockProof();

      await expect(
        zkEngine.verifyAgeThreshold(tokenId, 18, true, proof)
      ).to.be.revertedWithCustomError(zkEngine, "CredentialRevoked");
    });

    it("should reject proof for suspended credential", async function () {
      const { zkEngine, claimToken, issuer, tokenId } = await loadFixture(setupAgeVerificationFixture);

      // Suspend the credential
      await claimToken.connect(issuer).suspend(tokenId, "Test suspension");

      const proof = createMockProof();

      await expect(
        zkEngine.verifyAgeThreshold(tokenId, 18, true, proof)
      ).to.be.revertedWithCustomError(zkEngine, "CredentialSuspended");
    });

    it("should reject proof for expired credential", async function () {
      const { zkEngine, claimToken, issuer, subject, verifierAdmin, mockVerifier } =
        await loadFixture(deployZKEngineFixture);

      // Register verifier
      const disclosureType = await zkEngine.DISCLOSURE_AGE_THRESHOLD();
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      // Create credential that expires in 1 hour
      const now = await time.latest();
      const request = await createMintRequest(ClaimTypes.IDENTITY_BIRTH, subject.address, BigInt(now + 3600));
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      // Advance time past expiration
      await time.increase(3601);

      const proof = createMockProof();

      await expect(
        zkEngine.verifyAgeThreshold(1n, 18, true, proof)
      ).to.be.revertedWithCustomError(zkEngine, "CredentialExpired");
    });

    it("should reject when verifier not registered", async function () {
      const { zkEngine, claimToken, issuer, subject } = await loadFixture(deployZKEngineFixture);

      // Mint credential (no verifier registered)
      await mintCredential(claimToken, issuer, subject);

      const proof = createMockProof();

      await expect(
        zkEngine.verifyAgeThreshold(1n, 18, true, proof)
      ).to.be.revertedWithCustomError(zkEngine, "VerifierNotRegistered");
    });
  });

  // ============================================
  // Proof Replay Prevention Tests (INV-04)
  // ============================================

  describe("Proof Replay Prevention", function () {
    async function setupReplayPreventionFixture() {
      const fixture = await deployZKEngineFixture();
      const { zkEngine, claimToken, mockVerifier, issuer, subject, verifierAdmin } = fixture;

      // Register verifier
      const disclosureType = await zkEngine.DISCLOSURE_AGE_THRESHOLD();
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      // Mint credential
      await mintCredential(claimToken, issuer, subject, ClaimTypes.IDENTITY_BIRTH);

      // Ensure mock verifier accepts proofs
      await mockVerifier.setAcceptAll(true);

      return { ...fixture, tokenId: 1n };
    }

    it("should reject replayed proof (INV-04)", async function () {
      const { zkEngine, tokenId } = await loadFixture(setupReplayPreventionFixture);

      const proof = createMockProof();

      // First verification should succeed
      await zkEngine.verifyAgeThreshold(tokenId, 18, true, proof);

      // Second verification with same proof should fail
      await expect(
        zkEngine.verifyAgeThreshold(tokenId, 18, true, proof)
      ).to.be.revertedWithCustomError(zkEngine, "ProofReplayed");
    });

    it("should track used proofs correctly", async function () {
      const { zkEngine, tokenId } = await loadFixture(setupReplayPreventionFixture);

      const proof = createMockProof();
      const proofHash = ethers.keccak256(proof);

      // Should not be used initially
      expect(await zkEngine.isProofUsed(proofHash)).to.be.false;

      // Verify proof
      await zkEngine.verifyAgeThreshold(tokenId, 18, true, proof);

      // Should be marked as used
      expect(await zkEngine.isProofUsed(proofHash)).to.be.true;
    });

    it("should allow different proofs for same credential", async function () {
      const { zkEngine, tokenId } = await loadFixture(setupReplayPreventionFixture);

      const proof1 = createMockProof();

      // Create a different proof
      const pA: [bigint, bigint] = [10n, 20n];
      const pB: [[bigint, bigint], [bigint, bigint]] = [
        [30n, 40n],
        [50n, 60n],
      ];
      const pC: [bigint, bigint] = [70n, 80n];
      const proof2 = ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256[2]", "uint256[2][2]", "uint256[2]"],
        [pA, pB, pC]
      );

      // First proof should succeed
      await zkEngine.verifyAgeThreshold(tokenId, 18, true, proof1);

      // Different proof should also succeed
      await expect(zkEngine.verifyAgeThreshold(tokenId, 18, true, proof2))
        .to.emit(zkEngine, "ProofVerified");
    });
  });

  // ============================================
  // Date Range Verification Tests
  // ============================================

  describe("Date Range Verification", function () {
    async function setupDateRangeFixture() {
      const fixture = await deployZKEngineFixture();
      const { zkEngine, claimToken, mockVerifier, issuer, subject, verifierAdmin } = fixture;

      // Register verifier
      const disclosureType = await zkEngine.DISCLOSURE_DATE_RANGE();
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      // Mint credential
      await mintCredential(claimToken, issuer, subject);

      // Ensure mock verifier accepts proofs
      await mockVerifier.setAcceptAll(true);

      return { ...fixture, tokenId: 1n };
    }

    it("should verify valid date range proof", async function () {
      const { zkEngine, tokenId } = await loadFixture(setupDateRangeFixture);

      const proof = createMockProof();
      const start = BigInt(Math.floor(Date.now() / 1000) - 86400); // Yesterday
      const end = BigInt(Math.floor(Date.now() / 1000) + 86400); // Tomorrow

      await expect(zkEngine.verifyDateRange(tokenId, start, end, proof))
        .to.emit(zkEngine, "ProofVerified");
    });

    it("should reject when verifier not registered", async function () {
      const { zkEngine, claimToken, issuer, subject } = await loadFixture(deployZKEngineFixture);

      // Mint credential (no verifier registered for date range)
      await mintCredential(claimToken, issuer, subject);

      const proof = createMockProof();
      const start = BigInt(Math.floor(Date.now() / 1000));
      const end = BigInt(Math.floor(Date.now() / 1000) + 86400);

      await expect(
        zkEngine.verifyDateRange(1n, start, end, proof)
      ).to.be.revertedWithCustomError(zkEngine, "VerifierNotRegistered");
    });
  });

  // ============================================
  // Value Range Verification Tests
  // ============================================

  describe("Value Range Verification", function () {
    async function setupValueRangeFixture() {
      const fixture = await deployZKEngineFixture();
      const { zkEngine, claimToken, mockVerifier, issuer, subject, verifierAdmin } = fixture;

      // Register verifier
      const disclosureType = await zkEngine.DISCLOSURE_VALUE_RANGE();
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      // Mint credential
      await mintCredential(claimToken, issuer, subject);

      // Ensure mock verifier accepts proofs
      await mockVerifier.setAcceptAll(true);

      return { ...fixture, tokenId: 1n };
    }

    it("should verify valid value range proof", async function () {
      const { zkEngine, tokenId } = await loadFixture(setupValueRangeFixture);

      const proof = createMockProof();
      const field = ethers.keccak256(ethers.toUtf8Bytes("salary"));
      const min = 50000n;
      const max = 150000n;

      await expect(zkEngine.verifyValueRange(tokenId, field, min, max, proof))
        .to.emit(zkEngine, "ProofVerified");
    });
  });

  // ============================================
  // Set Membership Verification Tests
  // ============================================

  describe("Set Membership Verification", function () {
    async function setupSetMembershipFixture() {
      const fixture = await deployZKEngineFixture();
      const { zkEngine, claimToken, mockVerifier, issuer, subject, verifierAdmin } = fixture;

      // Register verifier
      const disclosureType = await zkEngine.DISCLOSURE_SET_MEMBERSHIP();
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      // Mint credential
      await mintCredential(claimToken, issuer, subject);

      // Ensure mock verifier accepts proofs
      await mockVerifier.setAcceptAll(true);

      return { ...fixture, tokenId: 1n };
    }

    it("should verify valid set membership proof", async function () {
      const { zkEngine, tokenId } = await loadFixture(setupSetMembershipFixture);

      const proof = createMockProof();
      const field = ethers.keccak256(ethers.toUtf8Bytes("country"));
      const setRoot = ethers.keccak256(ethers.toUtf8Bytes("allowed-countries-merkle-root"));

      await expect(zkEngine.verifySetMembership(tokenId, field, setRoot, proof))
        .to.emit(zkEngine, "ProofVerified");
    });
  });

  // ============================================
  // Existence Verification Tests
  // ============================================

  describe("Existence Verification", function () {
    async function setupExistenceFixture() {
      const fixture = await deployZKEngineFixture();
      const { zkEngine, claimToken, mockVerifier, issuer, subject, verifierAdmin } = fixture;

      // Register verifier
      const disclosureType = await zkEngine.DISCLOSURE_EXISTENCE();
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      // Mint credential
      await mintCredential(claimToken, issuer, subject);

      // Ensure mock verifier accepts proofs
      await mockVerifier.setAcceptAll(true);

      return { ...fixture, tokenId: 1n };
    }

    it("should verify valid existence proof", async function () {
      const { zkEngine, tokenId } = await loadFixture(setupExistenceFixture);

      const proof = createMockProof();

      await expect(zkEngine.verifyExistence(tokenId, proof))
        .to.emit(zkEngine, "ProofVerified");
    });
  });

  // ============================================
  // Compound Proof Verification Tests
  // ============================================

  describe("Compound Proof Verification", function () {
    async function setupCompoundFixture() {
      const fixture = await deployZKEngineFixture();
      const { zkEngine, claimToken, mockVerifier, issuer, subject, verifierAdmin } = fixture;

      // Register verifier
      const disclosureType = await zkEngine.DISCLOSURE_COMPOUND();
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      // Mint credential
      await mintCredential(claimToken, issuer, subject);

      // Ensure mock verifier accepts proofs
      await mockVerifier.setAcceptAll(true);

      return { ...fixture, tokenId: 1n };
    }

    it("should verify valid compound proof", async function () {
      const { zkEngine, tokenId } = await loadFixture(setupCompoundFixture);

      const proof = createMockProof();
      const disclosureTypes = [
        await zkEngine.DISCLOSURE_AGE_THRESHOLD(),
        await zkEngine.DISCLOSURE_DATE_RANGE(),
      ];
      const publicInputs = ethers.AbiCoder.defaultAbiCoder().encode(["uint256[]"], [[18, 1000, 2000]]);

      await expect(zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof))
        .to.emit(zkEngine, "ProofVerified");
    });

    it("should reject compound proof with empty disclosure types", async function () {
      const { zkEngine, tokenId } = await loadFixture(setupCompoundFixture);

      const proof = createMockProof();
      const publicInputs = "0x";

      await expect(
        zkEngine.verifyCompound(tokenId, [], publicInputs, proof)
      ).to.be.revertedWithCustomError(zkEngine, "EmptyArray");
    });
  });

  // ============================================
  // Generic Proof Verification Tests
  // ============================================

  describe("Generic Proof Verification", function () {
    async function setupGenericFixture() {
      const fixture = await deployZKEngineFixture();
      const { zkEngine, claimToken, mockVerifier, issuer, subject, verifierAdmin } = fixture;

      const disclosureType = await zkEngine.DISCLOSURE_AGE_THRESHOLD();

      // Register verifier
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      // Mint credential
      await mintCredential(claimToken, issuer, subject, ClaimTypes.IDENTITY_BIRTH);

      // Ensure mock verifier accepts proofs
      await mockVerifier.setAcceptAll(true);

      return { ...fixture, tokenId: 1n, disclosureType };
    }

    it("should verify valid generic proof request", async function () {
      const { zkEngine, tokenId, disclosureType } = await loadFixture(setupGenericFixture);

      const proof = createMockProof();
      const now = await time.latest();

      const request = {
        credentialId: tokenId,
        disclosureType: disclosureType,
        predicateHash: ethers.keccak256(ethers.toUtf8Bytes("age > 18")),
        proof: proof,
        generatedAt: BigInt(now),
        validUntil: BigInt(now + 3600), // 1 hour from now
        verifier: ethers.ZeroAddress, // Anyone can verify
      };

      await expect(zkEngine.verifyProof(request))
        .to.emit(zkEngine, "ProofVerified");
    });

    it("should reject expired proof", async function () {
      const { zkEngine, tokenId, disclosureType } = await loadFixture(setupGenericFixture);

      const proof = createMockProof();
      const now = await time.latest();

      const request = {
        credentialId: tokenId,
        disclosureType: disclosureType,
        predicateHash: ethers.keccak256(ethers.toUtf8Bytes("age > 18")),
        proof: proof,
        generatedAt: BigInt(now - 7200), // 2 hours ago
        validUntil: BigInt(now - 3600), // Expired 1 hour ago
        verifier: ethers.ZeroAddress,
      };

      await expect(zkEngine.verifyProof(request)).to.be.revertedWithCustomError(zkEngine, "ProofExpired");
    });

    it("should reject proof with wrong intended verifier", async function () {
      const { zkEngine, tokenId, disclosureType, other } = await loadFixture(setupGenericFixture);

      const proof = createMockProof();
      const now = await time.latest();

      const request = {
        credentialId: tokenId,
        disclosureType: disclosureType,
        predicateHash: ethers.keccak256(ethers.toUtf8Bytes("age > 18")),
        proof: proof,
        generatedAt: BigInt(now),
        validUntil: BigInt(now + 3600),
        verifier: other.address, // Specific verifier that is not msg.sender
      };

      // Call from owner (not the specified verifier)
      await expect(zkEngine.verifyProof(request)).to.be.revertedWithCustomError(zkEngine, "WrongVerifier");
    });
  });

  // ============================================
  // Disclosure Type Constants Tests
  // ============================================

  describe("Disclosure Type Constants", function () {
    it("should return correct age threshold type", async function () {
      const { zkEngine } = await loadFixture(deployZKEngineFixture);

      const expected = ethers.keccak256(ethers.toUtf8Bytes("AGE_THRESHOLD"));
      expect(await zkEngine.getAgeThresholdType()).to.equal(expected);
    });

    it("should return correct date range type", async function () {
      const { zkEngine } = await loadFixture(deployZKEngineFixture);

      const expected = ethers.keccak256(ethers.toUtf8Bytes("DATE_RANGE"));
      expect(await zkEngine.getDateRangeType()).to.equal(expected);
    });

    it("should return correct value range type", async function () {
      const { zkEngine } = await loadFixture(deployZKEngineFixture);

      const expected = ethers.keccak256(ethers.toUtf8Bytes("VALUE_RANGE"));
      expect(await zkEngine.getValueRangeType()).to.equal(expected);
    });

    it("should return correct set membership type", async function () {
      const { zkEngine } = await loadFixture(deployZKEngineFixture);

      const expected = ethers.keccak256(ethers.toUtf8Bytes("SET_MEMBERSHIP"));
      expect(await zkEngine.getSetMembershipType()).to.equal(expected);
    });

    it("should return correct existence type", async function () {
      const { zkEngine } = await loadFixture(deployZKEngineFixture);

      const expected = ethers.keccak256(ethers.toUtf8Bytes("EXISTENCE"));
      expect(await zkEngine.getExistenceType()).to.equal(expected);
    });

    it("should return correct compound type", async function () {
      const { zkEngine } = await loadFixture(deployZKEngineFixture);

      const expected = ethers.keccak256(ethers.toUtf8Bytes("COMPOUND"));
      expect(await zkEngine.getCompoundType()).to.equal(expected);
    });
  });

  // ============================================
  // Edge Cases and Security Tests
  // ============================================

  describe("Edge Cases and Security", function () {
    it("should handle empty proof gracefully", async function () {
      const { zkEngine, claimToken, mockVerifier, issuer, subject, verifierAdmin } =
        await loadFixture(deployZKEngineFixture);

      // Register verifier
      const disclosureType = await zkEngine.DISCLOSURE_AGE_THRESHOLD();
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      // Mint credential
      await mintCredential(claimToken, issuer, subject, ClaimTypes.IDENTITY_BIRTH);

      // Set mock to accept all (even invalid proofs)
      await mockVerifier.setAcceptAll(true);

      // Short proof (less than 256 bytes) should not revert but will have zeros
      const shortProof = "0x" + "00".repeat(32);

      // Should not revert, but verification will use default values
      await expect(zkEngine.verifyAgeThreshold(1n, 18, true, shortProof))
        .to.emit(zkEngine, "ProofVerified");
    });

    it("should handle credential with no commitments", async function () {
      const { zkEngine, claimToken, mockVerifier, issuer, subject, verifierAdmin } =
        await loadFixture(deployZKEngineFixture);

      // Register verifier
      const disclosureType = await zkEngine.DISCLOSURE_AGE_THRESHOLD();
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      // Create request with no commitments
      const now = await time.latest();
      const request = {
        claimType: ClaimTypes.IDENTITY_BIRTH,
        subject: subject.address,
        encryptedPayload: "0x" + "ab".repeat(100),
        payloadHash: ethers.keccak256(ethers.toUtf8Bytes("test")),
        commitments: [], // No commitments
        expiresAt: BigInt(now + 365 * 24 * 60 * 60),
        metadataURI: "ipfs://test",
      };
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      // Set mock to accept all
      await mockVerifier.setAcceptAll(true);

      const proof = createMockProof();

      // Should use bytes32(0) as commitment
      await expect(zkEngine.verifyAgeThreshold(1n, 18, true, proof))
        .to.emit(zkEngine, "ProofVerified");
    });

    it("should reject verification for non-existent credential", async function () {
      const { zkEngine, mockVerifier, verifierAdmin } = await loadFixture(deployZKEngineFixture);

      // Register verifier
      const disclosureType = await zkEngine.DISCLOSURE_AGE_THRESHOLD();
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      const proof = createMockProof();

      // Token ID 999 doesn't exist
      await expect(
        zkEngine.verifyAgeThreshold(999n, 18, true, proof)
      ).to.be.revertedWithCustomError(zkEngine, "InvalidCredentialStatus");
    });
  });

  // ============================================
  // Gas Optimization Tests
  // ============================================

  describe("Gas Optimization", function () {
    it("should have reasonable gas cost for age threshold verification", async function () {
      const { zkEngine, claimToken, mockVerifier, issuer, subject, verifierAdmin } =
        await loadFixture(deployZKEngineFixture);

      // Register verifier
      const disclosureType = await zkEngine.DISCLOSURE_AGE_THRESHOLD();
      await zkEngine.connect(verifierAdmin).registerVerifier(disclosureType, await mockVerifier.getAddress());

      // Mint credential
      await mintCredential(claimToken, issuer, subject, ClaimTypes.IDENTITY_BIRTH);

      await mockVerifier.setAcceptAll(true);

      const proof = createMockProof();

      const tx = await zkEngine.verifyAgeThreshold(1n, 18, true, proof);
      const receipt = await tx.wait();

      // Gas cost should be reasonable (< 300,000 as per NFR-02)
      expect(receipt!.gasUsed).to.be.lt(300000);
    });
  });
});
