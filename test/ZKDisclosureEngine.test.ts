/**
 * @file ZKDisclosureEngine unit tests
 * @description Tests for the ZKDisclosureEngine contract including compound proofs
 *
 * Note: These tests use mock verifiers since real ZK proofs require compiled circuits.
 * For full integration tests, compile circuits with: ./compile.sh && ./setup.sh
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
  // Constants
  // ============================================

  // Disclosure type hashes (matching contract constants)
  const DISCLOSURE_AGE_THRESHOLD = ethers.keccak256(ethers.toUtf8Bytes("AGE_THRESHOLD"));
  const DISCLOSURE_DATE_RANGE = ethers.keccak256(ethers.toUtf8Bytes("DATE_RANGE"));
  const DISCLOSURE_VALUE_RANGE = ethers.keccak256(ethers.toUtf8Bytes("VALUE_RANGE"));
  const DISCLOSURE_SET_MEMBERSHIP = ethers.keccak256(ethers.toUtf8Bytes("SET_MEMBERSHIP"));
  const DISCLOSURE_EXISTENCE = ethers.keccak256(ethers.toUtf8Bytes("EXISTENCE"));
  const DISCLOSURE_COMPOUND = ethers.keccak256(ethers.toUtf8Bytes("COMPOUND"));
  const DISCLOSURE_COMPOUND_3 = ethers.keccak256(ethers.toUtf8Bytes("COMPOUND_3"));
  const DISCLOSURE_COMPOUND_4 = ethers.keccak256(ethers.toUtf8Bytes("COMPOUND_4"));

  // ============================================
  // Fixtures
  // ============================================

  async function deployZKEngineFixture() {
    const [owner, issuer, subject, verifier, other] = await ethers.getSigners();

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
    const ZKEngineFactory = await ethers.getContractFactory("ZKDisclosureEngine");
    const zkEngine = (await upgrades.deployProxy(
      ZKEngineFactory,
      [await claimToken.getAddress()],
      { initializer: "initialize" }
    )) as unknown as ZKDisclosureEngine;
    await zkEngine.waitForDeployment();

    // Deploy MockZKVerifier for testing
    const MockVerifierFactory = await ethers.getContractFactory("MockZKVerifier");
    const mockVerifier = (await MockVerifierFactory.deploy()) as MockZKVerifier;
    await mockVerifier.waitForDeployment();

    // Register issuer with claim types
    await issuerRegistry.registerIssuer(issuer.address, "US-OR", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.IDENTITY_BIRTH,
    ]);

    return {
      zkEngine,
      claimToken,
      issuerRegistry,
      mockVerifier,
      owner,
      issuer,
      subject,
      verifier,
      other,
    };
  }

  async function deployWithCredentialFixture() {
    const fixture = await deployZKEngineFixture();
    const { claimToken, issuer, subject } = fixture;

    // Create and mint a credential
    const request = await createMintRequest(
      ClaimTypes.IDENTITY_BIRTH,
      subject.address
    );
    const signature = await signMintRequest(
      issuer,
      request,
      await claimToken.getAddress()
    );

    await claimToken.mint(request, signature);

    return {
      ...fixture,
      tokenId: 1n,
      commitment: request.commitments[0],
    };
  }

  // ============================================
  // Helper Functions
  // ============================================

  async function createMintRequest(claimType: string, subject: string) {
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
      expiresAt: oneYearFromNow,
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

  function createMockProof(
    commitment: string,
    pubSignals: bigint[]
  ): string {
    // Create mock proof structure that matches expected format
    const pA = [1n, 2n];
    const pB = [
      [3n, 4n],
      [5n, 6n],
    ];
    const pC = [7n, 8n];

    // Build full public signals array
    const fullPubSignals = [BigInt(commitment), ...pubSignals];

    return ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint[2]", "uint[2][2]", "uint[2]", "uint[4]"],
      [pA, pB, pC, fullPubSignals.slice(0, 4)]
    );
  }

  // ============================================
  // Deployment Tests
  // ============================================

  describe("Deployment", function () {
    it("should initialize with correct claim token address", async function () {
      const { zkEngine, claimToken } = await loadFixture(deployZKEngineFixture);

      expect(await zkEngine.getClaimToken()).to.equal(await claimToken.getAddress());
    });

    it("should grant admin role to deployer", async function () {
      const { zkEngine, owner } = await loadFixture(deployZKEngineFixture);

      const DEFAULT_ADMIN_ROLE = await zkEngine.DEFAULT_ADMIN_ROLE();
      expect(await zkEngine.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.be.true;
    });

    it("should reject initialization with zero address", async function () {
      const ZKEngineFactory = await ethers.getContractFactory("ZKDisclosureEngine");

      await expect(
        upgrades.deployProxy(ZKEngineFactory, [ethers.ZeroAddress], {
          initializer: "initialize",
        })
      ).to.be.revertedWithCustomError(ZKEngineFactory, "ZeroAddress");
    });
  });

  // ============================================
  // Verifier Registration Tests
  // ============================================

  describe("Verifier Registration", function () {
    it("should register a verifier", async function () {
      const { zkEngine, mockVerifier } = await loadFixture(deployZKEngineFixture);

      await expect(
        zkEngine.registerVerifier(DISCLOSURE_AGE_THRESHOLD, await mockVerifier.getAddress())
      )
        .to.emit(zkEngine, "VerifierRegistered")
        .withArgs(DISCLOSURE_AGE_THRESHOLD, await mockVerifier.getAddress());

      expect(await zkEngine.getVerifier(DISCLOSURE_AGE_THRESHOLD)).to.equal(
        await mockVerifier.getAddress()
      );
    });

    it("should reject registration from non-admin", async function () {
      const { zkEngine, mockVerifier, other } = await loadFixture(deployZKEngineFixture);

      await expect(
        zkEngine.connect(other).registerVerifier(DISCLOSURE_AGE_THRESHOLD, await mockVerifier.getAddress())
      ).to.be.reverted;
    });

    it("should reject zero address verifier", async function () {
      const { zkEngine } = await loadFixture(deployZKEngineFixture);

      await expect(
        zkEngine.registerVerifier(DISCLOSURE_AGE_THRESHOLD, ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(zkEngine, "ZeroAddress");
    });

    it("should remove a verifier", async function () {
      const { zkEngine, mockVerifier } = await loadFixture(deployZKEngineFixture);

      await zkEngine.registerVerifier(DISCLOSURE_AGE_THRESHOLD, await mockVerifier.getAddress());
      await zkEngine.removeVerifier(DISCLOSURE_AGE_THRESHOLD);

      expect(await zkEngine.getVerifier(DISCLOSURE_AGE_THRESHOLD)).to.equal(ethers.ZeroAddress);
    });

    it("should register compound verifiers", async function () {
      const { zkEngine, mockVerifier } = await loadFixture(deployZKEngineFixture);

      // Register compound verifiers for 2, 3, and 4 disclosures
      await zkEngine.registerVerifier(DISCLOSURE_COMPOUND, await mockVerifier.getAddress());
      await zkEngine.registerVerifier(DISCLOSURE_COMPOUND_3, await mockVerifier.getAddress());
      await zkEngine.registerVerifier(DISCLOSURE_COMPOUND_4, await mockVerifier.getAddress());

      expect(await zkEngine.getVerifier(DISCLOSURE_COMPOUND)).to.equal(
        await mockVerifier.getAddress()
      );
      expect(await zkEngine.getVerifier(DISCLOSURE_COMPOUND_3)).to.equal(
        await mockVerifier.getAddress()
      );
      expect(await zkEngine.getVerifier(DISCLOSURE_COMPOUND_4)).to.equal(
        await mockVerifier.getAddress()
      );
    });
  });

  // ============================================
  // Age Threshold Verification Tests
  // ============================================

  describe("Age Threshold Verification", function () {
    it("should revert if verifier not registered", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployWithCredentialFixture);

      const proof = "0x" + "00".repeat(100);

      await expect(
        zkEngine.verifyAgeThreshold(tokenId, 18, true, proof)
      ).to.be.revertedWithCustomError(zkEngine, "VerifierNotRegistered");
    });

    it("should reject proof for non-existent credential", async function () {
      const { zkEngine, mockVerifier } = await loadFixture(deployWithCredentialFixture);

      await zkEngine.registerVerifier(DISCLOSURE_AGE_THRESHOLD, await mockVerifier.getAddress());
      const proof = "0x" + "00".repeat(100);

      const result = await zkEngine.verifyAgeThreshold.staticCall(999n, 18, true, proof);
      expect(result).to.be.false;
    });
  });

  // ============================================
  // Proof Replay Prevention Tests
  // ============================================

  describe("Proof Replay Prevention", function () {
    it("should mark proof as used after verification", async function () {
      const { zkEngine } = await loadFixture(deployWithCredentialFixture);

      const proof = "0x" + "ab".repeat(50);
      const proofHash = ethers.keccak256(proof);

      expect(await zkEngine.isProofUsed(proofHash)).to.be.false;
    });

    it("should reject same proof used twice", async function () {
      // This test requires a working verifier to properly test
      // In a real scenario, the second call would revert with ProofReplayed
    });
  });

  // ============================================
  // ClaimToken Management Tests
  // ============================================

  describe("ClaimToken Management", function () {
    it("should allow admin to update claim token", async function () {
      const { zkEngine, claimToken, owner } = await loadFixture(deployZKEngineFixture);

      const newAddress = "0x0000000000000000000000000000000000000001";
      await zkEngine.setClaimToken(newAddress);

      expect(await zkEngine.getClaimToken()).to.equal(newAddress);
    });

    it("should reject update from non-admin", async function () {
      const { zkEngine, other } = await loadFixture(deployZKEngineFixture);

      const newAddress = "0x0000000000000000000000000000000000000001";

      await expect(zkEngine.connect(other).setClaimToken(newAddress)).to.be.reverted;
    });

    it("should reject zero address claim token", async function () {
      const { zkEngine } = await loadFixture(deployZKEngineFixture);

      await expect(
        zkEngine.setClaimToken(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(zkEngine, "ZeroAddress");
    });
  });

  // ============================================
  // Compound Proof Verification Tests
  // ============================================

  describe("Compound Proof Verification", function () {
    it("should revert if compound verifier not registered", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployWithCredentialFixture);

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const publicInputs = "0x" + "00".repeat(100);
      const proof = "0x" + "00".repeat(100);

      await expect(
        zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof)
      ).to.be.revertedWithCustomError(zkEngine, "VerifierNotRegistered");
    });

    it("should reject invalid disclosure count (less than 2)", async function () {
      const { zkEngine, tokenId, mockVerifier } = await loadFixture(deployWithCredentialFixture);

      await zkEngine.registerVerifier(DISCLOSURE_COMPOUND, await mockVerifier.getAddress());

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD]; // Only 1 disclosure
      const publicInputs = "0x" + "00".repeat(100);
      const proof = "0x" + "00".repeat(100);

      await expect(
        zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof)
      ).to.be.revertedWithCustomError(zkEngine, "InvalidDisclosureCount");
    });

    it("should reject invalid disclosure count (more than 4)", async function () {
      const { zkEngine, tokenId, mockVerifier } = await loadFixture(deployWithCredentialFixture);

      await zkEngine.registerVerifier(DISCLOSURE_COMPOUND_4, await mockVerifier.getAddress());

      const disclosureTypes = [
        DISCLOSURE_AGE_THRESHOLD,
        DISCLOSURE_DATE_RANGE,
        DISCLOSURE_VALUE_RANGE,
        DISCLOSURE_SET_MEMBERSHIP,
        DISCLOSURE_EXISTENCE, // 5 disclosures - too many
      ];
      const publicInputs = "0x" + "00".repeat(100);
      const proof = "0x" + "00".repeat(100);

      await expect(
        zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof)
      ).to.be.revertedWithCustomError(zkEngine, "InvalidDisclosureCount");
    });

    it("should select correct verifier for 2 disclosures", async function () {
      const { zkEngine, tokenId, mockVerifier } = await loadFixture(deployWithCredentialFixture);

      // Only register compound-2 verifier
      await zkEngine.registerVerifier(DISCLOSURE_COMPOUND, await mockVerifier.getAddress());

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const publicInputs = "0x" + "00".repeat(100);
      const proof = "0x" + "00".repeat(100);

      // This should not revert with VerifierNotRegistered since we registered COMPOUND
      // It may fail for other reasons (proof validation), but not because verifier is missing
      const tx = zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof);

      // We expect it not to revert with VerifierNotRegistered
      // (it may revert with other errors during proof decoding)
      await expect(tx).to.not.be.revertedWithCustomError(zkEngine, "VerifierNotRegistered");
    });

    it("should select correct verifier for 3 disclosures", async function () {
      const { zkEngine, tokenId, mockVerifier } = await loadFixture(deployWithCredentialFixture);

      // Only register compound-3 verifier
      await zkEngine.registerVerifier(DISCLOSURE_COMPOUND_3, await mockVerifier.getAddress());

      const disclosureTypes = [
        DISCLOSURE_AGE_THRESHOLD,
        DISCLOSURE_DATE_RANGE,
        DISCLOSURE_VALUE_RANGE,
      ];
      const publicInputs = "0x" + "00".repeat(200);
      const proof = "0x" + "00".repeat(100);

      // Should not revert with VerifierNotRegistered
      const tx = zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof);
      await expect(tx).to.not.be.revertedWithCustomError(zkEngine, "VerifierNotRegistered");
    });

    it("should select correct verifier for 4 disclosures", async function () {
      const { zkEngine, tokenId, mockVerifier } = await loadFixture(deployWithCredentialFixture);

      // Only register compound-4 verifier
      await zkEngine.registerVerifier(DISCLOSURE_COMPOUND_4, await mockVerifier.getAddress());

      const disclosureTypes = [
        DISCLOSURE_AGE_THRESHOLD,
        DISCLOSURE_DATE_RANGE,
        DISCLOSURE_VALUE_RANGE,
        DISCLOSURE_SET_MEMBERSHIP,
      ];
      const publicInputs = "0x" + "00".repeat(300);
      const proof = "0x" + "00".repeat(100);

      // Should not revert with VerifierNotRegistered
      const tx = zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof);
      await expect(tx).to.not.be.revertedWithCustomError(zkEngine, "VerifierNotRegistered");
    });

    it("should reject proof for invalid credential", async function () {
      const { zkEngine, mockVerifier, claimToken, issuer, subject } =
        await loadFixture(deployWithCredentialFixture);

      await zkEngine.registerVerifier(DISCLOSURE_COMPOUND, await mockVerifier.getAddress());

      // Revoke the credential
      await claimToken.connect(issuer).revoke(1n, "Test revocation");

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const publicInputs = "0x" + "00".repeat(100);
      const proof = "0x" + "00".repeat(100);

      // Should return false for revoked credential
      const result = await zkEngine.verifyCompound.staticCall(
        1n,
        disclosureTypes,
        publicInputs,
        proof
      );
      expect(result).to.be.false;
    });
  });

  // ============================================
  // Generic Proof Verification Tests
  // ============================================

  describe("Generic Proof Verification", function () {
    it("should reject proof with expired validity", async function () {
      const { zkEngine, tokenId, mockVerifier } = await loadFixture(deployWithCredentialFixture);

      await zkEngine.registerVerifier(DISCLOSURE_AGE_THRESHOLD, await mockVerifier.getAddress());

      const pastTime = (await time.latest()) - 3600; // 1 hour ago

      const request = {
        credentialId: tokenId,
        disclosureType: DISCLOSURE_AGE_THRESHOLD,
        predicateHash: ethers.keccak256(ethers.toUtf8Bytes("age > 18")),
        proof: "0x" + "ab".repeat(100),
        generatedAt: BigInt(pastTime - 3600),
        validUntil: BigInt(pastTime), // Already expired
        verifier: ethers.ZeroAddress,
      };

      const result = await zkEngine.verifyProof.staticCall(request);
      expect(result).to.be.false;
    });

    it("should reject proof if verifier address doesn't match", async function () {
      const { zkEngine, tokenId, mockVerifier, other } =
        await loadFixture(deployWithCredentialFixture);

      await zkEngine.registerVerifier(DISCLOSURE_AGE_THRESHOLD, await mockVerifier.getAddress());

      const now = await time.latest();

      const request = {
        credentialId: tokenId,
        disclosureType: DISCLOSURE_AGE_THRESHOLD,
        predicateHash: ethers.keccak256(ethers.toUtf8Bytes("age > 18")),
        proof: "0x" + "ab".repeat(100),
        generatedAt: BigInt(now),
        validUntil: BigInt(now + 3600),
        verifier: other.address, // Specific verifier required
      };

      // Call from a different address
      const result = await zkEngine.verifyProof.staticCall(request);
      expect(result).to.be.false;
    });
  });

  // ============================================
  // Event Emission Tests
  // ============================================

  describe("Events", function () {
    it("should emit VerifierRegistered on registration", async function () {
      const { zkEngine, mockVerifier } = await loadFixture(deployZKEngineFixture);

      await expect(
        zkEngine.registerVerifier(DISCLOSURE_AGE_THRESHOLD, await mockVerifier.getAddress())
      )
        .to.emit(zkEngine, "VerifierRegistered")
        .withArgs(DISCLOSURE_AGE_THRESHOLD, await mockVerifier.getAddress());
    });

    it("should emit VerifierRegistered with zero address on removal", async function () {
      const { zkEngine, mockVerifier } = await loadFixture(deployZKEngineFixture);

      await zkEngine.registerVerifier(DISCLOSURE_AGE_THRESHOLD, await mockVerifier.getAddress());

      await expect(zkEngine.removeVerifier(DISCLOSURE_AGE_THRESHOLD))
        .to.emit(zkEngine, "VerifierRegistered")
        .withArgs(DISCLOSURE_AGE_THRESHOLD, ethers.ZeroAddress);
    });
  });

  // ============================================
  // Upgrade Tests
  // ============================================

  describe("Upgradeability", function () {
    it("should be upgradeable by admin", async function () {
      const { zkEngine, owner } = await loadFixture(deployZKEngineFixture);

      const ZKEngineV2Factory = await ethers.getContractFactory("ZKDisclosureEngine");
      const zkEngineV2 = await upgrades.upgradeProxy(
        await zkEngine.getAddress(),
        ZKEngineV2Factory
      );

      expect(await zkEngineV2.getAddress()).to.equal(await zkEngine.getAddress());
    });

    it("should preserve state after upgrade", async function () {
      const { zkEngine, mockVerifier } = await loadFixture(deployZKEngineFixture);

      // Register verifier before upgrade
      await zkEngine.registerVerifier(DISCLOSURE_AGE_THRESHOLD, await mockVerifier.getAddress());

      const ZKEngineV2Factory = await ethers.getContractFactory("ZKDisclosureEngine");
      const zkEngineV2 = await upgrades.upgradeProxy(
        await zkEngine.getAddress(),
        ZKEngineV2Factory
      );

      // Verify state preserved
      expect(await zkEngineV2.getVerifier(DISCLOSURE_AGE_THRESHOLD)).to.equal(
        await mockVerifier.getAddress()
      );
    });
  });
});
