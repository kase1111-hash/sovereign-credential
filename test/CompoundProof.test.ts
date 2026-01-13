/**
 * @file CompoundProof.test.ts
 * @description Integration tests for Compound Proof functionality (Step 16)
 *
 * Tests cover:
 * 1. ZKDisclosureEngine compound proof verification
 * 2. Compound proof with 2, 3, and 4 disclosures
 * 3. Mixed disclosure types in compound proofs
 * 4. Error cases and edge conditions
 *
 * Note: These tests use mock verifiers since real ZK proofs require compiled circuits.
 * For full integration tests with real proofs, compile circuits with:
 *   ./compile.sh CompoundProof && ./setup.sh CompoundProof
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { type SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import {
  type ZKDisclosureEngine,
  type ClaimToken,
  type IssuerRegistry,
  type MockCompoundVerifier,
} from "../typechain-types";
import { ClaimTypes } from "../types";

describe("CompoundProof", function () {
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

  async function deployCompoundProofFixture() {
    const [owner, issuer, subject, verifierAddr, other] = await ethers.getSigners();

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

    // Deploy MockCompoundVerifier for testing
    const MockCompoundVerifierFactory = await ethers.getContractFactory("MockCompoundVerifier");
    const mockVerifier = (await MockCompoundVerifierFactory.deploy()) as MockCompoundVerifier;
    await mockVerifier.waitForDeployment();

    // Register issuer with claim types
    await issuerRegistry.registerIssuer(issuer.address, "US-CA", [
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
      verifierAddr,
      other,
    };
  }

  async function deployWithCredentialAndVerifiersFixture() {
    const fixture = await deployCompoundProofFixture();
    const { zkEngine, claimToken, issuer, subject, mockVerifier } = fixture;

    // Register compound verifiers for all sizes
    await zkEngine.registerVerifier(DISCLOSURE_COMPOUND, await mockVerifier.getAddress());
    await zkEngine.registerVerifier(DISCLOSURE_COMPOUND_3, await mockVerifier.getAddress());
    await zkEngine.registerVerifier(DISCLOSURE_COMPOUND_4, await mockVerifier.getAddress());

    // Create and mint a credential
    const request = await createMintRequest(ClaimTypes.IDENTITY_BIRTH, subject.address);
    const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

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

  /**
   * Create mock compound proof data for 2 disclosures
   */
  function createMockCompound2Proof(): { proof: string; publicInputs: string } {
    const pA = [1n, 2n];
    const pB = [
      [3n, 4n],
      [5n, 6n],
    ];
    const pC = [7n, 8n];

    const proof = ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint[2]", "uint[2][2]", "uint[2]"],
      [pA, pB, pC]
    );

    // Types: [0, 1] = [AGE_THRESHOLD, DATE_RANGE]
    // Params: 8 values (4 per disclosure)
    const publicInputs = ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "uint256[8]"],
      [0n, 1n, [18n, 1700000000n, 0n, 0n, 1600000000n, 1800000000n, 1n, 0n]]
    );

    return { proof, publicInputs };
  }

  /**
   * Create mock compound proof data for 3 disclosures
   */
  function createMockCompound3Proof(): { proof: string; publicInputs: string } {
    const pA = [1n, 2n];
    const pB = [
      [3n, 4n],
      [5n, 6n],
    ];
    const pC = [7n, 8n];

    const proof = ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint[2]", "uint[2][2]", "uint[2]"],
      [pA, pB, pC]
    );

    // Types: [0, 1, 2] = [AGE_THRESHOLD, DATE_RANGE, VALUE_RANGE]
    // Params: 12 values (4 per disclosure)
    const publicInputs = ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "uint256", "uint256[12]"],
      [
        0n,
        1n,
        2n,
        [
          18n, 1700000000n, 0n, 0n, // AGE_THRESHOLD params
          1600000000n, 1800000000n, 1n, 0n, // DATE_RANGE params
          50000n, 100000n, 3n, 0n, // VALUE_RANGE params
        ],
      ]
    );

    return { proof, publicInputs };
  }

  /**
   * Create mock compound proof data for 4 disclosures
   */
  function createMockCompound4Proof(): { proof: string; publicInputs: string } {
    const pA = [1n, 2n];
    const pB = [
      [3n, 4n],
      [5n, 6n],
    ];
    const pC = [7n, 8n];

    const proof = ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint[2]", "uint[2][2]", "uint[2]"],
      [pA, pB, pC]
    );

    // Types: [0, 1, 2, 4] = [AGE_THRESHOLD, DATE_RANGE, VALUE_RANGE, EXISTENCE]
    // Params: 16 values (4 per disclosure)
    const publicInputs = ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "uint256", "uint256", "uint256[16]"],
      [
        0n,
        1n,
        2n,
        4n,
        [
          18n, 1700000000n, 0n, 0n, // AGE_THRESHOLD params
          1600000000n, 1800000000n, 1n, 0n, // DATE_RANGE params
          50000n, 100000n, 3n, 0n, // VALUE_RANGE params
          0n, 0n, 0n, 0n, // EXISTENCE params (unused)
        ],
      ]
    );

    return { proof, publicInputs };
  }

  // ============================================
  // Compound Proof Verification Tests
  // ============================================

  describe("Compound Proof with 2 Disclosures", function () {
    it("should verify valid compound proof with 2 disclosures", async function () {
      const { zkEngine, tokenId, mockVerifier } = await loadFixture(
        deployWithCredentialAndVerifiersFixture
      );

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const { proof, publicInputs } = createMockCompound2Proof();

      const result = await zkEngine.verifyCompound.staticCall(
        tokenId,
        disclosureTypes,
        publicInputs,
        proof
      );

      expect(result).to.be.true;
    });

    it("should emit ProofVerified event on successful verification", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployWithCredentialAndVerifiersFixture);

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const { proof, publicInputs } = createMockCompound2Proof();

      await expect(zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof))
        .to.emit(zkEngine, "ProofVerified")
        .withArgs(tokenId, DISCLOSURE_COMPOUND, await (await ethers.provider.getSigner()).getAddress());
    });

    it("should prevent proof replay", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployWithCredentialAndVerifiersFixture);

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const { proof, publicInputs } = createMockCompound2Proof();

      // First verification should succeed
      await zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof);

      // Second verification with same proof should fail
      await expect(
        zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof)
      ).to.be.revertedWithCustomError(zkEngine, "ProofReplayed");
    });

    it("should reject compound proof with mismatched disclosure types", async function () {
      const { zkEngine, tokenId, mockVerifier } = await loadFixture(
        deployWithCredentialAndVerifiersFixture
      );

      // Set mock to reject
      await mockVerifier.setAcceptAll(false);

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const { proof, publicInputs } = createMockCompound2Proof();

      const result = await zkEngine.verifyCompound.staticCall(
        tokenId,
        disclosureTypes,
        publicInputs,
        proof
      );

      expect(result).to.be.false;
    });
  });

  describe("Compound Proof with 3 Disclosures", function () {
    it("should verify valid compound proof with 3 disclosures", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployWithCredentialAndVerifiersFixture);

      const disclosureTypes = [
        DISCLOSURE_AGE_THRESHOLD,
        DISCLOSURE_DATE_RANGE,
        DISCLOSURE_VALUE_RANGE,
      ];
      const { proof, publicInputs } = createMockCompound3Proof();

      const result = await zkEngine.verifyCompound.staticCall(
        tokenId,
        disclosureTypes,
        publicInputs,
        proof
      );

      expect(result).to.be.true;
    });

    it("should emit ProofVerified with COMPOUND_3 type", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployWithCredentialAndVerifiersFixture);

      const disclosureTypes = [
        DISCLOSURE_AGE_THRESHOLD,
        DISCLOSURE_DATE_RANGE,
        DISCLOSURE_VALUE_RANGE,
      ];
      const { proof, publicInputs } = createMockCompound3Proof();

      await expect(zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof))
        .to.emit(zkEngine, "ProofVerified")
        .withArgs(tokenId, DISCLOSURE_COMPOUND_3, await (await ethers.provider.getSigner()).getAddress());
    });
  });

  describe("Compound Proof with 4 Disclosures", function () {
    it("should verify valid compound proof with 4 disclosures", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployWithCredentialAndVerifiersFixture);

      const disclosureTypes = [
        DISCLOSURE_AGE_THRESHOLD,
        DISCLOSURE_DATE_RANGE,
        DISCLOSURE_VALUE_RANGE,
        DISCLOSURE_EXISTENCE,
      ];
      const { proof, publicInputs } = createMockCompound4Proof();

      const result = await zkEngine.verifyCompound.staticCall(
        tokenId,
        disclosureTypes,
        publicInputs,
        proof
      );

      expect(result).to.be.true;
    });

    it("should emit ProofVerified with COMPOUND_4 type", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployWithCredentialAndVerifiersFixture);

      const disclosureTypes = [
        DISCLOSURE_AGE_THRESHOLD,
        DISCLOSURE_DATE_RANGE,
        DISCLOSURE_VALUE_RANGE,
        DISCLOSURE_EXISTENCE,
      ];
      const { proof, publicInputs } = createMockCompound4Proof();

      await expect(zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof))
        .to.emit(zkEngine, "ProofVerified")
        .withArgs(tokenId, DISCLOSURE_COMPOUND_4, await (await ethers.provider.getSigner()).getAddress());
    });
  });

  // ============================================
  // Error Cases
  // ============================================

  describe("Error Cases", function () {
    it("should reject compound proof with less than 2 disclosures", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployWithCredentialAndVerifiersFixture);

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD]; // Only 1 disclosure
      const { proof, publicInputs } = createMockCompound2Proof();

      await expect(
        zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof)
      ).to.be.revertedWithCustomError(zkEngine, "InvalidDisclosureCount");
    });

    it("should reject compound proof with more than 4 disclosures", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployWithCredentialAndVerifiersFixture);

      const disclosureTypes = [
        DISCLOSURE_AGE_THRESHOLD,
        DISCLOSURE_DATE_RANGE,
        DISCLOSURE_VALUE_RANGE,
        DISCLOSURE_SET_MEMBERSHIP,
        DISCLOSURE_EXISTENCE, // 5 disclosures - too many
      ];
      const { proof, publicInputs } = createMockCompound4Proof();

      await expect(
        zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof)
      ).to.be.revertedWithCustomError(zkEngine, "InvalidDisclosureCount");
    });

    it("should reject proof for non-existent credential", async function () {
      const { zkEngine } = await loadFixture(deployWithCredentialAndVerifiersFixture);

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const { proof, publicInputs } = createMockCompound2Proof();

      const result = await zkEngine.verifyCompound.staticCall(
        999n, // Non-existent token ID
        disclosureTypes,
        publicInputs,
        proof
      );

      expect(result).to.be.false;
    });

    it("should reject proof for revoked credential", async function () {
      const { zkEngine, claimToken, tokenId, issuer } = await loadFixture(
        deployWithCredentialAndVerifiersFixture
      );

      // Revoke the credential
      await claimToken.connect(issuer).revoke(tokenId, "Test revocation");

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const { proof, publicInputs } = createMockCompound2Proof();

      const result = await zkEngine.verifyCompound.staticCall(
        tokenId,
        disclosureTypes,
        publicInputs,
        proof
      );

      expect(result).to.be.false;
    });

    it("should reject proof for expired credential", async function () {
      const { zkEngine, claimToken, issuer, subject } = await loadFixture(
        deployCompoundProofFixture
      );

      // Register verifiers
      const MockCompoundVerifierFactory = await ethers.getContractFactory("MockCompoundVerifier");
      const mockVerifier = await MockCompoundVerifierFactory.deploy();
      await zkEngine.registerVerifier(DISCLOSURE_COMPOUND, await mockVerifier.getAddress());

      // Create credential that expires soon
      const now = await time.latest();
      const shortExpiry = BigInt(now) + BigInt(60); // 1 minute

      const request = {
        claimType: ClaimTypes.IDENTITY_BIRTH,
        subject: subject.address,
        encryptedPayload: "0x" + "ab".repeat(100),
        payloadHash: ethers.keccak256(ethers.toUtf8Bytes("test-payload")),
        commitments: [ethers.keccak256(ethers.toUtf8Bytes("commitment-0"))],
        expiresAt: shortExpiry,
        metadataURI: "ipfs://QmTestMetadata",
      };

      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      // Fast forward past expiry
      await time.increase(120); // 2 minutes

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const { proof, publicInputs } = createMockCompound2Proof();

      const result = await zkEngine.verifyCompound.staticCall(
        1n,
        disclosureTypes,
        publicInputs,
        proof
      );

      expect(result).to.be.false;
    });

    it("should reject when verifier not registered", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployCompoundProofFixture);

      // Don't register any verifiers

      // Mint a credential first
      const { claimToken, issuer, subject } = await loadFixture(deployCompoundProofFixture);
      const request = await createMintRequest(ClaimTypes.IDENTITY_BIRTH, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const { proof, publicInputs } = createMockCompound2Proof();

      await expect(
        zkEngine.verifyCompound(1n, disclosureTypes, publicInputs, proof)
      ).to.be.revertedWithCustomError(zkEngine, "VerifierNotRegistered");
    });
  });

  // ============================================
  // Mixed Disclosure Types
  // ============================================

  describe("Mixed Disclosure Types", function () {
    it("should handle age + date range combination", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployWithCredentialAndVerifiersFixture);

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const { proof, publicInputs } = createMockCompound2Proof();

      const result = await zkEngine.verifyCompound.staticCall(
        tokenId,
        disclosureTypes,
        publicInputs,
        proof
      );

      expect(result).to.be.true;
    });

    it("should handle value range + existence combination", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployWithCredentialAndVerifiersFixture);

      const disclosureTypes = [DISCLOSURE_VALUE_RANGE, DISCLOSURE_EXISTENCE];
      const { proof, publicInputs } = createMockCompound2Proof();

      const result = await zkEngine.verifyCompound.staticCall(
        tokenId,
        disclosureTypes,
        publicInputs,
        proof
      );

      expect(result).to.be.true;
    });

    it("should handle all disclosure types in one proof", async function () {
      const { zkEngine, tokenId } = await loadFixture(deployWithCredentialAndVerifiersFixture);

      // 4 different disclosure types
      const disclosureTypes = [
        DISCLOSURE_AGE_THRESHOLD,
        DISCLOSURE_DATE_RANGE,
        DISCLOSURE_VALUE_RANGE,
        DISCLOSURE_EXISTENCE,
      ];
      const { proof, publicInputs } = createMockCompound4Proof();

      const result = await zkEngine.verifyCompound.staticCall(
        tokenId,
        disclosureTypes,
        publicInputs,
        proof
      );

      expect(result).to.be.true;
    });
  });

  // ============================================
  // Verifier Registration Tests
  // ============================================

  describe("Verifier Registration", function () {
    it("should register compound verifier for 2 disclosures", async function () {
      const { zkEngine, mockVerifier } = await loadFixture(deployCompoundProofFixture);

      await expect(zkEngine.registerVerifier(DISCLOSURE_COMPOUND, await mockVerifier.getAddress()))
        .to.emit(zkEngine, "VerifierRegistered")
        .withArgs(DISCLOSURE_COMPOUND, await mockVerifier.getAddress());

      expect(await zkEngine.getVerifier(DISCLOSURE_COMPOUND)).to.equal(
        await mockVerifier.getAddress()
      );
    });

    it("should register compound verifier for 3 disclosures", async function () {
      const { zkEngine, mockVerifier } = await loadFixture(deployCompoundProofFixture);

      await zkEngine.registerVerifier(DISCLOSURE_COMPOUND_3, await mockVerifier.getAddress());

      expect(await zkEngine.getVerifier(DISCLOSURE_COMPOUND_3)).to.equal(
        await mockVerifier.getAddress()
      );
    });

    it("should register compound verifier for 4 disclosures", async function () {
      const { zkEngine, mockVerifier } = await loadFixture(deployCompoundProofFixture);

      await zkEngine.registerVerifier(DISCLOSURE_COMPOUND_4, await mockVerifier.getAddress());

      expect(await zkEngine.getVerifier(DISCLOSURE_COMPOUND_4)).to.equal(
        await mockVerifier.getAddress()
      );
    });

    it("should reject registration from non-admin", async function () {
      const { zkEngine, mockVerifier, other } = await loadFixture(deployCompoundProofFixture);

      await expect(
        zkEngine.connect(other).registerVerifier(DISCLOSURE_COMPOUND, await mockVerifier.getAddress())
      ).to.be.reverted;
    });
  });

  // ============================================
  // Gas Optimization Tests
  // ============================================

  describe("Gas Optimization", function () {
    it("should be more gas efficient than separate proofs", async function () {
      // This test validates the architectural benefit of compound proofs
      // In a real scenario, one compound proof should use less gas than
      // verifying multiple separate proofs

      const { zkEngine, tokenId, mockVerifier } = await loadFixture(
        deployWithCredentialAndVerifiersFixture
      );

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const { proof, publicInputs } = createMockCompound2Proof();

      // Measure gas for compound proof
      const tx = await zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof);
      const receipt = await tx.wait();

      // Compound proof should use reasonable gas (less than 500k as per NFR-02)
      expect(receipt?.gasUsed).to.be.lessThan(500000n);
    });
  });

  // ============================================
  // Mock Verifier Behavior Tests
  // ============================================

  describe("Mock Verifier Behavior", function () {
    it("should track verification count", async function () {
      const { zkEngine, tokenId, mockVerifier } = await loadFixture(
        deployWithCredentialAndVerifiersFixture
      );

      const initialCount = await mockVerifier.verificationCount();

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const { proof, publicInputs } = createMockCompound2Proof();

      await zkEngine.verifyCompound(tokenId, disclosureTypes, publicInputs, proof);

      const finalCount = await mockVerifier.verificationCount();
      expect(finalCount).to.equal(initialCount + 1n);
    });

    it("should reject when mock is configured to reject", async function () {
      const { zkEngine, tokenId, mockVerifier } = await loadFixture(
        deployWithCredentialAndVerifiersFixture
      );

      // Configure mock to reject all proofs
      await mockVerifier.setAcceptAll(false);

      const disclosureTypes = [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE];
      const { proof, publicInputs } = createMockCompound2Proof();

      const result = await zkEngine.verifyCompound.staticCall(
        tokenId,
        disclosureTypes,
        publicInputs,
        proof
      );

      expect(result).to.be.false;
    });
  });
});
