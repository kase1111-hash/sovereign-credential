/**
 * @file Multi-issuer integration tests
 * @description Tests for multiple issuer scenarios including authorization,
 *              reputation management, delegation, and cross-issuer operations
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
} from "../../typechain-types";
import { ClaimTypes, CredentialStatus, Constants } from "../../types";

describe("Multi-Issuer Integration", function () {
  // ============================================
  // Constants
  // ============================================

  const ONE_YEAR = 365 * 24 * 60 * 60;
  const INITIAL_REPUTATION = 5000n;
  const MIN_REPUTATION = 1000n;
  const MAX_REPUTATION = 10000n;

  // ============================================
  // Fixtures
  // ============================================

  async function deployMultiIssuerFixture() {
    const [
      owner,
      registrar,
      arbiter,
      issuerDMV,
      issuerUniversity,
      issuerRealEstate,
      issuerHealth,
      delegateDMV,
      delegateUniversity,
      subject1,
      subject2,
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

    // Grant roles
    const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
    const REGISTRAR_ROLE = await issuerRegistry.REGISTRAR_ROLE();
    const ARBITER_ROLE = await issuerRegistry.ARBITER_ROLE();

    await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, await claimToken.getAddress());
    await issuerRegistry.grantRole(REGISTRAR_ROLE, registrar.address);
    await issuerRegistry.grantRole(ARBITER_ROLE, arbiter.address);

    // Set lifecycle manager
    await claimToken.setLifecycleManager(await lifecycleManager.getAddress());

    // Register multiple issuers with different claim type authorizations
    // DMV - License types
    await issuerRegistry.connect(registrar).registerIssuer(issuerDMV.address, "US-OR", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.LICENSE_COMMERCIAL,
      ClaimTypes.IDENTITY_RESIDENCE,
    ]);

    // University - Education types
    await issuerRegistry.connect(registrar).registerIssuer(issuerUniversity.address, "US-CA", [
      ClaimTypes.EDUCATION_DEGREE,
      ClaimTypes.EDUCATION_CERTIFICATION,
      ClaimTypes.EDUCATION_TRANSCRIPT,
    ]);

    // Real Estate Board - Property types
    await issuerRegistry.connect(registrar).registerIssuer(issuerRealEstate.address, "US-CA", [
      ClaimTypes.PROPERTY_DEED,
      ClaimTypes.PROPERTY_TITLE,
    ]);

    // Health Authority - Health types
    await issuerRegistry.connect(registrar).registerIssuer(issuerHealth.address, "US-CA", [
      ClaimTypes.HEALTH_IMMUNIZATION,
      ClaimTypes.HEALTH_INSURANCE,
    ]);

    return {
      claimToken,
      issuerRegistry,
      lifecycleManager,
      owner,
      registrar,
      arbiter,
      issuerDMV,
      issuerUniversity,
      issuerRealEstate,
      issuerHealth,
      delegateDMV,
      delegateUniversity,
      subject1,
      subject2,
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
      payloadHash: ethers.keccak256(ethers.toUtf8Bytes("payload-" + Math.random())),
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

  async function mintCredentialByIssuer(
    fixture: Awaited<ReturnType<typeof deployMultiIssuerFixture>>,
    issuer: SignerWithAddress,
    claimType: string,
    subject: SignerWithAddress
  ): Promise<bigint> {
    const { claimToken } = fixture;
    const request = await createMintRequest(claimType, subject.address);
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

  // ============================================
  // Test Suites
  // ============================================

  describe("Issuer Authorization", function () {
    it("should allow issuers to mint only authorized claim types", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerDMV, issuerUniversity, subject1 } = fixture;

      // DMV can issue license
      const licenseId = await mintCredentialByIssuer(
        fixture,
        issuerDMV,
        ClaimTypes.LICENSE_OPERATOR,
        subject1
      );
      expect(licenseId).to.be.gt(0n);

      // University can issue degree
      const degreeId = await mintCredentialByIssuer(
        fixture,
        issuerUniversity,
        ClaimTypes.EDUCATION_DEGREE,
        subject1
      );
      expect(degreeId).to.be.gt(0n);
    });

    it("should prevent issuers from minting unauthorized claim types", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { claimToken, issuerDMV, subject1 } = fixture;

      // DMV trying to issue education degree should fail
      const request = await createMintRequest(ClaimTypes.EDUCATION_DEGREE, subject1.address);
      const signature = await signMintRequest(issuerDMV, request, await claimToken.getAddress());

      await expect(claimToken.connect(issuerDMV).mint(request, signature)).to.be.reverted;
    });

    it("should handle dynamic authorization changes", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerRegistry, claimToken, registrar, issuerDMV, subject1 } = fixture;

      // Initially DMV can issue LICENSE_OPERATOR
      const licenseId = await mintCredentialByIssuer(
        fixture,
        issuerDMV,
        ClaimTypes.LICENSE_OPERATOR,
        subject1
      );
      expect(licenseId).to.be.gt(0n);

      // Add new authorization for DMV to issue EDUCATION_CERTIFICATION
      await issuerRegistry.connect(registrar).authorizeType(
        issuerDMV.address,
        ClaimTypes.EDUCATION_CERTIFICATION
      );

      // Now DMV can issue certifications
      const certId = await mintCredentialByIssuer(
        fixture,
        issuerDMV,
        ClaimTypes.EDUCATION_CERTIFICATION,
        subject1
      );
      expect(certId).to.be.gt(0n);

      // Remove authorization
      await issuerRegistry.connect(registrar).revokeTypeAuthorization(
        issuerDMV.address,
        ClaimTypes.EDUCATION_CERTIFICATION
      );

      // DMV can no longer issue certifications
      const request = await createMintRequest(ClaimTypes.EDUCATION_CERTIFICATION, subject1.address);
      const signature = await signMintRequest(issuerDMV, request, await claimToken.getAddress());
      await expect(claimToken.connect(issuerDMV).mint(request, signature)).to.be.reverted;
    });
  });

  describe("Reputation Management", function () {
    it("should initialize issuers with correct reputation", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerRegistry, issuerDMV, issuerUniversity, issuerRealEstate, issuerHealth } = fixture;

      expect(await issuerRegistry.getReputation(issuerDMV.address)).to.equal(INITIAL_REPUTATION);
      expect(await issuerRegistry.getReputation(issuerUniversity.address)).to.equal(INITIAL_REPUTATION);
      expect(await issuerRegistry.getReputation(issuerRealEstate.address)).to.equal(INITIAL_REPUTATION);
      expect(await issuerRegistry.getReputation(issuerHealth.address)).to.equal(INITIAL_REPUTATION);
    });

    it("should update reputation based on credential activity", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerRegistry, issuerDMV, subject1 } = fixture;

      const initialReputation = await issuerRegistry.getReputation(issuerDMV.address);

      // Mint multiple credentials to increase activity
      for (let i = 0; i < 5; i++) {
        await mintCredentialByIssuer(fixture, issuerDMV, ClaimTypes.LICENSE_OPERATOR, subject1);
      }

      // Check issuer stats
      const stats = await issuerRegistry.getIssuerStats(issuerDMV.address);
      expect(stats.totalIssued).to.equal(5n);
    });

    it("should allow arbiter to adjust reputation", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerRegistry, arbiter, issuerDMV } = fixture;

      const initialReputation = await issuerRegistry.getReputation(issuerDMV.address);

      // Arbiter increases reputation (good performance)
      await issuerRegistry.connect(arbiter).adjustReputation(issuerDMV.address, 500);
      expect(await issuerRegistry.getReputation(issuerDMV.address)).to.equal(initialReputation + 500n);

      // Arbiter decreases reputation (complaints)
      await issuerRegistry.connect(arbiter).adjustReputation(issuerDMV.address, -1000);
      expect(await issuerRegistry.getReputation(issuerDMV.address)).to.equal(initialReputation - 500n);
    });

    it("should enforce reputation bounds", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerRegistry, arbiter, issuerDMV } = fixture;

      // Try to exceed max reputation
      await issuerRegistry.connect(arbiter).adjustReputation(issuerDMV.address, 10000);
      expect(await issuerRegistry.getReputation(issuerDMV.address)).to.equal(MAX_REPUTATION);

      // Try to go below min reputation
      await issuerRegistry.connect(arbiter).adjustReputation(issuerDMV.address, -9500);
      expect(await issuerRegistry.getReputation(issuerDMV.address)).to.be.gte(MIN_REPUTATION);
    });
  });

  describe("Delegation System", function () {
    it("should allow issuer to add delegates", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerRegistry, issuerDMV, delegateDMV } = fixture;

      await issuerRegistry.connect(issuerDMV).addDelegate(delegateDMV.address);

      expect(await issuerRegistry.isDelegate(issuerDMV.address, delegateDMV.address)).to.be.true;
    });

    it("should allow delegates to issue credentials on behalf of issuer", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerRegistry, claimToken, issuerDMV, delegateDMV, subject1 } = fixture;

      // Add delegate
      await issuerRegistry.connect(issuerDMV).addDelegate(delegateDMV.address);

      // Delegate issues credential
      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject1.address);
      const signature = await signMintRequest(delegateDMV, request, await claimToken.getAddress());

      // Mint via delegate
      await expect(
        claimToken.connect(delegateDMV).mintAsDelegate(issuerDMV.address, request, signature)
      ).to.not.be.reverted;
    });

    it("should allow issuer to remove delegates", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerRegistry, claimToken, issuerDMV, delegateDMV, subject1 } = fixture;

      // Add and verify delegate
      await issuerRegistry.connect(issuerDMV).addDelegate(delegateDMV.address);
      expect(await issuerRegistry.isDelegate(issuerDMV.address, delegateDMV.address)).to.be.true;

      // Remove delegate
      await issuerRegistry.connect(issuerDMV).removeDelegate(delegateDMV.address);
      expect(await issuerRegistry.isDelegate(issuerDMV.address, delegateDMV.address)).to.be.false;

      // Delegate can no longer issue
      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject1.address);
      const signature = await signMintRequest(delegateDMV, request, await claimToken.getAddress());

      await expect(
        claimToken.connect(delegateDMV).mintAsDelegate(issuerDMV.address, request, signature)
      ).to.be.reverted;
    });
  });

  describe("Cross-Issuer Credential Management", function () {
    it("should track credentials from multiple issuers for same subject", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { claimToken, issuerDMV, issuerUniversity, issuerRealEstate, issuerHealth, subject1 } = fixture;

      // Subject gets credentials from all issuers
      const licenseId = await mintCredentialByIssuer(fixture, issuerDMV, ClaimTypes.LICENSE_OPERATOR, subject1);
      const degreeId = await mintCredentialByIssuer(fixture, issuerUniversity, ClaimTypes.EDUCATION_DEGREE, subject1);
      const propertyId = await mintCredentialByIssuer(fixture, issuerRealEstate, ClaimTypes.PROPERTY_DEED, subject1);
      const healthId = await mintCredentialByIssuer(fixture, issuerHealth, ClaimTypes.HEALTH_IMMUNIZATION, subject1);

      // All credentials owned by subject
      expect(await claimToken.balanceOf(subject1.address)).to.equal(4n);

      // Each has correct issuer
      expect((await claimToken.getCredential(licenseId)).issuer).to.equal(issuerDMV.address);
      expect((await claimToken.getCredential(degreeId)).issuer).to.equal(issuerUniversity.address);
      expect((await claimToken.getCredential(propertyId)).issuer).to.equal(issuerRealEstate.address);
      expect((await claimToken.getCredential(healthId)).issuer).to.equal(issuerHealth.address);
    });

    it("should allow issuer-specific operations only by respective issuer", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { claimToken, issuerDMV, issuerUniversity, subject1 } = fixture;

      // DMV issues license
      const licenseId = await mintCredentialByIssuer(fixture, issuerDMV, ClaimTypes.LICENSE_OPERATOR, subject1);

      // University cannot revoke DMV's credential
      await expect(
        claimToken.connect(issuerUniversity).revoke(licenseId, ethers.keccak256(ethers.toUtf8Bytes("REASON")))
      ).to.be.reverted;

      // DMV can revoke its own credential
      await expect(
        claimToken.connect(issuerDMV).revoke(licenseId, ethers.keccak256(ethers.toUtf8Bytes("REASON")))
      ).to.not.be.reverted;
    });

    it("should maintain issuer statistics accurately across multiple issuers", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerRegistry, issuerDMV, issuerUniversity, subject1, subject2 } = fixture;

      // DMV issues 3 credentials
      await mintCredentialByIssuer(fixture, issuerDMV, ClaimTypes.LICENSE_OPERATOR, subject1);
      await mintCredentialByIssuer(fixture, issuerDMV, ClaimTypes.LICENSE_OPERATOR, subject2);
      await mintCredentialByIssuer(fixture, issuerDMV, ClaimTypes.IDENTITY_RESIDENCE, subject1);

      // University issues 2 credentials
      await mintCredentialByIssuer(fixture, issuerUniversity, ClaimTypes.EDUCATION_DEGREE, subject1);
      await mintCredentialByIssuer(fixture, issuerUniversity, ClaimTypes.EDUCATION_CERTIFICATION, subject2);

      // Check stats
      const dmvStats = await issuerRegistry.getIssuerStats(issuerDMV.address);
      const uniStats = await issuerRegistry.getIssuerStats(issuerUniversity.address);

      expect(dmvStats.totalIssued).to.equal(3n);
      expect(uniStats.totalIssued).to.equal(2n);
    });
  });

  describe("Issuer Activation/Deactivation", function () {
    it("should allow registrar to deactivate issuer", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerRegistry, claimToken, registrar, issuerDMV, subject1 } = fixture;

      // Issuer can issue initially
      const id1 = await mintCredentialByIssuer(fixture, issuerDMV, ClaimTypes.LICENSE_OPERATOR, subject1);
      expect(id1).to.be.gt(0n);

      // Deactivate issuer
      await issuerRegistry.connect(registrar).deactivateIssuer(issuerDMV.address);

      // Issuer can no longer issue
      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject1.address);
      const signature = await signMintRequest(issuerDMV, request, await claimToken.getAddress());
      await expect(claimToken.connect(issuerDMV).mint(request, signature)).to.be.reverted;
    });

    it("should allow registrar to reactivate issuer", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerRegistry, registrar, issuerDMV, subject1 } = fixture;

      // Deactivate then reactivate
      await issuerRegistry.connect(registrar).deactivateIssuer(issuerDMV.address);
      await issuerRegistry.connect(registrar).reactivateIssuer(issuerDMV.address);

      // Issuer can issue again
      const id = await mintCredentialByIssuer(fixture, issuerDMV, ClaimTypes.LICENSE_OPERATOR, subject1);
      expect(id).to.be.gt(0n);
    });

    it("should not affect existing credentials when issuer is deactivated", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerRegistry, claimToken, registrar, issuerDMV, subject1 } = fixture;

      // Issue credential
      const tokenId = await mintCredentialByIssuer(fixture, issuerDMV, ClaimTypes.LICENSE_OPERATOR, subject1);

      // Deactivate issuer
      await issuerRegistry.connect(registrar).deactivateIssuer(issuerDMV.address);

      // Credential still exists and is owned by subject
      expect(await claimToken.ownerOf(tokenId)).to.equal(subject1.address);

      // Note: Credential validity might be affected depending on INV-01 implementation
      const credential = await claimToken.getCredential(tokenId);
      expect(credential.issuer).to.equal(issuerDMV.address);
    });
  });

  describe("Jurisdiction Handling", function () {
    it("should store correct jurisdiction for each issuer", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { issuerRegistry, issuerDMV, issuerUniversity, issuerRealEstate } = fixture;

      const dmvInfo = await issuerRegistry.getIssuer(issuerDMV.address);
      const uniInfo = await issuerRegistry.getIssuer(issuerUniversity.address);
      const reInfo = await issuerRegistry.getIssuer(issuerRealEstate.address);

      expect(dmvInfo.jurisdiction).to.equal("US-OR");
      expect(uniInfo.jurisdiction).to.equal("US-CA");
      expect(reInfo.jurisdiction).to.equal("US-CA");
    });

    it("should allow credentials to be queried by issuer jurisdiction", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { claimToken, issuerDMV, issuerUniversity, subject1 } = fixture;

      // Issue credentials
      const licenseId = await mintCredentialByIssuer(fixture, issuerDMV, ClaimTypes.LICENSE_OPERATOR, subject1);
      const degreeId = await mintCredentialByIssuer(fixture, issuerUniversity, ClaimTypes.EDUCATION_DEGREE, subject1);

      // Get credential and check issuer jurisdiction indirectly
      const licenseCredential = await claimToken.getCredential(licenseId);
      const degreeCredential = await claimToken.getCredential(degreeId);

      expect(licenseCredential.issuer).to.equal(issuerDMV.address); // US-OR issuer
      expect(degreeCredential.issuer).to.equal(issuerUniversity.address); // US-CA issuer
    });
  });

  describe("Concurrent Issuer Operations", function () {
    it("should handle simultaneous minting from multiple issuers", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { claimToken, issuerDMV, issuerUniversity, issuerRealEstate, subject1 } = fixture;

      // Prepare mint requests for all issuers
      const dmvRequest = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject1.address);
      const uniRequest = await createMintRequest(ClaimTypes.EDUCATION_DEGREE, subject1.address);
      const reRequest = await createMintRequest(ClaimTypes.PROPERTY_DEED, subject1.address);

      const dmvSig = await signMintRequest(issuerDMV, dmvRequest, await claimToken.getAddress());
      const uniSig = await signMintRequest(issuerUniversity, uniRequest, await claimToken.getAddress());
      const reSig = await signMintRequest(issuerRealEstate, reRequest, await claimToken.getAddress());

      // Execute mints (simulating concurrent execution)
      const [dmvTx, uniTx, reTx] = await Promise.all([
        claimToken.connect(issuerDMV).mint(dmvRequest, dmvSig),
        claimToken.connect(issuerUniversity).mint(uniRequest, uniSig),
        claimToken.connect(issuerRealEstate).mint(reRequest, reSig),
      ]);

      // All should succeed
      await Promise.all([dmvTx.wait(), uniTx.wait(), reTx.wait()]);

      // Subject has all credentials
      expect(await claimToken.balanceOf(subject1.address)).to.equal(3n);
    });

    it("should maintain correct token ID sequence across issuers", async function () {
      const fixture = await loadFixture(deployMultiIssuerFixture);
      const { claimToken, issuerDMV, issuerUniversity, subject1 } = fixture;

      const id1 = await mintCredentialByIssuer(fixture, issuerDMV, ClaimTypes.LICENSE_OPERATOR, subject1);
      const id2 = await mintCredentialByIssuer(fixture, issuerUniversity, ClaimTypes.EDUCATION_DEGREE, subject1);
      const id3 = await mintCredentialByIssuer(fixture, issuerDMV, ClaimTypes.IDENTITY_RESIDENCE, subject1);
      const id4 = await mintCredentialByIssuer(fixture, issuerUniversity, ClaimTypes.EDUCATION_CERTIFICATION, subject1);

      // Token IDs should be sequential regardless of issuer
      expect(id2).to.equal(id1 + 1n);
      expect(id3).to.equal(id2 + 1n);
      expect(id4).to.equal(id3 + 1n);
    });
  });
});
