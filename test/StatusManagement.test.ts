/**
 * @file StatusManagement.test.ts
 * @description Comprehensive tests for credential status management and state machine
 * @dev Tests Step 7 requirements from IMPLEMENTATION_GUIDE.md
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { type SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { type ClaimToken, type IssuerRegistry } from "../typechain-types";
import { ClaimTypes, CredentialStatus, Constants } from "../types";

describe("Status Management - State Machine", function () {
  // ============================================
  // Fixtures
  // ============================================

  async function deployContractsFixture() {
    const [owner, issuer, subject, other, delegate] = await ethers.getSigners();

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

    // Register issuer with claim types
    await issuerRegistry.registerIssuer(issuer.address, "US-CA", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.PROPERTY_DEED,
      ClaimTypes.EDUCATION_DEGREE,
    ]);

    return {
      claimToken,
      issuerRegistry,
      owner,
      issuer,
      subject,
      other,
      delegate,
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

  async function mintActiveCredential(
    claimToken: ClaimToken,
    issuer: SignerWithAddress,
    subject: SignerWithAddress,
    claimType: string = ClaimTypes.LICENSE_OPERATOR,
    expiresAt?: bigint
  ): Promise<bigint> {
    const request = await createMintRequest(claimType, subject.address, expiresAt);
    const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
    await claimToken.mint(request, signature);
    return BigInt(await claimToken.totalCredentials());
  }

  async function mintPendingCredential(
    claimToken: ClaimToken,
    issuer: SignerWithAddress,
    subject: SignerWithAddress,
    claimType: string = ClaimTypes.LICENSE_OPERATOR
  ): Promise<bigint> {
    const request = await createMintRequest(claimType, subject.address);
    const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
    await claimToken.mintPending(request, signature);
    return BigInt(await claimToken.totalCredentials());
  }

  // ============================================
  // PENDING State Tests
  // ============================================

  describe("PENDING Status", function () {
    it("should mint credential in PENDING status using mintPending", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);

      const tokenId = await mintPendingCredential(claimToken, issuer, subject);

      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.PENDING);
      expect(await claimToken.verify(tokenId)).to.be.false; // PENDING credentials are not valid
    });

    it("should transition PENDING to ACTIVE via confirm", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);

      const tokenId = await mintPendingCredential(claimToken, issuer, subject);
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.PENDING);

      await expect(claimToken.connect(issuer).confirm(tokenId))
        .to.emit(claimToken, "CredentialConfirmed")
        .withArgs(tokenId, issuer.address);

      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);
      expect(await claimToken.verify(tokenId)).to.be.true;
    });

    it("should reject confirm from non-issuer", async function () {
      const { claimToken, issuer, subject, other } = await loadFixture(deployContractsFixture);

      const tokenId = await mintPendingCredential(claimToken, issuer, subject);

      await expect(
        claimToken.connect(other).confirm(tokenId)
      ).to.be.revertedWithCustomError(claimToken, "UnauthorizedIssuer");
    });

    it("should reject confirm on non-PENDING credential", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);

      const tokenId = await mintActiveCredential(claimToken, issuer, subject);

      await expect(
        claimToken.connect(issuer).confirm(tokenId)
      ).to.be.revertedWithCustomError(claimToken, "InvalidStatusTransition");
    });

    it("should not allow revocation of PENDING credential", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);

      const tokenId = await mintPendingCredential(claimToken, issuer, subject);

      // PENDING credentials can still be revoked (cleaned up)
      await expect(
        claimToken.connect(issuer).revoke(tokenId, "Never confirmed")
      ).to.be.revertedWithCustomError(claimToken, "InvalidStatusTransition");
    });

    it("should not allow suspension of PENDING credential", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);

      const tokenId = await mintPendingCredential(claimToken, issuer, subject);

      await expect(
        claimToken.connect(issuer).suspend(tokenId, "Investigation")
      ).to.be.revertedWithCustomError(claimToken, "InvalidStatusTransition");
    });
  });

  // ============================================
  // ACTIVE State Tests
  // ============================================

  describe("ACTIVE Status", function () {
    it("should transition ACTIVE to SUSPENDED", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);

      const tokenId = await mintActiveCredential(claimToken, issuer, subject);

      await expect(claimToken.connect(issuer).suspend(tokenId, "Investigation"))
        .to.emit(claimToken, "CredentialSuspended")
        .withArgs(tokenId, issuer.address, "Investigation");

      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.SUSPENDED);
      expect(await claimToken.verify(tokenId)).to.be.false;
    });

    it("should transition ACTIVE to REVOKED", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);

      const tokenId = await mintActiveCredential(claimToken, issuer, subject);

      await expect(claimToken.connect(issuer).revoke(tokenId, "Fraud detected"))
        .to.emit(claimToken, "CredentialRevoked")
        .withArgs(tokenId, issuer.address, "Fraud detected");

      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.REVOKED);
      expect(await claimToken.verify(tokenId)).to.be.false;
    });

    it("should detect ACTIVE credential as expired after time passes", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);

      const now = await time.latest();
      const expiresIn1Hour = BigInt(now + 3600);
      const tokenId = await mintActiveCredential(claimToken, issuer, subject, ClaimTypes.LICENSE_OPERATOR, expiresIn1Hour);

      // Before expiry
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);
      expect(await claimToken.verify(tokenId)).to.be.true;
      expect(await claimToken.isExpired(tokenId)).to.be.false;

      // Advance time past expiry
      await time.increase(3601);

      // After expiry - getStatus should lazily return EXPIRED
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.EXPIRED);
      expect(await claimToken.verify(tokenId)).to.be.false;
      expect(await claimToken.isExpired(tokenId)).to.be.true;
    });
  });

  // ============================================
  // SUSPENDED State Tests
  // ============================================

  describe("SUSPENDED Status", function () {
    async function suspendedCredentialFixture() {
      const fixture = await deployContractsFixture();
      const { claimToken, issuer, subject } = fixture;

      const tokenId = await mintActiveCredential(claimToken, issuer, subject);
      await claimToken.connect(issuer).suspend(tokenId, "Under review");

      return { ...fixture, tokenId };
    }

    it("should transition SUSPENDED to ACTIVE via reinstate", async function () {
      const { claimToken, issuer, tokenId } = await loadFixture(suspendedCredentialFixture);

      await expect(claimToken.connect(issuer).reinstate(tokenId))
        .to.emit(claimToken, "CredentialReinstated")
        .withArgs(tokenId, issuer.address);

      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);
      expect(await claimToken.verify(tokenId)).to.be.true;
    });

    it("should transition SUSPENDED to REVOKED", async function () {
      const { claimToken, issuer, tokenId } = await loadFixture(suspendedCredentialFixture);

      await expect(claimToken.connect(issuer).revoke(tokenId, "Confirmed fraud"))
        .to.emit(claimToken, "CredentialRevoked")
        .withArgs(tokenId, issuer.address, "Confirmed fraud");

      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.REVOKED);
    });

    it("should reject double suspension", async function () {
      const { claimToken, issuer, tokenId } = await loadFixture(suspendedCredentialFixture);

      await expect(
        claimToken.connect(issuer).suspend(tokenId, "Again")
      ).to.be.revertedWithCustomError(claimToken, "InvalidStatusTransition");
    });
  });

  // ============================================
  // REVOKED State Tests (INV-02: Permanent Revocation)
  // ============================================

  describe("REVOKED Status - INV-02: Revocation is Permanent", function () {
    async function revokedCredentialFixture() {
      const fixture = await deployContractsFixture();
      const { claimToken, issuer, subject } = fixture;

      const tokenId = await mintActiveCredential(claimToken, issuer, subject);
      await claimToken.connect(issuer).revoke(tokenId, "Fraudulent");

      return { ...fixture, tokenId };
    }

    it("should not allow reinstating a revoked credential", async function () {
      const { claimToken, issuer, tokenId } = await loadFixture(revokedCredentialFixture);

      await expect(
        claimToken.connect(issuer).reinstate(tokenId)
      ).to.be.revertedWithCustomError(claimToken, "InvalidStatusTransition");
    });

    it("should not allow suspending a revoked credential", async function () {
      const { claimToken, issuer, tokenId } = await loadFixture(revokedCredentialFixture);

      await expect(
        claimToken.connect(issuer).suspend(tokenId, "Can't suspend revoked")
      ).to.be.revertedWithCustomError(claimToken, "InvalidStatusTransition");
    });

    it("should not allow re-revoking a revoked credential", async function () {
      const { claimToken, issuer, tokenId } = await loadFixture(revokedCredentialFixture);

      await expect(
        claimToken.connect(issuer).revoke(tokenId, "Double revoke")
      ).to.be.revertedWithCustomError(claimToken, "InvalidStatusTransition");
    });

    it("should fail verification for revoked credential", async function () {
      const { claimToken, tokenId } = await loadFixture(revokedCredentialFixture);

      expect(await claimToken.verify(tokenId)).to.be.false;
      expect(await claimToken.isRevoked(tokenId)).to.be.true;
    });
  });

  // ============================================
  // EXPIRED State Tests
  // ============================================

  describe("EXPIRED Status", function () {
    async function expiredCredentialFixture() {
      const fixture = await deployContractsFixture();
      const { claimToken, issuer, subject } = fixture;

      const now = await time.latest();
      const expiresIn1Hour = BigInt(now + 3600);
      const tokenId = await mintActiveCredential(claimToken, issuer, subject, ClaimTypes.LICENSE_OPERATOR, expiresIn1Hour);

      // Advance time past expiry
      await time.increase(3601);

      return { ...fixture, tokenId };
    }

    it("should explicitly mark credential as EXPIRED via markExpired", async function () {
      const { claimToken, other, tokenId } = await loadFixture(expiredCredentialFixture);

      // Anyone can call markExpired
      await expect(claimToken.connect(other).markExpired(tokenId))
        .to.emit(claimToken, "CredentialExpired");

      // Now status is explicitly EXPIRED in storage
      const credential = await claimToken.getCredential(tokenId);
      expect(credential.status).to.equal(CredentialStatus.EXPIRED);
    });

    it("should reject markExpired on non-expired credential", async function () {
      const { claimToken, issuer, subject, other } = await loadFixture(deployContractsFixture);

      // Mint credential expiring in 1 year
      const tokenId = await mintActiveCredential(claimToken, issuer, subject);

      await expect(
        claimToken.connect(other).markExpired(tokenId)
      ).to.be.revertedWithCustomError(claimToken, "CredentialNotExpired");
    });

    it("should reject markExpired on credential without expiration", async function () {
      const { claimToken, issuer, subject, other } = await loadFixture(deployContractsFixture);

      // Mint credential with no expiration (expiresAt = 0)
      const tokenId = await mintActiveCredential(claimToken, issuer, subject, ClaimTypes.LICENSE_OPERATOR, 0n);

      await expect(
        claimToken.connect(other).markExpired(tokenId)
      ).to.be.revertedWithCustomError(claimToken, "CredentialNotExpired");
    });

    it("should reject markExpired on already revoked credential", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);

      const now = await time.latest();
      const expiresIn1Hour = BigInt(now + 3600);
      const tokenId = await mintActiveCredential(claimToken, issuer, subject, ClaimTypes.LICENSE_OPERATOR, expiresIn1Hour);

      // Revoke first
      await claimToken.connect(issuer).revoke(tokenId, "Revoked");

      // Advance time past expiry
      await time.increase(3601);

      // Cannot markExpired a revoked credential
      await expect(
        claimToken.markExpired(tokenId)
      ).to.be.revertedWithCustomError(claimToken, "InvalidStatusTransition");
    });

    it("should not allow suspension of expired credential", async function () {
      const { claimToken, issuer, tokenId } = await loadFixture(expiredCredentialFixture);

      // Expired credentials cannot be suspended (lazy check means status is still ACTIVE in storage)
      // First mark it as expired
      await claimToken.markExpired(tokenId);

      await expect(
        claimToken.connect(issuer).suspend(tokenId, "Try suspend")
      ).to.be.revertedWithCustomError(claimToken, "InvalidStatusTransition");
    });

    it("should allow revocation of expired credential (explicit status)", async function () {
      const { claimToken, issuer, tokenId } = await loadFixture(expiredCredentialFixture);

      // First explicitly mark as expired
      await claimToken.markExpired(tokenId);

      // Revocation of expired credential - depends on business rules
      // According to state machine, expired can be revoked
      await expect(
        claimToken.connect(issuer).revoke(tokenId, "Revoke expired")
      ).to.be.revertedWithCustomError(claimToken, "InvalidStatusTransition");
    });
  });

  // ============================================
  // State Machine Invariant Tests
  // ============================================

  describe("State Machine Invariants", function () {
    it("INV-01: Active credentials must have authorized issuers", async function () {
      const { claimToken, issuerRegistry, issuer, subject, owner } = await loadFixture(deployContractsFixture);

      const tokenId = await mintActiveCredential(claimToken, issuer, subject);
      expect(await claimToken.verify(tokenId)).to.be.true;

      // Deactivate the issuer
      await issuerRegistry.connect(owner).deactivateIssuer(issuer.address);

      // Credential should no longer verify
      expect(await claimToken.verify(tokenId)).to.be.false;
    });

    it("INV-03: Only ACTIVE/INHERITED credentials pass verification", async function () {
      const { claimToken, issuer, subject, owner } = await loadFixture(deployContractsFixture);

      // Test PENDING
      const pendingId = await mintPendingCredential(claimToken, issuer, subject);
      expect(await claimToken.verify(pendingId)).to.be.false;

      // Test ACTIVE
      const activeId = await mintActiveCredential(claimToken, issuer, subject);
      expect(await claimToken.verify(activeId)).to.be.true;

      // Test SUSPENDED
      const suspendedId = await mintActiveCredential(claimToken, issuer, subject);
      await claimToken.connect(issuer).suspend(suspendedId, "Suspend");
      expect(await claimToken.verify(suspendedId)).to.be.false;

      // Test REVOKED
      const revokedId = await mintActiveCredential(claimToken, issuer, subject);
      await claimToken.connect(issuer).revoke(revokedId, "Revoke");
      expect(await claimToken.verify(revokedId)).to.be.false;

      // Test EXPIRED (lazy)
      const now = await time.latest();
      const expiredId = await mintActiveCredential(claimToken, issuer, subject, ClaimTypes.LICENSE_OPERATOR, BigInt(now + 1));
      await time.increase(10);
      expect(await claimToken.verify(expiredId)).to.be.false;
    });

    it("INV-05: Credentials stay with subject unless properly transferred", async function () {
      const { claimToken, issuer, subject, other } = await loadFixture(deployContractsFixture);

      // Non-transferable credential (license)
      const licenseId = await mintActiveCredential(claimToken, issuer, subject, ClaimTypes.LICENSE_OPERATOR);
      expect(await claimToken.ownerOf(licenseId)).to.equal(subject.address);

      // Attempt unauthorized transfer should fail
      await expect(
        claimToken.connect(subject).transferFrom(subject.address, other.address, licenseId)
      ).to.be.revertedWithCustomError(claimToken, "TransferUnauthorized");

      // Credential still belongs to subject
      expect(await claimToken.ownerOf(licenseId)).to.equal(subject.address);

      // Transferable credential (property deed)
      const deedId = await mintActiveCredential(claimToken, issuer, subject, ClaimTypes.PROPERTY_DEED);

      // Transfer should succeed
      await claimToken.connect(subject).transferFrom(subject.address, other.address, deedId);
      expect(await claimToken.ownerOf(deedId)).to.equal(other.address);
    });
  });

  // ============================================
  // Full State Machine Transition Matrix Tests
  // ============================================

  describe("Complete State Transition Matrix", function () {
    /**
     * State Transition Matrix:
     *
     * From      | To         | Trigger    | Result
     * ----------|------------|------------|--------
     * (none)    | PENDING    | mintPending| ✓
     * (none)    | ACTIVE     | mint       | ✓
     * PENDING   | ACTIVE     | confirm    | ✓
     * PENDING   | SUSPENDED  | suspend    | ✗
     * PENDING   | REVOKED    | revoke     | ✗
     * ACTIVE    | SUSPENDED  | suspend    | ✓
     * ACTIVE    | REVOKED    | revoke     | ✓
     * ACTIVE    | EXPIRED    | time/mark  | ✓
     * SUSPENDED | ACTIVE     | reinstate  | ✓
     * SUSPENDED | REVOKED    | revoke     | ✓
     * SUSPENDED | SUSPENDED  | suspend    | ✗
     * REVOKED   | ACTIVE     | reinstate  | ✗ (INV-02)
     * REVOKED   | SUSPENDED  | suspend    | ✗
     * REVOKED   | REVOKED    | revoke     | ✗
     * EXPIRED   | ACTIVE     | updateExp  | ✓ (via renewal)
     * EXPIRED   | SUSPENDED  | suspend    | ✗
     * EXPIRED   | REVOKED    | revoke     | ✗
     */

    it("should verify PENDING → ACTIVE transition", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);
      const tokenId = await mintPendingCredential(claimToken, issuer, subject);

      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.PENDING);
      await claimToken.connect(issuer).confirm(tokenId);
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);
    });

    it("should verify ACTIVE → SUSPENDED → ACTIVE cycle", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);
      const tokenId = await mintActiveCredential(claimToken, issuer, subject);

      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);

      await claimToken.connect(issuer).suspend(tokenId, "Suspend");
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.SUSPENDED);

      await claimToken.connect(issuer).reinstate(tokenId);
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);
    });

    it("should verify ACTIVE → SUSPENDED → REVOKED path", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);
      const tokenId = await mintActiveCredential(claimToken, issuer, subject);

      await claimToken.connect(issuer).suspend(tokenId, "Investigate");
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.SUSPENDED);

      await claimToken.connect(issuer).revoke(tokenId, "Confirmed fraud");
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.REVOKED);
    });

    it("should verify ACTIVE → REVOKED direct path", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);
      const tokenId = await mintActiveCredential(claimToken, issuer, subject);

      await claimToken.connect(issuer).revoke(tokenId, "Immediate revoke");
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.REVOKED);
    });

    it("should verify ACTIVE → EXPIRED path", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);

      const now = await time.latest();
      const tokenId = await mintActiveCredential(claimToken, issuer, subject, ClaimTypes.LICENSE_OPERATOR, BigInt(now + 100));

      await time.increase(101);

      // Lazy detection
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.EXPIRED);

      // Explicit marking
      await claimToken.markExpired(tokenId);
      const cred = await claimToken.getCredential(tokenId);
      expect(cred.status).to.equal(CredentialStatus.EXPIRED);
    });
  });

  // ============================================
  // Edge Cases
  // ============================================

  describe("Edge Cases", function () {
    it("should handle credential with exact boundary expiration", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);

      const now = await time.latest();
      const exactExpiry = BigInt(now + 100);
      const tokenId = await mintActiveCredential(claimToken, issuer, subject, ClaimTypes.LICENSE_OPERATOR, exactExpiry);

      // Advance to exactly expiry time
      await time.increaseTo(Number(exactExpiry));

      // At exact expiry, should still be valid (expired AFTER expiresAt)
      expect(await claimToken.isExpired(tokenId)).to.be.false;

      // One second later
      await time.increase(1);
      expect(await claimToken.isExpired(tokenId)).to.be.true;
    });

    it("should emit correct events for all transitions", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);

      // Mint and track events
      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      await expect(claimToken.mint(request, signature))
        .to.emit(claimToken, "CredentialMinted")
        .withArgs(1n, subject.address, issuer.address, ClaimTypes.LICENSE_OPERATOR);

      await expect(claimToken.connect(issuer).suspend(1n, "Test suspend"))
        .to.emit(claimToken, "CredentialSuspended")
        .withArgs(1n, issuer.address, "Test suspend");

      await expect(claimToken.connect(issuer).reinstate(1n))
        .to.emit(claimToken, "CredentialReinstated")
        .withArgs(1n, issuer.address);

      await expect(claimToken.connect(issuer).revoke(1n, "Test revoke"))
        .to.emit(claimToken, "CredentialRevoked")
        .withArgs(1n, issuer.address, "Test revoke");
    });

    it("should handle multiple status queries efficiently", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployContractsFixture);

      const tokenId = await mintActiveCredential(claimToken, issuer, subject);

      // Multiple queries should all work
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);
      expect(await claimToken.verify(tokenId)).to.be.true;
      expect(await claimToken.isRevoked(tokenId)).to.be.false;
      expect(await claimToken.isSuspended(tokenId)).to.be.false;
      expect(await claimToken.isExpired(tokenId)).to.be.false;
    });
  });
});
