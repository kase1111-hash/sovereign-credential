/**
 * @file CredentialLifecycleManager unit tests
 * @description Comprehensive tests for the CredentialLifecycleManager contract
 * @dev Tests Step 8 requirements from IMPLEMENTATION_GUIDE.md
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { type SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import {
  type ClaimToken,
  type IssuerRegistry,
  type CredentialLifecycleManager,
} from "../typechain-types";
import { ClaimTypes, CredentialStatus, Constants } from "../types";

describe("CredentialLifecycleManager", function () {
  // ============================================
  // Fixtures
  // ============================================

  async function deployContractsFixture() {
    const [owner, issuer, subject, beneficiary1, beneficiary2, other] =
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

    // Grant roles
    const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
    await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, await claimToken.getAddress());

    // Set lifecycle manager in ClaimToken
    await claimToken.setLifecycleManager(await lifecycleManager.getAddress());

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
      owner,
      issuer,
      subject,
      beneficiary1,
      beneficiary2,
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

  async function signRenewalApproval(
    signer: SignerWithAddress,
    tokenId: bigint,
    newExpiry: bigint,
    lifecycleManagerAddress: string
  ): Promise<string> {
    const chainId = (await ethers.provider.getNetwork()).chainId;

    const messageHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["string", "uint256", "uint64", "uint256", "address"],
        ["RENEWAL_APPROVAL", tokenId, newExpiry, chainId, lifecycleManagerAddress]
      )
    );

    return signer.signMessage(ethers.getBytes(messageHash));
  }

  async function mintCredential(
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

  // ============================================
  // Deployment Tests
  // ============================================

  describe("Deployment", function () {
    it("should initialize with correct contract references", async function () {
      const { lifecycleManager, claimToken, issuerRegistry } = await loadFixture(
        deployContractsFixture
      );

      expect(await lifecycleManager.claimToken()).to.equal(
        await claimToken.getAddress()
      );
      expect(await lifecycleManager.issuerRegistry()).to.equal(
        await issuerRegistry.getAddress()
      );
    });

    it("should grant admin role to deployer", async function () {
      const { lifecycleManager, owner } = await loadFixture(deployContractsFixture);

      const DEFAULT_ADMIN_ROLE = await lifecycleManager.DEFAULT_ADMIN_ROLE();
      expect(await lifecycleManager.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.be
        .true;
    });

    it("should initialize property types as splittable", async function () {
      const { lifecycleManager } = await loadFixture(deployContractsFixture);

      expect(await lifecycleManager.isSplittable(ClaimTypes.PROPERTY_DEED)).to.be.true;
      expect(await lifecycleManager.isSplittable(ClaimTypes.PROPERTY_TITLE)).to.be.true;
      expect(await lifecycleManager.isSplittable(ClaimTypes.LICENSE_OPERATOR)).to.be
        .false;
    });

    it("should reject initialization with zero addresses", async function () {
      const LifecycleManagerFactory = await ethers.getContractFactory(
        "CredentialLifecycleManager"
      );

      await expect(
        upgrades.deployProxy(
          LifecycleManagerFactory,
          [ethers.ZeroAddress, ethers.ZeroAddress],
          { initializer: "initialize" }
        )
      ).to.be.revertedWithCustomError(LifecycleManagerFactory, "ZeroAddress");
    });
  });

  // ============================================
  // Renewal Request Tests
  // ============================================

  describe("Renewal Requests", function () {
    async function credentialFixture() {
      const fixture = await deployContractsFixture();
      const { claimToken, issuer, subject } = fixture;

      const tokenId = await mintCredential(claimToken, issuer, subject);

      return { ...fixture, tokenId };
    }

    it("should allow holder to request renewal", async function () {
      const { lifecycleManager, subject, tokenId } = await loadFixture(credentialFixture);

      await expect(lifecycleManager.connect(subject).requestRenewal(tokenId))
        .to.emit(lifecycleManager, "RenewalRequested")
        .withArgs(tokenId, subject.address);

      expect(await lifecycleManager.hasRenewalRequest(tokenId)).to.be.true;
    });

    it("should reject renewal request from non-holder", async function () {
      const { lifecycleManager, other, tokenId } = await loadFixture(credentialFixture);

      await expect(
        lifecycleManager.connect(other).requestRenewal(tokenId)
      ).to.be.revertedWithCustomError(lifecycleManager, "NotHolder");
    });

    it("should reject duplicate renewal request", async function () {
      const { lifecycleManager, subject, tokenId } = await loadFixture(credentialFixture);

      await lifecycleManager.connect(subject).requestRenewal(tokenId);

      await expect(
        lifecycleManager.connect(subject).requestRenewal(tokenId)
      ).to.be.revertedWithCustomError(lifecycleManager, "RenewalAlreadyRequested");
    });

    it("should store renewal request data correctly", async function () {
      const { lifecycleManager, subject, tokenId } = await loadFixture(credentialFixture);

      const beforeTime = await time.latest();
      await lifecycleManager.connect(subject).requestRenewal(tokenId);
      const afterTime = await time.latest();

      const request = await lifecycleManager.getRenewalRequest(tokenId);
      expect(request.tokenId).to.equal(tokenId);
      expect(request.requester).to.equal(subject.address);
      expect(request.requestedAt).to.be.gte(beforeTime);
      expect(request.requestedAt).to.be.lte(afterTime);
      expect(request.newExpiry).to.equal(0n); // Set on approval
    });

    it("should allow holder to cancel renewal request", async function () {
      const { lifecycleManager, subject, tokenId } = await loadFixture(credentialFixture);

      await lifecycleManager.connect(subject).requestRenewal(tokenId);
      await lifecycleManager.connect(subject).cancelRenewalRequest(tokenId);

      expect(await lifecycleManager.hasRenewalRequest(tokenId)).to.be.false;
    });
  });

  // ============================================
  // Renewal Approval Tests
  // ============================================

  describe("Renewal Approval", function () {
    async function pendingRenewalFixture() {
      const fixture = await deployContractsFixture();
      const { claimToken, lifecycleManager, issuer, subject } = fixture;

      const tokenId = await mintCredential(claimToken, issuer, subject);
      await lifecycleManager.connect(subject).requestRenewal(tokenId);

      return { ...fixture, tokenId };
    }

    it("should allow issuer to approve renewal", async function () {
      const { lifecycleManager, issuer, tokenId } = await loadFixture(
        pendingRenewalFixture
      );

      const now = await time.latest();
      const newExpiry = BigInt(now) + BigInt(365 * 24 * 60 * 60); // 1 year

      const signature = await signRenewalApproval(
        issuer,
        tokenId,
        newExpiry,
        await lifecycleManager.getAddress()
      );

      await expect(
        lifecycleManager.connect(issuer).approveRenewal(tokenId, newExpiry, signature)
      )
        .to.emit(lifecycleManager, "RenewalApproved")
        .withArgs(tokenId, newExpiry);

      expect(await lifecycleManager.hasRenewalRequest(tokenId)).to.be.false;
    });

    it("should reject approval from non-issuer", async function () {
      const { lifecycleManager, issuer, other, tokenId } = await loadFixture(
        pendingRenewalFixture
      );

      const now = await time.latest();
      const newExpiry = BigInt(now) + BigInt(365 * 24 * 60 * 60);

      const signature = await signRenewalApproval(
        issuer,
        tokenId,
        newExpiry,
        await lifecycleManager.getAddress()
      );

      await expect(
        lifecycleManager.connect(other).approveRenewal(tokenId, newExpiry, signature)
      ).to.be.revertedWithCustomError(lifecycleManager, "UnauthorizedIssuer");
    });

    it("should reject approval without pending request", async function () {
      const { lifecycleManager, claimToken, issuer, subject } = await loadFixture(
        deployContractsFixture
      );

      const tokenId = await mintCredential(claimToken, issuer, subject);
      // No renewal request made

      const now = await time.latest();
      const newExpiry = BigInt(now) + BigInt(365 * 24 * 60 * 60);

      const signature = await signRenewalApproval(
        issuer,
        tokenId,
        newExpiry,
        await lifecycleManager.getAddress()
      );

      await expect(
        lifecycleManager.connect(issuer).approveRenewal(tokenId, newExpiry, signature)
      ).to.be.revertedWithCustomError(lifecycleManager, "NoRenewalRequest");
    });

    it("should allow issuer to deny renewal", async function () {
      const { lifecycleManager, issuer, tokenId } = await loadFixture(
        pendingRenewalFixture
      );

      await expect(
        lifecycleManager.connect(issuer).denyRenewal(tokenId, "Documentation incomplete")
      )
        .to.emit(lifecycleManager, "RenewalDenied")
        .withArgs(tokenId, "Documentation incomplete");

      expect(await lifecycleManager.hasRenewalRequest(tokenId)).to.be.false;
    });
  });

  // ============================================
  // Grace Period Tests
  // ============================================

  describe("Grace Period", function () {
    it("should allow renewal request for expired credential within grace period", async function () {
      const { claimToken, lifecycleManager, issuer, subject } = await loadFixture(
        deployContractsFixture
      );

      // Mint credential expiring in 1 hour
      const now = await time.latest();
      const tokenId = await mintCredential(
        claimToken,
        issuer,
        subject,
        ClaimTypes.LICENSE_OPERATOR,
        BigInt(now + 3600)
      );

      // Advance time past expiry but within grace period (90 days)
      await time.increase(3601 + 86400); // 1 day after expiry

      // Should still be able to request renewal
      await expect(lifecycleManager.connect(subject).requestRenewal(tokenId))
        .to.emit(lifecycleManager, "RenewalRequested")
        .withArgs(tokenId, subject.address);
    });

    it("should reject renewal request after grace period expires", async function () {
      const { claimToken, lifecycleManager, issuer, subject } = await loadFixture(
        deployContractsFixture
      );

      // Mint credential expiring in 1 hour
      const now = await time.latest();
      const tokenId = await mintCredential(
        claimToken,
        issuer,
        subject,
        ClaimTypes.LICENSE_OPERATOR,
        BigInt(now + 3600)
      );

      // Advance time past grace period (90 days + expiry)
      await time.increase(3600 + 91 * 24 * 60 * 60);

      // Should fail - grace period expired
      await expect(
        lifecycleManager.connect(subject).requestRenewal(tokenId)
      ).to.be.revertedWithCustomError(lifecycleManager, "GracePeriodExpired");
    });
  });

  // ============================================
  // Inheritance Directive Tests
  // ============================================

  describe("Inheritance Directives", function () {
    async function credentialFixture() {
      const fixture = await deployContractsFixture();
      const { claimToken, issuer, subject } = fixture;

      const tokenId = await mintCredential(claimToken, issuer, subject);

      return { ...fixture, tokenId };
    }

    it("should allow holder to set inheritance directive", async function () {
      const { lifecycleManager, subject, beneficiary1, tokenId } = await loadFixture(
        credentialFixture
      );

      const directive = {
        credentialId: tokenId,
        beneficiaries: [beneficiary1.address],
        shares: [],
        requiresFIETrigger: false,
        fieIntentHash: ethers.ZeroHash,
        conditions: "0x",
      };

      await expect(
        lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive)
      )
        .to.emit(lifecycleManager, "InheritanceDirectiveSet")
        .withArgs(tokenId, [beneficiary1.address]);

      expect(await lifecycleManager.hasInheritanceDirective(tokenId)).to.be.true;
    });

    it("should store inheritance directive correctly", async function () {
      const { lifecycleManager, subject, beneficiary1, beneficiary2, tokenId } =
        await loadFixture(credentialFixture);

      const fieIntentHash = ethers.keccak256(ethers.toUtf8Bytes("test-intent"));
      const directive = {
        credentialId: tokenId,
        beneficiaries: [beneficiary1.address, beneficiary2.address],
        shares: [60, 40],
        requiresFIETrigger: true,
        fieIntentHash: fieIntentHash,
        conditions: "0x1234",
      };

      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);

      const stored = await lifecycleManager.getInheritanceDirective(tokenId);
      expect(stored.credentialId).to.equal(tokenId);
      expect(stored.beneficiaries).to.deep.equal([
        beneficiary1.address,
        beneficiary2.address,
      ]);
      expect(stored.shares).to.deep.equal([60, 40]);
      expect(stored.requiresFIETrigger).to.be.true;
      expect(stored.fieIntentHash).to.equal(fieIntentHash);
    });

    it("should reject setting directive from non-holder", async function () {
      const { lifecycleManager, other, beneficiary1, tokenId } = await loadFixture(
        credentialFixture
      );

      const directive = {
        credentialId: tokenId,
        beneficiaries: [beneficiary1.address],
        shares: [],
        requiresFIETrigger: false,
        fieIntentHash: ethers.ZeroHash,
        conditions: "0x",
      };

      await expect(
        lifecycleManager.connect(other).setInheritanceDirective(tokenId, directive)
      ).to.be.revertedWithCustomError(lifecycleManager, "NotHolder");
    });

    it("should reject directive with empty beneficiaries", async function () {
      const { lifecycleManager, subject, tokenId } = await loadFixture(credentialFixture);

      const directive = {
        credentialId: tokenId,
        beneficiaries: [],
        shares: [],
        requiresFIETrigger: false,
        fieIntentHash: ethers.ZeroHash,
        conditions: "0x",
      };

      await expect(
        lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive)
      ).to.be.revertedWithCustomError(lifecycleManager, "EmptyArray");
    });

    it("should reject directive with zero address beneficiary", async function () {
      const { lifecycleManager, subject, tokenId } = await loadFixture(credentialFixture);

      const directive = {
        credentialId: tokenId,
        beneficiaries: [ethers.ZeroAddress],
        shares: [],
        requiresFIETrigger: false,
        fieIntentHash: ethers.ZeroHash,
        conditions: "0x",
      };

      await expect(
        lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive)
      ).to.be.revertedWithCustomError(lifecycleManager, "BeneficiaryInvalid");
    });

    it("should reject directive with shares not summing to 100", async function () {
      const { lifecycleManager, subject, beneficiary1, beneficiary2, tokenId } =
        await loadFixture(credentialFixture);

      const directive = {
        credentialId: tokenId,
        beneficiaries: [beneficiary1.address, beneficiary2.address],
        shares: [50, 40], // Only 90%
        requiresFIETrigger: false,
        fieIntentHash: ethers.ZeroHash,
        conditions: "0x",
      };

      await expect(
        lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive)
      ).to.be.revertedWithCustomError(lifecycleManager, "InvalidShares");
    });

    it("should allow holder to remove inheritance directive", async function () {
      const { lifecycleManager, subject, beneficiary1, tokenId } = await loadFixture(
        credentialFixture
      );

      const directive = {
        credentialId: tokenId,
        beneficiaries: [beneficiary1.address],
        shares: [],
        requiresFIETrigger: false,
        fieIntentHash: ethers.ZeroHash,
        conditions: "0x",
      };

      await lifecycleManager.connect(subject).setInheritanceDirective(tokenId, directive);
      expect(await lifecycleManager.hasInheritanceDirective(tokenId)).to.be.true;

      await expect(lifecycleManager.connect(subject).removeInheritanceDirective(tokenId))
        .to.emit(lifecycleManager, "InheritanceDirectiveRemoved")
        .withArgs(tokenId);

      expect(await lifecycleManager.hasInheritanceDirective(tokenId)).to.be.false;
    });
  });

  // ============================================
  // Batch Operations Tests
  // ============================================

  describe("Batch Operations", function () {
    it("should allow batch setting of inheritance directives", async function () {
      const { claimToken, lifecycleManager, issuer, subject, beneficiary1 } =
        await loadFixture(deployContractsFixture);

      // Mint multiple credentials
      const tokenId1 = await mintCredential(claimToken, issuer, subject);
      const tokenId2 = await mintCredential(claimToken, issuer, subject);

      const directive = {
        credentialId: 0n, // Will be overwritten
        beneficiaries: [beneficiary1.address],
        shares: [],
        requiresFIETrigger: false,
        fieIntentHash: ethers.ZeroHash,
        conditions: "0x",
      };

      await lifecycleManager
        .connect(subject)
        .batchSetInheritance([tokenId1, tokenId2], [directive, directive]);

      expect(await lifecycleManager.hasInheritanceDirective(tokenId1)).to.be.true;
      expect(await lifecycleManager.hasInheritanceDirective(tokenId2)).to.be.true;
    });

    it("should reject batch operations with mismatched array lengths", async function () {
      const { claimToken, lifecycleManager, issuer, subject, beneficiary1 } =
        await loadFixture(deployContractsFixture);

      const tokenId1 = await mintCredential(claimToken, issuer, subject);
      const tokenId2 = await mintCredential(claimToken, issuer, subject);

      const directive = {
        credentialId: 0n,
        beneficiaries: [beneficiary1.address],
        shares: [],
        requiresFIETrigger: false,
        fieIntentHash: ethers.ZeroHash,
        conditions: "0x",
      };

      // 2 tokens but only 1 directive
      await expect(
        lifecycleManager
          .connect(subject)
          .batchSetInheritance([tokenId1, tokenId2], [directive])
      ).to.be.revertedWithCustomError(lifecycleManager, "ArrayLengthMismatch");
    });

    it("should emit BatchTransferred event for batch transfers", async function () {
      const { claimToken, lifecycleManager, issuer, subject, other } = await loadFixture(
        deployContractsFixture
      );

      // Mint transferable credentials (property deeds)
      const tokenId1 = await mintCredential(
        claimToken,
        issuer,
        subject,
        ClaimTypes.PROPERTY_DEED
      );
      const tokenId2 = await mintCredential(
        claimToken,
        issuer,
        subject,
        ClaimTypes.PROPERTY_DEED
      );

      await expect(
        lifecycleManager.connect(subject).batchTransfer([tokenId1, tokenId2], other.address)
      )
        .to.emit(lifecycleManager, "BatchTransferred")
        .withArgs([tokenId1, tokenId2], subject.address, other.address);
    });

    it("should reject batch transfer with empty array", async function () {
      const { lifecycleManager, subject, other } = await loadFixture(
        deployContractsFixture
      );

      await expect(
        lifecycleManager.connect(subject).batchTransfer([], other.address)
      ).to.be.revertedWithCustomError(lifecycleManager, "EmptyArray");
    });

    it("should reject batch transfer to zero address", async function () {
      const { claimToken, lifecycleManager, issuer, subject } = await loadFixture(
        deployContractsFixture
      );

      const tokenId = await mintCredential(claimToken, issuer, subject);

      await expect(
        lifecycleManager.connect(subject).batchTransfer([tokenId], ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(lifecycleManager, "ZeroAddress");
    });
  });

  // ============================================
  // Query Functions Tests
  // ============================================

  describe("Query Functions", function () {
    it("should return all pending renewals", async function () {
      const { claimToken, lifecycleManager, issuer, subject } = await loadFixture(
        deployContractsFixture
      );

      const tokenId1 = await mintCredential(claimToken, issuer, subject);
      const tokenId2 = await mintCredential(claimToken, issuer, subject);

      await lifecycleManager.connect(subject).requestRenewal(tokenId1);
      await lifecycleManager.connect(subject).requestRenewal(tokenId2);

      const pendingRenewals = await lifecycleManager.getPendingRenewals();
      expect(pendingRenewals.length).to.equal(2);
      expect(pendingRenewals).to.include(tokenId1);
      expect(pendingRenewals).to.include(tokenId2);
    });

    it("should return credentials with inheritance for a holder", async function () {
      const { claimToken, lifecycleManager, issuer, subject, beneficiary1 } =
        await loadFixture(deployContractsFixture);

      const tokenId1 = await mintCredential(claimToken, issuer, subject);
      const tokenId2 = await mintCredential(claimToken, issuer, subject);

      const directive = {
        credentialId: 0n,
        beneficiaries: [beneficiary1.address],
        shares: [],
        requiresFIETrigger: false,
        fieIntentHash: ethers.ZeroHash,
        conditions: "0x",
      };

      await lifecycleManager
        .connect(subject)
        .setInheritanceDirective(tokenId1, directive);

      const credentialsWithInheritance =
        await lifecycleManager.getCredentialsWithInheritance(subject.address);
      expect(credentialsWithInheritance.length).to.equal(1);
      expect(credentialsWithInheritance[0]).to.equal(tokenId1);
    });
  });

  // ============================================
  // Administrative Tests
  // ============================================

  describe("Administration", function () {
    it("should allow admin to set ClaimToken address", async function () {
      const { lifecycleManager, owner, other } = await loadFixture(
        deployContractsFixture
      );

      await lifecycleManager.connect(owner).setClaimToken(other.address);
      expect(await lifecycleManager.claimToken()).to.equal(other.address);
    });

    it("should allow admin to set IssuerRegistry address", async function () {
      const { lifecycleManager, owner, other } = await loadFixture(
        deployContractsFixture
      );

      await lifecycleManager.connect(owner).setIssuerRegistry(other.address);
      expect(await lifecycleManager.issuerRegistry()).to.equal(other.address);
    });

    it("should allow admin to set FIE bridge", async function () {
      const { lifecycleManager, owner, other } = await loadFixture(
        deployContractsFixture
      );

      await lifecycleManager.connect(owner).setFIEBridge(other.address);
      expect(await lifecycleManager.fieBridge()).to.equal(other.address);

      // Check role was granted
      const FIE_BRIDGE_ROLE = await lifecycleManager.FIE_BRIDGE_ROLE();
      expect(await lifecycleManager.hasRole(FIE_BRIDGE_ROLE, other.address)).to.be.true;
    });

    it("should allow admin to set splittable types", async function () {
      const { lifecycleManager, owner } = await loadFixture(deployContractsFixture);

      // LICENSE_OPERATOR is not splittable by default
      expect(await lifecycleManager.isSplittable(ClaimTypes.LICENSE_OPERATOR)).to.be
        .false;

      await lifecycleManager.connect(owner).setSplittable(ClaimTypes.LICENSE_OPERATOR, true);

      expect(await lifecycleManager.isSplittable(ClaimTypes.LICENSE_OPERATOR)).to.be
        .true;
    });

    it("should reject admin functions from non-admin", async function () {
      const { lifecycleManager, other } = await loadFixture(deployContractsFixture);

      await expect(
        lifecycleManager.connect(other).setClaimToken(other.address)
      ).to.be.reverted;

      await expect(
        lifecycleManager.connect(other).setIssuerRegistry(other.address)
      ).to.be.reverted;

      await expect(
        lifecycleManager.connect(other).setSplittable(ClaimTypes.LICENSE_OPERATOR, true)
      ).to.be.reverted;
    });

    it("should reject setting zero addresses", async function () {
      const { lifecycleManager, owner } = await loadFixture(deployContractsFixture);

      await expect(
        lifecycleManager.connect(owner).setClaimToken(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(lifecycleManager, "ZeroAddress");

      await expect(
        lifecycleManager.connect(owner).setIssuerRegistry(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(lifecycleManager, "ZeroAddress");
    });
  });

  // ============================================
  // Splittable Credential Tests
  // ============================================

  describe("Splittable Credentials", function () {
    it("should reject splitting non-splittable credential type", async function () {
      const { claimToken, lifecycleManager, issuer, subject, owner, beneficiary1 } =
        await loadFixture(deployContractsFixture);

      // LICENSE_OPERATOR is not splittable
      const tokenId = await mintCredential(
        claimToken,
        issuer,
        subject,
        ClaimTypes.LICENSE_OPERATOR
      );

      // Grant admin role to try splitting
      const FIE_BRIDGE_ROLE = await lifecycleManager.FIE_BRIDGE_ROLE();
      await lifecycleManager.connect(owner).grantRole(FIE_BRIDGE_ROLE, owner.address);

      await expect(
        lifecycleManager.connect(owner).splitCredential(tokenId, [beneficiary1.address], [100])
      ).to.be.revertedWithCustomError(lifecycleManager, "NotSplittable");
    });

    it("should emit CredentialSplit event for splittable credentials", async function () {
      const {
        claimToken,
        lifecycleManager,
        issuer,
        subject,
        owner,
        beneficiary1,
        beneficiary2,
      } = await loadFixture(deployContractsFixture);

      // PROPERTY_DEED is splittable
      const tokenId = await mintCredential(
        claimToken,
        issuer,
        subject,
        ClaimTypes.PROPERTY_DEED
      );

      // Grant FIE_BRIDGE_ROLE to owner for testing
      const FIE_BRIDGE_ROLE = await lifecycleManager.FIE_BRIDGE_ROLE();
      await lifecycleManager.connect(owner).grantRole(FIE_BRIDGE_ROLE, owner.address);

      await expect(
        lifecycleManager
          .connect(owner)
          .splitCredential(
            tokenId,
            [beneficiary1.address, beneficiary2.address],
            [60, 40]
          )
      ).to.emit(lifecycleManager, "CredentialSplit");
    });

    it("should reject split with shares not summing to 100", async function () {
      const {
        claimToken,
        lifecycleManager,
        issuer,
        subject,
        owner,
        beneficiary1,
        beneficiary2,
      } = await loadFixture(deployContractsFixture);

      const tokenId = await mintCredential(
        claimToken,
        issuer,
        subject,
        ClaimTypes.PROPERTY_DEED
      );

      const FIE_BRIDGE_ROLE = await lifecycleManager.FIE_BRIDGE_ROLE();
      await lifecycleManager.connect(owner).grantRole(FIE_BRIDGE_ROLE, owner.address);

      await expect(
        lifecycleManager
          .connect(owner)
          .splitCredential(
            tokenId,
            [beneficiary1.address, beneficiary2.address],
            [50, 40]
          )
      ).to.be.revertedWithCustomError(lifecycleManager, "InvalidShares");
    });
  });
});
