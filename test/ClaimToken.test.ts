/**
 * @file ClaimToken unit tests
 * @description Comprehensive tests for the ClaimToken ERC721 credential contract
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { type SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { type ClaimToken, type IssuerRegistry } from "../typechain-types";
import { ClaimTypes, CredentialStatus, Constants } from "../types";

describe("ClaimToken", function () {
  // ============================================
  // Fixtures
  // ============================================

  async function deployClaimTokenFixture() {
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
    await issuerRegistry.registerIssuer(issuer.address, "US-OR", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.EDUCATION_DEGREE,
      ClaimTypes.PROPERTY_DEED,
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

  // ============================================
  // Deployment Tests
  // ============================================

  describe("Deployment", function () {
    it("should initialize with correct name and symbol", async function () {
      const { claimToken } = await loadFixture(deployClaimTokenFixture);

      expect(await claimToken.name()).to.equal("SovereignCredential");
      expect(await claimToken.symbol()).to.equal("SCRED");
    });

    it("should set issuer registry correctly", async function () {
      const { claimToken, issuerRegistry } = await loadFixture(deployClaimTokenFixture);

      expect(await claimToken.issuerRegistry()).to.equal(await issuerRegistry.getAddress());
    });

    it("should grant admin role to deployer", async function () {
      const { claimToken, owner } = await loadFixture(deployClaimTokenFixture);

      const DEFAULT_ADMIN_ROLE = await claimToken.DEFAULT_ADMIN_ROLE();
      expect(await claimToken.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.be.true;
    });

    it("should start with zero total credentials", async function () {
      const { claimToken } = await loadFixture(deployClaimTokenFixture);

      expect(await claimToken.totalCredentials()).to.equal(0n);
    });

    it("should reject initialization with zero address registry", async function () {
      const ClaimTokenFactory = await ethers.getContractFactory("ClaimToken");

      await expect(
        upgrades.deployProxy(ClaimTokenFactory, [ethers.ZeroAddress], {
          initializer: "initialize",
        })
      ).to.be.revertedWithCustomError(ClaimTokenFactory, "ZeroAddress");
    });
  });

  // ============================================
  // Minting Tests
  // ============================================

  describe("Minting", function () {
    it("should mint a credential with valid signature", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployClaimTokenFixture);

      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      await expect(claimToken.mint(request, signature))
        .to.emit(claimToken, "CredentialMinted")
        .withArgs(1n, subject.address, issuer.address, ClaimTypes.LICENSE_OPERATOR);

      expect(await claimToken.totalCredentials()).to.equal(1n);
      expect(await claimToken.ownerOf(1n)).to.equal(subject.address);
    });

    it("should store credential data correctly", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployClaimTokenFixture);

      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      await claimToken.mint(request, signature);

      const credential = await claimToken.getCredential(1n);

      expect(credential.claimType).to.equal(ClaimTypes.LICENSE_OPERATOR);
      expect(credential.subject).to.equal(subject.address);
      expect(credential.issuer).to.equal(issuer.address);
      expect(credential.payloadHash).to.equal(request.payloadHash);
      expect(credential.expiresAt).to.equal(request.expiresAt);
      expect(credential.status).to.equal(CredentialStatus.ACTIVE);
      expect(credential.metadataURI).to.equal(request.metadataURI);
    });

    it("should reject mint from unauthorized issuer", async function () {
      const { claimToken, other, subject } = await loadFixture(deployClaimTokenFixture);

      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(other, request, await claimToken.getAddress());

      await expect(claimToken.mint(request, signature)).to.be.revertedWithCustomError(
        claimToken,
        "UnauthorizedIssuer"
      );
    });

    it("should reject mint with invalid signature", async function () {
      const { claimToken, subject } = await loadFixture(deployClaimTokenFixture);

      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const invalidSignature = "0x" + "ab".repeat(65);

      await expect(claimToken.mint(request, invalidSignature)).to.be.reverted;
    });

    it("should reject mint with zero address subject", async function () {
      const { claimToken, issuer } = await loadFixture(deployClaimTokenFixture);

      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, ethers.ZeroAddress);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      await expect(claimToken.mint(request, signature)).to.be.revertedWithCustomError(
        claimToken,
        "InvalidSubject"
      );
    });

    it("should reject mint with unsupported claim type", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployClaimTokenFixture);

      // Create request with invalid claim type (not in valid ranges)
      const request = {
        claimType: ethers.ZeroHash, // Invalid type
        subject: subject.address,
        encryptedPayload: "0x" + "ab".repeat(100),
        payloadHash: ethers.keccak256(ethers.toUtf8Bytes("test")),
        commitments: [],
        expiresAt: BigInt(Math.floor(Date.now() / 1000) + 86400),
        metadataURI: "ipfs://test",
      };
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      await expect(claimToken.mint(request, signature)).to.be.revertedWithCustomError(
        claimToken,
        "UnsupportedClaimType"
      );
    });

    it("should reject replay of same signature", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployClaimTokenFixture);

      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      // First mint succeeds
      await claimToken.mint(request, signature);

      // Second mint with same signature fails
      await expect(claimToken.mint(request, signature)).to.be.revertedWithCustomError(
        claimToken,
        "ProofReplayed"
      );
    });

    it("should batch mint multiple credentials", async function () {
      const { claimToken, issuer, subject, other } = await loadFixture(deployClaimTokenFixture);

      const request1 = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const request2 = await createMintRequest(ClaimTypes.EDUCATION_DEGREE, other.address);

      const sig1 = await signMintRequest(issuer, request1, await claimToken.getAddress());
      const sig2 = await signMintRequest(issuer, request2, await claimToken.getAddress());

      const tokenIds = await claimToken.batchMint.staticCall(
        [request1, request2],
        [sig1, sig2]
      );

      await claimToken.batchMint([request1, request2], [sig1, sig2]);

      expect(tokenIds.length).to.equal(2);
      expect(await claimToken.ownerOf(tokenIds[0])).to.equal(subject.address);
      expect(await claimToken.ownerOf(tokenIds[1])).to.equal(other.address);
    });

    it("should reject batch mint with mismatched array lengths", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployClaimTokenFixture);

      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      await expect(
        claimToken.batchMint([request], [signature, signature])
      ).to.be.revertedWithCustomError(claimToken, "ArrayLengthMismatch");
    });
  });

  // ============================================
  // Status Management Tests
  // ============================================

  describe("Status Management", function () {
    async function mintCredentialFixture() {
      const fixture = await deployClaimTokenFixture();
      const { claimToken, issuer, subject } = fixture;

      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      return { ...fixture, tokenId: 1n };
    }

    describe("Revocation", function () {
      it("should revoke an active credential", async function () {
        const { claimToken, issuer, tokenId } = await loadFixture(mintCredentialFixture);

        await expect(claimToken.connect(issuer).revoke(tokenId, "Fraudulent"))
          .to.emit(claimToken, "CredentialRevoked")
          .withArgs(tokenId, issuer.address, "Fraudulent");

        expect(await claimToken.isRevoked(tokenId)).to.be.true;
        expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.REVOKED);
      });

      it("should reject revocation from non-issuer", async function () {
        const { claimToken, other, tokenId } = await loadFixture(mintCredentialFixture);

        await expect(
          claimToken.connect(other).revoke(tokenId, "Attempt")
        ).to.be.revertedWithCustomError(claimToken, "UnauthorizedIssuer");
      });

      it("should reject revocation of already revoked credential", async function () {
        const { claimToken, issuer, tokenId } = await loadFixture(mintCredentialFixture);

        await claimToken.connect(issuer).revoke(tokenId, "First");

        await expect(
          claimToken.connect(issuer).revoke(tokenId, "Second")
        ).to.be.revertedWithCustomError(claimToken, "InvalidStatusTransition");
      });
    });

    describe("Suspension", function () {
      it("should suspend an active credential", async function () {
        const { claimToken, issuer, tokenId } = await loadFixture(mintCredentialFixture);

        await expect(claimToken.connect(issuer).suspend(tokenId, "Investigation"))
          .to.emit(claimToken, "CredentialSuspended")
          .withArgs(tokenId, issuer.address, "Investigation");

        expect(await claimToken.isSuspended(tokenId)).to.be.true;
      });

      it("should reinstate a suspended credential", async function () {
        const { claimToken, issuer, tokenId } = await loadFixture(mintCredentialFixture);

        await claimToken.connect(issuer).suspend(tokenId, "Investigation");

        await expect(claimToken.connect(issuer).reinstate(tokenId))
          .to.emit(claimToken, "CredentialReinstated")
          .withArgs(tokenId, issuer.address);

        expect(await claimToken.isSuspended(tokenId)).to.be.false;
        expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);
      });

      it("should reject reinstatement of non-suspended credential", async function () {
        const { claimToken, issuer, tokenId } = await loadFixture(mintCredentialFixture);

        await expect(
          claimToken.connect(issuer).reinstate(tokenId)
        ).to.be.revertedWithCustomError(claimToken, "InvalidStatusTransition");
      });

      it("should allow revocation of suspended credential", async function () {
        const { claimToken, issuer, tokenId } = await loadFixture(mintCredentialFixture);

        await claimToken.connect(issuer).suspend(tokenId, "Investigation");
        await claimToken.connect(issuer).revoke(tokenId, "Confirmed fraud");

        expect(await claimToken.isRevoked(tokenId)).to.be.true;
      });
    });
  });

  // ============================================
  // Verification Tests
  // ============================================

  describe("Verification", function () {
    async function mintCredentialFixture() {
      const fixture = await deployClaimTokenFixture();
      const { claimToken, issuer, subject } = fixture;

      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      return { ...fixture, tokenId: 1n, request };
    }

    it("should verify an active credential", async function () {
      const { claimToken, tokenId } = await loadFixture(mintCredentialFixture);

      expect(await claimToken.verify(tokenId)).to.be.true;
    });

    it("should fail verification for revoked credential", async function () {
      const { claimToken, issuer, tokenId } = await loadFixture(mintCredentialFixture);

      await claimToken.connect(issuer).revoke(tokenId, "Test");

      expect(await claimToken.verify(tokenId)).to.be.false;
    });

    it("should fail verification for suspended credential", async function () {
      const { claimToken, issuer, tokenId } = await loadFixture(mintCredentialFixture);

      await claimToken.connect(issuer).suspend(tokenId, "Test");

      expect(await claimToken.verify(tokenId)).to.be.false;
    });

    it("should fail verification for expired credential", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployClaimTokenFixture);

      // Create credential that expires in 1 hour
      const now = await time.latest();
      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address,
        BigInt(now + 3600)
      );
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      // Advance time past expiration
      await time.increase(3601);

      expect(await claimToken.verify(1n)).to.be.false;
      expect(await claimToken.isExpired(1n)).to.be.true;
    });

    it("should return false for non-existent credential", async function () {
      const { claimToken } = await loadFixture(deployClaimTokenFixture);

      expect(await claimToken.verify(999n)).to.be.false;
    });

    it("should handle credential with no expiration", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployClaimTokenFixture);

      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address,
        0n // Never expires
      );
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      // Advance time significantly
      await time.increase(365 * 24 * 60 * 60 * 10); // 10 years

      expect(await claimToken.verify(1n)).to.be.true;
      expect(await claimToken.isExpired(1n)).to.be.false;
    });
  });

  // ============================================
  // Query Function Tests
  // ============================================

  describe("Query Functions", function () {
    async function mintMultipleCredentialsFixture() {
      const fixture = await deployClaimTokenFixture();
      const { claimToken, issuer, subject, other } = fixture;

      // Mint multiple credentials
      const request1 = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const sig1 = await signMintRequest(issuer, request1, await claimToken.getAddress());
      await claimToken.mint(request1, sig1);

      const request2 = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, other.address);
      const sig2 = await signMintRequest(issuer, request2, await claimToken.getAddress());
      await claimToken.mint(request2, sig2);

      const request3 = await createMintRequest(ClaimTypes.EDUCATION_DEGREE, subject.address);
      const sig3 = await signMintRequest(issuer, request3, await claimToken.getAddress());
      await claimToken.mint(request3, sig3);

      return fixture;
    }

    it("should get credentials by subject", async function () {
      const { claimToken, subject } = await loadFixture(mintMultipleCredentialsFixture);

      const credentials = await claimToken.getCredentialsBySubject(subject.address);
      expect(credentials.length).to.equal(2);
      expect(credentials).to.include(1n);
      expect(credentials).to.include(3n);
    });

    it("should get credentials by type", async function () {
      const { claimToken } = await loadFixture(mintMultipleCredentialsFixture);

      const credentials = await claimToken.getCredentialsByType(ClaimTypes.LICENSE_OPERATOR);
      expect(credentials.length).to.equal(2);
      expect(credentials).to.include(1n);
      expect(credentials).to.include(2n);
    });

    it("should get credentials by issuer", async function () {
      const { claimToken, issuer } = await loadFixture(mintMultipleCredentialsFixture);

      const credentials = await claimToken.getCredentialsByIssuer(issuer.address);
      expect(credentials.length).to.equal(3);
    });

    it("should return token URI as metadata URI", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployClaimTokenFixture);

      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      expect(await claimToken.tokenURI(1n)).to.equal("ipfs://QmTestMetadata");
    });

    it("should get commitments", async function () {
      const { claimToken, issuer, subject } = await loadFixture(deployClaimTokenFixture);

      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      const commitments = await claimToken.getCommitments(1n);
      expect(commitments.length).to.equal(2);
      expect(commitments[0]).to.equal(request.commitments[0]);
      expect(commitments[1]).to.equal(request.commitments[1]);
    });
  });

  // ============================================
  // Transfer Tests
  // ============================================

  describe("Transfers", function () {
    it("should allow transfer of transferable credential", async function () {
      const { claimToken, issuer, subject, other } = await loadFixture(deployClaimTokenFixture);

      // Property deeds are transferable
      const request = await createMintRequest(ClaimTypes.PROPERTY_DEED, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      await claimToken.connect(subject).transferFrom(subject.address, other.address, 1n);

      expect(await claimToken.ownerOf(1n)).to.equal(other.address);
    });

    it("should block transfer of non-transferable credential", async function () {
      const { claimToken, issuer, subject, other } = await loadFixture(deployClaimTokenFixture);

      // License is non-transferable
      const request = await createMintRequest(ClaimTypes.LICENSE_OPERATOR, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      await expect(
        claimToken.connect(subject).transferFrom(subject.address, other.address, 1n)
      ).to.be.revertedWithCustomError(claimToken, "TransferUnauthorized");
    });

    it("should allow return of non-transferable credential to original subject", async function () {
      const { claimToken, issuer, subject, other, owner } = await loadFixture(
        deployClaimTokenFixture
      );

      // Property deed is transferable, so we can transfer it away first
      const request = await createMintRequest(ClaimTypes.PROPERTY_DEED, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      // Transfer to other
      await claimToken.connect(subject).transferFrom(subject.address, other.address, 1n);

      // Transfer back to subject
      await claimToken.connect(other).transferFrom(other.address, subject.address, 1n);

      expect(await claimToken.ownerOf(1n)).to.equal(subject.address);
    });

    it("should emit CredentialTransferred event", async function () {
      const { claimToken, issuer, subject, other } = await loadFixture(deployClaimTokenFixture);

      const request = await createMintRequest(ClaimTypes.PROPERTY_DEED, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      await expect(claimToken.connect(subject).transferFrom(subject.address, other.address, 1n))
        .to.emit(claimToken, "CredentialTransferred")
        .withArgs(1n, subject.address, other.address);
    });
  });

  // ============================================
  // Administrative Tests
  // ============================================

  describe("Administration", function () {
    it("should allow admin to set ZK engine", async function () {
      const { claimToken, owner, other } = await loadFixture(deployClaimTokenFixture);

      await claimToken.connect(owner).setZKEngine(other.address);
      expect(await claimToken.zkEngine()).to.equal(other.address);
    });

    it("should allow admin to set lifecycle manager", async function () {
      const { claimToken, owner, other } = await loadFixture(deployClaimTokenFixture);

      await claimToken.connect(owner).setLifecycleManager(other.address);
      expect(await claimToken.lifecycleManager()).to.equal(other.address);

      // Check role was granted
      const LIFECYCLE_MANAGER_ROLE = await claimToken.LIFECYCLE_MANAGER_ROLE();
      expect(await claimToken.hasRole(LIFECYCLE_MANAGER_ROLE, other.address)).to.be.true;
    });

    it("should reject non-admin setting issuer registry", async function () {
      const { claimToken, other } = await loadFixture(deployClaimTokenFixture);

      await expect(
        claimToken.connect(other).setIssuerRegistry(other.address)
      ).to.be.reverted;
    });

    it("should reject setting zero address as issuer registry", async function () {
      const { claimToken, owner } = await loadFixture(deployClaimTokenFixture);

      await expect(
        claimToken.connect(owner).setIssuerRegistry(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(claimToken, "ZeroAddress");
    });
  });

  // ============================================
  // ERC721 Compliance Tests
  // ============================================

  describe("ERC721 Compliance", function () {
    async function mintCredentialFixture() {
      const fixture = await deployClaimTokenFixture();
      const { claimToken, issuer, subject } = fixture;

      const request = await createMintRequest(ClaimTypes.PROPERTY_DEED, subject.address);
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.mint(request, signature);

      return { ...fixture, tokenId: 1n };
    }

    it("should support ERC721 interface", async function () {
      const { claimToken } = await loadFixture(deployClaimTokenFixture);

      // ERC721 interface ID
      expect(await claimToken.supportsInterface("0x80ac58cd")).to.be.true;
    });

    it("should support ERC721Enumerable interface", async function () {
      const { claimToken } = await loadFixture(deployClaimTokenFixture);

      // ERC721Enumerable interface ID
      expect(await claimToken.supportsInterface("0x780e9d63")).to.be.true;
    });

    it("should track balance correctly", async function () {
      const { claimToken, subject, tokenId } = await loadFixture(mintCredentialFixture);

      expect(await claimToken.balanceOf(subject.address)).to.equal(1n);
    });

    it("should enumerate tokens by owner", async function () {
      const { claimToken, subject, tokenId } = await loadFixture(mintCredentialFixture);

      expect(await claimToken.tokenOfOwnerByIndex(subject.address, 0)).to.equal(tokenId);
    });

    it("should enumerate all tokens", async function () {
      const { claimToken, tokenId } = await loadFixture(mintCredentialFixture);

      expect(await claimToken.totalSupply()).to.equal(1n);
      expect(await claimToken.tokenByIndex(0)).to.equal(tokenId);
    });

    it("should handle approval", async function () {
      const { claimToken, subject, other, tokenId } = await loadFixture(mintCredentialFixture);

      await claimToken.connect(subject).approve(other.address, tokenId);
      expect(await claimToken.getApproved(tokenId)).to.equal(other.address);
    });
  });
});
