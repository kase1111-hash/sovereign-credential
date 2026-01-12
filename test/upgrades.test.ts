/**
 * @file upgrades.test.ts
 * @description Tests for contract upgradeability and state preservation
 * @dev Verifies UUPS upgrade pattern works correctly for all contracts
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
import { ClaimTypes, CredentialStatus } from "../types";

describe("Contract Upgrades", function () {
  // ============================================
  // Fixtures
  // ============================================

  async function deployContractsFixture() {
    const [owner, issuer, subject, upgrader, other] = await ethers.getSigners();

    // Deploy IssuerRegistry
    const IssuerRegistryFactory = await ethers.getContractFactory("IssuerRegistry");
    const issuerRegistry = (await upgrades.deployProxy(IssuerRegistryFactory, [], {
      initializer: "initialize",
      kind: "uups",
    })) as unknown as IssuerRegistry;
    await issuerRegistry.waitForDeployment();

    // Deploy ClaimToken
    const ClaimTokenFactory = await ethers.getContractFactory("ClaimToken");
    const claimToken = (await upgrades.deployProxy(
      ClaimTokenFactory,
      [await issuerRegistry.getAddress()],
      { initializer: "initialize", kind: "uups" }
    )) as unknown as ClaimToken;
    await claimToken.waitForDeployment();

    // Deploy CredentialLifecycleManager
    const LifecycleManagerFactory = await ethers.getContractFactory(
      "CredentialLifecycleManager"
    );
    const lifecycleManager = (await upgrades.deployProxy(
      LifecycleManagerFactory,
      [await claimToken.getAddress(), await issuerRegistry.getAddress()],
      { initializer: "initialize", kind: "uups" }
    )) as unknown as CredentialLifecycleManager;
    await lifecycleManager.waitForDeployment();

    // Setup roles
    const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
    await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, await claimToken.getAddress());

    await claimToken.setLifecycleManager(await lifecycleManager.getAddress());

    // Grant UPGRADER_ROLE to upgrader
    const UPGRADER_ROLE = await issuerRegistry.UPGRADER_ROLE();
    await issuerRegistry.grantRole(UPGRADER_ROLE, upgrader.address);
    await claimToken.grantRole(await claimToken.UPGRADER_ROLE(), upgrader.address);
    await lifecycleManager.grantRole(await lifecycleManager.UPGRADER_ROLE(), upgrader.address);

    // Register issuer
    await issuerRegistry.registerIssuer(issuer.address, "US-CA", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.PROPERTY_DEED,
    ]);

    return {
      issuerRegistry,
      claimToken,
      lifecycleManager,
      owner,
      issuer,
      subject,
      upgrader,
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

  // ============================================
  // IssuerRegistry Upgrade Tests
  // ============================================

  describe("IssuerRegistry Upgrades", function () {
    it("should preserve issuer data after upgrade", async function () {
      const { issuerRegistry, issuer, upgrader, owner } = await loadFixture(
        deployContractsFixture
      );

      // Get initial state
      const initialIssuerData = await issuerRegistry.getIssuer(issuer.address);
      const initialIsAuthorized = await issuerRegistry.isAuthorized(
        issuer.address,
        ClaimTypes.LICENSE_OPERATOR
      );

      // Perform upgrade
      const IssuerRegistryV2 = await ethers.getContractFactory("IssuerRegistry");
      const upgraded = await upgrades.upgradeProxy(
        await issuerRegistry.getAddress(),
        IssuerRegistryV2,
        { kind: "uups" }
      );

      // Verify state is preserved
      const postUpgradeIssuerData = await upgraded.getIssuer(issuer.address);
      const postUpgradeIsAuthorized = await upgraded.isAuthorized(
        issuer.address,
        ClaimTypes.LICENSE_OPERATOR
      );

      expect(postUpgradeIssuerData.issuerAddress).to.equal(
        initialIssuerData.issuerAddress
      );
      expect(postUpgradeIssuerData.jurisdiction).to.equal(
        initialIssuerData.jurisdiction
      );
      expect(postUpgradeIssuerData.isActive).to.equal(initialIssuerData.isActive);
      expect(postUpgradeIsAuthorized).to.equal(initialIsAuthorized);
    });

    it("should preserve role assignments after upgrade", async function () {
      const { issuerRegistry, owner, upgrader } = await loadFixture(
        deployContractsFixture
      );

      const DEFAULT_ADMIN_ROLE = await issuerRegistry.DEFAULT_ADMIN_ROLE();
      const UPGRADER_ROLE = await issuerRegistry.UPGRADER_ROLE();

      // Check initial roles
      expect(await issuerRegistry.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.be
        .true;
      expect(await issuerRegistry.hasRole(UPGRADER_ROLE, upgrader.address)).to.be.true;

      // Perform upgrade
      const IssuerRegistryV2 = await ethers.getContractFactory("IssuerRegistry");
      const upgraded = await upgrades.upgradeProxy(
        await issuerRegistry.getAddress(),
        IssuerRegistryV2,
        { kind: "uups" }
      );

      // Verify roles preserved
      expect(await upgraded.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.be.true;
      expect(await upgraded.hasRole(UPGRADER_ROLE, upgrader.address)).to.be.true;
    });

    it("should only allow UPGRADER_ROLE to upgrade", async function () {
      const { issuerRegistry, other } = await loadFixture(deployContractsFixture);

      const IssuerRegistryV2 = await ethers.getContractFactory(
        "IssuerRegistry",
        other
      );

      // Attempt upgrade without UPGRADER_ROLE
      await expect(
        upgrades.upgradeProxy(await issuerRegistry.getAddress(), IssuerRegistryV2, {
          kind: "uups",
        })
      ).to.be.reverted;
    });

    it("should change implementation address after upgrade", async function () {
      const { issuerRegistry } = await loadFixture(deployContractsFixture);

      const proxyAddress = await issuerRegistry.getAddress();
      const initialImpl = await upgrades.erc1967.getImplementationAddress(proxyAddress);

      // Perform upgrade
      const IssuerRegistryV2 = await ethers.getContractFactory("IssuerRegistry");
      await upgrades.upgradeProxy(proxyAddress, IssuerRegistryV2, { kind: "uups" });

      const newImpl = await upgrades.erc1967.getImplementationAddress(proxyAddress);

      expect(newImpl).to.not.equal(initialImpl);
    });
  });

  // ============================================
  // ClaimToken Upgrade Tests
  // ============================================

  describe("ClaimToken Upgrades", function () {
    async function mintedCredentialFixture() {
      const fixture = await deployContractsFixture();
      const { claimToken, issuer, subject } = fixture;

      // Mint a credential
      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address
      );
      const signature = await signMintRequest(
        issuer,
        request,
        await claimToken.getAddress()
      );
      await claimToken.mint(request, signature);

      return { ...fixture, tokenId: 1n, request };
    }

    it("should preserve credential data after upgrade", async function () {
      const { claimToken, tokenId, request, subject, issuer } = await loadFixture(
        mintedCredentialFixture
      );

      // Get initial credential data
      const initialCredential = await claimToken.getCredential(tokenId);
      const initialOwner = await claimToken.ownerOf(tokenId);
      const initialTotalCredentials = await claimToken.totalCredentials();

      // Perform upgrade
      const ClaimTokenV2 = await ethers.getContractFactory("ClaimToken");
      const upgraded = await upgrades.upgradeProxy(
        await claimToken.getAddress(),
        ClaimTokenV2,
        { kind: "uups" }
      );

      // Verify credential data preserved
      const postUpgradeCredential = await upgraded.getCredential(tokenId);
      const postUpgradeOwner = await upgraded.ownerOf(tokenId);
      const postUpgradeTotalCredentials = await upgraded.totalCredentials();

      expect(postUpgradeCredential.tokenId).to.equal(initialCredential.tokenId);
      expect(postUpgradeCredential.claimType).to.equal(initialCredential.claimType);
      expect(postUpgradeCredential.subject).to.equal(initialCredential.subject);
      expect(postUpgradeCredential.issuer).to.equal(initialCredential.issuer);
      expect(postUpgradeCredential.status).to.equal(initialCredential.status);
      expect(postUpgradeOwner).to.equal(initialOwner);
      expect(postUpgradeTotalCredentials).to.equal(initialTotalCredentials);
    });

    it("should preserve ERC721 token ownership after upgrade", async function () {
      const { claimToken, tokenId, subject } = await loadFixture(
        mintedCredentialFixture
      );

      // Check initial ownership
      expect(await claimToken.ownerOf(tokenId)).to.equal(subject.address);
      expect(await claimToken.balanceOf(subject.address)).to.equal(1n);

      // Perform upgrade
      const ClaimTokenV2 = await ethers.getContractFactory("ClaimToken");
      const upgraded = await upgrades.upgradeProxy(
        await claimToken.getAddress(),
        ClaimTokenV2,
        { kind: "uups" }
      );

      // Verify ownership preserved
      expect(await upgraded.ownerOf(tokenId)).to.equal(subject.address);
      expect(await upgraded.balanceOf(subject.address)).to.equal(1n);
    });

    it("should preserve credential indexes after upgrade", async function () {
      const { claimToken, issuer, subject, other } = await loadFixture(
        deployContractsFixture
      );

      // Mint multiple credentials
      const request1 = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address
      );
      const sig1 = await signMintRequest(issuer, request1, await claimToken.getAddress());
      await claimToken.mint(request1, sig1);

      const request2 = await createMintRequest(
        ClaimTypes.PROPERTY_DEED,
        other.address
      );
      const sig2 = await signMintRequest(issuer, request2, await claimToken.getAddress());
      await claimToken.mint(request2, sig2);

      // Get initial index data
      const initialBySubject = await claimToken.getCredentialsBySubject(subject.address);
      const initialByType = await claimToken.getCredentialsByType(
        ClaimTypes.LICENSE_OPERATOR
      );
      const initialByIssuer = await claimToken.getCredentialsByIssuer(issuer.address);

      // Perform upgrade
      const ClaimTokenV2 = await ethers.getContractFactory("ClaimToken");
      const upgraded = await upgrades.upgradeProxy(
        await claimToken.getAddress(),
        ClaimTokenV2,
        { kind: "uups" }
      );

      // Verify indexes preserved
      const postBySubject = await upgraded.getCredentialsBySubject(subject.address);
      const postByType = await upgraded.getCredentialsByType(ClaimTypes.LICENSE_OPERATOR);
      const postByIssuer = await upgraded.getCredentialsByIssuer(issuer.address);

      expect(postBySubject).to.deep.equal(initialBySubject);
      expect(postByType).to.deep.equal(initialByType);
      expect(postByIssuer).to.deep.equal(initialByIssuer);
    });

    it("should preserve credential status after upgrade", async function () {
      const { claimToken, issuer, tokenId } = await loadFixture(mintedCredentialFixture);

      // Suspend the credential
      await claimToken.connect(issuer).suspend(tokenId, "Test suspension");
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.SUSPENDED);

      // Perform upgrade
      const ClaimTokenV2 = await ethers.getContractFactory("ClaimToken");
      const upgraded = await upgrades.upgradeProxy(
        await claimToken.getAddress(),
        ClaimTokenV2,
        { kind: "uups" }
      );

      // Verify status preserved
      expect(await upgraded.getStatus(tokenId)).to.equal(CredentialStatus.SUSPENDED);
    });

    it("should allow minting new credentials after upgrade", async function () {
      const { claimToken, issuer, subject, other } = await loadFixture(
        mintedCredentialFixture
      );

      // Perform upgrade
      const ClaimTokenV2 = await ethers.getContractFactory("ClaimToken");
      const upgraded = (await upgrades.upgradeProxy(
        await claimToken.getAddress(),
        ClaimTokenV2,
        { kind: "uups" }
      )) as unknown as ClaimToken;

      // Mint new credential after upgrade
      const request = await createMintRequest(ClaimTypes.PROPERTY_DEED, other.address);
      const signature = await signMintRequest(
        issuer,
        request,
        await upgraded.getAddress()
      );
      await upgraded.mint(request, signature);

      // Verify new credential minted correctly
      expect(await upgraded.totalCredentials()).to.equal(2n);
      expect(await upgraded.ownerOf(2n)).to.equal(other.address);
    });
  });

  // ============================================
  // CredentialLifecycleManager Upgrade Tests
  // ============================================

  describe("CredentialLifecycleManager Upgrades", function () {
    async function withInheritanceDirectiveFixture() {
      const fixture = await deployContractsFixture();
      const { claimToken, lifecycleManager, issuer, subject, other } = fixture;

      // Mint a credential
      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address
      );
      const signature = await signMintRequest(
        issuer,
        request,
        await claimToken.getAddress()
      );
      await claimToken.mint(request, signature);

      // Set inheritance directive
      const directive = {
        credentialId: 1n,
        beneficiaries: [other.address],
        shares: [],
        requiresFIETrigger: false,
        fieIntentHash: ethers.ZeroHash,
        conditions: "0x",
      };
      await lifecycleManager.connect(subject).setInheritanceDirective(1n, directive);

      return { ...fixture, tokenId: 1n, directive };
    }

    it("should preserve inheritance directives after upgrade", async function () {
      const { lifecycleManager, tokenId, other } = await loadFixture(
        withInheritanceDirectiveFixture
      );

      // Get initial directive
      const initialDirective = await lifecycleManager.getInheritanceDirective(tokenId);
      expect(initialDirective.beneficiaries).to.deep.equal([other.address]);

      // Perform upgrade
      const LifecycleManagerV2 = await ethers.getContractFactory(
        "CredentialLifecycleManager"
      );
      const upgraded = await upgrades.upgradeProxy(
        await lifecycleManager.getAddress(),
        LifecycleManagerV2,
        { kind: "uups" }
      );

      // Verify directive preserved
      const postUpgradeDirective = await upgraded.getInheritanceDirective(tokenId);
      expect(postUpgradeDirective.beneficiaries).to.deep.equal([other.address]);
    });

    it("should preserve pending renewals after upgrade", async function () {
      const { claimToken, lifecycleManager, issuer, subject } = await loadFixture(
        deployContractsFixture
      );

      // Mint credential and request renewal
      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address
      );
      const signature = await signMintRequest(
        issuer,
        request,
        await claimToken.getAddress()
      );
      await claimToken.mint(request, signature);
      await lifecycleManager.connect(subject).requestRenewal(1n);

      // Verify renewal request exists
      expect(await lifecycleManager.hasRenewalRequest(1n)).to.be.true;

      // Perform upgrade
      const LifecycleManagerV2 = await ethers.getContractFactory(
        "CredentialLifecycleManager"
      );
      const upgraded = await upgrades.upgradeProxy(
        await lifecycleManager.getAddress(),
        LifecycleManagerV2,
        { kind: "uups" }
      );

      // Verify renewal request preserved
      expect(await upgraded.hasRenewalRequest(1n)).to.be.true;
      const pendingRenewals = await upgraded.getPendingRenewals();
      expect(pendingRenewals).to.include(1n);
    });

    it("should preserve splittable type configuration after upgrade", async function () {
      const { lifecycleManager, owner } = await loadFixture(deployContractsFixture);

      // Check default splittable type
      expect(await lifecycleManager.isSplittable(ClaimTypes.PROPERTY_DEED)).to.be.true;

      // Add custom splittable type
      await lifecycleManager
        .connect(owner)
        .setSplittable(ClaimTypes.LICENSE_OPERATOR, true);
      expect(await lifecycleManager.isSplittable(ClaimTypes.LICENSE_OPERATOR)).to.be
        .true;

      // Perform upgrade
      const LifecycleManagerV2 = await ethers.getContractFactory(
        "CredentialLifecycleManager"
      );
      const upgraded = await upgrades.upgradeProxy(
        await lifecycleManager.getAddress(),
        LifecycleManagerV2,
        { kind: "uups" }
      );

      // Verify splittable configuration preserved
      expect(await upgraded.isSplittable(ClaimTypes.PROPERTY_DEED)).to.be.true;
      expect(await upgraded.isSplittable(ClaimTypes.LICENSE_OPERATOR)).to.be.true;
    });
  });

  // ============================================
  // Cross-Contract Upgrade Tests
  // ============================================

  describe("Cross-Contract Upgrade Compatibility", function () {
    it("should maintain cross-references after upgrading all contracts", async function () {
      const { issuerRegistry, claimToken, lifecycleManager } = await loadFixture(
        deployContractsFixture
      );

      // Get initial addresses
      const issuerRegistryAddress = await issuerRegistry.getAddress();
      const claimTokenAddress = await claimToken.getAddress();
      const lifecycleManagerAddress = await lifecycleManager.getAddress();

      // Upgrade all contracts
      const IssuerRegistryV2 = await ethers.getContractFactory("IssuerRegistry");
      await upgrades.upgradeProxy(issuerRegistryAddress, IssuerRegistryV2, {
        kind: "uups",
      });

      const ClaimTokenV2 = await ethers.getContractFactory("ClaimToken");
      const upgradedClaimToken = (await upgrades.upgradeProxy(
        claimTokenAddress,
        ClaimTokenV2,
        { kind: "uups" }
      )) as unknown as ClaimToken;

      const LifecycleManagerV2 = await ethers.getContractFactory(
        "CredentialLifecycleManager"
      );
      const upgradedLifecycleManager = (await upgrades.upgradeProxy(
        lifecycleManagerAddress,
        LifecycleManagerV2,
        { kind: "uups" }
      )) as unknown as CredentialLifecycleManager;

      // Verify cross-references maintained
      expect(await upgradedClaimToken.issuerRegistry()).to.equal(issuerRegistryAddress);
      expect(await upgradedLifecycleManager.claimToken()).to.equal(claimTokenAddress);
      expect(await upgradedLifecycleManager.issuerRegistry()).to.equal(
        issuerRegistryAddress
      );
    });

    it("should allow credential operations after upgrading all contracts", async function () {
      const { issuerRegistry, claimToken, lifecycleManager, issuer, subject } =
        await loadFixture(deployContractsFixture);

      // Upgrade all contracts
      const IssuerRegistryV2 = await ethers.getContractFactory("IssuerRegistry");
      await upgrades.upgradeProxy(await issuerRegistry.getAddress(), IssuerRegistryV2, {
        kind: "uups",
      });

      const ClaimTokenV2 = await ethers.getContractFactory("ClaimToken");
      const upgradedClaimToken = (await upgrades.upgradeProxy(
        await claimToken.getAddress(),
        ClaimTokenV2,
        { kind: "uups" }
      )) as unknown as ClaimToken;

      const LifecycleManagerV2 = await ethers.getContractFactory(
        "CredentialLifecycleManager"
      );
      const upgradedLifecycleManager = (await upgrades.upgradeProxy(
        await lifecycleManager.getAddress(),
        LifecycleManagerV2,
        { kind: "uups" }
      )) as unknown as CredentialLifecycleManager;

      // Perform credential operations after upgrade
      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address
      );
      const signature = await signMintRequest(
        issuer,
        request,
        await upgradedClaimToken.getAddress()
      );

      // Mint should work
      await upgradedClaimToken.mint(request, signature);
      expect(await upgradedClaimToken.totalCredentials()).to.equal(1n);

      // Lifecycle operations should work
      await upgradedLifecycleManager.connect(subject).requestRenewal(1n);
      expect(await upgradedLifecycleManager.hasRenewalRequest(1n)).to.be.true;
    });
  });

  // ============================================
  // Storage Layout Compatibility Tests
  // ============================================

  describe("Storage Layout Compatibility", function () {
    it("should validate upgrade compatibility for IssuerRegistry", async function () {
      const { issuerRegistry } = await loadFixture(deployContractsFixture);

      const IssuerRegistryV2 = await ethers.getContractFactory("IssuerRegistry");

      // This will throw if storage layout is incompatible
      await expect(
        upgrades.validateUpgrade(await issuerRegistry.getAddress(), IssuerRegistryV2, {
          kind: "uups",
        })
      ).to.not.be.rejected;
    });

    it("should validate upgrade compatibility for ClaimToken", async function () {
      const { claimToken } = await loadFixture(deployContractsFixture);

      const ClaimTokenV2 = await ethers.getContractFactory("ClaimToken");

      // This will throw if storage layout is incompatible
      await expect(
        upgrades.validateUpgrade(await claimToken.getAddress(), ClaimTokenV2, {
          kind: "uups",
        })
      ).to.not.be.rejected;
    });

    it("should validate upgrade compatibility for CredentialLifecycleManager", async function () {
      const { lifecycleManager } = await loadFixture(deployContractsFixture);

      const LifecycleManagerV2 = await ethers.getContractFactory(
        "CredentialLifecycleManager"
      );

      // This will throw if storage layout is incompatible
      await expect(
        upgrades.validateUpgrade(
          await lifecycleManager.getAddress(),
          LifecycleManagerV2,
          { kind: "uups" }
        )
      ).to.not.be.rejected;
    });
  });
});
