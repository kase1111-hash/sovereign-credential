/**
 * @file IssuerRegistry unit tests
 * @description Comprehensive tests for the IssuerRegistry contract
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { type SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { type IssuerRegistry } from "../typechain-types";
import { ClaimTypes, Constants } from "../types";

describe("IssuerRegistry", function () {
  // ============================================
  // Fixtures
  // ============================================

  async function deployIssuerRegistryFixture() {
    const [owner, registrar, arbiter, issuer1, issuer2, delegate1, delegate2, other] =
      await ethers.getSigners();

    // Deploy as upgradeable proxy
    const IssuerRegistryFactory = await ethers.getContractFactory("IssuerRegistry");
    const issuerRegistry = (await upgrades.deployProxy(IssuerRegistryFactory, [], {
      initializer: "initialize",
    })) as unknown as IssuerRegistry;

    await issuerRegistry.waitForDeployment();

    // Get role identifiers
    const DEFAULT_ADMIN_ROLE = await issuerRegistry.DEFAULT_ADMIN_ROLE();
    const REGISTRAR_ROLE = await issuerRegistry.REGISTRAR_ROLE();
    const ARBITER_ROLE = await issuerRegistry.ARBITER_ROLE();
    const UPGRADER_ROLE = await issuerRegistry.UPGRADER_ROLE();
    const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();

    // Grant roles
    await issuerRegistry.grantRole(REGISTRAR_ROLE, registrar.address);
    await issuerRegistry.grantRole(ARBITER_ROLE, arbiter.address);

    return {
      issuerRegistry,
      owner,
      registrar,
      arbiter,
      issuer1,
      issuer2,
      delegate1,
      delegate2,
      other,
      DEFAULT_ADMIN_ROLE,
      REGISTRAR_ROLE,
      ARBITER_ROLE,
      UPGRADER_ROLE,
      CREDENTIAL_CONTRACT_ROLE,
    };
  }

  async function deployWithIssuersFixture() {
    const fixture = await deployIssuerRegistryFixture();
    const { issuerRegistry, registrar, issuer1, issuer2 } = fixture;

    // Register issuers
    await issuerRegistry
      .connect(registrar)
      .registerIssuer(issuer1.address, "US-OR", [
        ClaimTypes.LICENSE_OPERATOR,
        ClaimTypes.IDENTITY_RESIDENCE,
      ]);

    await issuerRegistry
      .connect(registrar)
      .registerIssuer(issuer2.address, "US-CA", [
        ClaimTypes.EDUCATION_DEGREE,
        ClaimTypes.EDUCATION_CERTIFICATION,
      ]);

    return fixture;
  }

  // ============================================
  // Deployment Tests
  // ============================================

  describe("Deployment", function () {
    it("should initialize with correct roles granted to deployer", async function () {
      const { issuerRegistry, owner, DEFAULT_ADMIN_ROLE, REGISTRAR_ROLE, ARBITER_ROLE, UPGRADER_ROLE } =
        await loadFixture(deployIssuerRegistryFixture);

      expect(await issuerRegistry.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.be.true;
      expect(await issuerRegistry.hasRole(REGISTRAR_ROLE, owner.address)).to.be.true;
      expect(await issuerRegistry.hasRole(ARBITER_ROLE, owner.address)).to.be.true;
      expect(await issuerRegistry.hasRole(UPGRADER_ROLE, owner.address)).to.be.true;
    });

    it("should have correct constants", async function () {
      const { issuerRegistry } = await loadFixture(deployIssuerRegistryFixture);

      expect(await issuerRegistry.MIN_REPUTATION()).to.equal(1000n);
      expect(await issuerRegistry.MAX_REPUTATION()).to.equal(10000n);
      expect(await issuerRegistry.INITIAL_REPUTATION()).to.equal(5000n);
    });

    it("should start with zero issuers", async function () {
      const { issuerRegistry } = await loadFixture(deployIssuerRegistryFixture);

      expect(await issuerRegistry.totalIssuers()).to.equal(0n);
    });
  });

  // ============================================
  // Registration Tests
  // ============================================

  describe("Registration", function () {
    it("should register a new issuer with initial claim types", async function () {
      const { issuerRegistry, registrar, issuer1 } = await loadFixture(deployIssuerRegistryFixture);

      await expect(
        issuerRegistry
          .connect(registrar)
          .registerIssuer(issuer1.address, "US-OR", [ClaimTypes.LICENSE_OPERATOR])
      )
        .to.emit(issuerRegistry, "IssuerRegistered")
        .withArgs(issuer1.address, "US-OR")
        .and.to.emit(issuerRegistry, "TypeAuthorized")
        .withArgs(issuer1.address, ClaimTypes.LICENSE_OPERATOR);

      expect(await issuerRegistry.isRegistered(issuer1.address)).to.be.true;
      expect(await issuerRegistry.isActive(issuer1.address)).to.be.true;
      expect(await issuerRegistry.totalIssuers()).to.equal(1n);
    });

    it("should set initial reputation to 5000", async function () {
      const { issuerRegistry, registrar, issuer1 } = await loadFixture(deployIssuerRegistryFixture);

      await issuerRegistry.connect(registrar).registerIssuer(issuer1.address, "US-OR", []);

      expect(await issuerRegistry.getReputation(issuer1.address)).to.equal(5000n);
    });

    it("should reject registration from non-registrar", async function () {
      const { issuerRegistry, other, issuer1 } = await loadFixture(deployIssuerRegistryFixture);

      await expect(
        issuerRegistry.connect(other).registerIssuer(issuer1.address, "US-OR", [])
      ).to.be.reverted;
    });

    it("should reject registration of zero address", async function () {
      const { issuerRegistry, registrar } = await loadFixture(deployIssuerRegistryFixture);

      await expect(
        issuerRegistry.connect(registrar).registerIssuer(ethers.ZeroAddress, "US-OR", [])
      ).to.be.revertedWithCustomError(issuerRegistry, "ZeroAddress");
    });

    it("should reject duplicate registration", async function () {
      const { issuerRegistry, registrar, issuer1 } = await loadFixture(deployIssuerRegistryFixture);

      await issuerRegistry.connect(registrar).registerIssuer(issuer1.address, "US-OR", []);

      await expect(
        issuerRegistry.connect(registrar).registerIssuer(issuer1.address, "US-CA", [])
      ).to.be.revertedWithCustomError(issuerRegistry, "IssuerAlreadyRegistered");
    });

    it("should register multiple issuers", async function () {
      const { issuerRegistry, registrar, issuer1, issuer2 } = await loadFixture(
        deployIssuerRegistryFixture
      );

      await issuerRegistry.connect(registrar).registerIssuer(issuer1.address, "US-OR", []);
      await issuerRegistry.connect(registrar).registerIssuer(issuer2.address, "US-CA", []);

      expect(await issuerRegistry.totalIssuers()).to.equal(2n);

      const allIssuers = await issuerRegistry.getAllIssuers();
      expect(allIssuers).to.include(issuer1.address);
      expect(allIssuers).to.include(issuer2.address);
    });
  });

  // ============================================
  // Deactivation Tests
  // ============================================

  describe("Deactivation", function () {
    it("should deactivate an active issuer", async function () {
      const { issuerRegistry, registrar, issuer1 } = await loadFixture(deployWithIssuersFixture);

      await expect(issuerRegistry.connect(registrar).deactivateIssuer(issuer1.address, "Violation"))
        .to.emit(issuerRegistry, "IssuerDeactivated")
        .withArgs(issuer1.address, "Violation");

      expect(await issuerRegistry.isActive(issuer1.address)).to.be.false;
    });

    it("should prevent deactivated issuer from being authorized", async function () {
      const { issuerRegistry, registrar, issuer1 } = await loadFixture(deployWithIssuersFixture);

      // Before deactivation
      expect(await issuerRegistry.isAuthorized(issuer1.address, ClaimTypes.LICENSE_OPERATOR)).to.be
        .true;

      await issuerRegistry.connect(registrar).deactivateIssuer(issuer1.address, "Violation");

      // After deactivation
      expect(await issuerRegistry.isAuthorized(issuer1.address, ClaimTypes.LICENSE_OPERATOR)).to.be
        .false;
    });

    it("should reject deactivation of non-existent issuer", async function () {
      const { issuerRegistry, registrar, other } = await loadFixture(deployIssuerRegistryFixture);

      await expect(
        issuerRegistry.connect(registrar).deactivateIssuer(other.address, "Test")
      ).to.be.revertedWithCustomError(issuerRegistry, "IssuerNotFound");
    });

    it("should reject deactivation of already deactivated issuer", async function () {
      const { issuerRegistry, registrar, issuer1 } = await loadFixture(deployWithIssuersFixture);

      await issuerRegistry.connect(registrar).deactivateIssuer(issuer1.address, "First");

      await expect(
        issuerRegistry.connect(registrar).deactivateIssuer(issuer1.address, "Second")
      ).to.be.revertedWithCustomError(issuerRegistry, "IssuerNotActive");
    });

    it("should reactivate a deactivated issuer", async function () {
      const { issuerRegistry, registrar, issuer1 } = await loadFixture(deployWithIssuersFixture);

      await issuerRegistry.connect(registrar).deactivateIssuer(issuer1.address, "Temporary");

      await expect(issuerRegistry.connect(registrar).reactivateIssuer(issuer1.address))
        .to.emit(issuerRegistry, "IssuerReactivated")
        .withArgs(issuer1.address);

      expect(await issuerRegistry.isActive(issuer1.address)).to.be.true;
      expect(await issuerRegistry.isAuthorized(issuer1.address, ClaimTypes.LICENSE_OPERATOR)).to.be
        .true;
    });
  });

  // ============================================
  // Type Authorization Tests
  // ============================================

  describe("Type Authorization", function () {
    it("should authorize additional claim types", async function () {
      const { issuerRegistry, registrar, issuer1 } = await loadFixture(deployWithIssuersFixture);

      await expect(
        issuerRegistry
          .connect(registrar)
          .authorizeType(issuer1.address, ClaimTypes.HEALTH_IMMUNIZATION)
      )
        .to.emit(issuerRegistry, "TypeAuthorized")
        .withArgs(issuer1.address, ClaimTypes.HEALTH_IMMUNIZATION);

      expect(await issuerRegistry.isAuthorized(issuer1.address, ClaimTypes.HEALTH_IMMUNIZATION)).to
        .be.true;
    });

    it("should revoke claim type authorization", async function () {
      const { issuerRegistry, registrar, issuer1 } = await loadFixture(deployWithIssuersFixture);

      await expect(
        issuerRegistry.connect(registrar).revokeType(issuer1.address, ClaimTypes.LICENSE_OPERATOR)
      )
        .to.emit(issuerRegistry, "TypeRevoked")
        .withArgs(issuer1.address, ClaimTypes.LICENSE_OPERATOR);

      expect(await issuerRegistry.isAuthorized(issuer1.address, ClaimTypes.LICENSE_OPERATOR)).to.be
        .false;
    });

    it("should batch authorize multiple types", async function () {
      const { issuerRegistry, registrar, issuer1 } = await loadFixture(deployWithIssuersFixture);

      const newTypes = [
        ClaimTypes.HEALTH_IMMUNIZATION,
        ClaimTypes.FINANCIAL_ACCOUNT,
        ClaimTypes.MEMBERSHIP_DAO,
      ];

      await issuerRegistry.connect(registrar).batchAuthorizeTypes(issuer1.address, newTypes);

      for (const claimType of newTypes) {
        expect(await issuerRegistry.isAuthorized(issuer1.address, claimType)).to.be.true;
      }
    });

    it("should return all issuers for a claim type", async function () {
      const { issuerRegistry, registrar, issuer1, issuer2 } = await loadFixture(
        deployWithIssuersFixture
      );

      // Authorize both issuers for same type
      await issuerRegistry
        .connect(registrar)
        .authorizeType(issuer2.address, ClaimTypes.LICENSE_OPERATOR);

      const issuers = await issuerRegistry.getIssuersByType(ClaimTypes.LICENSE_OPERATOR);
      expect(issuers).to.include(issuer1.address);
      expect(issuers).to.include(issuer2.address);
    });

    it("should return authorized types for an issuer", async function () {
      const { issuerRegistry, issuer1 } = await loadFixture(deployWithIssuersFixture);

      const types = await issuerRegistry.getAuthorizedTypes(issuer1.address);
      expect(types).to.include(ClaimTypes.LICENSE_OPERATOR);
      expect(types).to.include(ClaimTypes.IDENTITY_RESIDENCE);
    });
  });

  // ============================================
  // Delegate Management Tests
  // ============================================

  describe("Delegate Management", function () {
    it("should allow issuer to add a delegate", async function () {
      const { issuerRegistry, issuer1, delegate1 } = await loadFixture(deployWithIssuersFixture);

      await expect(issuerRegistry.connect(issuer1).addDelegate(delegate1.address))
        .to.emit(issuerRegistry, "DelegateAdded")
        .withArgs(issuer1.address, delegate1.address);

      expect(await issuerRegistry.isDelegate(issuer1.address, delegate1.address)).to.be.true;
      expect(await issuerRegistry.getPrincipal(delegate1.address)).to.equal(issuer1.address);
    });

    it("should allow issuer to remove a delegate", async function () {
      const { issuerRegistry, issuer1, delegate1 } = await loadFixture(deployWithIssuersFixture);

      await issuerRegistry.connect(issuer1).addDelegate(delegate1.address);

      await expect(issuerRegistry.connect(issuer1).removeDelegate(delegate1.address))
        .to.emit(issuerRegistry, "DelegateRemoved")
        .withArgs(issuer1.address, delegate1.address);

      expect(await issuerRegistry.isDelegate(issuer1.address, delegate1.address)).to.be.false;
      expect(await issuerRegistry.getPrincipal(delegate1.address)).to.equal(ethers.ZeroAddress);
    });

    it("should reject adding zero address as delegate", async function () {
      const { issuerRegistry, issuer1 } = await loadFixture(deployWithIssuersFixture);

      await expect(
        issuerRegistry.connect(issuer1).addDelegate(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(issuerRegistry, "ZeroAddress");
    });

    it("should reject adding self as delegate", async function () {
      const { issuerRegistry, issuer1 } = await loadFixture(deployWithIssuersFixture);

      await expect(
        issuerRegistry.connect(issuer1).addDelegate(issuer1.address)
      ).to.be.revertedWithCustomError(issuerRegistry, "OperationNotAllowed");
    });

    it("should reject adding delegate already assigned to another issuer", async function () {
      const { issuerRegistry, issuer1, issuer2, delegate1 } = await loadFixture(
        deployWithIssuersFixture
      );

      await issuerRegistry.connect(issuer1).addDelegate(delegate1.address);

      await expect(
        issuerRegistry.connect(issuer2).addDelegate(delegate1.address)
      ).to.be.revertedWithCustomError(issuerRegistry, "DelegateAlreadyExists");
    });

    it("should authorize delegate to sign for issuer claim types", async function () {
      const { issuerRegistry, issuer1, delegate1 } = await loadFixture(deployWithIssuersFixture);

      await issuerRegistry.connect(issuer1).addDelegate(delegate1.address);

      const [authorized, principal] = await issuerRegistry.isAuthorizedSigner(
        delegate1.address,
        ClaimTypes.LICENSE_OPERATOR
      );

      expect(authorized).to.be.true;
      expect(principal).to.equal(issuer1.address);
    });

    it("should not authorize delegate for types issuer doesn't have", async function () {
      const { issuerRegistry, issuer1, delegate1 } = await loadFixture(deployWithIssuersFixture);

      await issuerRegistry.connect(issuer1).addDelegate(delegate1.address);

      const [authorized] = await issuerRegistry.isAuthorizedSigner(
        delegate1.address,
        ClaimTypes.EDUCATION_DEGREE // issuer1 doesn't have this
      );

      expect(authorized).to.be.false;
    });

    it("should return all delegates for an issuer", async function () {
      const { issuerRegistry, issuer1, delegate1, delegate2 } = await loadFixture(
        deployWithIssuersFixture
      );

      await issuerRegistry.connect(issuer1).addDelegate(delegate1.address);
      await issuerRegistry.connect(issuer1).addDelegate(delegate2.address);

      const delegates = await issuerRegistry.getDelegates(issuer1.address);
      expect(delegates).to.include(delegate1.address);
      expect(delegates).to.include(delegate2.address);
    });
  });

  // ============================================
  // Reputation Tests
  // ============================================

  describe("Reputation", function () {
    it("should adjust reputation positively", async function () {
      const { issuerRegistry, arbiter, issuer1 } = await loadFixture(deployWithIssuersFixture);

      await expect(
        issuerRegistry.connect(arbiter).adjustReputation(issuer1.address, 1000, "Good performance")
      )
        .to.emit(issuerRegistry, "ReputationAdjusted")
        .withArgs(issuer1.address, 1000, 6000n, "Good performance");

      expect(await issuerRegistry.getReputation(issuer1.address)).to.equal(6000n);
    });

    it("should adjust reputation negatively", async function () {
      const { issuerRegistry, arbiter, issuer1 } = await loadFixture(deployWithIssuersFixture);

      await expect(
        issuerRegistry.connect(arbiter).adjustReputation(issuer1.address, -2000, "Complaint")
      )
        .to.emit(issuerRegistry, "ReputationAdjusted")
        .withArgs(issuer1.address, -2000, 3000n, "Complaint");

      expect(await issuerRegistry.getReputation(issuer1.address)).to.equal(3000n);
    });

    it("should cap reputation at maximum", async function () {
      const { issuerRegistry, arbiter, issuer1 } = await loadFixture(deployWithIssuersFixture);

      // Try to increase beyond max (initial is 5000, max is 10000)
      await issuerRegistry.connect(arbiter).adjustReputation(issuer1.address, 6000, "Excellent");

      expect(await issuerRegistry.getReputation(issuer1.address)).to.equal(10000n);
    });

    it("should floor reputation at zero", async function () {
      const { issuerRegistry, arbiter, issuer1 } = await loadFixture(deployWithIssuersFixture);

      // Try to decrease below 0 (initial is 5000)
      await issuerRegistry.connect(arbiter).adjustReputation(issuer1.address, -10000, "Major issue");

      expect(await issuerRegistry.getReputation(issuer1.address)).to.equal(0n);
    });

    it("should prevent authorization when below minimum reputation", async function () {
      const { issuerRegistry, arbiter, issuer1 } = await loadFixture(deployWithIssuersFixture);

      // Reduce reputation below minimum (1000)
      await issuerRegistry.connect(arbiter).adjustReputation(issuer1.address, -4500, "Issues");

      // Reputation is now 500, below minimum 1000
      expect(await issuerRegistry.getReputation(issuer1.address)).to.equal(500n);
      expect(await issuerRegistry.isAuthorized(issuer1.address, ClaimTypes.LICENSE_OPERATOR)).to.be
        .false;
    });

    it("should check reputation threshold", async function () {
      const { issuerRegistry, issuer1 } = await loadFixture(deployWithIssuersFixture);

      // Initial reputation is 5000
      expect(await issuerRegistry.meetsReputationThreshold(issuer1.address, 5000n)).to.be.true;
      expect(await issuerRegistry.meetsReputationThreshold(issuer1.address, 5001n)).to.be.false;
    });

    it("should reject reputation adjustment from non-arbiter", async function () {
      const { issuerRegistry, other, issuer1 } = await loadFixture(deployWithIssuersFixture);

      await expect(
        issuerRegistry.connect(other).adjustReputation(issuer1.address, 100, "Attempt")
      ).to.be.reverted;
    });
  });

  // ============================================
  // Statistics Tests
  // ============================================

  describe("Statistics", function () {
    it("should record issuance stats", async function () {
      const { issuerRegistry, owner, issuer1, CREDENTIAL_CONTRACT_ROLE } = await loadFixture(
        deployWithIssuersFixture
      );

      // Grant credential contract role to owner for testing
      await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, owner.address);

      await issuerRegistry.recordIssuance(issuer1.address);
      await issuerRegistry.recordIssuance(issuer1.address);

      const [issued, revoked, disputed] = await issuerRegistry.getStats(issuer1.address);
      expect(issued).to.equal(2n);
      expect(revoked).to.equal(0n);
      expect(disputed).to.equal(0n);
    });

    it("should record revocation stats", async function () {
      const { issuerRegistry, owner, issuer1, CREDENTIAL_CONTRACT_ROLE } = await loadFixture(
        deployWithIssuersFixture
      );

      await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, owner.address);

      await issuerRegistry.recordIssuance(issuer1.address);
      await issuerRegistry.recordRevocation(issuer1.address);

      const [issued, revoked, disputed] = await issuerRegistry.getStats(issuer1.address);
      expect(issued).to.equal(1n);
      expect(revoked).to.equal(1n);
      expect(disputed).to.equal(0n);
    });

    it("should record dispute stats", async function () {
      const { issuerRegistry, arbiter, issuer1 } = await loadFixture(deployWithIssuersFixture);

      await issuerRegistry.connect(arbiter).recordDispute(issuer1.address);

      const [, , disputed] = await issuerRegistry.getStats(issuer1.address);
      expect(disputed).to.equal(1n);
    });

    it("should emit stats updated event", async function () {
      const { issuerRegistry, owner, issuer1, CREDENTIAL_CONTRACT_ROLE } = await loadFixture(
        deployWithIssuersFixture
      );

      await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, owner.address);

      await expect(issuerRegistry.recordIssuance(issuer1.address))
        .to.emit(issuerRegistry, "IssuerStatsUpdated")
        .withArgs(issuer1.address, 1n, 0n, 0n);
    });
  });

  // ============================================
  // Query Function Tests
  // ============================================

  describe("Query Functions", function () {
    it("should return full issuer data", async function () {
      const { issuerRegistry, issuer1, delegate1 } = await loadFixture(deployWithIssuersFixture);

      await issuerRegistry.connect(issuer1).addDelegate(delegate1.address);

      const issuer = await issuerRegistry.getIssuer(issuer1.address);

      expect(issuer.issuerAddress).to.equal(issuer1.address);
      expect(issuer.jurisdiction).to.equal("US-OR");
      expect(issuer.reputationScore).to.equal(5000n);
      expect(issuer.isActive).to.be.true;
      expect(issuer.authorizedTypes).to.include(ClaimTypes.LICENSE_OPERATOR);
      expect(issuer.delegates).to.include(delegate1.address);
    });

    it("should check if address is authorized signer (direct issuer)", async function () {
      const { issuerRegistry, issuer1 } = await loadFixture(deployWithIssuersFixture);

      const [authorized, principal] = await issuerRegistry.isAuthorizedSigner(
        issuer1.address,
        ClaimTypes.LICENSE_OPERATOR
      );

      expect(authorized).to.be.true;
      expect(principal).to.equal(issuer1.address);
    });

    it("should return false for unregistered address", async function () {
      const { issuerRegistry, other } = await loadFixture(deployWithIssuersFixture);

      const [authorized, principal] = await issuerRegistry.isAuthorizedSigner(
        other.address,
        ClaimTypes.LICENSE_OPERATOR
      );

      expect(authorized).to.be.false;
      expect(principal).to.equal(ethers.ZeroAddress);
    });

    it("should return minimum reputation constant", async function () {
      const { issuerRegistry } = await loadFixture(deployIssuerRegistryFixture);

      expect(await issuerRegistry.getMinReputation()).to.equal(1000n);
    });
  });

  // ============================================
  // Edge Cases
  // ============================================

  describe("Edge Cases", function () {
    it("should handle issuer with no claim types", async function () {
      const { issuerRegistry, registrar, issuer1 } = await loadFixture(deployIssuerRegistryFixture);

      await issuerRegistry.connect(registrar).registerIssuer(issuer1.address, "US-OR", []);

      const types = await issuerRegistry.getAuthorizedTypes(issuer1.address);
      expect(types.length).to.equal(0);

      // Should not be authorized for any type
      expect(await issuerRegistry.isAuthorized(issuer1.address, ClaimTypes.LICENSE_OPERATOR)).to.be
        .false;
    });

    it("should handle duplicate type authorization gracefully", async function () {
      const { issuerRegistry, registrar, issuer1 } = await loadFixture(deployWithIssuersFixture);

      // Try to authorize same type again
      await issuerRegistry
        .connect(registrar)
        .authorizeType(issuer1.address, ClaimTypes.LICENSE_OPERATOR);

      // Should still only have it once
      const types = await issuerRegistry.getAuthorizedTypes(issuer1.address);
      const count = types.filter((t) => t === ClaimTypes.LICENSE_OPERATOR).length;
      expect(count).to.equal(1);
    });

    it("should reject revoking non-authorized type", async function () {
      const { issuerRegistry, registrar, issuer1 } = await loadFixture(deployWithIssuersFixture);

      await expect(
        issuerRegistry.connect(registrar).revokeType(issuer1.address, ClaimTypes.EDUCATION_DEGREE)
      ).to.be.revertedWithCustomError(issuerRegistry, "OperationNotAllowed");
    });

    it("should reject removing non-existent delegate", async function () {
      const { issuerRegistry, issuer1, delegate1 } = await loadFixture(deployWithIssuersFixture);

      await expect(
        issuerRegistry.connect(issuer1).removeDelegate(delegate1.address)
      ).to.be.revertedWithCustomError(issuerRegistry, "DelegateNotFound");
    });
  });
});
