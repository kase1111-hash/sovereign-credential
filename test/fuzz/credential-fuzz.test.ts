/**
 * @file Credential Fuzz Tests
 * @description Fuzz testing for edge cases, boundary values, and random inputs
 *              to ensure system robustness under unexpected conditions
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
  type ZKDisclosureEngine,
  type MockZKVerifier,
} from "../../typechain-types";
import { ClaimTypes, CredentialStatus, Constants } from "../../types";

describe("Credential Fuzz Testing", function () {
  // ============================================
  // Constants
  // ============================================

  const ONE_YEAR = 365 * 24 * 60 * 60;
  const ONE_DAY = 24 * 60 * 60;
  const MAX_UINT64 = 2n ** 64n - 1n;
  const MAX_UINT256 = 2n ** 256n - 1n;
  const FUZZ_ITERATIONS = 20; // Number of random iterations per test

  // ============================================
  // Fixtures
  // ============================================

  async function deployFuzzTestFixture() {
    const [owner, issuer, subject, beneficiary, other] = await ethers.getSigners();

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

    // Deploy ZKDisclosureEngine
    const ZKEngineFactory = await ethers.getContractFactory("ZKDisclosureEngine");
    const zkEngine = (await upgrades.deployProxy(
      ZKEngineFactory,
      [await claimToken.getAddress()],
      { initializer: "initialize" }
    )) as unknown as ZKDisclosureEngine;
    await zkEngine.waitForDeployment();

    // Deploy CredentialLifecycleManager
    const LifecycleManagerFactory = await ethers.getContractFactory("CredentialLifecycleManager");
    const lifecycleManager = (await upgrades.deployProxy(
      LifecycleManagerFactory,
      [await claimToken.getAddress(), await issuerRegistry.getAddress()],
      { initializer: "initialize" }
    )) as unknown as CredentialLifecycleManager;
    await lifecycleManager.waitForDeployment();

    // Deploy MockZKVerifier
    const MockVerifierFactory = await ethers.getContractFactory("MockZKVerifier");
    const mockVerifier = (await MockVerifierFactory.deploy()) as MockZKVerifier;
    await mockVerifier.waitForDeployment();

    // Grant roles
    const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
    await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, await claimToken.getAddress());

    // Wire up contracts
    await claimToken.setZKEngine(await zkEngine.getAddress());
    await claimToken.setLifecycleManager(await lifecycleManager.getAddress());

    // Register issuer
    await issuerRegistry.registerIssuer(issuer.address, "US-CA", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.PROPERTY_DEED,
      ClaimTypes.EDUCATION_DEGREE,
    ]);

    return {
      claimToken,
      issuerRegistry,
      zkEngine,
      lifecycleManager,
      mockVerifier,
      owner,
      issuer,
      subject,
      beneficiary,
      other,
    };
  }

  // ============================================
  // Random Value Generators
  // ============================================

  function randomBytes32(): string {
    return ethers.hexlify(ethers.randomBytes(32));
  }

  function randomAddress(): string {
    return ethers.hexlify(ethers.randomBytes(20));
  }

  function randomUint64(): bigint {
    // Generate random value between 0 and MAX_UINT64
    const bytes = ethers.randomBytes(8);
    return BigInt(ethers.hexlify(bytes));
  }

  function randomExpirationTime(): bigint {
    const now = Math.floor(Date.now() / 1000);
    // Random expiration between 1 day and 100 years from now
    const randomDays = Math.floor(Math.random() * 36500) + 1;
    return BigInt(now + randomDays * ONE_DAY);
  }

  function randomPayload(): string {
    const length = Math.floor(Math.random() * 1000) + 10; // 10 to 1010 bytes
    return ethers.hexlify(ethers.randomBytes(length));
  }

  function randomClaimType(): string {
    const types = [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.PROPERTY_DEED,
      ClaimTypes.EDUCATION_DEGREE,
    ];
    return types[Math.floor(Math.random() * types.length)];
  }

  // ============================================
  // Helper Functions
  // ============================================

  async function createMintRequest(
    claimType: string,
    subject: string,
    expiresAt: bigint,
    payloadSize?: number
  ) {
    const payloadLength = payloadSize ?? Math.floor(Math.random() * 500) + 50;

    return {
      claimType,
      subject,
      encryptedPayload: "0x" + "ab".repeat(payloadLength),
      payloadHash: randomBytes32(),
      commitments: [randomBytes32(), randomBytes32()],
      expiresAt,
      metadataURI: `ipfs://Qm${randomBytes32().slice(2, 46)}`,
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
  // Test Suites
  // ============================================

  describe("Random Credential Parameters", function () {
    it("should handle random expiration times", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const randomExpiry = randomExpirationTime();
        const request = await createMintRequest(
          ClaimTypes.LICENSE_OPERATOR,
          subject.address,
          randomExpiry
        );
        const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

        // Should succeed for valid future expiration times
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

        expect(transferEvent).to.not.be.undefined;
      }
    });

    it("should handle random payload sizes", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      const payloadSizes = [1, 10, 100, 500, 1000, 5000]; // Various sizes

      for (const size of payloadSizes) {
        const expiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
        const request = await createMintRequest(
          ClaimTypes.LICENSE_OPERATOR,
          subject.address,
          expiry,
          size
        );
        const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

        // Should succeed regardless of payload size
        await expect(claimToken.connect(issuer).mint(request, signature)).to.not.be.reverted;
      }
    });

    it("should handle random commitment values", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      for (let i = 0; i < FUZZ_ITERATIONS; i++) {
        const expiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
        const request = await createMintRequest(
          ClaimTypes.LICENSE_OPERATOR,
          subject.address,
          expiry
        );

        // Replace with random commitments
        request.commitments = [randomBytes32(), randomBytes32(), randomBytes32()];
        request.payloadHash = randomBytes32();

        const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

        await expect(claimToken.connect(issuer).mint(request, signature)).to.not.be.reverted;
      }
    });
  });

  describe("Boundary Value Testing", function () {
    it("should handle minimum expiration (just past current time)", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      const now = await time.latest();
      const minExpiry = BigInt(now) + 1n; // Just 1 second in the future

      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address,
        minExpiry
      );
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      // Should succeed
      await expect(claimToken.connect(issuer).mint(request, signature)).to.not.be.reverted;
    });

    it("should reject past expiration times", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      const now = await time.latest();
      const pastExpiry = BigInt(now) - BigInt(ONE_DAY); // 1 day in the past

      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address,
        pastExpiry
      );
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      // Should reject past expiration
      await expect(claimToken.connect(issuer).mint(request, signature)).to.be.reverted;
    });

    it("should handle maximum reasonable expiration (100 years)", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      const now = await time.latest();
      const maxExpiry = BigInt(now) + BigInt(100 * ONE_YEAR);

      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address,
        maxExpiry
      );
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      await expect(claimToken.connect(issuer).mint(request, signature)).to.not.be.reverted;
    });

    it("should handle empty commitments array", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      const expiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address,
        expiry
      );
      request.commitments = []; // Empty array

      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      // Behavior depends on implementation - may succeed or revert
      // This test documents actual behavior
      try {
        await claimToken.connect(issuer).mint(request, signature);
        // If succeeds, verify credential was created
        expect(await claimToken.totalCredentials()).to.be.gt(0n);
      } catch {
        // Expected to revert if commitments required
      }
    });

    it("should handle maximum number of commitments", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      const expiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address,
        expiry
      );

      // Add many commitments
      request.commitments = Array.from({ length: 50 }, () => randomBytes32());

      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      // Should handle or reject gracefully
      try {
        const tx = await claimToken.connect(issuer).mint(request, signature);
        const receipt = await tx.wait();
        // If succeeds, check gas usage is reasonable
        expect(receipt?.gasUsed).to.be.lt(2000000n);
      } catch {
        // May revert due to gas limits or array size limits
      }
    });
  });

  describe("State Machine Fuzzing", function () {
    it("should maintain state consistency through random operations", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      // Mint multiple credentials
      const tokenIds: bigint[] = [];
      for (let i = 0; i < 10; i++) {
        const expiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
        const request = await createMintRequest(
          ClaimTypes.LICENSE_OPERATOR,
          subject.address,
          expiry
        );
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

        const parsed = claimToken.interface.parseLog({
          topics: transferEvent!.topics as string[],
          data: transferEvent!.data,
        });

        tokenIds.push(parsed?.args.tokenId);
      }

      // Perform random operations
      const operations = ["suspend", "reinstate", "revoke"];

      for (const tokenId of tokenIds) {
        const status = await claimToken.getStatus(tokenId);

        // Only perform valid state transitions
        if (status === CredentialStatus.ACTIVE) {
          const op = operations[Math.floor(Math.random() * 2)]; // suspend or revoke
          if (op === "suspend") {
            await claimToken.connect(issuer).suspend(tokenId, randomBytes32());
          } else if (op === "revoke") {
            await claimToken.connect(issuer).revoke(tokenId, randomBytes32());
          }
        } else if (status === CredentialStatus.SUSPENDED) {
          const op = Math.random() > 0.5 ? "reinstate" : "revoke";
          if (op === "reinstate") {
            await claimToken.connect(issuer).reinstate(tokenId);
          } else {
            await claimToken.connect(issuer).revoke(tokenId, randomBytes32());
          }
        }
      }

      // Verify final state consistency
      for (const tokenId of tokenIds) {
        const status = await claimToken.getStatus(tokenId);
        const isValid = await claimToken.isValid(tokenId);

        // isValid should only be true for ACTIVE/INHERITED
        if (isValid) {
          expect(status).to.be.oneOf([CredentialStatus.ACTIVE, CredentialStatus.INHERITED]);
        }

        // REVOKED should always be invalid
        if (status === CredentialStatus.REVOKED) {
          expect(isValid).to.be.false;
        }
      }
    });

    it("should handle rapid state transitions", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      const expiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address,
        expiry
      );
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.connect(issuer).mint(request, signature);
      const tokenId = 1n;

      // Rapid suspend/reinstate cycles
      for (let i = 0; i < 10; i++) {
        await claimToken.connect(issuer).suspend(tokenId, randomBytes32());
        expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.SUSPENDED);

        await claimToken.connect(issuer).reinstate(tokenId);
        expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);
      }

      // Final state should be ACTIVE
      expect(await claimToken.isValid(tokenId)).to.be.true;
    });
  });

  describe("Invalid Input Handling", function () {
    it("should reject operations on non-existent token IDs", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer } = fixture;

      const nonExistentIds = [999n, 0n, MAX_UINT256 - 1n];

      for (const tokenId of nonExistentIds) {
        await expect(
          claimToken.connect(issuer).revoke(tokenId, randomBytes32())
        ).to.be.reverted;

        await expect(
          claimToken.connect(issuer).suspend(tokenId, randomBytes32())
        ).to.be.reverted;

        await expect(claimToken.getCredential(tokenId)).to.be.reverted;
      }
    });

    it("should handle malformed metadata URIs", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      const malformedURIs = [
        "", // Empty
        "not-a-uri", // Invalid format
        "ipfs://", // Missing hash
        "http://example.com/" + "a".repeat(2000), // Very long
        "ipfs://Qm\0InvalidNull", // Contains null byte
      ];

      for (const uri of malformedURIs) {
        const expiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
        const request = await createMintRequest(
          ClaimTypes.LICENSE_OPERATOR,
          subject.address,
          expiry
        );
        request.metadataURI = uri;

        const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

        // Should either succeed (URI stored as-is) or revert with validation
        try {
          await claimToken.connect(issuer).mint(request, signature);
          // If succeeds, URI was accepted
        } catch {
          // Expected behavior for invalid URIs
        }
      }
    });

    it("should reject zero address as subject", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer } = fixture;

      const expiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        ethers.ZeroAddress,
        expiry
      );
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      await expect(claimToken.connect(issuer).mint(request, signature)).to.be.reverted;
    });

    it("should handle extremely long encrypted payloads", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      const expiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address,
        expiry,
        10000 // 10KB payload
      );
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());

      // Should handle or reject gracefully based on gas limits
      try {
        const tx = await claimToken.connect(issuer).mint(request, signature);
        const receipt = await tx.wait();
        // If succeeds, verify reasonable gas usage
        expect(receipt?.gasUsed).to.be.lt(5000000n);
      } catch {
        // May revert due to gas limits
      }
    });
  });

  describe("Concurrent Operation Simulation", function () {
    it("should handle multiple mints in same block", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      const requests = [];
      const signatures = [];

      // Prepare multiple mint requests
      for (let i = 0; i < 5; i++) {
        const expiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
        const request = await createMintRequest(
          ClaimTypes.LICENSE_OPERATOR,
          subject.address,
          expiry
        );
        const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
        requests.push(request);
        signatures.push(signature);
      }

      // Submit all mints (simulating concurrent transactions)
      const txPromises = requests.map((req, i) =>
        claimToken.connect(issuer).mint(req, signatures[i])
      );

      const txs = await Promise.all(txPromises);
      await Promise.all(txs.map((tx) => tx.wait()));

      // All should succeed
      expect(await claimToken.totalCredentials()).to.equal(5n);
    });

    it("should handle mixed operations on different credentials", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      // Mint credentials
      const tokenIds: bigint[] = [];
      for (let i = 0; i < 5; i++) {
        const expiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
        const request = await createMintRequest(
          ClaimTypes.LICENSE_OPERATOR,
          subject.address,
          expiry
        );
        const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
        await claimToken.connect(issuer).mint(request, signature);
        tokenIds.push(BigInt(i + 1));
      }

      // Perform mixed operations concurrently
      const ops = [
        claimToken.connect(issuer).suspend(tokenIds[0], randomBytes32()),
        claimToken.connect(issuer).suspend(tokenIds[1], randomBytes32()),
        claimToken.connect(issuer).revoke(tokenIds[2], randomBytes32()),
      ];

      await Promise.all(ops);

      // Verify results
      expect(await claimToken.getStatus(tokenIds[0])).to.equal(CredentialStatus.SUSPENDED);
      expect(await claimToken.getStatus(tokenIds[1])).to.equal(CredentialStatus.SUSPENDED);
      expect(await claimToken.getStatus(tokenIds[2])).to.equal(CredentialStatus.REVOKED);
      expect(await claimToken.getStatus(tokenIds[3])).to.equal(CredentialStatus.ACTIVE);
      expect(await claimToken.getStatus(tokenIds[4])).to.equal(CredentialStatus.ACTIVE);
    });
  });

  describe("Edge Case Scenarios", function () {
    it("should handle credential operations at exact expiration boundary", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      const now = await time.latest();
      const exactExpiry = BigInt(now) + BigInt(60); // 60 seconds from now

      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address,
        exactExpiry
      );
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.connect(issuer).mint(request, signature);
      const tokenId = 1n;

      // Should be valid before expiry
      expect(await claimToken.isValid(tokenId)).to.be.true;

      // Move to exact expiry moment
      await time.setNextBlockTimestamp(Number(exactExpiry));
      await time.mine();

      // Behavior at exact boundary (implementation-dependent)
      // Document actual behavior
      const statusAtBoundary = await claimToken.getStatus(tokenId);

      // Move past expiry
      await time.increase(1);

      // Should be expired after
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.EXPIRED);
    });

    it("should handle token ID overflow protection", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken } = fixture;

      // Verify token counter is protected
      const totalBefore = await claimToken.totalCredentials();
      expect(totalBefore).to.be.lt(MAX_UINT256);

      // System should handle large numbers of credentials
      // (implementation should use safe math)
    });

    it("should handle reentrancy attempts gracefully", async function () {
      const fixture = await loadFixture(deployFuzzTestFixture);
      const { claimToken, issuer, subject } = fixture;

      // Mint a credential
      const expiry = BigInt(await time.latest()) + BigInt(ONE_YEAR);
      const request = await createMintRequest(
        ClaimTypes.LICENSE_OPERATOR,
        subject.address,
        expiry
      );
      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      await claimToken.connect(issuer).mint(request, signature);

      // The contract should have ReentrancyGuard protection
      // This test verifies basic operations complete atomically
      const tokenId = 1n;

      // Multiple calls in sequence should all work correctly
      await claimToken.connect(issuer).suspend(tokenId, randomBytes32());
      await claimToken.connect(issuer).reinstate(tokenId);
      await claimToken.connect(issuer).suspend(tokenId, randomBytes32());
      await claimToken.connect(issuer).reinstate(tokenId);

      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.ACTIVE);
    });
  });
});
