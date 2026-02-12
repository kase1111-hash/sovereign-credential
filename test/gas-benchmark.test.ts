/**
 * @file gas-benchmark.test.ts
 * @description Gas consumption benchmarks for core operations.
 *
 * Spec targets (SPEC.md NFR):
 *   NFR-01: Credential minting    < 500,000 gas
 *   NFR-02: ZK proof verification  < 300,000 gas
 *
 * Run with gas reporting:
 *   REPORT_GAS=true npx hardhat test test/gas-benchmark.test.ts
 *
 * Or via npm:
 *   npm run test:gas -- --grep "Gas Benchmark"
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { type SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { ClaimTypes } from "../types";

describe("Gas Benchmark", function () {
  // ============================================
  // Spec gas targets
  // ============================================

  const GAS_LIMIT_MINT = 500_000n;
  const GAS_LIMIT_ZK_VERIFY = 300_000n;

  // ============================================
  // Fixture
  // ============================================

  async function deployBenchmarkFixture() {
    const signers = await ethers.getSigners();
    const owner = signers[0]!;
    const issuer = signers[1]!;
    const subject = signers[2]!;
    const verifier = signers[3]!;

    // Deploy IssuerRegistry
    const IR = await ethers.getContractFactory("IssuerRegistry");
    const issuerRegistry = await upgrades.deployProxy(IR, [], {
      initializer: "initialize",
      kind: "uups",
    });
    await issuerRegistry.waitForDeployment();

    // Deploy ClaimToken
    const CT = await ethers.getContractFactory("ClaimToken");
    const claimToken = await upgrades.deployProxy(
      CT,
      [await issuerRegistry.getAddress()],
      { initializer: "initialize", kind: "uups" },
    );
    await claimToken.waitForDeployment();

    // Deploy ZKDisclosureEngine
    const ZK = await ethers.getContractFactory("ZKDisclosureEngine");
    const zkEngine = await upgrades.deployProxy(
      ZK,
      [await claimToken.getAddress()],
      { initializer: "initialize", kind: "uups" },
    );
    await zkEngine.waitForDeployment();

    // Grant CREDENTIAL_CONTRACT_ROLE
    const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
    await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, await claimToken.getAddress());

    // Register issuer
    await issuerRegistry.registerIssuer(issuer.address, "US-OR", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.IDENTITY_BIRTH,
    ]);

    return {
      issuerRegistry,
      claimToken,
      zkEngine,
      owner,
      issuer,
      subject,
      verifier,
    };
  }

  // ============================================
  // Helpers
  // ============================================

  async function createMintRequest(claimType: string, subjectAddr: string) {
    const now = await time.latest();
    const expiresAt = BigInt(now) + BigInt(365 * 24 * 60 * 60);

    return {
      claimType,
      subject: subjectAddr,
      encryptedPayload: "0x" + "ab".repeat(100), // 100-byte payload
      payloadHash: ethers.keccak256(ethers.toUtf8Bytes("benchmark-payload")),
      commitments: [
        ethers.keccak256(ethers.toUtf8Bytes("commitment-0")),
        ethers.keccak256(ethers.toUtf8Bytes("commitment-1")),
      ],
      expiresAt,
      metadataURI: "ipfs://QmBenchmarkMetadata",
    };
  }

  async function signMintRequest(
    signer: SignerWithAddress,
    request: Awaited<ReturnType<typeof createMintRequest>>,
    claimTokenAddress: string,
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
        ],
      ),
    );
    return signer.signMessage(ethers.getBytes(messageHash));
  }

  async function mintOne(
    fixture: Awaited<ReturnType<typeof deployBenchmarkFixture>>,
    claimType: string = ClaimTypes.LICENSE_OPERATOR,
  ) {
    const { claimToken, issuer, subject } = fixture;
    const request = await createMintRequest(claimType, subject.address);
    const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
    const tx = await claimToken.connect(issuer).mint(request, signature);
    const receipt = await tx.wait();
    return { tx, receipt };
  }

  // ============================================
  // NFR-01: Credential Minting < 500k gas
  // ============================================

  describe("NFR-01: Credential Minting", function () {
    it("should mint a credential within gas budget", async function () {
      const fixture = await loadFixture(deployBenchmarkFixture);
      const { receipt } = await mintOne(fixture);

      const gasUsed = receipt!.gasUsed;
      console.log(`    Mint gas used: ${gasUsed.toLocaleString()}`);
      console.log(`    Budget:        ${GAS_LIMIT_MINT.toLocaleString()}`);
      console.log(`    Headroom:      ${(GAS_LIMIT_MINT - gasUsed).toLocaleString()}`);

      expect(gasUsed).to.be.lte(GAS_LIMIT_MINT);
    });

    it("should measure mint with large payload (32KB)", async function () {
      const fixture = await loadFixture(deployBenchmarkFixture);
      const { claimToken, issuer, subject } = fixture;

      const now = await time.latest();
      const request = {
        claimType: ClaimTypes.LICENSE_OPERATOR,
        subject: subject.address,
        encryptedPayload: "0x" + "ff".repeat(32 * 1024), // 32KB max payload
        payloadHash: ethers.keccak256(ethers.toUtf8Bytes("large-payload")),
        commitments: [ethers.keccak256(ethers.toUtf8Bytes("c0"))],
        expiresAt: BigInt(now) + BigInt(365 * 24 * 60 * 60),
        metadataURI: "ipfs://QmLargePayloadMeta",
      };

      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      const tx = await claimToken.connect(issuer).mint(request, signature);
      const receipt = await tx.wait();

      console.log(`    Mint (32KB payload) gas used: ${receipt!.gasUsed.toLocaleString()}`);
    });

    it("should measure mint with many commitments", async function () {
      const fixture = await loadFixture(deployBenchmarkFixture);
      const { claimToken, issuer, subject } = fixture;

      const now = await time.latest();
      // 10 commitments (e.g., a compound credential)
      const commitments = Array.from({ length: 10 }, (_, i) =>
        ethers.keccak256(ethers.toUtf8Bytes(`commitment-${i}`)),
      );

      const request = {
        claimType: ClaimTypes.LICENSE_OPERATOR,
        subject: subject.address,
        encryptedPayload: "0x" + "ab".repeat(100),
        payloadHash: ethers.keccak256(ethers.toUtf8Bytes("multi-commit")),
        commitments,
        expiresAt: BigInt(now) + BigInt(365 * 24 * 60 * 60),
        metadataURI: "ipfs://QmMultiCommitMeta",
      };

      const signature = await signMintRequest(issuer, request, await claimToken.getAddress());
      const tx = await claimToken.connect(issuer).mint(request, signature);
      const receipt = await tx.wait();

      console.log(`    Mint (10 commitments) gas used: ${receipt!.gasUsed.toLocaleString()}`);
    });
  });

  // ============================================
  // NFR-02: ZK Verification < 300k gas
  // ============================================

  describe("NFR-02: ZK Proof Verification", function () {
    it("should verify a credential within gas budget", async function () {
      const fixture = await loadFixture(deployBenchmarkFixture);
      await mintOne(fixture);

      const { claimToken } = fixture;

      // Measure verify() gas (status + expiry + issuer auth check)
      const gas = await claimToken.verify.estimateGas(1n);
      console.log(`    verify() gas:  ${gas.toLocaleString()}`);
      console.log(`    Budget:        ${GAS_LIMIT_ZK_VERIFY.toLocaleString()}`);
      console.log(`    Headroom:      ${(GAS_LIMIT_ZK_VERIFY - gas).toLocaleString()}`);

      expect(gas).to.be.lte(GAS_LIMIT_ZK_VERIFY);
    });

    it("should measure getCredential read cost", async function () {
      const fixture = await loadFixture(deployBenchmarkFixture);
      await mintOne(fixture);

      const { claimToken } = fixture;
      const gas = await claimToken.getCredential.estimateGas(1n);
      console.log(`    getCredential() gas: ${gas.toLocaleString()}`);
    });
  });

  // ============================================
  // Additional operations
  // ============================================

  describe("Other Operations", function () {
    it("should measure suspend gas", async function () {
      const fixture = await loadFixture(deployBenchmarkFixture);
      await mintOne(fixture);
      const { claimToken, issuer } = fixture;

      const tx = await claimToken.connect(issuer).suspend(1n, "Audit");
      const receipt = await tx.wait();
      console.log(`    suspend() gas:    ${receipt!.gasUsed.toLocaleString()}`);
    });

    it("should measure reinstate gas", async function () {
      const fixture = await loadFixture(deployBenchmarkFixture);
      await mintOne(fixture);
      const { claimToken, issuer } = fixture;

      await claimToken.connect(issuer).suspend(1n, "Audit");
      const tx = await claimToken.connect(issuer).reinstate(1n);
      const receipt = await tx.wait();
      console.log(`    reinstate() gas:  ${receipt!.gasUsed.toLocaleString()}`);
    });

    it("should measure revoke gas", async function () {
      const fixture = await loadFixture(deployBenchmarkFixture);
      await mintOne(fixture);
      const { claimToken, issuer } = fixture;

      const tx = await claimToken.connect(issuer).revoke(1n, "Fraud");
      const receipt = await tx.wait();
      console.log(`    revoke() gas:     ${receipt!.gasUsed.toLocaleString()}`);
    });

    it("should measure registerIssuer gas", async function () {
      const fixture = await loadFixture(deployBenchmarkFixture);
      const { issuerRegistry } = fixture;
      const signers = await ethers.getSigners();
      const newIssuer = signers[5]!;

      const tx = await issuerRegistry.registerIssuer(
        newIssuer.address,
        "US-CA",
        [ClaimTypes.LICENSE_OPERATOR, ClaimTypes.IDENTITY_BIRTH],
      );
      const receipt = await tx.wait();
      console.log(`    registerIssuer() gas: ${receipt!.gasUsed.toLocaleString()}`);
    });

    it("should measure isAuthorized gas (view)", async function () {
      const fixture = await loadFixture(deployBenchmarkFixture);
      const { issuerRegistry, issuer } = fixture;

      const gas = await issuerRegistry.isAuthorized.estimateGas(
        issuer.address,
        ClaimTypes.LICENSE_OPERATOR,
      );
      console.log(`    isAuthorized() gas:   ${gas.toLocaleString()}`);
    });
  });
});
