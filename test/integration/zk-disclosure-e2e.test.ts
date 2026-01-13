/**
 * @file ZK Disclosure end-to-end integration tests
 * @description Tests for zero-knowledge proof generation and verification
 *              including all disclosure types and compound proofs
 * @dev Tests Step 19 requirements from IMPLEMENTATION_GUIDE.md
 */

import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { type SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import {
  type ClaimToken,
  type IssuerRegistry,
  type ZKDisclosureEngine,
  type MockZKVerifier,
} from "../../typechain-types";
import { ClaimTypes, CredentialStatus, Constants } from "../../types";

describe("ZK Disclosure End-to-End Integration", function () {
  // ============================================
  // Constants
  // ============================================

  const ONE_YEAR = 365 * 24 * 60 * 60;

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

  async function deployZKSystemFixture() {
    const [owner, issuer, subject, verifierService, relayer, other] = await ethers.getSigners();

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

    // Deploy MockZKVerifier for testing
    const MockVerifierFactory = await ethers.getContractFactory("MockZKVerifier");
    const mockVerifier = (await MockVerifierFactory.deploy()) as MockZKVerifier;
    await mockVerifier.waitForDeployment();

    // Grant roles
    const CREDENTIAL_CONTRACT_ROLE = await issuerRegistry.CREDENTIAL_CONTRACT_ROLE();
    await issuerRegistry.grantRole(CREDENTIAL_CONTRACT_ROLE, await claimToken.getAddress());

    // Set ZK engine in ClaimToken
    await claimToken.setZKEngine(await zkEngine.getAddress());

    // Register verifiers for each disclosure type
    await zkEngine.registerVerifier(DISCLOSURE_AGE_THRESHOLD, await mockVerifier.getAddress());
    await zkEngine.registerVerifier(DISCLOSURE_DATE_RANGE, await mockVerifier.getAddress());
    await zkEngine.registerVerifier(DISCLOSURE_VALUE_RANGE, await mockVerifier.getAddress());
    await zkEngine.registerVerifier(DISCLOSURE_SET_MEMBERSHIP, await mockVerifier.getAddress());
    await zkEngine.registerVerifier(DISCLOSURE_EXISTENCE, await mockVerifier.getAddress());
    await zkEngine.registerVerifier(DISCLOSURE_COMPOUND, await mockVerifier.getAddress());
    await zkEngine.registerVerifier(DISCLOSURE_COMPOUND_3, await mockVerifier.getAddress());
    await zkEngine.registerVerifier(DISCLOSURE_COMPOUND_4, await mockVerifier.getAddress());

    // Register issuer with all claim types
    await issuerRegistry.registerIssuer(issuer.address, "US-OR", [
      ClaimTypes.LICENSE_OPERATOR,
      ClaimTypes.IDENTITY_BIRTH,
      ClaimTypes.EDUCATION_DEGREE,
      ClaimTypes.PROPERTY_DEED,
      ClaimTypes.HEALTH_IMMUNIZATION,
    ]);

    return {
      claimToken,
      issuerRegistry,
      zkEngine,
      mockVerifier,
      owner,
      issuer,
      subject,
      verifierService,
      relayer,
      other,
    };
  }

  // ============================================
  // Helper Functions
  // ============================================

  async function createMintRequest(
    claimType: string,
    subject: string,
    expiresAt?: bigint,
    customCommitments?: string[]
  ) {
    const now = await time.latest();
    const oneYearFromNow = BigInt(now) + BigInt(ONE_YEAR);

    return {
      claimType,
      subject,
      encryptedPayload: "0x" + "ab".repeat(100),
      payloadHash: ethers.keccak256(ethers.toUtf8Bytes("test-payload-" + Math.random())),
      commitments: customCommitments ?? [
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

  async function mintCredentialWithCommitments(
    fixture: Awaited<ReturnType<typeof deployZKSystemFixture>>,
    claimType: string,
    commitments: string[]
  ): Promise<{ tokenId: bigint; commitments: string[] }> {
    const { claimToken, issuer, subject } = fixture;
    const request = await createMintRequest(claimType, subject.address, undefined, commitments);
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

    return {
      tokenId: parsed?.args.tokenId,
      commitments,
    };
  }

  function createMockProof(commitment: string, pubSignals: bigint[]): string {
    // Create mock Groth16 proof structure
    const pA = [1n, 2n];
    const pB = [
      [3n, 4n],
      [5n, 6n],
    ];
    const pC = [7n, 8n];

    // Build full public signals array
    const fullPubSignals = [BigInt(commitment), ...pubSignals];

    return ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint[2]", "uint[2][2]", "uint[2]", "uint[8]"],
      [pA, pB, pC, fullPubSignals.concat(Array(8 - fullPubSignals.length).fill(0n)).slice(0, 8)]
    );
  }

  function generateCommitment(value: number, salt: string): string {
    return ethers.keccak256(
      ethers.solidityPacked(["uint256", "bytes32"], [value, salt])
    );
  }

  // ============================================
  // Test Suites
  // ============================================

  describe("Age Threshold Disclosure", function () {
    it("should verify age above threshold without revealing exact age", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, verifierService } = fixture;

      // Create commitment for birthdate (1990-01-01 timestamp)
      const birthdate = 631152000; // Unix timestamp for 1990-01-01
      const salt = ethers.keccak256(ethers.toUtf8Bytes("salt1"));
      const birthdateCommitment = generateCommitment(birthdate, salt);

      const { tokenId, commitments } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.IDENTITY_BIRTH,
        [birthdateCommitment]
      );

      // Create disclosure request: prove age >= 21
      const threshold = 21;
      const currentTime = await time.latest();

      // Create proof (using mock verifier)
      const proof = createMockProof(birthdateCommitment, [
        BigInt(threshold),
        BigInt(currentTime),
        1n, // Above threshold = true
      ]);

      // Verify proof
      const disclosureRequest = {
        tokenId,
        disclosureType: DISCLOSURE_AGE_THRESHOLD,
        parameters: ethers.AbiCoder.defaultAbiCoder().encode(
          ["uint256", "uint256"],
          [threshold, currentTime]
        ),
        proof,
        commitment: birthdateCommitment,
        nullifier: ethers.keccak256(ethers.toUtf8Bytes("nullifier1")),
      };

      // Execute verification
      const result = await zkEngine.connect(verifierService).verifyDisclosure(disclosureRequest);
      expect(result).to.be.true;
    });

    it("should reject proof with invalid commitment", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, mockVerifier, verifierService } = fixture;

      // Mint credential with specific commitment
      const birthdate = 631152000;
      const salt = ethers.keccak256(ethers.toUtf8Bytes("salt-original"));
      const originalCommitment = generateCommitment(birthdate, salt);

      const { tokenId } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.IDENTITY_BIRTH,
        [originalCommitment]
      );

      // Try to verify with different commitment
      const fakeCommitment = generateCommitment(birthdate, ethers.keccak256(ethers.toUtf8Bytes("fake")));
      const proof = createMockProof(fakeCommitment, [21n, BigInt(await time.latest()), 1n]);

      const disclosureRequest = {
        tokenId,
        disclosureType: DISCLOSURE_AGE_THRESHOLD,
        parameters: ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [21, await time.latest()]),
        proof,
        commitment: fakeCommitment,
        nullifier: ethers.keccak256(ethers.toUtf8Bytes("nullifier")),
      };

      // Should fail because commitment doesn't match credential
      await expect(
        zkEngine.connect(verifierService).verifyDisclosure(disclosureRequest)
      ).to.be.reverted;
    });
  });

  describe("Date Range Disclosure", function () {
    it("should verify date falls within specified range", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, verifierService } = fixture;

      // Create commitment for graduation date (June 2023)
      const graduationDate = 1685577600; // 2023-06-01
      const salt = ethers.keccak256(ethers.toUtf8Bytes("grad-salt"));
      const dateCommitment = generateCommitment(graduationDate, salt);

      const { tokenId } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.EDUCATION_DEGREE,
        [dateCommitment]
      );

      // Verify date is between 2020 and 2024
      const rangeStart = 1577836800; // 2020-01-01
      const rangeEnd = 1735689600; // 2025-01-01

      const proof = createMockProof(dateCommitment, [
        BigInt(rangeStart),
        BigInt(rangeEnd),
        1n, // In range = true
      ]);

      const disclosureRequest = {
        tokenId,
        disclosureType: DISCLOSURE_DATE_RANGE,
        parameters: ethers.AbiCoder.defaultAbiCoder().encode(
          ["uint256", "uint256"],
          [rangeStart, rangeEnd]
        ),
        proof,
        commitment: dateCommitment,
        nullifier: ethers.keccak256(ethers.toUtf8Bytes("nullifier-date")),
      };

      const result = await zkEngine.connect(verifierService).verifyDisclosure(disclosureRequest);
      expect(result).to.be.true;
    });
  });

  describe("Value Range Disclosure", function () {
    it("should verify numeric value within range without revealing exact value", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, verifierService } = fixture;

      // Create commitment for property value ($1,500,000)
      const propertyValue = 1500000;
      const salt = ethers.keccak256(ethers.toUtf8Bytes("value-salt"));
      const valueCommitment = generateCommitment(propertyValue, salt);

      const { tokenId } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.PROPERTY_DEED,
        [valueCommitment]
      );

      // Verify value is between $1M and $2M
      const minValue = 1000000;
      const maxValue = 2000000;

      const proof = createMockProof(valueCommitment, [
        BigInt(minValue),
        BigInt(maxValue),
        1n, // In range = true
      ]);

      const disclosureRequest = {
        tokenId,
        disclosureType: DISCLOSURE_VALUE_RANGE,
        parameters: ethers.AbiCoder.defaultAbiCoder().encode(
          ["uint256", "uint256"],
          [minValue, maxValue]
        ),
        proof,
        commitment: valueCommitment,
        nullifier: ethers.keccak256(ethers.toUtf8Bytes("nullifier-value")),
      };

      const result = await zkEngine.connect(verifierService).verifyDisclosure(disclosureRequest);
      expect(result).to.be.true;
    });
  });

  describe("Set Membership Disclosure", function () {
    it("should verify value is in allowed set without revealing which one", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, verifierService } = fixture;

      // Create commitment for license class (Class C)
      const licenseClass = 67; // ASCII for 'C'
      const salt = ethers.keccak256(ethers.toUtf8Bytes("class-salt"));
      const classCommitment = generateCommitment(licenseClass, salt);

      const { tokenId } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.LICENSE_OPERATOR,
        [classCommitment]
      );

      // Verify class is in set [A, B, C] (allowed commercial classes)
      const allowedSet = [65, 66, 67]; // ASCII for A, B, C
      const merkleRoot = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(["uint256[]"], [allowedSet])
      );

      const proof = createMockProof(classCommitment, [
        BigInt(merkleRoot),
        1n, // Is member = true
      ]);

      const disclosureRequest = {
        tokenId,
        disclosureType: DISCLOSURE_SET_MEMBERSHIP,
        parameters: ethers.AbiCoder.defaultAbiCoder().encode(["bytes32"], [merkleRoot]),
        proof,
        commitment: classCommitment,
        nullifier: ethers.keccak256(ethers.toUtf8Bytes("nullifier-set")),
      };

      const result = await zkEngine.connect(verifierService).verifyDisclosure(disclosureRequest);
      expect(result).to.be.true;
    });
  });

  describe("Existence Disclosure", function () {
    it("should verify credential existence without revealing contents", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, claimToken, verifierService, subject } = fixture;

      const commitment = ethers.keccak256(ethers.toUtf8Bytes("existence-commitment"));
      const { tokenId } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.HEALTH_IMMUNIZATION,
        [commitment]
      );

      // Verify credential exists and is valid
      const proof = createMockProof(commitment, [
        BigInt(tokenId),
        BigInt(CredentialStatus.ACTIVE),
        1n, // Exists = true
      ]);

      const disclosureRequest = {
        tokenId,
        disclosureType: DISCLOSURE_EXISTENCE,
        parameters: "0x",
        proof,
        commitment,
        nullifier: ethers.keccak256(ethers.toUtf8Bytes("nullifier-exist")),
      };

      const result = await zkEngine.connect(verifierService).verifyDisclosure(disclosureRequest);
      expect(result).to.be.true;

      // Verify the credential is indeed active
      expect(await claimToken.isValid(tokenId)).to.be.true;
    });
  });

  describe("Compound Proofs", function () {
    it("should verify compound proof combining age and set membership", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, verifierService } = fixture;

      // Create commitments for age and license class
      const birthdate = 631152000;
      const licenseClass = 67;
      const salt1 = ethers.keccak256(ethers.toUtf8Bytes("salt-age"));
      const salt2 = ethers.keccak256(ethers.toUtf8Bytes("salt-class"));

      const ageCommitment = generateCommitment(birthdate, salt1);
      const classCommitment = generateCommitment(licenseClass, salt2);

      const { tokenId } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.LICENSE_OPERATOR,
        [ageCommitment, classCommitment]
      );

      // Compound proof: age >= 21 AND class in [A, B, C]
      const proof = createMockProof(ageCommitment, [
        21n, // Age threshold
        BigInt(await time.latest()),
        1n, // Age check passed
        BigInt(ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["uint256[]"], [[65, 66, 67]]))),
        1n, // Set membership passed
      ]);

      const disclosureRequest = {
        tokenId,
        disclosureType: DISCLOSURE_COMPOUND,
        parameters: ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32", "bytes32", "uint256"],
          [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_SET_MEMBERSHIP, 2]
        ),
        proof,
        commitment: ageCommitment,
        nullifier: ethers.keccak256(ethers.toUtf8Bytes("nullifier-compound")),
      };

      const result = await zkEngine.connect(verifierService).verifyDisclosure(disclosureRequest);
      expect(result).to.be.true;
    });

    it("should verify compound-3 proof with three disclosures", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, verifierService } = fixture;

      const commitment1 = ethers.keccak256(ethers.toUtf8Bytes("commit1"));
      const commitment2 = ethers.keccak256(ethers.toUtf8Bytes("commit2"));
      const commitment3 = ethers.keccak256(ethers.toUtf8Bytes("commit3"));

      const { tokenId } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.LICENSE_OPERATOR,
        [commitment1, commitment2, commitment3]
      );

      // Compound-3: age + date range + value range
      const proof = createMockProof(commitment1, [
        1n, // Check 1 passed
        1n, // Check 2 passed
        1n, // Check 3 passed
      ]);

      const disclosureRequest = {
        tokenId,
        disclosureType: DISCLOSURE_COMPOUND_3,
        parameters: ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32", "bytes32", "bytes32"],
          [DISCLOSURE_AGE_THRESHOLD, DISCLOSURE_DATE_RANGE, DISCLOSURE_VALUE_RANGE]
        ),
        proof,
        commitment: commitment1,
        nullifier: ethers.keccak256(ethers.toUtf8Bytes("nullifier-compound3")),
      };

      const result = await zkEngine.connect(verifierService).verifyDisclosure(disclosureRequest);
      expect(result).to.be.true;
    });
  });

  describe("Proof Replay Prevention", function () {
    it("should prevent same proof from being used twice (nullifier check)", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, verifierService } = fixture;

      const commitment = ethers.keccak256(ethers.toUtf8Bytes("replay-commit"));
      const { tokenId } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.IDENTITY_BIRTH,
        [commitment]
      );

      const nullifier = ethers.keccak256(ethers.toUtf8Bytes("unique-nullifier"));
      const proof = createMockProof(commitment, [21n, BigInt(await time.latest()), 1n]);

      const disclosureRequest = {
        tokenId,
        disclosureType: DISCLOSURE_AGE_THRESHOLD,
        parameters: ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [21, await time.latest()]),
        proof,
        commitment,
        nullifier,
      };

      // First use should succeed
      await zkEngine.connect(verifierService).verifyDisclosure(disclosureRequest);

      // Second use with same nullifier should fail (replay attack prevention)
      await expect(
        zkEngine.connect(verifierService).verifyDisclosure(disclosureRequest)
      ).to.be.revertedWithCustomError(zkEngine, "NullifierAlreadyUsed");
    });

    it("should allow same proof type with different nullifiers", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, verifierService } = fixture;

      const commitment = ethers.keccak256(ethers.toUtf8Bytes("multi-use-commit"));
      const { tokenId } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.IDENTITY_BIRTH,
        [commitment]
      );

      // First verification
      const nullifier1 = ethers.keccak256(ethers.toUtf8Bytes("nullifier-1"));
      const proof1 = createMockProof(commitment, [21n, BigInt(await time.latest()), 1n]);

      await zkEngine.connect(verifierService).verifyDisclosure({
        tokenId,
        disclosureType: DISCLOSURE_AGE_THRESHOLD,
        parameters: ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [21, await time.latest()]),
        proof: proof1,
        commitment,
        nullifier: nullifier1,
      });

      // Second verification with different nullifier should succeed
      const nullifier2 = ethers.keccak256(ethers.toUtf8Bytes("nullifier-2"));
      const proof2 = createMockProof(commitment, [18n, BigInt(await time.latest()), 1n]);

      const result = await zkEngine.connect(verifierService).verifyDisclosure({
        tokenId,
        disclosureType: DISCLOSURE_AGE_THRESHOLD,
        parameters: ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [18, await time.latest()]),
        proof: proof2,
        commitment,
        nullifier: nullifier2,
      });

      expect(result).to.be.true;
    });
  });

  describe("Expired/Revoked Credential Disclosures", function () {
    it("should reject disclosure for expired credential", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, claimToken, verifierService } = fixture;

      // Mint credential with very short expiration
      const shortExpiry = BigInt(await time.latest()) + BigInt(60); // 60 seconds
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("expire-commit"));

      const { tokenId } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.IDENTITY_BIRTH,
        [commitment]
      );

      // Wait for expiration
      await time.increase(120);

      // Verify credential is expired
      expect(await claimToken.getStatus(tokenId)).to.equal(CredentialStatus.EXPIRED);

      // Attempt disclosure should fail
      const proof = createMockProof(commitment, [21n, BigInt(await time.latest()), 1n]);

      await expect(
        zkEngine.connect(verifierService).verifyDisclosure({
          tokenId,
          disclosureType: DISCLOSURE_AGE_THRESHOLD,
          parameters: ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [21, await time.latest()]),
          proof,
          commitment,
          nullifier: ethers.keccak256(ethers.toUtf8Bytes("expired-nullifier")),
        })
      ).to.be.revertedWithCustomError(zkEngine, "CredentialNotActive");
    });

    it("should reject disclosure for revoked credential", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, claimToken, issuer, verifierService } = fixture;

      const commitment = ethers.keccak256(ethers.toUtf8Bytes("revoked-commit"));
      const { tokenId } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.LICENSE_OPERATOR,
        [commitment]
      );

      // Revoke the credential
      await claimToken.connect(issuer).revoke(tokenId, ethers.keccak256(ethers.toUtf8Bytes("REVOKED")));

      // Attempt disclosure should fail
      const proof = createMockProof(commitment, [21n, BigInt(await time.latest()), 1n]);

      await expect(
        zkEngine.connect(verifierService).verifyDisclosure({
          tokenId,
          disclosureType: DISCLOSURE_AGE_THRESHOLD,
          parameters: ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [21, await time.latest()]),
          proof,
          commitment,
          nullifier: ethers.keccak256(ethers.toUtf8Bytes("revoked-nullifier")),
        })
      ).to.be.revertedWithCustomError(zkEngine, "CredentialNotActive");
    });
  });

  describe("Verifier Management", function () {
    it("should allow admin to register new verifiers", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, owner } = fixture;

      const newDisclosureType = ethers.keccak256(ethers.toUtf8Bytes("CUSTOM_TYPE"));
      const MockVerifierFactory = await ethers.getContractFactory("MockZKVerifier");
      const newVerifier = await MockVerifierFactory.deploy();
      await newVerifier.waitForDeployment();

      await expect(
        zkEngine.connect(owner).registerVerifier(newDisclosureType, await newVerifier.getAddress())
      ).to.emit(zkEngine, "VerifierRegistered");

      const registeredVerifier = await zkEngine.getVerifier(newDisclosureType);
      expect(registeredVerifier).to.equal(await newVerifier.getAddress());
    });

    it("should reject verification for unregistered disclosure type", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, verifierService } = fixture;

      const commitment = ethers.keccak256(ethers.toUtf8Bytes("unknown-commit"));
      const { tokenId } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.IDENTITY_BIRTH,
        [commitment]
      );

      const unknownType = ethers.keccak256(ethers.toUtf8Bytes("UNKNOWN_TYPE"));
      const proof = createMockProof(commitment, [1n]);

      await expect(
        zkEngine.connect(verifierService).verifyDisclosure({
          tokenId,
          disclosureType: unknownType,
          parameters: "0x",
          proof,
          commitment,
          nullifier: ethers.keccak256(ethers.toUtf8Bytes("unknown-nullifier")),
        })
      ).to.be.revertedWithCustomError(zkEngine, "VerifierNotRegistered");
    });
  });

  describe("Gas Optimization Verification", function () {
    it("should verify proof within gas limit (NFR-02: <300k)", async function () {
      const fixture = await loadFixture(deployZKSystemFixture);
      const { zkEngine, verifierService } = fixture;

      const commitment = ethers.keccak256(ethers.toUtf8Bytes("gas-commit"));
      const { tokenId } = await mintCredentialWithCommitments(
        fixture,
        ClaimTypes.IDENTITY_BIRTH,
        [commitment]
      );

      const proof = createMockProof(commitment, [21n, BigInt(await time.latest()), 1n]);

      const tx = await zkEngine.connect(verifierService).verifyDisclosure({
        tokenId,
        disclosureType: DISCLOSURE_AGE_THRESHOLD,
        parameters: ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [21, await time.latest()]),
        proof,
        commitment,
        nullifier: ethers.keccak256(ethers.toUtf8Bytes("gas-nullifier")),
      });

      const receipt = await tx.wait();

      // Verify gas is under 300k (NFR-02)
      expect(receipt?.gasUsed).to.be.lt(300000n);
    });
  });
});
