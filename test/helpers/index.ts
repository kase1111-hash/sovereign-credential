/**
 * @file Test helpers index
 * @description Re-exports all test helpers for easy importing
 */

// Signature helpers
export {
  // Domain
  DOMAIN_NAME,
  DOMAIN_VERSION,
  getDomain,
  getLocalDomain,

  // Type definitions
  MintRequestTypes,
  RenewalTypes,
  RevocationTypes,

  // Signature generation
  signMintRequest,
  signRenewal,
  signRevocation,
  signMintRequestSimple,
  signCredential,

  // Hashing
  hashMintRequest,
  hashCredential,

  // Verification
  recoverMintRequestSigner,
  verifyMintRequestSignature,
  recoverCredentialSigner,

  // Batch signing
  signBatchMintRequests,
  signBatchMintRequestsTyped,

  // Invalid signatures (for negative tests)
  generateInvalidSignature,
  generateInvalidVSignature,
  generateWrongMessageSignature,
  corruptSignature,

  // Delegation
  signDelegation,
  verifyDelegationSignature,

  // Nonce management
  generateNonce,
  NonceTracker,
} from "./signatures";

// Encryption helpers
export {
  // Key management
  generateKeyPair,
  derivePublicKey,
  deriveAddress,

  // ECIES encryption
  encryptPayload,
  decryptPayload,
  decryptPayloadToObject,

  // Payload encoding
  encodeEncryptedPayload,
  decodeEncryptedPayload,

  // Hashing
  hashPayload,
  verifyPayloadHash,

  // Test helpers
  createEncryptedCredentialPayload,
  createDummyEncryptedPayload,
  createDeterministicPayload,

  // Commitment generation
  generateCommitment,
  generateSalt,
  generatePayloadCommitments,

  // Key storage
  TestKeyStore,
} from "./encryption";

// Time helpers
export {
  // Constants
  SECONDS_PER_MINUTE,
  SECONDS_PER_HOUR,
  SECONDS_PER_DAY,
  SECONDS_PER_WEEK,
  SECONDS_PER_YEAR,
  RENEWAL_GRACE_PERIOD,
  SUSPENSION_AUTO_REVOKE_PERIOD,

  // Conversion
  daysToSeconds,
  hoursToSeconds,
  minutesToSeconds,
  yearsToSeconds,
  now,
  daysFromNow,
  daysAgo,
  yearsFromNow,
  yearsAgo,

  // Hardhat time manipulation
  getBlockTimestamp,
  advanceTimeBySeconds,
  advanceTimeByDays,
  advanceTimeByHours,
  advanceTimeByYears,
  setNextBlockTimestamp,
  advanceToTimestamp,
  mineBlock,
  mineBlocks,

  // Credential expiration
  advanceToBeforeExpiration,
  advanceToAfterExpiration,
  advanceToWithinGracePeriod,
  advanceToAfterGracePeriod,
  advanceToAutoRevokeTime,

  // Age calculation
  calculateAge,
  getBirthdateForAge,
  isAboveAge,
  isAtLeastAge,

  // Snapshots
  takeSnapshot,
  revertToSnapshot,
  withTimeContext,

  // Formatting
  formatTimestamp,
  formatTimestampReadable,
  parseISODate,

  // Timeline helpers
  type TimelineEvent,
  createCredentialTimeline,
  executeTimeline,
} from "./time";
