/**
 * @file Time manipulation helpers for testing
 * @description Utilities for manipulating blockchain time in tests
 */

import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

// ============================================
// Time Constants
// ============================================

export const SECONDS_PER_MINUTE = 60;
export const SECONDS_PER_HOUR = 60 * 60;
export const SECONDS_PER_DAY = 24 * 60 * 60;
export const SECONDS_PER_WEEK = 7 * 24 * 60 * 60;
export const SECONDS_PER_YEAR = 365 * 24 * 60 * 60;

// Grace periods from spec
export const RENEWAL_GRACE_PERIOD = 90 * SECONDS_PER_DAY;
export const SUSPENSION_AUTO_REVOKE_PERIOD = 365 * SECONDS_PER_DAY;

// ============================================
// Time Conversion Helpers
// ============================================

/**
 * Convert days to seconds
 */
export function daysToSeconds(days: number): number {
  return days * SECONDS_PER_DAY;
}

/**
 * Convert hours to seconds
 */
export function hoursToSeconds(hours: number): number {
  return hours * SECONDS_PER_HOUR;
}

/**
 * Convert minutes to seconds
 */
export function minutesToSeconds(minutes: number): number {
  return minutes * SECONDS_PER_MINUTE;
}

/**
 * Convert years to seconds
 */
export function yearsToSeconds(years: number): number {
  return years * SECONDS_PER_YEAR;
}

/**
 * Get current Unix timestamp
 */
export function now(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Get timestamp for N days from now
 */
export function daysFromNow(days: number): number {
  return now() + daysToSeconds(days);
}

/**
 * Get timestamp for N days ago
 */
export function daysAgo(days: number): number {
  return now() - daysToSeconds(days);
}

/**
 * Get timestamp for N years from now
 */
export function yearsFromNow(years: number): number {
  return now() + yearsToSeconds(years);
}

/**
 * Get timestamp for N years ago
 */
export function yearsAgo(years: number): number {
  return now() - yearsToSeconds(years);
}

// ============================================
// Hardhat Time Manipulation
// ============================================

/**
 * Get the current block timestamp
 */
export async function getBlockTimestamp(): Promise<number> {
  return time.latest();
}

/**
 * Advance time by a number of seconds
 */
export async function advanceTimeBySeconds(seconds: number): Promise<void> {
  await time.increase(seconds);
}

/**
 * Advance time by a number of days
 */
export async function advanceTimeByDays(days: number): Promise<void> {
  await time.increase(daysToSeconds(days));
}

/**
 * Advance time by a number of hours
 */
export async function advanceTimeByHours(hours: number): Promise<void> {
  await time.increase(hoursToSeconds(hours));
}

/**
 * Advance time by a number of years
 */
export async function advanceTimeByYears(years: number): Promise<void> {
  await time.increase(yearsToSeconds(years));
}

/**
 * Set the next block timestamp to a specific value
 */
export async function setNextBlockTimestamp(timestamp: number): Promise<void> {
  await time.setNextBlockTimestamp(timestamp);
}

/**
 * Advance to a specific timestamp
 */
export async function advanceToTimestamp(timestamp: number): Promise<void> {
  await time.increaseTo(timestamp);
}

/**
 * Mine a new block
 */
export async function mineBlock(): Promise<void> {
  await ethers.provider.send("evm_mine", []);
}

/**
 * Mine multiple blocks
 */
export async function mineBlocks(count: number): Promise<void> {
  for (let i = 0; i < count; i++) {
    await mineBlock();
  }
}

// ============================================
// Credential Expiration Helpers
// ============================================

/**
 * Advance time to just before a credential expires
 */
export async function advanceToBeforeExpiration(expiresAt: bigint): Promise<void> {
  const current = await getBlockTimestamp();
  const target = Number(expiresAt) - 1;
  if (target > current) {
    await advanceToTimestamp(target);
  }
}

/**
 * Advance time to just after a credential expires
 */
export async function advanceToAfterExpiration(expiresAt: bigint): Promise<void> {
  const current = await getBlockTimestamp();
  const target = Number(expiresAt) + 1;
  if (target > current) {
    await advanceToTimestamp(target);
  }
}

/**
 * Advance time to within the renewal grace period
 */
export async function advanceToWithinGracePeriod(expiresAt: bigint): Promise<void> {
  const current = await getBlockTimestamp();
  // Go to middle of grace period
  const target = Number(expiresAt) + RENEWAL_GRACE_PERIOD / 2;
  if (target > current) {
    await advanceToTimestamp(target);
  }
}

/**
 * Advance time to after the renewal grace period
 */
export async function advanceToAfterGracePeriod(expiresAt: bigint): Promise<void> {
  const current = await getBlockTimestamp();
  const target = Number(expiresAt) + RENEWAL_GRACE_PERIOD + 1;
  if (target > current) {
    await advanceToTimestamp(target);
  }
}

/**
 * Advance time to trigger auto-revoke of suspended credential
 */
export async function advanceToAutoRevokeTime(suspendedAt: number): Promise<void> {
  const current = await getBlockTimestamp();
  const target = suspendedAt + SUSPENSION_AUTO_REVOKE_PERIOD + 1;
  if (target > current) {
    await advanceToTimestamp(target);
  }
}

// ============================================
// Age Calculation Helpers
// ============================================

/**
 * Calculate age in years from birthdate to current time
 */
export function calculateAge(birthdateTimestamp: number, currentTimestamp: number): number {
  return Math.floor((currentTimestamp - birthdateTimestamp) / SECONDS_PER_YEAR);
}

/**
 * Get a birthdate timestamp for a person of a specific age
 */
export function getBirthdateForAge(age: number, referenceTimestamp?: number): number {
  const reference = referenceTimestamp ?? now();
  return reference - yearsToSeconds(age);
}

/**
 * Check if a person is above a certain age threshold
 */
export function isAboveAge(
  birthdateTimestamp: number,
  threshold: number,
  currentTimestamp?: number
): boolean {
  const current = currentTimestamp ?? now();
  const age = calculateAge(birthdateTimestamp, current);
  return age > threshold;
}

/**
 * Check if a person is at least a certain age (inclusive)
 */
export function isAtLeastAge(
  birthdateTimestamp: number,
  threshold: number,
  currentTimestamp?: number
): boolean {
  const current = currentTimestamp ?? now();
  const age = calculateAge(birthdateTimestamp, current);
  return age >= threshold;
}

// ============================================
// Snapshot Helpers
// ============================================

/**
 * Take a snapshot of the current blockchain state
 */
export async function takeSnapshot(): Promise<string> {
  return ethers.provider.send("evm_snapshot", []);
}

/**
 * Revert to a previous snapshot
 */
export async function revertToSnapshot(snapshotId: string): Promise<void> {
  await ethers.provider.send("evm_revert", [snapshotId]);
}

/**
 * Create a time context that automatically reverts after the test
 */
export async function withTimeContext<T>(
  fn: () => Promise<T>
): Promise<T> {
  const snapshotId = await takeSnapshot();
  try {
    return await fn();
  } finally {
    await revertToSnapshot(snapshotId);
  }
}

// ============================================
// Date Formatting Helpers
// ============================================

/**
 * Format a Unix timestamp as ISO date string
 */
export function formatTimestamp(timestamp: number): string {
  return new Date(timestamp * 1000).toISOString();
}

/**
 * Format a Unix timestamp as human-readable date
 */
export function formatTimestampReadable(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleString();
}

/**
 * Parse an ISO date string to Unix timestamp
 */
export function parseISODate(isoString: string): number {
  return Math.floor(new Date(isoString).getTime() / 1000);
}

// ============================================
// Test Scenario Helpers
// ============================================

/**
 * Create a timeline of events for testing
 */
export interface TimelineEvent {
  name: string;
  timestamp: number;
  description?: string;
}

/**
 * Create a credential lifecycle timeline
 */
export function createCredentialTimeline(
  issuedAt: number,
  expiresAt: number
): TimelineEvent[] {
  return [
    { name: "issued", timestamp: issuedAt, description: "Credential issued" },
    {
      name: "midpoint",
      timestamp: Math.floor((issuedAt + expiresAt) / 2),
      description: "Midpoint of validity",
    },
    {
      name: "nearExpiry",
      timestamp: expiresAt - SECONDS_PER_DAY,
      description: "1 day before expiry",
    },
    { name: "expires", timestamp: expiresAt, description: "Credential expires" },
    {
      name: "graceEnd",
      timestamp: expiresAt + RENEWAL_GRACE_PERIOD,
      description: "Grace period ends",
    },
  ];
}

/**
 * Execute a function at each point in a timeline
 */
export async function executeTimeline<T>(
  timeline: TimelineEvent[],
  fn: (event: TimelineEvent) => Promise<T>
): Promise<Map<string, T>> {
  const results = new Map<string, T>();

  // Sort by timestamp
  const sorted = [...timeline].sort((a, b) => a.timestamp - b.timestamp);

  for (const event of sorted) {
    await advanceToTimestamp(event.timestamp);
    await mineBlock();
    results.set(event.name, await fn(event));
  }

  return results;
}
