/**
 * Threshold key management via Shamir Secret Sharing (2-of-3).
 *
 * Uses `shamir-secret-sharing` by Privy (Cure53 + Zellic audited).
 * Pure TypeScript, Web Crypto API only.
 *
 * @module threshold
 */

import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { split, combine } from "shamir-secret-sharing";

// Ed25519 requires sha512 — set sync fallback for Node environments
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

// --- Types ---

/** A single share of a split key. */
export interface KeyShare {
  /** Share index (1-based). */
  index: number;
  /** The share data. */
  data: Uint8Array;
  /** Identifier of the KEK this share belongs to. */
  kekId: string;
  /** Which share holder this is assigned to. */
  holder: ShareHolder;
}

/** Identifies a share holder in the threshold scheme. */
export interface ShareHolder {
  /** Unique identifier for this holder. */
  id: string;
  /** Human-readable label (e.g. "operator", "oracle", "auditor"). */
  label: string;
  /** Ed25519 public key for verifying attestations. */
  publicKey: Uint8Array;
}

/** A signed attestation that a share holder destroyed their share. */
export interface DestructionAttestation {
  /** KEK identifier. */
  kekId: string;
  /** Share index that was destroyed. */
  shareIndex: number;
  /** Share holder who destroyed the share. */
  holder: ShareHolder;
  /** ISO 8601 timestamp of destruction. */
  destroyedAt: string;
  /** Ed25519 signature over (kekId || shareIndex || destroyedAt). */
  signature: Uint8Array;
}

/** Result of a threshold key split. */
export interface SplitResult {
  /** The three shares. */
  shares: [KeyShare, KeyShare, KeyShare];
  /** KEK identifier. */
  kekId: string;
}

/** Configuration for the threshold scheme. */
export interface ThresholdConfig {
  /** Total number of shares (default: 3). */
  totalShares: number;
  /** Minimum shares needed to reconstruct (default: 2). */
  threshold: number;
  /** The share holders. Must have exactly `totalShares` entries. */
  holders: ShareHolder[];
}

// --- Functions ---

/**
 * Split a KEK into threshold shares.
 */
export async function splitKey(
  keyMaterial: Uint8Array,
  kekId: string,
  config: ThresholdConfig,
): Promise<SplitResult> {
  if (config.totalShares !== 3) {
    throw new Error("Only 2-of-3 threshold is currently supported");
  }
  if (config.holders.length !== config.totalShares) {
    throw new Error("holders.length must equal totalShares");
  }
  if (config.threshold < 2 || config.threshold > config.totalShares) {
    throw new Error("threshold must be >= 2 and <= totalShares");
  }
  if (keyMaterial.length !== 32) {
    throw new Error("keyMaterial must be 32 bytes");
  }

  const rawShares = await split(keyMaterial, config.totalShares, config.threshold);

  const shares = rawShares.map((data, i) => ({
    index: i + 1,
    data: new Uint8Array(data),
    kekId,
    holder: config.holders[i],
  })) as [KeyShare, KeyShare, KeyShare];

  return { shares, kekId };
}

/**
 * Reconstruct a KEK from threshold shares.
 * Requires at least `threshold` shares.
 */
export async function reconstructKey(
  shares: KeyShare[],
  threshold: number,
): Promise<Uint8Array> {
  if (shares.length < threshold) {
    throw new Error("insufficient shares for reconstruction");
  }

  const firstKekId = shares[0]!.kekId;
  if (!shares.every((s) => s.kekId === firstKekId)) {
    throw new Error("shares must belong to the same KEK");
  }

  const rawShares = shares.map((s) => s.data);
  return new Uint8Array(await combine(rawShares));
}

/**
 * Create a signed destruction attestation.
 * Called by each share holder after they destroy their share.
 */
export async function createDestructionAttestation(
  kekId: string,
  shareIndex: number,
  holder: ShareHolder,
  signingKey: Uint8Array,
): Promise<DestructionAttestation> {
  const destroyedAt = new Date().toISOString();
  const message = new TextEncoder().encode(
    `vd-destroy-v1:${kekId}:${shareIndex}:${destroyedAt}`,
  );
  const signature = await ed.signAsync(message, signingKey);

  return {
    kekId,
    shareIndex,
    holder,
    destroyedAt,
    signature: new Uint8Array(signature),
  };
}

/**
 * Verify a destruction attestation signature.
 */
export async function verifyDestructionAttestation(
  attestation: DestructionAttestation,
): Promise<boolean> {
  const message = new TextEncoder().encode(
    `vd-destroy-v1:${attestation.kekId}:${attestation.shareIndex}:${attestation.destroyedAt}`,
  );
  return ed.verifyAsync(attestation.signature, message, attestation.holder.publicKey);
}

/**
 * Verify that sufficient attestations exist for a given KEK.
 * Returns true if at least `threshold` valid attestations are present.
 */
export async function verifyThresholdDestruction(
  attestations: DestructionAttestation[],
  threshold: number,
): Promise<boolean> {
  if (attestations.length < threshold) {
    return false;
  }

  // All attestations must reference the same KEK
  const firstKekId = attestations[0]!.kekId;
  if (!attestations.every((a) => a.kekId === firstKekId)) {
    return false;
  }

  // No duplicate share indices
  const indices = new Set(attestations.map((a) => a.shareIndex));
  if (indices.size !== attestations.length) {
    return false;
  }

  // Verify each signature
  for (const attestation of attestations) {
    const valid = await verifyDestructionAttestation(attestation);
    if (!valid) {
      return false;
    }
  }

  return true;
}
