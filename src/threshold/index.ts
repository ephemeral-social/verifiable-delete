/**
 * Threshold key management via Shamir Secret Sharing (2-of-3).
 *
 * Uses `shamir-secret-sharing` by Privy (Cure53 + Zellic audited).
 * Pure TypeScript, Web Crypto API only.
 *
 * @module threshold
 */

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
  _keyMaterial: Uint8Array,
  _kekId: string,
  _config: ThresholdConfig,
): Promise<SplitResult> {
  throw new Error("Not implemented");
}

/**
 * Reconstruct a KEK from threshold shares.
 * Requires at least `threshold` shares.
 */
export async function reconstructKey(
  _shares: KeyShare[],
  _threshold: number,
): Promise<Uint8Array> {
  throw new Error("Not implemented");
}

/**
 * Create a signed destruction attestation.
 * Called by each share holder after they destroy their share.
 */
export async function createDestructionAttestation(
  _kekId: string,
  _shareIndex: number,
  _holder: ShareHolder,
  _signingKey: Uint8Array,
): Promise<DestructionAttestation> {
  throw new Error("Not implemented");
}

/**
 * Verify a destruction attestation signature.
 */
export async function verifyDestructionAttestation(
  _attestation: DestructionAttestation,
): Promise<boolean> {
  throw new Error("Not implemented");
}

/**
 * Verify that sufficient attestations exist for a given KEK.
 * Returns true if at least `threshold` valid attestations are present.
 */
export async function verifyThresholdDestruction(
  _attestations: DestructionAttestation[],
  _threshold: number,
): Promise<boolean> {
  throw new Error("Not implemented");
}
