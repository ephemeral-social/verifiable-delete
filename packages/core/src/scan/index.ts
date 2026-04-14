/**
 * Post-deletion verification scanning.
 *
 * Scans storage backends after key destruction to confirm data absence.
 * Platform-agnostic: storage scanner interface for Cloudflare, AWS, etc.
 *
 * @module scan
 */

import { sha256hex, canonicalJSON } from "../utils.js";

// --- Types ---

/** Result of scanning a single storage backend. */
export interface BackendScanResult {
  /** Storage backend type (e.g. "d1", "kv", "r2", "postgresql"). */
  type: string;
  /** Identifier queried (e.g. table name, key prefix). */
  identifier: string;
  /** Query or operation performed. */
  query: string;
  /** Whether data was confirmed absent. */
  absent: boolean;
  /** ISO 8601 timestamp of the scan. */
  scannedAt: string;
  /** Any notes (e.g. eventual consistency caveats). */
  note?: string;
}

/** Result of attempting decryption with a destroyed key. */
export interface KeyVerificationResult {
  /** ID of the test ciphertext used. */
  testCiphertextId: string;
  /** Whether decryption failed as expected. */
  expectedFailure: boolean;
  /** The error message from the failed decryption. */
  error?: string;
}

/** Complete scan result for a deletion event. */
export interface ScanResult {
  /** Unique scan ID. */
  scanId: string;
  /** ISO 8601 timestamp when scan started. */
  timestamp: string;
  /** Entity that was deleted. */
  entityId: string;
  /** Results from each storage backend. */
  backends: BackendScanResult[];
  /** Result of key destruction verification. */
  keyVerification: KeyVerificationResult;
  /** Whether all backends confirmed absence AND key is verified destroyed. */
  allVerified: boolean;
  /** Caveats about eventual consistency or backup retention. */
  caveats: string[];
}

/**
 * Storage scanner interface.
 * Implement for your platform to check data absence in each backend.
 */
export interface StorageScanner {
  /** Backend type identifier. */
  type: string;
  /** Check whether data for the given entity is absent. */
  checkAbsence(entityId: string): Promise<BackendScanResult>;
}

// --- Functions ---

/**
 * Run a complete post-deletion scan across all backends.
 *
 * @param entityId - The entity that was deleted
 * @param scanners - Array of storage scanners (one per backend)
 * @param testCiphertextId - ID of the test ciphertext used for key verification
 * @param keyVerified - Whether key destruction was verified
 * @param keyError - Error message if key verification failed
 */
export async function runDeletionScan(params: {
  entityId: string;
  scanners: StorageScanner[];
  testCiphertextId: string;
  keyVerified: boolean;
  keyError?: string;
}): Promise<ScanResult> {
  const { entityId, scanners, testCiphertextId, keyVerified, keyError } = params;

  const scanId = crypto.randomUUID();
  const timestamp = new Date().toISOString();

  // Run all scanners in parallel, wrapping each in try/catch
  const backends = await Promise.all(
    scanners.map(async (scanner) => {
      try {
        return await scanner.checkAbsence(entityId);
      } catch (err) {
        return {
          type: scanner.type,
          identifier: "unknown",
          query: "unknown",
          absent: false,
          scannedAt: new Date().toISOString(),
          note: `Scanner error: ${err instanceof Error ? err.message : String(err)}`,
        } satisfies BackendScanResult;
      }
    }),
  );

  // Build key verification result
  const keyVerification: KeyVerificationResult = {
    testCiphertextId,
    expectedFailure: keyVerified,
    ...(keyError !== undefined ? { error: keyError } : {}),
  };

  // allVerified: all backends absent (vacuously true if zero scanners) AND key verified
  const allVerified =
    (backends.length === 0 || backends.every((b) => b.absent)) && keyVerified;

  // Build caveats from backend notes and key failure
  const caveats: string[] = [];
  for (const backend of backends) {
    if (backend.note !== undefined) {
      caveats.push(`${backend.type}: ${backend.note}`);
    }
  }
  if (!keyVerified) {
    caveats.push(`Key verification failed${keyError !== undefined ? `: ${keyError}` : ""}`);
  }

  return {
    scanId,
    timestamp,
    entityId,
    backends,
    keyVerification,
    allVerified,
    caveats,
  };
}

/**
 * Compute the SHA-256 hash of a scan result for inclusion in receipts.
 */
export async function hashScanResult(result: ScanResult): Promise<string> {
  return sha256hex(new TextEncoder().encode(canonicalJSON(result)));
}
