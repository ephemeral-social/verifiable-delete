/**
 * Shared internal helpers for verifiable-delete modules.
 * NOT exported in package.json — internal only.
 *
 * @internal
 */

import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

/** Recursively sort object keys for deterministic JSON serialization. */
export function canonicalJSON(obj: unknown): string {
  return JSON.stringify(obj, (_key, value) => {
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(value as Record<string, unknown>).sort()) {
        sorted[k] = (value as Record<string, unknown>)[k];
      }
      return sorted;
    }
    return value;
  });
}

/** SHA-256 of a Uint8Array, returned as lowercase hex. */
export function sha256hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}
