/**
 * Core key share storage logic, extracted for unit testability.
 *
 * Uses a SqlStorageLike interface so it can be tested with an
 * in-memory mock instead of requiring the Cloudflare runtime.
 *
 * @module key-share-storage
 */

import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  createDestructionAttestation,
  serializeAttestation,
  type ShareHolder,
  type SerializedDestructionAttestation,
} from "@ephemeral-social/verifiable-delete";

// Ed25519 requires sha512 — set sync fallback for non-browser environments
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

/** Minimal interface matching DO SqlStorage for testability. */
export interface SqlStorageLike {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  exec<T = Record<string, any>>(query: string, ...bindings: unknown[]): { toArray(): T[] };
}

/** Core key share storage logic, extracted for testability. */
export class KeyShareStorage {
  constructor(private sql: SqlStorageLike) {
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS keypair (id INTEGER PRIMARY KEY CHECK(id=1), private_key TEXT NOT NULL, public_key TEXT NOT NULL)",
    );
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS shares (kek_id TEXT PRIMARY KEY, share_index INTEGER NOT NULL, share_data TEXT NOT NULL)",
    );
  }

  async getOrCreateKeypair(): Promise<{ publicKey: string; privateKey: Uint8Array }> {
    const rows = this.sql
      .exec<{ private_key: string; public_key: string }>(
        "SELECT private_key, public_key FROM keypair WHERE id = 1",
      )
      .toArray();
    if (rows[0]) {
      return {
        privateKey: hexToBytes(rows[0].private_key),
        publicKey: rows[0].public_key,
      };
    }
    const privateKey = crypto.getRandomValues(new Uint8Array(32));
    const publicKey = await ed.getPublicKeyAsync(privateKey);
    const publicKeyHex = bytesToHex(publicKey);
    this.sql.exec(
      "INSERT INTO keypair (id, private_key, public_key) VALUES (1, ?, ?)",
      bytesToHex(privateKey),
      publicKeyHex,
    );
    return { privateKey, publicKey: publicKeyHex };
  }

  async getPublicKey(): Promise<string> {
    const { publicKey } = await this.getOrCreateKeypair();
    return publicKey;
  }

  async getShareHolder(label: string): Promise<ShareHolder> {
    const { publicKey } = await this.getOrCreateKeypair();
    return {
      id: publicKey.slice(0, 16),
      label,
      publicKey: hexToBytes(publicKey),
    };
  }

  async storeShare(kekId: string, shareIndex: number, shareData: Uint8Array): Promise<void> {
    this.sql.exec(
      "INSERT OR REPLACE INTO shares (kek_id, share_index, share_data) VALUES (?, ?, ?)",
      kekId,
      shareIndex,
      bytesToHex(shareData),
    );
  }

  async hasShare(kekId: string): Promise<boolean> {
    const rows = this.sql
      .exec<{ kek_id: string }>("SELECT kek_id FROM shares WHERE kek_id = ?", kekId)
      .toArray();
    return rows.length > 0;
  }

  async destroyShare(kekId: string, holderLabel: string): Promise<SerializedDestructionAttestation> {
    // Get share info BEFORE deletion
    const rows = this.sql
      .exec<{ share_index: number; share_data: string }>(
        "SELECT share_index, share_data FROM shares WHERE kek_id = ?",
        kekId,
      )
      .toArray();
    if (!rows[0]) {
      throw new Error(`No share found for kekId: ${kekId}`);
    }
    const shareIndex = rows[0].share_index;

    // DELETE share BEFORE creating attestation (safe failure order)
    this.sql.exec("DELETE FROM shares WHERE kek_id = ?", kekId);

    // Create attestation (needs raw Uint8Array privateKey internally)
    const { privateKey } = await this.getOrCreateKeypair();
    const holder = await this.getShareHolder(holderLabel);
    const attestation = await createDestructionAttestation(kekId, shareIndex, holder, privateKey);

    // Serialize for safe transport across DO RPC boundary
    return serializeAttestation(attestation);
  }
}
