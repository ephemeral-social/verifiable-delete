/**
 * TransparencyLogDO — Durable Object wrapping the core transparency log.
 *
 * Manages signing key lifecycle and delegates to createLog() from core.
 * Uses DO SQLite storage via DOLogStorageAdapter.
 *
 * @module transparency-log
 */

import { DurableObject } from "cloudflare:workers";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  createLog,
  type LogEntry,
  type InclusionProof,
  type SignedTreeHead,
  type ConsistencyProof,
  type TransparencyLog,
} from "@ephemeral-social/verifiable-delete";
import type { Env } from "../env.js";
import { DOLogStorageAdapter } from "./log-storage-adapter.js";

// Ed25519 sync setup for Workers runtime
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

export class TransparencyLogDO extends DurableObject<Env> {
  private log: TransparencyLog | null = null;
  private adapter: DOLogStorageAdapter | null = null;

  private getAdapter(): DOLogStorageAdapter {
    if (!this.adapter) {
      this.adapter = new DOLogStorageAdapter(this.ctx.storage.sql);
    }
    return this.adapter;
  }

  private async getLog(): Promise<TransparencyLog> {
    if (!this.log) {
      const adapter = this.getAdapter();
      const signingKey = await this.getOrCreateSigningKey();
      this.log = createLog(adapter, signingKey);
    }
    return this.log;
  }

  private async getOrCreateSigningKey(): Promise<Uint8Array> {
    // Prefer the operator signing key from env (ensures tree heads are verifiable
    // with the same well-known public key as receipts and log entries)
    if (this.env.OPERATOR_SIGNING_KEY) {
      return hexToBytes(this.env.OPERATOR_SIGNING_KEY);
    }

    // Fallback: generate and persist a per-DO key (legacy / unconfigured)
    const sql = this.getAdapter()["sql"];
    sql.exec("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)");
    const existing = sql.exec<{ value: string }>(
      "SELECT value FROM config WHERE key = 'signing_key'"
    ).toArray();
    if (existing[0]) {
      return hexToBytes(existing[0].value);
    }
    const privateKey = crypto.getRandomValues(new Uint8Array(32));
    sql.exec(
      "INSERT INTO config (key, value) VALUES ('signing_key', ?)",
      bytesToHex(privateKey)
    );
    return privateKey;
  }

  async getPublicKey(): Promise<string> {
    const signingKey = await this.getOrCreateSigningKey();
    return bytesToHex(await ed.getPublicKeyAsync(signingKey));
  }

  async append(entry: Omit<LogEntry, "index">): Promise<InclusionProof> {
    const log = await this.getLog();
    return log.append(entry);
  }

  async getTreeHead(): Promise<SignedTreeHead> {
    const log = await this.getLog();
    return log.getTreeHead();
  }

  async getInclusionProof(index: number): Promise<InclusionProof> {
    const log = await this.getLog();
    return log.getInclusionProof(index);
  }

  async getConsistencyProof(from: number, to: number): Promise<ConsistencyProof> {
    const log = await this.getLog();
    return log.getConsistencyProof(from, to);
  }

  async getEntry(receiptId: string): Promise<LogEntry | null> {
    const log = await this.getLog();
    return log.getEntry(receiptId);
  }

  async getEntries(offset: number, limit: number): Promise<LogEntry[]> {
    const log = await this.getLog();
    return log.getEntries(offset, limit);
  }
}
