/**
 * SparseMerkleTreeDO — Durable Object wrapping an in-memory SMT
 * with event-sourcing persistence via SQLite.
 *
 * Supports add/remove/getRoot operations. On cold start, the SMT
 * is rebuilt by replaying the operation log from SQLite storage.
 *
 * @module sparse-merkle-tree
 */

import { DurableObject } from "cloudflare:workers";
import {
  createSMT,
  entityToKey,
  serializeProof,
} from "@ephemeral-social/verifiable-delete";
import type { SparseMerkleTree } from "@zk-kit/sparse-merkle-tree";
import type { NonMembershipProof } from "@ephemeral-social/verifiable-delete";
import type { Env } from "../env.js";

export class SparseMerkleTreeDO extends DurableObject<Env> {
  private smt: SparseMerkleTree | null = null;

  private ensureSchema(): void {
    this.ctx.storage.sql.exec(
      "CREATE TABLE IF NOT EXISTS smt_ops (op TEXT NOT NULL, entity_key TEXT NOT NULL, entity_value TEXT NOT NULL)",
    );
  }

  private ensureTree(): SparseMerkleTree {
    if (this.smt) return this.smt;
    this.ensureSchema();
    this.smt = createSMT();
    const rows = this.ctx.storage.sql.exec(
      "SELECT op, entity_key, entity_value FROM smt_ops ORDER BY rowid",
    );
    for (const row of rows) {
      if (row.op === "add") {
        this.smt.add(row.entity_key as string, row.entity_value as string);
      } else if (row.op === "delete") {
        this.smt.delete(row.entity_key as string);
      }
    }
    return this.smt;
  }

  async addEntity(entityId: string): Promise<string> {
    const smt = this.ensureTree();
    const key = entityToKey(entityId);
    smt.add(key, key);
    this.ctx.storage.sql.exec(
      "INSERT INTO smt_ops (op, entity_key, entity_value) VALUES ('add', ?, ?)",
      key,
      key,
    );
    return smt.root as string;
  }

  async removeEntity(entityId: string): Promise<NonMembershipProof> {
    const smt = this.ensureTree();
    const key = entityToKey(entityId);
    smt.delete(key);
    this.ctx.storage.sql.exec(
      "INSERT INTO smt_ops (op, entity_key, entity_value) VALUES ('delete', ?, ?)",
      key,
      key,
    );
    const proof = smt.createProof(key);
    return serializeProof(proof, entityId);
  }

  async getRoot(): Promise<string> {
    const smt = this.ensureTree();
    return smt.root as string;
  }
}
