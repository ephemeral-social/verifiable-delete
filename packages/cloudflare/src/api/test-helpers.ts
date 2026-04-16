/**
 * Shared test infrastructure for API tests.
 * Provides a simple in-memory D1 mock and env factory.
 * @module api/test-helpers
 */

import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { bytesToHex } from "@noble/hashes/utils";
import { sha256 } from "@noble/hashes/sha2";
import {
  createSMT,
  entityToKey,
  serializeProof,
  type InclusionProof,
  type SignedTreeHead,
  type LogEntry,
} from "@ephemeral-social/verifiable-delete";
import type { Env } from "../env.js";

// Ed25519 sync setup
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

// --- In-Memory D1 Mock ---

type Row = Record<string, unknown>;

/**
 * Minimal in-memory D1 mock that supports basic SQL operations.
 * Supports: INSERT, SELECT, UPDATE, DELETE with WHERE clauses.
 * Also supports INSERT OR REPLACE for upserts.
 */
export class MockD1Database {
  tables: Map<string, Row[]> = new Map();

  private getTable(name: string): Row[] {
    if (!this.tables.has(name)) {
      this.tables.set(name, []);
    }
    return this.tables.get(name)!;
  }

  prepare(sql: string): MockD1PreparedStatement {
    return new MockD1PreparedStatement(this, sql);
  }

  async exec(_sql: string): Promise<unknown> {
    // Schema creation — no-op for mock
    return { success: true };
  }

  // Internal: execute a query with bindings
  _execute(
    sql: string,
    bindings: unknown[],
  ): { rows: Row[]; changes: number; success: boolean } {
    const trimmed = sql.trim();

    // INSERT OR REPLACE / INSERT OR IGNORE
    if (/^INSERT\s+OR\s+(REPLACE|IGNORE)\s+INTO/i.test(trimmed)) {
      return this._executeInsert(trimmed, bindings, true);
    }

    if (/^INSERT\s+INTO/i.test(trimmed)) {
      return this._executeInsert(trimmed, bindings, false);
    }

    if (/^SELECT/i.test(trimmed)) {
      return this._executeSelect(trimmed, bindings);
    }

    if (/^UPDATE/i.test(trimmed)) {
      return this._executeUpdate(trimmed, bindings);
    }

    if (/^DELETE\s+FROM/i.test(trimmed)) {
      return this._executeDelete(trimmed, bindings);
    }

    return { rows: [], changes: 0, success: true };
  }

  private _executeInsert(
    sql: string,
    bindings: unknown[],
    upsert: boolean,
  ): { rows: Row[]; changes: number; success: boolean } {
    const tableMatch = sql.match(
      /INSERT\s+(?:OR\s+(?:REPLACE|IGNORE)\s+)?INTO\s+(\w+)\s*\(([^)]+)\)/i,
    );
    if (!tableMatch) return { rows: [], changes: 0, success: false };

    const tableName = tableMatch[1]!;
    const columns = tableMatch[2]!.split(",").map((c) => c.trim());
    const table = this.getTable(tableName);

    const row: Row = {};
    for (let i = 0; i < columns.length; i++) {
      row[columns[i]!] = bindings[i] ?? null;
    }

    if (upsert) {
      // For INSERT OR REPLACE, remove existing row with same primary key (first column)
      const pkCol = columns[0]!;
      const idx = table.findIndex((r) => r[pkCol] === row[pkCol]);
      if (idx >= 0) {
        table[idx] = row;
      } else {
        table.push(row);
      }
    } else {
      table.push(row);
    }

    return { rows: [], changes: 1, success: true };
  }

  private _executeSelect(
    sql: string,
    bindings: unknown[],
  ): { rows: Row[]; changes: number; success: boolean } {
    // Parse table name
    const fromMatch = sql.match(/FROM\s+(\w+)/i);
    if (!fromMatch) return { rows: [], changes: 0, success: true };

    const tableName = fromMatch[1]!;
    const table = this.getTable(tableName);

    // Parse WHERE conditions
    let rows = this._applyWhere(table, sql, bindings);

    // Parse ORDER BY
    const orderMatch = sql.match(
      /ORDER\s+BY\s+(\w+)\s*(ASC|DESC)?/i,
    );
    if (orderMatch) {
      const col = orderMatch[1]!;
      const desc = orderMatch[2]?.toUpperCase() === "DESC";
      rows.sort((a, b) => {
        const va = String(a[col] ?? "");
        const vb = String(b[col] ?? "");
        return desc ? vb.localeCompare(va) : va.localeCompare(vb);
      });
    }

    // Parse LIMIT
    const limitMatch = sql.match(/LIMIT\s+(\d+)/i);
    if (limitMatch) {
      rows = rows.slice(0, parseInt(limitMatch[1]!, 10));
    }

    // Handle COUNT(*)
    if (/SELECT\s+COUNT\(\*\)/i.test(sql)) {
      return { rows: [{ count: rows.length }], changes: 0, success: true };
    }

    // Handle specific columns
    const selectMatch = sql.match(/SELECT\s+(.+?)\s+FROM/i);
    if (selectMatch && selectMatch[1] !== "*") {
      const cols = selectMatch[1]!.split(",").map((c) => c.trim());
      rows = rows.map((r) => {
        const filtered: Row = {};
        for (const c of cols) {
          filtered[c] = r[c];
        }
        return filtered;
      });
    }

    return { rows, changes: 0, success: true };
  }

  private _executeUpdate(
    sql: string,
    bindings: unknown[],
  ): { rows: Row[]; changes: number; success: boolean } {
    const tableMatch = sql.match(/UPDATE\s+(\w+)\s+SET/i);
    if (!tableMatch) return { rows: [], changes: 0, success: false };

    const tableName = tableMatch[1]!;
    const table = this.getTable(tableName);

    // Parse SET clause columns (before WHERE)
    const setClause = sql.match(/SET\s+(.+?)(?:\s+WHERE|$)/i);
    if (!setClause) return { rows: [], changes: 0, success: false };

    const setCols = setClause[1]!
      .split(",")
      .map((s) => s.trim().split(/\s*=\s*/)[0]!.trim());

    // Count how many bindings are for SET vs WHERE
    const whereClause = sql.match(/WHERE\s+(.+)$/i);

    const setBindings = bindings.slice(0, setCols.length);
    const whereBindings = bindings.slice(setCols.length);

    // Find matching rows
    const matchingRows = whereClause
      ? this._applyWhereWithBindings(table, whereClause[1]!, whereBindings)
      : table;

    let changes = 0;
    for (const row of matchingRows) {
      for (let i = 0; i < setCols.length; i++) {
        row[setCols[i]!] = setBindings[i] ?? null;
      }
      changes++;
    }

    return { rows: [], changes, success: true };
  }

  private _executeDelete(
    sql: string,
    bindings: unknown[],
  ): { rows: Row[]; changes: number; success: boolean } {
    const tableMatch = sql.match(/DELETE\s+FROM\s+(\w+)/i);
    if (!tableMatch) return { rows: [], changes: 0, success: false };

    const tableName = tableMatch[1]!;
    const table = this.getTable(tableName);
    const before = table.length;

    const remaining = this._applyWhereInverse(table, sql, bindings);
    this.tables.set(tableName, remaining);

    return { rows: [], changes: before - remaining.length, success: true };
  }

  private _applyWhere(
    table: Row[],
    sql: string,
    bindings: unknown[],
  ): Row[] {
    const whereMatch = sql.match(/WHERE\s+(.+?)(?:\s+ORDER|\s+LIMIT|$)/i);
    if (!whereMatch) return [...table];
    return this._applyWhereWithBindings(table, whereMatch[1]!, bindings);
  }

  private _applyWhereWithBindings(
    table: Row[],
    whereClause: string,
    bindings: unknown[],
  ): Row[] {
    // Parse conditions like "col = ?" or "col IS NULL" or "col IS NOT NULL"
    const conditions = whereClause.split(/\s+AND\s+/i);
    let bindIdx = 0;

    return table.filter((row) => {
      let localIdx = bindIdx;
      const match = conditions.every((cond) => {
        const isNullMatch = cond.match(/(\w+)\s+IS\s+NULL/i);
        if (isNullMatch) {
          return row[isNullMatch[1]!] === null || row[isNullMatch[1]!] === undefined;
        }

        const isNotNullMatch = cond.match(/(\w+)\s+IS\s+NOT\s+NULL/i);
        if (isNotNullMatch) {
          return row[isNotNullMatch[1]!] !== null && row[isNotNullMatch[1]!] !== undefined;
        }

        const eqMatch = cond.match(/(\w+)\s*=\s*\?/i);
        if (eqMatch) {
          const val = bindings[localIdx++];
          return row[eqMatch[1]!] === val;
        }

        return true;
      });
      // Advance binding index for the next row check
      return match;
    });
  }

  private _applyWhereInverse(
    table: Row[],
    sql: string,
    bindings: unknown[],
  ): Row[] {
    const whereMatch = sql.match(/WHERE\s+(.+?)(?:\s+ORDER|\s+LIMIT|$)/i);
    if (!whereMatch) return [];

    const matching = this._applyWhereWithBindings(table, whereMatch[1]!, bindings);
    return table.filter((r) => !matching.includes(r));
  }
}

class MockD1PreparedStatement {
  private bindings: unknown[] = [];

  constructor(
    private db: MockD1Database,
    private sql: string,
  ) {}

  bind(...values: unknown[]): MockD1PreparedStatement {
    this.bindings = values;
    return this;
  }

  async first<T = Row>(column?: string): Promise<T | null> {
    const result = this.db._execute(this.sql, this.bindings);
    if (result.rows.length === 0) return null;
    if (column) return (result.rows[0]![column] as T) ?? null;
    return result.rows[0] as T;
  }

  async run(): Promise<{ success: boolean; meta: { changes: number } }> {
    const result = this.db._execute(this.sql, this.bindings);
    return { success: result.success, meta: { changes: result.changes } };
  }

  async all<T = Row>(): Promise<{ results: T[] }> {
    const result = this.db._execute(this.sql, this.bindings);
    return { results: result.rows as T[] };
  }
}

// --- Mock Env Factory ---

export interface MockEnvOptions {
  operatorSigningKey?: string;
  adminSecret?: string;
}

export function createApiMockEnv(opts?: MockEnvOptions): Env & { mockDB: MockD1Database } {
  const operatorKey = opts?.operatorSigningKey ?? bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  const adminSecret = opts?.adminSecret ?? "test-admin-secret";
  const mockDB = new MockD1Database();

  const smt = createSMT();
  const entitySet = new Set<string>();

  const logEntries: LogEntry[] = [];
  const logSigningKey = crypto.getRandomValues(new Uint8Array(32));

  const env: Env & { mockDB: MockD1Database } = {
    mockDB,
    DB: mockDB as unknown as D1Database,

    KV: {
      put: async () => {},
      get: async () => null,
      delete: async () => {},
    } as unknown as KVNamespace,

    BUCKET: {
      put: async () => {},
      head: async () => null,
      delete: async () => {},
    } as unknown as R2Bucket,

    KEY_SHARE_DO: {
      idFromName: (name: string) => ({ toString: () => name }),
      get: () =>
        new Proxy(
          {},
          {
            get: (_target, prop: string) => {
              if (prop === "getShareHolder") {
                return async (label: string) => {
                  const pk = crypto.getRandomValues(new Uint8Array(32));
                  const publicKey = await ed.getPublicKeyAsync(pk);
                  return { id: bytesToHex(publicKey).slice(0, 16), label, publicKey };
                };
              }
              if (prop === "storeShare") return async () => {};
              if (prop === "destroyShare") {
                return async (kekId: string, holderLabel: string) => {
                  const pk = crypto.getRandomValues(new Uint8Array(32));
                  const publicKey = await ed.getPublicKeyAsync(pk);
                  const destroyedAt = new Date().toISOString();
                  const msg = new TextEncoder().encode(
                    `vd-destroy-v1:${kekId}:1:${destroyedAt}`,
                  );
                  const signature = await ed.signAsync(msg, pk);
                  return {
                    kekId,
                    shareIndex: 1,
                    holder: { id: bytesToHex(publicKey).slice(0, 16), label: holderLabel, publicKey: bytesToHex(publicKey) },
                    destroyedAt,
                    signature: bytesToHex(new Uint8Array(signature)),
                  };
                };
              }
              if (prop === "hasShare") return async () => true;
              return undefined;
            },
          },
        ),
    } as unknown as Env["KEY_SHARE_DO"],

    TRANSPARENCY_LOG_DO: {
      idFromName: () => ({ toString: () => "main" }),
      get: () => ({
        append: async (entry: Omit<LogEntry, "index">): Promise<InclusionProof> => {
          const fullEntry: LogEntry = { ...entry, index: logEntries.length };
          logEntries.push(fullEntry);
          return {
            logIndex: fullEntry.index,
            treeSize: logEntries.length,
            rootHash: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
            hashes: [],
          };
        },
        getTreeHead: async (): Promise<SignedTreeHead> => {
          const timestamp = new Date().toISOString();
          const rootHash = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
          const msg = new TextEncoder().encode(
            `vd-tree-head-v1:${logEntries.length}:${rootHash}:${timestamp}`,
          );
          const signature = bytesToHex(await ed.signAsync(msg, logSigningKey));
          return { treeSize: logEntries.length, rootHash, timestamp, signature };
        },
        getInclusionProof: async (index: number): Promise<InclusionProof> => {
          if (index >= logEntries.length) throw new Error("Index out of range");
          return {
            logIndex: index,
            treeSize: logEntries.length,
            rootHash: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
            hashes: [],
          };
        },
        getConsistencyProof: async () => ({
          fromSize: 0,
          toSize: logEntries.length,
          fromRoot: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
          toRoot: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
          hashes: [],
        }),
        getEntry: async (receiptId: string) =>
          logEntries.find((e) => e.receiptId === receiptId) ?? null,
        getEntries: async (offset: number, limit: number) =>
          logEntries.slice(offset, offset + limit),
      }),
    } as unknown as Env["TRANSPARENCY_LOG_DO"],

    SMT_DO: {
      idFromName: (name: string) => ({ toString: () => name }),
      get: () => ({
        addEntity: async (entityId: string) => {
          const key = entityToKey(entityId);
          smt.add(key, key);
          entitySet.add(entityId);
          return smt.root as string;
        },
        removeEntity: async (entityId: string) => {
          const key = entityToKey(entityId);
          smt.delete(key);
          entitySet.delete(entityId);
          const proof = smt.createProof(key);
          return serializeProof(proof, entityId);
        },
        hasEntity: async (entityId: string) => {
          return entitySet.has(entityId);
        },
        getRoot: async () => smt.root as string,
      }),
    } as unknown as Env["SMT_DO"],

    OPERATOR_SIGNING_KEY: operatorKey,
    VD_ADMIN_SECRET: adminSecret,
  };

  return env;
}

// --- Helper: Seed a customer + API key ---

export function sha256hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

export async function seedCustomerAndKey(
  db: MockD1Database,
  customerId: string,
  rawApiKey: string,
): Promise<void> {
  const keyHash = sha256hex(new TextEncoder().encode(rawApiKey));
  const keyPrefix = rawApiKey.slice(0, 12);
  const now = new Date().toISOString();

  db._execute(
    "INSERT INTO customers (id, name, email, plan, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    [customerId, "Test Co", "test@example.com", "standard", "active", now],
  );

  db._execute(
    "INSERT INTO api_keys (id, customer_id, key_hash, key_prefix, label, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [crypto.randomUUID(), customerId, keyHash, keyPrefix, "test", now, null],
  );
}

// --- Helper: Make a request ---

export function makeRequest(
  path: string,
  method = "GET",
  body?: unknown,
  headers?: Record<string, string>,
): Request {
  const opts: RequestInit = { method };
  const h: Record<string, string> = { ...(headers ?? {}) };
  if (body) {
    h["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  opts.headers = h;
  return new Request(`http://localhost${path}`, opts);
}
