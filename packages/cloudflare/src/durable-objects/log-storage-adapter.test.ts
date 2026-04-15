import { describe, it, expect, beforeEach } from "vitest";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import {
  createLog,
  verifyInclusionProof,
  verifyTreeHead,
  computeLeafHash,
  type LogEntry,
} from "@ephemeral-social/verifiable-delete";
import { DOLogStorageAdapter, type SqlStorageLike, type SqlStorageCursorLike } from "./log-storage-adapter.js";

// Ed25519 sync setup for Node
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

// --- Mock SQL storage ---

interface TableRow {
  [key: string]: unknown;
}

interface TableDef {
  rows: TableRow[];
  primaryKeys: string[];
  autoIncrement: string | null;
  nextAutoId: number;
  uniqueColumns: string[];
}

class MockSqlStorage implements SqlStorageLike {
  private tables: Map<string, TableDef> = new Map();

  exec<T = Record<string, unknown>>(query: string, ...bindings: unknown[]): SqlStorageCursorLike<T> {
    const trimmed = query.trim();

    if (trimmed.startsWith("CREATE TABLE IF NOT EXISTS")) {
      return this.handleCreateTable<T>(trimmed);
    }
    if (trimmed.startsWith("INSERT OR REPLACE INTO")) {
      return this.handleInsertOrReplace<T>(trimmed, bindings);
    }
    if (trimmed.startsWith("INSERT INTO")) {
      return this.handleInsert<T>(trimmed, bindings);
    }
    if (trimmed.startsWith("SELECT")) {
      return this.handleSelect<T>(trimmed, bindings);
    }

    return { toArray: () => [] as T[], rowsRead: 0 };
  }

  private handleCreateTable<T>(query: string): SqlStorageCursorLike<T> {
    // Extract table name
    const nameMatch = query.match(/CREATE TABLE IF NOT EXISTS (\w+)/);
    if (!nameMatch) return { toArray: () => [] as T[], rowsRead: 0 };

    const tableName = nameMatch[1]!;
    if (!this.tables.has(tableName)) {
      // Parse columns for AUTOINCREMENT and UNIQUE
      let autoIncrement: string | null = null;
      const uniqueColumns: string[] = [];

      const autoMatch = query.match(/(\w+)\s+INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT/i);
      if (autoMatch) {
        autoIncrement = autoMatch[1]!;
      }

      const uniqueMatches = query.matchAll(/(\w+)\s+TEXT\s+UNIQUE/gi);
      for (const m of uniqueMatches) {
        uniqueColumns.push(m[1]!);
      }

      // Extract primary key columns
      const primaryKeys: string[] = [];
      // Single-column PRIMARY KEY inline
      const inlinePKMatch = query.match(/(\w+)\s+INTEGER\s+PRIMARY\s+KEY(?:\s+AUTOINCREMENT)?/i);
      if (inlinePKMatch) {
        primaryKeys.push(inlinePKMatch[1]!);
      }
      // Composite PRIMARY KEY (col1, col2)
      const compositePKMatch = query.match(/PRIMARY\s+KEY\s*\(([^)]+)\)/i);
      if (compositePKMatch && !query.match(/\w+\s+INTEGER\s+PRIMARY\s+KEY/i)) {
        // Only use composite if no inline PK found
        const cols = compositePKMatch[1]!.split(",").map(c => c.trim());
        primaryKeys.length = 0;
        for (const c of cols) primaryKeys.push(c);
      } else if (compositePKMatch && primaryKeys.length > 0) {
        // Has both inline and composite — composite takes precedence for multi-column
        const cols = compositePKMatch[1]!.split(",").map(c => c.trim());
        if (cols.length > 1) {
          primaryKeys.length = 0;
          for (const c of cols) primaryKeys.push(c);
        }
      }

      this.tables.set(tableName, {
        rows: [],
        primaryKeys,
        autoIncrement,
        nextAutoId: 1,
        uniqueColumns,
      });
    }

    return { toArray: () => [] as T[], rowsRead: 0 };
  }

  private handleInsert<T>(query: string, bindings: unknown[]): SqlStorageCursorLike<T> {
    const match = query.match(/INSERT INTO (\w+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/i);
    if (!match) return { toArray: () => [] as T[], rowsRead: 0 };

    const tableName = match[1]!;
    const columns = match[2]!.split(",").map(c => c.trim());
    const table = this.tables.get(tableName);
    if (!table) return { toArray: () => [] as T[], rowsRead: 0 };

    const row: TableRow = {};
    let bindIdx = 0;
    for (const col of columns) {
      if (col === table.autoIncrement) {
        row[col] = table.nextAutoId++;
      } else {
        row[col] = bindings[bindIdx++];
      }
    }

    // Handle auto-increment if not in column list
    if (table.autoIncrement && !columns.includes(table.autoIncrement)) {
      row[table.autoIncrement] = table.nextAutoId++;
    }

    table.rows.push(row);
    return { toArray: () => [] as T[], rowsRead: 0 };
  }

  private handleInsertOrReplace<T>(query: string, bindings: unknown[]): SqlStorageCursorLike<T> {
    const match = query.match(/INSERT OR REPLACE INTO (\w+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/i);
    if (!match) return { toArray: () => [] as T[], rowsRead: 0 };

    const tableName = match[1]!;
    const columns = match[2]!.split(",").map(c => c.trim());
    const table = this.tables.get(tableName);
    if (!table) return { toArray: () => [] as T[], rowsRead: 0 };

    const row: TableRow = {};
    let bindIdx = 0;
    for (const col of columns) {
      row[col] = bindings[bindIdx++];
    }

    // Find existing row by primary key and replace if exists
    const existingIdx = table.rows.findIndex(r => {
      return table.primaryKeys.every(pk => r[pk] === row[pk]);
    });

    if (existingIdx >= 0) {
      table.rows[existingIdx] = row;
    } else {
      table.rows.push(row);
    }

    return { toArray: () => [] as T[], rowsRead: 0 };
  }

  private handleSelect<T>(query: string, bindings: unknown[]): SqlStorageCursorLike<T> {
    // SELECT COUNT(*) as cnt FROM table
    const countMatch = query.match(/SELECT COUNT\(\*\)\s+as\s+(\w+)\s+FROM\s+(\w+)/i);
    if (countMatch) {
      const alias = countMatch[1]!;
      const tableName = countMatch[2]!;
      const table = this.tables.get(tableName);
      const cnt = table ? table.rows.length : 0;
      const result = [{ [alias]: cnt }] as T[];
      return { toArray: () => result, rowsRead: 1 };
    }

    // Parse SELECT columns FROM table [WHERE ...] [ORDER BY ...] [LIMIT ... OFFSET ...]
    const selectMatch = query.match(
      /SELECT\s+(.+?)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+?))?(?:\s+ORDER BY\s+(.+?))?(?:\s+LIMIT\s+\?(?:\s+OFFSET\s+\?)?)?$/i
    );
    if (!selectMatch) return { toArray: () => [] as T[], rowsRead: 0 };

    const tableName = selectMatch[2]!;
    const whereClause = selectMatch[3];
    const orderClause = selectMatch[4];
    const hasLimit = /LIMIT\s+\?/i.test(query);
    const hasOffset = /OFFSET\s+\?/i.test(query);

    const table = this.tables.get(tableName);
    if (!table) return { toArray: () => [] as T[], rowsRead: 0 };

    let rows = [...table.rows];
    let bindIdx = 0;

    // Apply WHERE
    if (whereClause) {
      const conditions = whereClause.split(/\s+AND\s+/i);
      for (const cond of conditions) {
        const trimCond = cond.trim();
        // col >= ?
        const gteMatch = trimCond.match(/(\w+)\s*>=\s*\?/);
        if (gteMatch) {
          const col = gteMatch[1]!;
          const val = bindings[bindIdx++] as number;
          rows = rows.filter(r => (r[col] as number) >= val);
          continue;
        }
        // col < ?
        const ltMatch = trimCond.match(/(\w+)\s*<\s*\?/);
        if (ltMatch) {
          const col = ltMatch[1]!;
          const val = bindings[bindIdx++] as number;
          rows = rows.filter(r => (r[col] as number) < val);
          continue;
        }
        // col = ?
        const eqMatch = trimCond.match(/(\w+)\s*=\s*\?/);
        if (eqMatch) {
          const col = eqMatch[1]!;
          const val = bindings[bindIdx++];
          rows = rows.filter(r => r[col] === val);
          continue;
        }
      }
    }

    // Apply ORDER BY
    if (orderClause) {
      const orderParts = orderClause.trim().split(/\s+/);
      const orderCol = orderParts[0]!;
      const orderDir = (orderParts[1] ?? "ASC").toUpperCase();
      rows.sort((a, b) => {
        const aVal = a[orderCol] as number;
        const bVal = b[orderCol] as number;
        return orderDir === "DESC" ? bVal - aVal : aVal - bVal;
      });
    }

    // Apply LIMIT/OFFSET
    if (hasLimit) {
      const limit = bindings[bindIdx++] as number;
      if (hasOffset) {
        const offset = bindings[bindIdx++] as number;
        rows = rows.slice(offset, offset + limit);
      } else {
        rows = rows.slice(0, limit);
      }
    }

    // Project columns
    const colDefs = selectMatch[1]!;
    const results = rows.map(r => {
      const projected: Record<string, unknown> = {};
      const cols = colDefs.split(",").map(c => c.trim());
      for (const col of cols) {
        projected[col] = r[col];
      }
      return projected;
    }) as T[];

    return { toArray: () => results, rowsRead: results.length };
  }
}

// --- Test helpers ---

function mockEntry(i: number): LogEntry {
  return {
    index: i,
    receiptId: `receipt-${i}`,
    timestamp: new Date(1700000000000 + i * 1000).toISOString(),
    entityType: `entity_type_${i}`,
    commitment: `commitment_${i}`,
    deletionMethod: "crypto_shredding",
    thresholdSignatures: [`sig_${i}_a`, `sig_${i}_b`],
    scanHash: `scan_hash_${i}`,
    smtRoot: `smt_root_${i}`,
    operatorSignature: `op_sig_${i}`,
  };
}

function mockEntryWithoutIndex(i: number): Omit<LogEntry, "index"> {
  return {
    receiptId: `receipt-${i}`,
    timestamp: new Date(1700000000000 + i * 1000).toISOString(),
    entityType: `entity_type_${i}`,
    commitment: `commitment_${i}`,
    deletionMethod: "crypto_shredding",
    thresholdSignatures: [`sig_${i}_a`, `sig_${i}_b`],
    scanHash: `scan_hash_${i}`,
    smtRoot: `smt_root_${i}`,
    operatorSignature: `op_sig_${i}`,
  };
}

// --- Tests ---

describe("DOLogStorageAdapter", () => {
  let sql: MockSqlStorage;
  let adapter: DOLogStorageAdapter;

  beforeEach(() => {
    sql = new MockSqlStorage();
    adapter = new DOLogStorageAdapter(sql);
  });

  it("appendLeaf stores hash and returns incremented size", async () => {
    const size1 = await adapter.appendLeaf("hash_a");
    expect(size1).toBe(1);

    const size2 = await adapter.appendLeaf("hash_b");
    expect(size2).toBe(2);
  });

  it("getLeaves returns correct range", async () => {
    await adapter.appendLeaf("hash_0");
    await adapter.appendLeaf("hash_1");
    await adapter.appendLeaf("hash_2");
    await adapter.appendLeaf("hash_3");

    const range = await adapter.getLeaves(1, 3);
    expect(range).toEqual(["hash_1", "hash_2"]);

    const all = await adapter.getLeaves(0, 4);
    expect(all).toEqual(["hash_0", "hash_1", "hash_2", "hash_3"]);
  });

  it("getNode returns null for missing node", async () => {
    const result = await adapter.getNode(0, 0);
    expect(result).toBeNull();
  });

  it("setNode then getNode roundtrips", async () => {
    await adapter.setNode(1, 2, "node_hash_abc");
    const result = await adapter.getNode(1, 2);
    expect(result).toBe("node_hash_abc");

    // Overwrite with INSERT OR REPLACE
    await adapter.setNode(1, 2, "node_hash_xyz");
    const updated = await adapter.getNode(1, 2);
    expect(updated).toBe("node_hash_xyz");
  });

  it("getTreeSize returns 0 for empty log", async () => {
    const size = await adapter.getTreeSize();
    expect(size).toBe(0);
  });

  it("storeEntry then getEntry by index roundtrips", async () => {
    const entry = mockEntry(0);
    await adapter.storeEntry(0, entry);

    const retrieved = await adapter.getEntry(0);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.receiptId).toBe("receipt-0");
    expect(retrieved!.index).toBe(0);
    expect(retrieved!.entityType).toBe("entity_type_0");
    expect(retrieved!.commitment).toBe("commitment_0");
    expect(retrieved!.deletionMethod).toBe("crypto_shredding");
    expect(retrieved!.thresholdSignatures).toEqual(["sig_0_a", "sig_0_b"]);
    expect(retrieved!.scanHash).toBe("scan_hash_0");
    expect(retrieved!.smtRoot).toBe("smt_root_0");
    expect(retrieved!.operatorSignature).toBe("op_sig_0");
  });

  it("getEntryByReceiptId returns correct entry", async () => {
    await adapter.storeEntry(0, mockEntry(0));
    await adapter.storeEntry(1, mockEntry(1));
    await adapter.storeEntry(2, mockEntry(2));

    const entry = await adapter.getEntryByReceiptId("receipt-1");
    expect(entry).not.toBeNull();
    expect(entry!.index).toBe(1);
    expect(entry!.receiptId).toBe("receipt-1");
  });

  it("getEntryByReceiptId returns null for unknown", async () => {
    await adapter.storeEntry(0, mockEntry(0));

    const entry = await adapter.getEntryByReceiptId("nonexistent");
    expect(entry).toBeNull();
  });

  it("getEntries pagination (offset/limit)", async () => {
    for (let i = 0; i < 5; i++) {
      await adapter.storeEntry(i, mockEntry(i));
    }

    const page = await adapter.getEntries(2, 2);
    expect(page.length).toBe(2);
    expect(page[0]!.index).toBe(2);
    expect(page[1]!.index).toBe(3);

    // Beyond range
    const last = await adapter.getEntries(4, 10);
    expect(last.length).toBe(1);
    expect(last[0]!.index).toBe(4);
  });

  it("storeTreeHead and getTreeHeads roundtrip (newest-first)", async () => {
    await adapter.storeTreeHead({
      treeSize: 1,
      rootHash: "root_1",
      timestamp: "2024-01-01T00:00:00.000Z",
      signature: "sig_1",
    });
    await adapter.storeTreeHead({
      treeSize: 2,
      rootHash: "root_2",
      timestamp: "2024-01-02T00:00:00.000Z",
      signature: "sig_2",
    });
    await adapter.storeTreeHead({
      treeSize: 3,
      rootHash: "root_3",
      timestamp: "2024-01-03T00:00:00.000Z",
      signature: "sig_3",
    });

    const heads = await adapter.getTreeHeads(10);
    expect(heads.length).toBe(3);
    // Newest first (descending by autoincrement id)
    expect(heads[0]!.treeSize).toBe(3);
    expect(heads[1]!.treeSize).toBe(2);
    expect(heads[2]!.treeSize).toBe(1);

    // Limit respected
    const limited = await adapter.getTreeHeads(2);
    expect(limited.length).toBe(2);
    expect(limited[0]!.treeSize).toBe(3);
  });

  it("appendLeaves (batch) returns correct total", async () => {
    const size = await adapter.appendLeaves(["h1", "h2", "h3"]);
    expect(size).toBe(3);

    const leaves = await adapter.getLeaves(0, 3);
    expect(leaves).toEqual(["h1", "h2", "h3"]);

    // Append more
    const newSize = await adapter.appendLeaves(["h4", "h5"]);
    expect(newSize).toBe(5);
  });

  it("integration: DOLogStorageAdapter + createLog end-to-end", async () => {
    const signingKey = crypto.getRandomValues(new Uint8Array(32));
    const publicKey = await ed.getPublicKeyAsync(signingKey);
    const log = createLog(adapter, signingKey);

    // Append 3 entries
    const proofs = [];
    for (let i = 0; i < 3; i++) {
      proofs.push(await log.append(mockEntryWithoutIndex(i)));
    }

    // Verify all 3 inclusion proofs
    for (let i = 0; i < 3; i++) {
      const leafHash = computeLeafHash({ ...mockEntryWithoutIndex(i), index: i });
      const valid = await verifyInclusionProof(leafHash, proofs[i]!);
      expect(valid).toBe(true);
    }

    // Verify tree head
    const head = await log.getTreeHead();
    expect(head.treeSize).toBe(3);

    const headValid = await verifyTreeHead(head, publicKey);
    expect(headValid).toBe(true);

    // Verify getInclusionProof after the fact
    for (let i = 0; i < 3; i++) {
      const proof = await log.getInclusionProof(i);
      const leafHash = computeLeafHash({ ...mockEntryWithoutIndex(i), index: i });
      const valid = await verifyInclusionProof(leafHash, proof);
      expect(valid).toBe(true);
    }
  });
});
