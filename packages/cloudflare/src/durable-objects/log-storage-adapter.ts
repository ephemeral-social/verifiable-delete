/**
 * Durable Object SQLite-backed LogStorageAdapter.
 *
 * Implements the core LogStorageAdapter interface using DO SqlStorage.
 * Extracted as a standalone class for unit testability with mock SQL.
 *
 * @module log-storage-adapter
 */

import type { LogStorageAdapter, LogEntry, SignedTreeHead } from "@ephemeral-social/verifiable-delete";

/** Minimal interface matching DO SqlStorage for testability. */
export interface SqlStorageLike {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  exec<T = Record<string, any>>(query: string, ...bindings: unknown[]): SqlStorageCursorLike<T>;
}

export interface SqlStorageCursorLike<T> {
  toArray(): T[];
}

export class DOLogStorageAdapter implements LogStorageAdapter {
  constructor(private sql: SqlStorageLike) {
    this.sql.exec(`CREATE TABLE IF NOT EXISTS leaves (idx INTEGER PRIMARY KEY, hash TEXT NOT NULL)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS nodes (level INTEGER NOT NULL, idx INTEGER NOT NULL, hash TEXT NOT NULL, PRIMARY KEY (level, idx))`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS entries (idx INTEGER PRIMARY KEY, receipt_id TEXT UNIQUE NOT NULL, data TEXT NOT NULL)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS tree_heads (id INTEGER PRIMARY KEY AUTOINCREMENT, tree_size INTEGER NOT NULL, root_hash TEXT NOT NULL, timestamp TEXT NOT NULL, signature TEXT NOT NULL)`);
  }

  async getLeaves(start: number, end: number): Promise<string[]> {
    const rows = this.sql.exec<{ hash: string }>(
      "SELECT hash FROM leaves WHERE idx >= ? AND idx < ? ORDER BY idx", start, end
    ).toArray();
    return rows.map(r => r.hash);
  }

  async appendLeaf(hash: string): Promise<number> {
    const sizeRows = this.sql.exec<{ cnt: number }>("SELECT COUNT(*) as cnt FROM leaves").toArray();
    const currentSize = sizeRows[0]?.cnt ?? 0;
    this.sql.exec("INSERT INTO leaves (idx, hash) VALUES (?, ?)", currentSize, hash);
    return currentSize + 1;
  }

  async getNode(level: number, index: number): Promise<string | null> {
    const rows = this.sql.exec<{ hash: string }>(
      "SELECT hash FROM nodes WHERE level = ? AND idx = ?", level, index
    ).toArray();
    return rows[0]?.hash ?? null;
  }

  async setNode(level: number, index: number, hash: string): Promise<void> {
    this.sql.exec(
      "INSERT OR REPLACE INTO nodes (level, idx, hash) VALUES (?, ?, ?)", level, index, hash
    );
  }

  async getTreeSize(): Promise<number> {
    const rows = this.sql.exec<{ cnt: number }>("SELECT COUNT(*) as cnt FROM leaves").toArray();
    return rows[0]?.cnt ?? 0;
  }

  async storeEntry(index: number, entry: LogEntry): Promise<void> {
    this.sql.exec(
      "INSERT OR REPLACE INTO entries (idx, receipt_id, data) VALUES (?, ?, ?)",
      index, entry.receiptId, JSON.stringify(entry)
    );
  }

  async getEntry(index: number): Promise<LogEntry | null> {
    const rows = this.sql.exec<{ data: string }>(
      "SELECT data FROM entries WHERE idx = ?", index
    ).toArray();
    if (!rows[0]) return null;
    return JSON.parse(rows[0].data) as LogEntry;
  }

  async getEntryByReceiptId(receiptId: string): Promise<LogEntry | null> {
    const rows = this.sql.exec<{ data: string }>(
      "SELECT data FROM entries WHERE receipt_id = ?", receiptId
    ).toArray();
    if (!rows[0]) return null;
    return JSON.parse(rows[0].data) as LogEntry;
  }

  async getEntries(offset: number, limit: number): Promise<LogEntry[]> {
    const rows = this.sql.exec<{ data: string }>(
      "SELECT data FROM entries ORDER BY idx LIMIT ? OFFSET ?", limit, offset
    ).toArray();
    return rows.map(r => JSON.parse(r.data) as LogEntry);
  }

  async appendLeaves(hashes: string[]): Promise<number> {
    const sizeRows = this.sql.exec<{ cnt: number }>("SELECT COUNT(*) as cnt FROM leaves").toArray();
    let currentSize = sizeRows[0]?.cnt ?? 0;
    for (const hash of hashes) {
      this.sql.exec("INSERT INTO leaves (idx, hash) VALUES (?, ?)", currentSize, hash);
      currentSize++;
    }
    return currentSize;
  }

  async storeTreeHead(head: SignedTreeHead): Promise<void> {
    this.sql.exec(
      "INSERT INTO tree_heads (tree_size, root_hash, timestamp, signature) VALUES (?, ?, ?, ?)",
      head.treeSize, head.rootHash, head.timestamp, head.signature
    );
  }

  async getTreeHeads(limit: number): Promise<SignedTreeHead[]> {
    const rows = this.sql.exec<{ tree_size: number; root_hash: string; timestamp: string; signature: string }>(
      "SELECT tree_size, root_hash, timestamp, signature FROM tree_heads ORDER BY id DESC LIMIT ?", limit
    ).toArray();
    return rows.map(r => ({
      treeSize: r.tree_size,
      rootHash: r.root_hash,
      timestamp: r.timestamp,
      signature: r.signature,
    }));
  }
}
