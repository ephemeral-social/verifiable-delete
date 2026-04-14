/**
 * Append-only Merkle tree transparency log.
 *
 * Provides: append, batch append, inclusion proofs, consistency proofs,
 * signed tree heads, tree head history, max size enforcement, concurrency control.
 * Platform-agnostic: storage adapter interface for Durable Objects, SQLite, etc.
 *
 * @module log
 */

import { sha256 } from "@noble/hashes/sha2";
import { sha512 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as ed from "@noble/ed25519";
import { canonicalJSON } from "../utils.js";

// Ed25519 sync setup for Node
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

// --- Types ---

/** Configuration options for the transparency log. */
export interface LogConfig {
  /** Maximum number of entries allowed in the log. Unlimited if omitted. */
  maxTreeSize?: number;
}

/** A signed tree head representing the current state of the log. */
export interface SignedTreeHead {
  /** Number of entries in the log. */
  treeSize: number;
  /** SHA-256 root hash of the Merkle tree. */
  rootHash: string;
  /** ISO 8601 timestamp of this tree head. */
  timestamp: string;
  /** Ed25519 signature over (treeSize || rootHash || timestamp). */
  signature: string;
}

/** Merkle inclusion proof for a specific log entry. */
export interface InclusionProof {
  /** Index of the entry in the log. */
  logIndex: number;
  /** Tree size at time of proof generation. */
  treeSize: number;
  /** Root hash at time of proof generation. */
  rootHash: string;
  /** Sibling hashes from leaf to root. */
  hashes: string[];
}

/** Consistency proof between two tree sizes. */
export interface ConsistencyProof {
  /** The smaller tree size. */
  fromSize: number;
  /** The larger tree size. */
  toSize: number;
  /** Root hash of the smaller tree. */
  fromRoot: string;
  /** Root hash of the larger tree. */
  toRoot: string;
  /** Proof hashes demonstrating consistency. */
  hashes: string[];
}

/** A blinded log entry as it appears in the public log. */
export interface LogEntry {
  /** Sequential index in the log. */
  index: number;
  /** Receipt ID (random UUID). */
  receiptId: string;
  /** ISO 8601 deletion timestamp. */
  timestamp: string;
  /** General entity type (e.g. "event_data", "user_rsvp"). */
  entityType: string;
  /** SHA256(entityType || entityId || salt), hiding identity. */
  commitment: string;
  /** Description of deletion method. */
  deletionMethod: string;
  /** Threshold attestation signatures (hex encoded). */
  thresholdSignatures: string[];
  /** SHA-256 hash of the scan result document. */
  scanHash: string;
  /** SMT root hash at time of deletion. */
  smtRoot: string;
  /** Ed25519 signature over this entry by the operator. */
  operatorSignature: string;
}

/**
 * Storage adapter interface.
 * Implement this for your platform (Durable Objects, SQLite, PostgreSQL, etc).
 */
export interface LogStorageAdapter {
  /** Read a range of leaf hashes. */
  getLeaves(start: number, end: number): Promise<string[]>;
  /** Append a new leaf hash. Returns the new tree size. */
  appendLeaf(hash: string): Promise<number>;
  /** Read a node hash at the given level and index. */
  getNode(level: number, index: number): Promise<string | null>;
  /** Write a node hash at the given level and index. */
  setNode(level: number, index: number, hash: string): Promise<void>;
  /** Get the current tree size. */
  getTreeSize(): Promise<number>;
  /** Store a log entry by index. */
  storeEntry(index: number, entry: LogEntry): Promise<void>;
  /** Retrieve a log entry by index. */
  getEntry(index: number): Promise<LogEntry | null>;
  /** Retrieve a log entry by receipt ID. */
  getEntryByReceiptId(receiptId: string): Promise<LogEntry | null>;
  /** Retrieve a range of entries (for pagination). */
  getEntries(offset: number, limit: number): Promise<LogEntry[]>;

  // --- Optional methods (existing adapters still work without these) ---

  /** Append multiple leaf hashes at once. Returns the new tree size. */
  appendLeaves?(hashes: string[]): Promise<number>;
  /** Persist a signed tree head for history. */
  storeTreeHead?(head: SignedTreeHead): Promise<void>;
  /** Retrieve past signed tree heads, newest first. */
  getTreeHeads?(limit: number): Promise<SignedTreeHead[]>;
}

// --- Internal helpers ---

/** RFC 6962 leaf hash: SHA-256(0x00 || data) */
function leafHash(data: Uint8Array): string {
  const prefixed = new Uint8Array(1 + data.length);
  prefixed[0] = 0x00;
  prefixed.set(data, 1);
  return bytesToHex(sha256(prefixed));
}

/** RFC 6962 internal node hash: SHA-256(0x01 || left || right) */
function nodeHash(left: string, right: string): string {
  const leftBytes = hexToBytes(left);
  const rightBytes = hexToBytes(right);
  const data = new Uint8Array(1 + leftBytes.length + rightBytes.length);
  data[0] = 0x01;
  data.set(leftBytes, 1);
  data.set(rightBytes, 1 + leftBytes.length);
  return bytesToHex(sha256(data));
}

/** Largest power of 2 less than n. */
function largestPow2LessThan(n: number): number {
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

/** Check if n is a power of 2. */
function isPowerOf2(n: number): boolean {
  return n > 0 && (n & (n - 1)) === 0;
}


/** Domain-separated message for tree head signing. */
function treeHeadMessage(treeSize: number, rootHash: string, timestamp: string): Uint8Array {
  const msg = `vd-tree-head-v1:${treeSize}:${rootHash}:${timestamp}`;
  return new TextEncoder().encode(msg);
}

// --- Cache-aware internal helpers ---

/**
 * Cache-aware subtree hash computation. O(log n) when cache is populated.
 *
 * For perfect power-of-2 subtrees, checks the node cache first.
 * For non-power-of-2 subtrees, splits at largestPow2LessThan and recurses.
 */
async function computeSubtreeHash(
  storage: LogStorageAdapter,
  start: number,
  count: number,
): Promise<string> {
  if (count === 0) {
    return bytesToHex(sha256(new Uint8Array(0)));
  }
  if (count === 1) {
    // Level 0 node = leaf hash
    const cached = await storage.getNode(0, start);
    if (cached !== null) return cached;
    const leaves = await storage.getLeaves(start, start + 1);
    return leaves[0]!;
  }
  // For perfect power-of-2 subtrees, check cache
  if (isPowerOf2(count)) {
    const level = Math.log2(count);
    const index = start / count;
    const cached = await storage.getNode(level, index);
    if (cached !== null) return cached;
  }
  const k = largestPow2LessThan(count);
  const left = await computeSubtreeHash(storage, start, k);
  const right = await computeSubtreeHash(storage, start + k, count - k);
  return nodeHash(left, right);
}

/**
 * After appending a leaf, walk up and cache perfect binary subtree roots.
 *
 * Level 0: always cache the leaf hash itself.
 * Level L (L>=1): cache (L, leafIndex >> L) when (leafIndex+1) % 2^L === 0,
 * meaning a complete perfect subtree of size 2^L just finished.
 */
async function updateCachedNodes(
  storage: LogStorageAdapter,
  leafIndex: number,
  leafHash: string,
): Promise<void> {
  // Cache the leaf itself at level 0
  await storage.setNode(0, leafIndex, leafHash);

  let level = 1;
  while ((leafIndex + 1) % (1 << level) === 0) {
    const nodeIndex = leafIndex >> level;
    const left = await storage.getNode(level - 1, nodeIndex * 2);
    const right = await storage.getNode(level - 1, nodeIndex * 2 + 1);
    if (left === null || right === null) break;
    await storage.setNode(level, nodeIndex, nodeHash(left, right));
    level++;
  }
}

/** Cache-aware inclusion path computation. */
async function computeCachedInclusionPath(
  storage: LogStorageAdapter,
  index: number,
  start: number,
  count: number,
): Promise<string[]> {
  if (count <= 1) return [];
  const k = largestPow2LessThan(count);
  if (index < k) {
    const path = await computeCachedInclusionPath(storage, index, start, k);
    path.push(await computeSubtreeHash(storage, start + k, count - k));
    return path;
  } else {
    const path = await computeCachedInclusionPath(storage, index - k, start + k, count - k);
    path.push(await computeSubtreeHash(storage, start, k));
    return path;
  }
}

/** Cache-aware consistency path computation. */
async function computeCachedConsistencyPath(
  storage: LogStorageAdapter,
  m: number,
  start: number,
  count: number,
  isStart: boolean,
): Promise<string[]> {
  if (m === count) {
    if (isStart) return [];
    return [await computeSubtreeHash(storage, start, count)];
  }
  if (m === 0) return [];
  const k = largestPow2LessThan(count);
  if (m <= k) {
    const path = await computeCachedConsistencyPath(storage, m, start, k, isStart);
    path.push(await computeSubtreeHash(storage, start + k, count - k));
    return path;
  } else {
    const path = await computeCachedConsistencyPath(storage, m - k, start + k, count - k, false);
    path.push(await computeSubtreeHash(storage, start, k));
    return path;
  }
}

// --- AsyncMutex for single-writer concurrency control ---

class AsyncMutex {
  private queue: (() => void)[] = [];
  private locked = false;

  async acquire(): Promise<void> {
    if (!this.locked) {
      this.locked = true;
      return;
    }
    return new Promise<void>((resolve) => {
      this.queue.push(resolve);
    });
  }

  release(): void {
    if (this.queue.length > 0) {
      const next = this.queue.shift()!;
      next();
    } else {
      this.locked = false;
    }
  }
}

// --- Exported functions ---

/**
 * Compute the leaf hash for a log entry.
 * Uses canonical JSON serialization + RFC 6962 leaf hash (0x00 prefix).
 */
export function computeLeafHash(entry: LogEntry): string {
  const json = canonicalJSON(entry);
  const data = new TextEncoder().encode(json);
  return leafHash(data);
}

/** The transparency log interface. */
export interface TransparencyLog {
  /** Append a deletion event to the log. Returns the inclusion proof. */
  append(entry: Omit<LogEntry, "index">): Promise<InclusionProof>;

  /** Append multiple deletion events in one call. Returns inclusion proofs for all. */
  appendBatch(entries: Omit<LogEntry, "index">[]): Promise<InclusionProof[]>;

  /** Get the current signed tree head. */
  getTreeHead(): Promise<SignedTreeHead>;

  /** Retrieve past signed tree heads, newest first. Returns [] if adapter lacks support. */
  getTreeHeadHistory(limit: number): Promise<SignedTreeHead[]>;

  /** Generate an inclusion proof for a specific entry. */
  getInclusionProof(index: number): Promise<InclusionProof>;

  /** Generate a consistency proof between two tree sizes. */
  getConsistencyProof(fromSize: number, toSize: number): Promise<ConsistencyProof>;

  /** Retrieve a log entry by receipt ID. */
  getEntry(receiptId: string): Promise<LogEntry | null>;

  /** Retrieve paginated entries. */
  getEntries(offset: number, limit: number): Promise<LogEntry[]>;
}

/**
 * Create a new transparency log instance.
 */
export function createLog(
  storage: LogStorageAdapter,
  signingKey: Uint8Array,
  config?: LogConfig,
): TransparencyLog {
  const mutex = new AsyncMutex();
  const maxTreeSize = config?.maxTreeSize;

  return {
    async append(entry: Omit<LogEntry, "index">): Promise<InclusionProof> {
      await mutex.acquire();
      try {
        const size = await storage.getTreeSize();

        if (maxTreeSize !== undefined && size >= maxTreeSize) {
          throw new Error(`Tree is full (maxTreeSize=${maxTreeSize})`);
        }

        const fullEntry: LogEntry = { ...entry, index: size };
        const hash = computeLeafHash(fullEntry);
        await storage.appendLeaf(hash);
        await storage.storeEntry(size, fullEntry);
        await updateCachedNodes(storage, size, hash);

        const newSize = size + 1;
        const rootHash = await computeSubtreeHash(storage, 0, newSize);
        const hashes = await computeCachedInclusionPath(storage, size, 0, newSize);

        return {
          logIndex: size,
          treeSize: newSize,
          rootHash,
          hashes,
        };
      } finally {
        mutex.release();
      }
    },

    async appendBatch(entries: Omit<LogEntry, "index">[]): Promise<InclusionProof[]> {
      if (entries.length === 0) return [];

      await mutex.acquire();
      try {
        const startSize = await storage.getTreeSize();

        if (maxTreeSize !== undefined && startSize + entries.length > maxTreeSize) {
          throw new Error(
            `Batch of ${entries.length} would exceed maxTreeSize=${maxTreeSize} (current size=${startSize})`,
          );
        }

        // Append all leaves
        const hashes: string[] = [];
        const fullEntries: LogEntry[] = [];
        for (let i = 0; i < entries.length; i++) {
          const fullEntry: LogEntry = { ...entries[i]!, index: startSize + i };
          fullEntries.push(fullEntry);
          hashes.push(computeLeafHash(fullEntry));
        }

        if (storage.appendLeaves) {
          await storage.appendLeaves(hashes);
        } else {
          for (const hash of hashes) {
            await storage.appendLeaf(hash);
          }
        }

        // Store entries and update cache for each leaf
        for (let i = 0; i < fullEntries.length; i++) {
          await storage.storeEntry(startSize + i, fullEntries[i]!);
          await updateCachedNodes(storage, startSize + i, hashes[i]!);
        }

        // Compute proofs for all appended entries
        const newSize = startSize + entries.length;
        const rootHash = await computeSubtreeHash(storage, 0, newSize);
        const proofs: InclusionProof[] = [];
        for (let i = 0; i < entries.length; i++) {
          const idx = startSize + i;
          const pathHashes = await computeCachedInclusionPath(storage, idx, 0, newSize);
          proofs.push({
            logIndex: idx,
            treeSize: newSize,
            rootHash,
            hashes: pathHashes,
          });
        }

        return proofs;
      } finally {
        mutex.release();
      }
    },

    async getTreeHead(): Promise<SignedTreeHead> {
      const size = await storage.getTreeSize();
      const rootHash = await computeSubtreeHash(storage, 0, size);
      const timestamp = new Date().toISOString();
      const msg = treeHeadMessage(size, rootHash, timestamp);
      const signature = bytesToHex(await ed.signAsync(msg, signingKey));

      const head: SignedTreeHead = { treeSize: size, rootHash, timestamp, signature };

      // Checkpoint if adapter supports it
      if (storage.storeTreeHead) {
        await storage.storeTreeHead(head);
      }

      return head;
    },

    async getTreeHeadHistory(limit: number): Promise<SignedTreeHead[]> {
      if (storage.getTreeHeads) {
        return storage.getTreeHeads(limit);
      }
      return [];
    },

    async getInclusionProof(index: number): Promise<InclusionProof> {
      const size = await storage.getTreeSize();
      if (index < 0 || index >= size) {
        throw new Error(`Index ${index} out of range [0, ${size})`);
      }
      const rootHash = await computeSubtreeHash(storage, 0, size);
      const hashes = await computeCachedInclusionPath(storage, index, 0, size);

      return { logIndex: index, treeSize: size, rootHash, hashes };
    },

    async getConsistencyProof(fromSize: number, toSize: number): Promise<ConsistencyProof> {
      const size = await storage.getTreeSize();
      if (fromSize < 0 || toSize > size || fromSize > toSize) {
        throw new Error(`Invalid range [${fromSize}, ${toSize}] for tree of size ${size}`);
      }

      const fromRoot = fromSize === 0
        ? bytesToHex(sha256(new Uint8Array(0)))
        : await computeSubtreeHash(storage, 0, fromSize);
      const toRoot = toSize === 0
        ? bytesToHex(sha256(new Uint8Array(0)))
        : await computeSubtreeHash(storage, 0, toSize);

      if (fromSize === toSize) {
        return { fromSize, toSize, fromRoot, toRoot, hashes: [] };
      }
      if (fromSize === 0) {
        return { fromSize, toSize, fromRoot, toRoot, hashes: [] };
      }

      const hashes = await computeCachedConsistencyPath(storage, fromSize, 0, toSize, true);
      return { fromSize, toSize, fromRoot, toRoot, hashes };
    },

    async getEntry(receiptId: string): Promise<LogEntry | null> {
      return storage.getEntryByReceiptId(receiptId);
    },

    async getEntries(offset: number, limit: number): Promise<LogEntry[]> {
      return storage.getEntries(offset, limit);
    },
  };
}

/**
 * Verify a Merkle inclusion proof.
 * Platform-agnostic: can be run by any verifier.
 */
export async function verifyInclusionProof(
  leafHashValue: string,
  proof: InclusionProof,
): Promise<boolean> {
  const { logIndex, treeSize, rootHash, hashes } = proof;

  if (treeSize === 0) return false;
  if (logIndex >= treeSize) return false;

  if (treeSize === 1 && hashes.length === 0) {
    return leafHashValue === rootHash;
  }

  // Determine split directions top-down (true = left subtree, false = right)
  const directions: boolean[] = [];
  let idx = logIndex;
  let sz = treeSize;
  while (sz > 1) {
    const k = largestPow2LessThan(sz);
    if (idx < k) {
      directions.push(true); // in left subtree, sibling is right
      sz = k;
    } else {
      directions.push(false); // in right subtree, sibling is left
      idx -= k;
      sz -= k;
    }
  }

  // Path hashes are bottom-to-top, directions are top-to-bottom — reverse
  directions.reverse();

  if (directions.length !== hashes.length) return false;

  let currentHash = leafHashValue;
  for (let i = 0; i < directions.length; i++) {
    if (directions[i]) {
      // We were in left subtree: nodeHash(current, sibling)
      currentHash = nodeHash(currentHash, hashes[i]!);
    } else {
      // We were in right subtree: nodeHash(sibling, current)
      currentHash = nodeHash(hashes[i]!, currentHash);
    }
  }

  return currentHash === rootHash;
}

/**
 * Verify a consistency proof between two tree heads.
 * Uses RFC 9162 §2.1.4.2 iterative verification with unsigned right shift (>>>).
 */
export async function verifyConsistencyProof(
  proof: ConsistencyProof,
): Promise<boolean> {
  const { fromSize, toSize, fromRoot, toRoot, hashes } = proof;

  if (fromSize === 0) {
    return hashes.length === 0;
  }

  if (fromSize === toSize) {
    return hashes.length === 0 && fromRoot === toRoot;
  }

  if (fromSize > toSize) return false;

  // RFC 9162 §2.1.4.2: when fromSize is a power of 2, prepend fromRoot
  // because SUBPROOF(m, D[n], true) omits the old root when m is a power of 2
  let path: string[];
  if (isPowerOf2(fromSize)) {
    path = [fromRoot, ...hashes];
  } else {
    path = [...hashes];
  }

  if (path.length === 0) return false;

  let fn = fromSize - 1;
  let sn = toSize - 1;

  // Step 2: strip common low bits while LSB(fn) is set
  while ((fn & 1) === 1) {
    fn = fn >>> 1;
    sn = sn >>> 1;
  }

  // Step 3: initialize fr and sr from first path element
  let fr = path[0]!;
  let sr = path[0]!;

  // Step 4: iterate over remaining path elements
  for (let i = 1; i < path.length; i++) {
    const c = path[i]!;

    // 4a
    if (sn === 0) return false;

    // 4b
    if ((fn & 1) === 1 || fn === sn) {
      // 4b-i, 4b-ii
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      // 4b-iii: while fn is non-zero and LSB(fn) is not set
      while (fn !== 0 && (fn & 1) === 0) {
        fn = fn >>> 1;
        sn = sn >>> 1;
      }
    } else {
      // 4b-iv
      sr = nodeHash(sr, c);
    }

    // 4c
    fn = fn >>> 1;
    sn = sn >>> 1;
  }

  // Step 5
  return sn === 0 && fr === fromRoot && sr === toRoot;
}

/**
 * Verify a signed tree head.
 */
export async function verifyTreeHead(
  treeHead: SignedTreeHead,
  publicKey: Uint8Array,
): Promise<boolean> {
  const msg = treeHeadMessage(treeHead.treeSize, treeHead.rootHash, treeHead.timestamp);
  const sigBytes = hexToBytes(treeHead.signature);
  try {
    return await ed.verifyAsync(sigBytes, msg, publicKey);
  } catch {
    return false;
  }
}
