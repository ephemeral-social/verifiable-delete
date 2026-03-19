/**
 * Append-only Merkle tree transparency log.
 *
 * Provides: append, inclusion proofs, consistency proofs, signed tree heads.
 * Platform-agnostic: storage adapter interface for Durable Objects, SQLite, etc.
 *
 * @module log
 */

// --- Types ---

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
}

// --- Functions ---

/**
 * Create a new transparency log instance.
 */
export function createLog(
  _storage: LogStorageAdapter,
  _signingKey: Uint8Array,
): TransparencyLog {
  throw new Error("Not implemented");
}

/** The transparency log interface. */
export interface TransparencyLog {
  /** Append a deletion event to the log. Returns the inclusion proof. */
  append(entry: Omit<LogEntry, "index">): Promise<InclusionProof>;

  /** Get the current signed tree head. */
  getTreeHead(): Promise<SignedTreeHead>;

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
 * Verify a Merkle inclusion proof.
 * Platform-agnostic: can be run by any verifier.
 */
export async function verifyInclusionProof(
  _leafHash: string,
  _proof: InclusionProof,
): Promise<boolean> {
  throw new Error("Not implemented");
}

/**
 * Verify a consistency proof between two tree heads.
 */
export async function verifyConsistencyProof(
  _proof: ConsistencyProof,
): Promise<boolean> {
  throw new Error("Not implemented");
}

/**
 * Verify a signed tree head.
 */
export async function verifyTreeHead(
  _treeHead: SignedTreeHead,
  _publicKey: Uint8Array,
): Promise<boolean> {
  throw new Error("Not implemented");
}
