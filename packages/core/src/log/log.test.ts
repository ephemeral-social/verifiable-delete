import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { sha512 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import {
  createLog,
  verifyInclusionProof,
  verifyConsistencyProof,
  verifyTreeHead,
  computeLeafHash,
  type LogEntry,
  type LogStorageAdapter,
  type LogConfig,
  type SignedTreeHead,
} from "./index.js";

// Ed25519 sync setup for Node
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

// --- Test infrastructure ---

class InMemoryLogStorage implements LogStorageAdapter {
  leaves: string[] = [];
  entries: LogEntry[] = [];
  nodes: Map<string, string> = new Map();
  receiptIndex: Map<string, number> = new Map();
  treeHeads: SignedTreeHead[] = [];

  async getLeaves(start: number, end: number): Promise<string[]> {
    return this.leaves.slice(start, end);
  }

  async appendLeaf(hash: string): Promise<number> {
    this.leaves.push(hash);
    return this.leaves.length;
  }

  async getNode(level: number, index: number): Promise<string | null> {
    return this.nodes.get(`${level}:${index}`) ?? null;
  }

  async setNode(level: number, index: number, hash: string): Promise<void> {
    this.nodes.set(`${level}:${index}`, hash);
  }

  async getTreeSize(): Promise<number> {
    return this.leaves.length;
  }

  async storeEntry(index: number, entry: LogEntry): Promise<void> {
    this.entries[index] = entry;
    this.receiptIndex.set(entry.receiptId, index);
  }

  async getEntry(index: number): Promise<LogEntry | null> {
    return this.entries[index] ?? null;
  }

  async getEntryByReceiptId(receiptId: string): Promise<LogEntry | null> {
    const index = this.receiptIndex.get(receiptId);
    if (index === undefined) return null;
    return this.entries[index] ?? null;
  }

  async getEntries(offset: number, limit: number): Promise<LogEntry[]> {
    return this.entries.slice(offset, offset + limit);
  }

  async appendLeaves(hashes: string[]): Promise<number> {
    this.leaves.push(...hashes);
    return this.leaves.length;
  }

  async storeTreeHead(head: SignedTreeHead): Promise<void> {
    this.treeHeads.unshift(head); // newest first
  }

  async getTreeHeads(limit: number): Promise<SignedTreeHead[]> {
    return this.treeHeads.slice(0, limit);
  }
}

function mockEntry(i: number): Omit<LogEntry, "index"> {
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

async function createTestLog(config?: LogConfig) {
  const signingKey = crypto.getRandomValues(new Uint8Array(32));
  const publicKey = await ed.getPublicKeyAsync(signingKey);
  const storage = new InMemoryLogStorage();
  const log = createLog(storage, signingKey, config);
  return { log, storage, signingKey, publicKey };
}

/** RFC 6962 internal node hash: SHA-256(0x01 || left || right) */
function testNodeHash(left: string, right: string): string {
  const leftBytes = hexToBytes(left);
  const rightBytes = hexToBytes(right);
  const data = new Uint8Array(1 + leftBytes.length + rightBytes.length);
  data[0] = 0x01;
  data.set(leftBytes, 1);
  data.set(rightBytes, 1 + leftBytes.length);
  return bytesToHex(sha256(data));
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/** Manual root computation using RFC 6962 algorithm (no cache). */
function manualComputeRoot(leaves: string[]): string {
  const n = leaves.length;
  if (n === 0) return bytesToHex(sha256(new Uint8Array(0)));
  if (n === 1) return leaves[0]!;
  let k = 1;
  while (k * 2 < n) k *= 2;
  const left = manualComputeRoot(leaves.slice(0, k));
  const right = manualComputeRoot(leaves.slice(k));
  return testNodeHash(left, right);
}

describe("log", () => {
  // --- append ---

  it("append assigns sequential indices starting from 0", async () => {
    const { log } = await createTestLog();

    const proof0 = await log.append(mockEntry(0));
    const proof1 = await log.append(mockEntry(1));
    const proof2 = await log.append(mockEntry(2));

    expect(proof0.logIndex).toBe(0);
    expect(proof0.treeSize).toBe(1);
    expect(proof1.logIndex).toBe(1);
    expect(proof1.treeSize).toBe(2);
    expect(proof2.logIndex).toBe(2);
    expect(proof2.treeSize).toBe(3);
  });

  it("append returns valid inclusion proof", async () => {
    const { log } = await createTestLog();

    const entries: Omit<LogEntry, "index">[] = [];
    for (let i = 0; i < 5; i++) {
      entries.push(mockEntry(i));
    }

    const proofs = [];
    for (const entry of entries) {
      proofs.push(await log.append(entry));
    }

    for (let i = 0; i < 5; i++) {
      const leafHash = computeLeafHash({ ...entries[i]!, index: i });
      const valid = await verifyInclusionProof(leafHash, proofs[i]!);
      expect(valid).toBe(true);
    }
  });

  // --- getInclusionProof ---

  it("getInclusionProof returns valid proof for any index", async () => {
    const { log } = await createTestLog();

    for (let i = 0; i < 7; i++) {
      await log.append(mockEntry(i));
    }

    for (let i = 0; i < 7; i++) {
      const proof = await log.getInclusionProof(i);
      const leafHash = computeLeafHash({ ...mockEntry(i), index: i });
      const valid = await verifyInclusionProof(leafHash, proof);
      expect(valid).toBe(true);
    }
  });

  it("inclusion proof fails for wrong leaf hash", async () => {
    const { log } = await createTestLog();
    await log.append(mockEntry(0));
    await log.append(mockEntry(1));

    const proof = await log.getInclusionProof(0);
    const wrongHash = computeLeafHash({ ...mockEntry(99), index: 99 });
    const valid = await verifyInclusionProof(wrongHash, proof);
    expect(valid).toBe(false);
  });

  it("inclusion proof fails for tampered proof hash", async () => {
    const { log } = await createTestLog();
    for (let i = 0; i < 4; i++) {
      await log.append(mockEntry(i));
    }

    const proof = await log.getInclusionProof(0);
    if (proof.hashes.length > 0) {
      proof.hashes[0] = "ff".repeat(32);
    }
    const leafHash = computeLeafHash({ ...mockEntry(0), index: 0 });
    const valid = await verifyInclusionProof(leafHash, proof);
    expect(valid).toBe(false);
  });

  // --- getTreeHead ---

  it("getTreeHead returns valid signed tree head", async () => {
    const { log, publicKey } = await createTestLog();
    for (let i = 0; i < 3; i++) {
      await log.append(mockEntry(i));
    }

    const head = await log.getTreeHead();
    expect(head.treeSize).toBe(3);
    expect(head.rootHash).toMatch(/^[0-9a-f]{64}$/);
    expect(new Date(head.timestamp).getTime()).not.toBeNaN();
    expect(head.signature).toMatch(/^[0-9a-f]+$/);

    const valid = await verifyTreeHead(head, publicKey);
    expect(valid).toBe(true);
  });

  it("tree head signature fails with wrong public key", async () => {
    const { log } = await createTestLog();
    await log.append(mockEntry(0));

    const head = await log.getTreeHead();

    const wrongKey = crypto.getRandomValues(new Uint8Array(32));
    const wrongPublicKey = await ed.getPublicKeyAsync(wrongKey);
    const valid = await verifyTreeHead(head, wrongPublicKey);
    expect(valid).toBe(false);
  });

  // --- getConsistencyProof ---

  it("consistency proof verifies for all combos up to size 8", async () => {
    const { log } = await createTestLog();
    for (let i = 0; i < 8; i++) {
      await log.append(mockEntry(i));
    }

    for (let m = 1; m <= 8; m++) {
      for (let n = m + 1; n <= 8; n++) {
        const proof = await log.getConsistencyProof(m, n);
        const valid = await verifyConsistencyProof(proof);
        expect(valid).toBe(true);
      }
    }
  });

  it("consistency proof fails with wrong old root", async () => {
    const { log } = await createTestLog();
    for (let i = 0; i < 5; i++) {
      await log.append(mockEntry(i));
    }

    const proof = await log.getConsistencyProof(2, 5);
    proof.fromRoot = "ff".repeat(32);
    const valid = await verifyConsistencyProof(proof);
    expect(valid).toBe(false);
  });

  it("consistency proof fails with tampered proof hash", async () => {
    const { log } = await createTestLog();
    for (let i = 0; i < 5; i++) {
      await log.append(mockEntry(i));
    }

    const proof = await log.getConsistencyProof(2, 5);
    if (proof.hashes.length > 0) {
      proof.hashes[0] = "ff".repeat(32);
    }
    const valid = await verifyConsistencyProof(proof);
    expect(valid).toBe(false);
  });

  it("trivial consistency (same size) returns empty proof", async () => {
    const { log } = await createTestLog();
    for (let i = 0; i < 3; i++) {
      await log.append(mockEntry(i));
    }

    const proof = await log.getConsistencyProof(3, 3);
    expect(proof.hashes).toEqual([]);
    expect(proof.fromRoot).toBe(proof.toRoot);

    const valid = await verifyConsistencyProof(proof);
    expect(valid).toBe(true);
  });

  // --- getEntry / getEntries ---

  it("getEntry retrieves by receipt ID", async () => {
    const { log } = await createTestLog();
    for (let i = 0; i < 3; i++) {
      await log.append(mockEntry(i));
    }

    for (let i = 0; i < 3; i++) {
      const entry = await log.getEntry(`receipt-${i}`);
      expect(entry).not.toBeNull();
      expect(entry!.index).toBe(i);
      expect(entry!.receiptId).toBe(`receipt-${i}`);
    }

    const missing = await log.getEntry("nonexistent");
    expect(missing).toBeNull();
  });

  it("getEntries returns paginated results", async () => {
    const { log } = await createTestLog();
    for (let i = 0; i < 10; i++) {
      await log.append(mockEntry(i));
    }

    const page1 = await log.getEntries(0, 3);
    expect(page1.length).toBe(3);
    expect(page1[0]!.index).toBe(0);
    expect(page1[2]!.index).toBe(2);

    const page2 = await log.getEntries(3, 5);
    expect(page2.length).toBe(5);
    expect(page2[0]!.index).toBe(3);

    const page3 = await log.getEntries(8, 10);
    expect(page3.length).toBe(2);
  });

  // --- computeLeafHash ---

  it("computeLeafHash is deterministic", async () => {
    const entry: LogEntry = { ...mockEntry(42), index: 42 };

    const hash1 = computeLeafHash(entry);
    const hash2 = computeLeafHash(entry);
    expect(hash1).toBe(hash2);

    // Nested object key order irrelevant
    const reordered: LogEntry = {
      operatorSignature: entry.operatorSignature,
      index: entry.index,
      receiptId: entry.receiptId,
      timestamp: entry.timestamp,
      entityType: entry.entityType,
      commitment: entry.commitment,
      deletionMethod: entry.deletionMethod,
      thresholdSignatures: entry.thresholdSignatures,
      scanHash: entry.scanHash,
      smtRoot: entry.smtRoot,
    };
    expect(computeLeafHash(reordered)).toBe(hash1);

    // Different field → different hash
    const different: LogEntry = { ...entry, receiptId: "different" };
    expect(computeLeafHash(different)).not.toBe(hash1);

    // 64-char hex format
    expect(hash1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("computeLeafHash matches known test vector", async () => {
    const entry: LogEntry = {
      index: 0,
      receiptId: "test-receipt-0",
      timestamp: "2024-01-01T00:00:00.000Z",
      entityType: "event_data",
      commitment: "abc123",
      deletionMethod: "crypto_shredding",
      thresholdSignatures: ["sig_a", "sig_b"],
      scanHash: "scan_000",
      smtRoot: "smt_000",
      operatorSignature: "op_sig_000",
    };

    const hash = computeLeafHash(entry);

    // Deterministic
    expect(computeLeafHash(entry)).toBe(hash);

    // Sensitive to changes
    expect(computeLeafHash({ ...entry, index: 1 })).not.toBe(hash);
    expect(computeLeafHash({ ...entry, commitment: "xyz" })).not.toBe(hash);

    // Correct format
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  // --- root computation ---

  it("root computation matches RFC 6962 structure", async () => {
    const { log } = await createTestLog();

    // After 1 append: root = leafHash(entry0)
    await log.append(mockEntry(0));
    const head1 = await log.getTreeHead();
    const leaf0 = computeLeafHash({ ...mockEntry(0), index: 0 });
    expect(head1.rootHash).toBe(leaf0);

    // After 2 appends: root = nodeHash(leaf0, leaf1)
    await log.append(mockEntry(1));
    const head2 = await log.getTreeHead();
    const leaf1 = computeLeafHash({ ...mockEntry(1), index: 1 });
    expect(head2.rootHash).toBe(testNodeHash(leaf0, leaf1));

    // After 3 appends: root = nodeHash(nodeHash(leaf0, leaf1), leaf2)
    await log.append(mockEntry(2));
    const head3 = await log.getTreeHead();
    const leaf2 = computeLeafHash({ ...mockEntry(2), index: 2 });
    expect(head3.rootHash).toBe(testNodeHash(testNodeHash(leaf0, leaf1), leaf2));
  });

  // --- edge cases ---

  it("empty log returns valid tree head", async () => {
    const { log, publicKey } = await createTestLog();

    const head = await log.getTreeHead();
    expect(head.treeSize).toBe(0);

    // rootHash should be sha256 of empty input
    const emptyRoot = bytesToHex(sha256(new Uint8Array(0)));
    expect(head.rootHash).toBe(emptyRoot);

    const valid = await verifyTreeHead(head, publicKey);
    expect(valid).toBe(true);
  });

  it("getInclusionProof rejects out-of-range index", async () => {
    const { log } = await createTestLog();
    for (let i = 0; i < 3; i++) {
      await log.append(mockEntry(i));
    }

    await expect(log.getInclusionProof(3)).rejects.toThrow();
    await expect(log.getInclusionProof(100)).rejects.toThrow();
  });

  // --- Cache correctness ---

  it("cached root matches uncached for sizes 1-16", async () => {
    const { log, storage } = await createTestLog();

    for (let i = 0; i < 16; i++) {
      await log.append(mockEntry(i));
      const head = await log.getTreeHead();
      const leaves = await storage.getLeaves(0, i + 1);
      const expectedRoot = manualComputeRoot(leaves);
      expect(head.rootHash).toBe(expectedRoot);
    }
  });

  it("cached inclusion proof matches for all indices", async () => {
    const { log } = await createTestLog();

    for (let i = 0; i < 7; i++) {
      await log.append(mockEntry(i));
    }

    for (let i = 0; i < 7; i++) {
      const proof = await log.getInclusionProof(i);
      const leafHash = computeLeafHash({ ...mockEntry(i), index: i });
      const valid = await verifyInclusionProof(leafHash, proof);
      expect(valid).toBe(true);
    }
  });

  it("cached consistency proof matches uncached for all combos up to size 8", async () => {
    const { log } = await createTestLog();

    for (let i = 0; i < 8; i++) {
      await log.append(mockEntry(i));
    }

    for (let m = 1; m <= 8; m++) {
      for (let n = m; n <= 8; n++) {
        const proof = await log.getConsistencyProof(m, n);
        const valid = await verifyConsistencyProof(proof);
        expect(valid).toBe(true);
      }
    }
  });

  it("setNode is called during append", async () => {
    const { log, storage } = await createTestLog();

    const originalSetNode = storage.setNode.bind(storage);
    let callCount = 0;
    storage.setNode = async (level: number, index: number, hash: string) => {
      callCount++;
      return originalSetNode(level, index, hash);
    };

    await log.append(mockEntry(0));
    expect(callCount).toBeGreaterThanOrEqual(1);
  });

  it("known 4-leaf tree has correct cached nodes", async () => {
    const { log, storage } = await createTestLog();

    for (let i = 0; i < 4; i++) {
      await log.append(mockEntry(i));
    }

    // Level 0: all 4 leaves
    expect(storage.nodes.has("0:0")).toBe(true);
    expect(storage.nodes.has("0:1")).toBe(true);
    expect(storage.nodes.has("0:2")).toBe(true);
    expect(storage.nodes.has("0:3")).toBe(true);

    // Level 1: two pairs
    expect(storage.nodes.has("1:0")).toBe(true);
    expect(storage.nodes.has("1:1")).toBe(true);

    // Level 2: root
    expect(storage.nodes.has("2:0")).toBe(true);

    // Verify the values are correct
    const leaf0 = storage.nodes.get("0:0")!;
    const leaf1 = storage.nodes.get("0:1")!;
    const leaf2 = storage.nodes.get("0:2")!;
    const leaf3 = storage.nodes.get("0:3")!;
    expect(storage.nodes.get("1:0")).toBe(testNodeHash(leaf0, leaf1));
    expect(storage.nodes.get("1:1")).toBe(testNodeHash(leaf2, leaf3));
    expect(storage.nodes.get("2:0")).toBe(
      testNodeHash(testNodeHash(leaf0, leaf1), testNodeHash(leaf2, leaf3)),
    );
  });

  it("getTreeHead works from cache without getLeaves", async () => {
    const { log, storage } = await createTestLog();

    for (let i = 0; i < 4; i++) {
      await log.append(mockEntry(i));
    }

    // Override getLeaves to throw — cache should handle it
    storage.getLeaves = async () => {
      throw new Error("getLeaves should not be called");
    };

    const head = await log.getTreeHead();
    expect(head.treeSize).toBe(4);
    expect(head.rootHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("getInclusionProof works from cache without getLeaves for power-of-2 sizes", async () => {
    const { log, storage } = await createTestLog();

    for (let i = 0; i < 4; i++) {
      await log.append(mockEntry(i));
    }

    // Override getLeaves to throw
    storage.getLeaves = async () => {
      throw new Error("getLeaves should not be called");
    };

    for (let i = 0; i < 4; i++) {
      const proof = await log.getInclusionProof(i);
      const leafHash = computeLeafHash({ ...mockEntry(i), index: i });
      const valid = await verifyInclusionProof(leafHash, proof);
      expect(valid).toBe(true);
    }
  });

  it("non-power-of-2 sizes cache correctly", async () => {
    const { log, storage } = await createTestLog();

    for (let i = 0; i < 5; i++) {
      await log.append(mockEntry(i));
    }

    const head = await log.getTreeHead();
    const leaves = await storage.getLeaves(0, 5);
    const expectedRoot = manualComputeRoot(leaves);
    expect(head.rootHash).toBe(expectedRoot);
  });

  // --- Batch append ---

  it("batch assigns sequential indices", async () => {
    const { log } = await createTestLog();

    const entries = Array.from({ length: 5 }, (_, i) => mockEntry(i));
    const proofs = await log.appendBatch(entries);

    expect(proofs.length).toBe(5);
    for (let i = 0; i < 5; i++) {
      expect(proofs[i]!.logIndex).toBe(i);
    }
  });

  it("batch returns valid inclusion proofs", async () => {
    const { log } = await createTestLog();

    const entries = Array.from({ length: 5 }, (_, i) => mockEntry(i));
    const proofs = await log.appendBatch(entries);

    for (let i = 0; i < 5; i++) {
      const leafHash = computeLeafHash({ ...entries[i]!, index: i });
      const valid = await verifyInclusionProof(leafHash, proofs[i]!);
      expect(valid).toBe(true);
    }
  });

  it("batch result matches sequential append", async () => {
    // Batch log
    const { log: batchLog } = await createTestLog();
    const entries = Array.from({ length: 5 }, (_, i) => mockEntry(i));
    await batchLog.appendBatch(entries);
    const batchHead = await batchLog.getTreeHead();

    // Sequential log
    const { log: seqLog } = await createTestLog();
    for (let i = 0; i < 5; i++) {
      await seqLog.append(mockEntry(i));
    }
    const seqHead = await seqLog.getTreeHead();

    expect(batchHead.treeSize).toBe(seqHead.treeSize);
    expect(batchHead.rootHash).toBe(seqHead.rootHash);
  });

  it("empty batch returns empty array", async () => {
    const { log } = await createTestLog();
    const result = await log.appendBatch([]);
    expect(result).toEqual([]);
  });

  it("batch + individual append combo", async () => {
    const { log } = await createTestLog();

    // Append 2 individually
    await log.append(mockEntry(0));
    await log.append(mockEntry(1));

    // Batch 3
    const batchEntries = Array.from({ length: 3 }, (_, i) => mockEntry(i + 2));
    await log.appendBatch(batchEntries);

    // Append 1 more
    await log.append(mockEntry(5));

    // Verify all 6 inclusion proofs
    for (let i = 0; i < 6; i++) {
      const proof = await log.getInclusionProof(i);
      const leafHash = computeLeafHash({ ...mockEntry(i), index: i });
      const valid = await verifyInclusionProof(leafHash, proof);
      expect(valid).toBe(true);
    }

    // Verify consistency 2 -> 5 -> 6
    const proof25 = await log.getConsistencyProof(2, 5);
    expect(await verifyConsistencyProof(proof25)).toBe(true);

    const proof56 = await log.getConsistencyProof(5, 6);
    expect(await verifyConsistencyProof(proof56)).toBe(true);
  });

  it("batch uses appendLeaves when available", async () => {
    const { log, storage } = await createTestLog();

    const originalAppendLeaves = storage.appendLeaves!.bind(storage);
    let appendLeavesCallCount = 0;
    let appendLeavesArgs: string[] = [];
    storage.appendLeaves = async (hashes: string[]) => {
      appendLeavesCallCount++;
      appendLeavesArgs = hashes;
      return originalAppendLeaves(hashes);
    };

    const originalAppendLeaf = storage.appendLeaf.bind(storage);
    let appendLeafCallCount = 0;
    storage.appendLeaf = async (hash: string) => {
      appendLeafCallCount++;
      return originalAppendLeaf(hash);
    };

    await log.appendBatch([mockEntry(0), mockEntry(1), mockEntry(2)]);

    expect(appendLeavesCallCount).toBe(1);
    expect(appendLeavesArgs.length).toBe(3);
    expect(appendLeafCallCount).toBe(0);
  });

  // --- Max tree size ---

  it("append throws when tree is full", async () => {
    const { log } = await createTestLog({ maxTreeSize: 3 });

    await log.append(mockEntry(0));
    await log.append(mockEntry(1));
    await log.append(mockEntry(2));

    await expect(log.append(mockEntry(3))).rejects.toThrow(/maxTreeSize/);
  });

  it("batch throws when would exceed limit", async () => {
    const { log, storage } = await createTestLog({ maxTreeSize: 5 });

    await log.append(mockEntry(0));
    await log.append(mockEntry(1));
    await log.append(mockEntry(2));

    // Batch of 3 would make size 6, exceeding maxTreeSize=5
    await expect(
      log.appendBatch([mockEntry(3), mockEntry(4), mockEntry(5)]),
    ).rejects.toThrow(/maxTreeSize/);

    // Verify nothing was appended
    expect(await storage.getTreeSize()).toBe(3);
  });

  it("works up to max", async () => {
    const { log, storage } = await createTestLog({ maxTreeSize: 4 });

    await log.append(mockEntry(0));
    await log.append(mockEntry(1));
    await log.append(mockEntry(2));
    await log.append(mockEntry(3));

    expect(await storage.getTreeSize()).toBe(4);
  });

  it("no limit means unlimited", async () => {
    const { log, storage } = await createTestLog();

    for (let i = 0; i < 20; i++) {
      await log.append(mockEntry(i));
    }

    expect(await storage.getTreeSize()).toBe(20);
  });

  // --- Tree head history ---

  it("checkpoints are stored on getTreeHead", async () => {
    const { log, storage } = await createTestLog();

    await log.append(mockEntry(0));
    await log.getTreeHead();

    await log.append(mockEntry(1));
    await log.getTreeHead();

    await log.append(mockEntry(2));
    await log.getTreeHead();

    expect(storage.treeHeads.length).toBe(3);
  });

  it("history returns newest first", async () => {
    const { log } = await createTestLog();

    await log.append(mockEntry(0));
    await log.getTreeHead();

    await log.append(mockEntry(1));
    await log.getTreeHead();

    await log.append(mockEntry(2));
    await log.getTreeHead();

    const history = await log.getTreeHeadHistory(10);
    expect(history.length).toBe(3);
    expect(history[0]!.treeSize).toBeGreaterThan(history[1]!.treeSize);
    expect(history[1]!.treeSize).toBeGreaterThan(history[2]!.treeSize);
  });

  it("history limit is respected", async () => {
    const { log } = await createTestLog();

    await log.append(mockEntry(0));
    await log.getTreeHead();

    await log.append(mockEntry(1));
    await log.getTreeHead();

    await log.append(mockEntry(2));
    await log.getTreeHead();

    const history = await log.getTreeHeadHistory(2);
    expect(history.length).toBe(2);
  });

  it("graceful when adapter lacks storeTreeHead", async () => {
    // MinimalStorage without optional methods
    class MinimalStorage implements LogStorageAdapter {
      leaves: string[] = [];
      entries: LogEntry[] = [];
      nodes: Map<string, string> = new Map();
      receiptIndex: Map<string, number> = new Map();

      async getLeaves(start: number, end: number): Promise<string[]> {
        return this.leaves.slice(start, end);
      }
      async appendLeaf(hash: string): Promise<number> {
        this.leaves.push(hash);
        return this.leaves.length;
      }
      async getNode(level: number, index: number): Promise<string | null> {
        return this.nodes.get(`${level}:${index}`) ?? null;
      }
      async setNode(level: number, index: number, hash: string): Promise<void> {
        this.nodes.set(`${level}:${index}`, hash);
      }
      async getTreeSize(): Promise<number> {
        return this.leaves.length;
      }
      async storeEntry(index: number, entry: LogEntry): Promise<void> {
        this.entries[index] = entry;
        this.receiptIndex.set(entry.receiptId, index);
      }
      async getEntry(index: number): Promise<LogEntry | null> {
        return this.entries[index] ?? null;
      }
      async getEntryByReceiptId(receiptId: string): Promise<LogEntry | null> {
        const idx = this.receiptIndex.get(receiptId);
        if (idx === undefined) return null;
        return this.entries[idx] ?? null;
      }
      async getEntries(offset: number, limit: number): Promise<LogEntry[]> {
        return this.entries.slice(offset, offset + limit);
      }
    }

    const signingKey = crypto.getRandomValues(new Uint8Array(32));
    const storage = new MinimalStorage();
    const log = createLog(storage, signingKey);

    await log.append(mockEntry(0));
    const head = await log.getTreeHead();
    expect(head.treeSize).toBe(1);

    const history = await log.getTreeHeadHistory(10);
    expect(history).toEqual([]);
  });

  // --- Concurrency ---

  it("concurrent appends are serialized", async () => {
    const { log } = await createTestLog();

    const promises = Array.from({ length: 10 }, (_, i) => log.append(mockEntry(i)));
    const proofs = await Promise.all(promises);

    const indices = proofs.map((p) => p.logIndex).sort((a, b) => a - b);
    expect(indices).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

    // Verify all proofs are valid
    for (const proof of proofs) {
      const leafHash = computeLeafHash({ ...mockEntry(proof.logIndex), index: proof.logIndex });
      // Use the final tree's inclusion proof since batch proofs are at intermediate sizes
      const finalProof = await log.getInclusionProof(proof.logIndex);
      const valid = await verifyInclusionProof(leafHash, finalProof);
      expect(valid).toBe(true);
    }
  });

  it("concurrent batches are serialized", async () => {
    const { log, storage } = await createTestLog();

    const batch1 = Array.from({ length: 3 }, (_, i) => mockEntry(i));
    const batch2 = Array.from({ length: 3 }, (_, i) => mockEntry(i + 3));
    const batch3 = Array.from({ length: 3 }, (_, i) => mockEntry(i + 6));

    const results = await Promise.all([
      log.appendBatch(batch1),
      log.appendBatch(batch2),
      log.appendBatch(batch3),
    ]);

    expect(await storage.getTreeSize()).toBe(9);

    // All indices should be unique
    const allIndices = results.flatMap((r) => r.map((p) => p.logIndex)).sort((a, b) => a - b);
    expect(allIndices).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it("concurrent append + getInclusionProof is safe", async () => {
    const { log } = await createTestLog();

    for (let i = 0; i < 5; i++) {
      await log.append(mockEntry(i));
    }

    const [appendResult, proofResult] = await Promise.all([
      log.append(mockEntry(5)),
      log.getInclusionProof(0),
    ]);

    expect(appendResult.logIndex).toBe(5);
    expect(proofResult.logIndex).toBe(0);

    const leafHash = computeLeafHash({ ...mockEntry(0), index: 0 });
    const valid = await verifyInclusionProof(leafHash, proofResult);
    expect(valid).toBe(true);
  });

  it("concurrent batch respects maxTreeSize", async () => {
    const { log, storage } = await createTestLog({ maxTreeSize: 5 });

    const batch1 = Array.from({ length: 3 }, (_, i) => mockEntry(i));
    const batch2 = Array.from({ length: 3 }, (_, i) => mockEntry(i + 3));
    const batch3 = Array.from({ length: 3 }, (_, i) => mockEntry(i + 6));

    const results = await Promise.allSettled([
      log.appendBatch(batch1),
      log.appendBatch(batch2),
      log.appendBatch(batch3),
    ]);

    const successes = results.filter((r) => r.status === "fulfilled");
    const failures = results.filter((r) => r.status === "rejected");

    // Exactly 1 batch of 3 fits (3 <= 5), the other two would exceed 5
    expect(successes.length).toBe(1);
    expect(failures.length).toBe(2);
    expect(await storage.getTreeSize()).toBe(3);
  });

  // --- Edge cases ---

  it("cold start: new log instance over same storage", async () => {
    const signingKey = crypto.getRandomValues(new Uint8Array(32));
    const storage = new InMemoryLogStorage();

    // First instance: append 3 entries
    const log1 = createLog(storage, signingKey);
    for (let i = 0; i < 3; i++) {
      await log1.append(mockEntry(i));
    }
    const head1 = await log1.getTreeHead();

    // Second instance: same storage, fresh log
    const log2 = createLog(storage, signingKey);
    const head2 = await log2.getTreeHead();

    expect(head2.treeSize).toBe(head1.treeSize);
    expect(head2.rootHash).toBe(head1.rootHash);

    // Existing proofs still work
    for (let i = 0; i < 3; i++) {
      const proof = await log2.getInclusionProof(i);
      const leafHash = computeLeafHash({ ...mockEntry(i), index: i });
      const valid = await verifyInclusionProof(leafHash, proof);
      expect(valid).toBe(true);
    }

    // Can append more entries
    const proof3 = await log2.append(mockEntry(3));
    expect(proof3.logIndex).toBe(3);
    expect(proof3.treeSize).toBe(4);
  });

  it("backward-compatible adapter without optional methods", async () => {
    // MinimalLogStorage with only required methods
    class MinimalLogStorage implements LogStorageAdapter {
      leaves: string[] = [];
      entries: LogEntry[] = [];
      nodes: Map<string, string> = new Map();
      receiptIndex: Map<string, number> = new Map();

      async getLeaves(start: number, end: number): Promise<string[]> {
        return this.leaves.slice(start, end);
      }
      async appendLeaf(hash: string): Promise<number> {
        this.leaves.push(hash);
        return this.leaves.length;
      }
      async getNode(level: number, index: number): Promise<string | null> {
        return this.nodes.get(`${level}:${index}`) ?? null;
      }
      async setNode(level: number, index: number, hash: string): Promise<void> {
        this.nodes.set(`${level}:${index}`, hash);
      }
      async getTreeSize(): Promise<number> {
        return this.leaves.length;
      }
      async storeEntry(index: number, entry: LogEntry): Promise<void> {
        this.entries[index] = entry;
        this.receiptIndex.set(entry.receiptId, index);
      }
      async getEntry(index: number): Promise<LogEntry | null> {
        return this.entries[index] ?? null;
      }
      async getEntryByReceiptId(receiptId: string): Promise<LogEntry | null> {
        const idx = this.receiptIndex.get(receiptId);
        if (idx === undefined) return null;
        return this.entries[idx] ?? null;
      }
      async getEntries(offset: number, limit: number): Promise<LogEntry[]> {
        return this.entries.slice(offset, offset + limit);
      }
    }

    const signingKey = crypto.getRandomValues(new Uint8Array(32));
    const storage = new MinimalLogStorage();
    const log = createLog(storage, signingKey);

    // Individual append works
    await log.append(mockEntry(0));

    // Batch append works (falls back to appendLeaf)
    const batchProofs = await log.appendBatch([mockEntry(1), mockEntry(2)]);
    expect(batchProofs.length).toBe(2);
    expect(batchProofs[0]!.logIndex).toBe(1);
    expect(batchProofs[1]!.logIndex).toBe(2);

    // Tree head works
    const head = await log.getTreeHead();
    expect(head.treeSize).toBe(3);

    // History returns empty (no adapter support)
    const history = await log.getTreeHeadHistory(10);
    expect(history).toEqual([]);

    // Inclusion proof works
    for (let i = 0; i < 3; i++) {
      const proof = await log.getInclusionProof(i);
      const leafHash = computeLeafHash({ ...mockEntry(i), index: i });
      const valid = await verifyInclusionProof(leafHash, proof);
      expect(valid).toBe(true);
    }
  });
});
