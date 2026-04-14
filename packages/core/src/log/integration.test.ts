/**
 * Integration test: crypto → threshold → log
 *
 * Exercises the real end-to-end flow:
 * 1. Generate KEK, encrypt data
 * 2. Split key via threshold, create destruction attestations
 * 3. Log the deletion event to the transparency log
 * 4. Verify inclusion proof, tree head, and consistency after multiple deletions
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { sha512 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

import {
  generateKEK,
  encrypt,
  decrypt,
  exportKeyMaterial,
  verifyKeyDestruction,
} from "../crypto/index.js";
import {
  splitKey,
  createDestructionAttestation,
  verifyDestructionAttestation,
  verifyThresholdDestruction,
  type ShareHolder,
  type ThresholdConfig,
} from "../threshold/index.js";
import {
  createLog,
  verifyInclusionProof,
  verifyConsistencyProof,
  verifyTreeHead,
  computeLeafHash,
  type LogEntry,
  type LogStorageAdapter,
  type SignedTreeHead,
} from "./index.js";

// Ed25519 sync setup for Node
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

// --- In-memory storage (same as unit tests) ---

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

async function createTestHolder(
  label: string,
): Promise<{ holder: ShareHolder; privateKey: Uint8Array }> {
  const privateKey = crypto.getRandomValues(new Uint8Array(32));
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return {
    holder: { id: crypto.randomUUID(), label, publicKey },
    privateKey,
  };
}

describe("integration: crypto → threshold → log", () => {
  it("full deletion lifecycle: encrypt, split, attest, log, verify", async () => {
    // --- Phase 1: Crypto — generate KEK and encrypt data ---
    const kek = await generateKEK();
    const plaintext = new TextEncoder().encode("sensitive user event data");
    const blob = await encrypt(plaintext, kek, "event-123");

    // Verify data is accessible before deletion
    const decrypted = await decrypt(blob, kek);
    expect(new TextDecoder().decode(decrypted)).toBe("sensitive user event data");

    // --- Phase 2: Threshold — split key and create destruction attestations ---
    const keyMaterial = await exportKeyMaterial(kek);
    const [h1, h2, h3] = await Promise.all([
      createTestHolder("operator"),
      createTestHolder("oracle"),
      createTestHolder("auditor"),
    ]);
    const config: ThresholdConfig = {
      totalShares: 3,
      threshold: 2,
      holders: [h1.holder, h2.holder, h3.holder],
    };
    const { shares } = await splitKey(keyMaterial, kek.id, config);

    // Simulate share destruction: operator and oracle destroy their shares
    const att1 = await createDestructionAttestation(
      kek.id,
      shares[0].index,
      h1.holder,
      h1.privateKey,
    );
    const att2 = await createDestructionAttestation(
      kek.id,
      shares[1].index,
      h2.holder,
      h2.privateKey,
    );

    // Verify individual attestations
    expect(await verifyDestructionAttestation(att1)).toBe(true);
    expect(await verifyDestructionAttestation(att2)).toBe(true);

    // Verify threshold destruction (2 of 3)
    expect(await verifyThresholdDestruction([att1, att2], 2)).toBe(true);

    // Verify key is "destroyed" (using a different key simulates destruction)
    const wrongKek = await generateKEK();
    expect(await verifyKeyDestruction(blob, wrongKek)).toBe(true);

    // --- Phase 3: Log — record deletion in transparency log ---
    const logSigningKey = crypto.getRandomValues(new Uint8Array(32));
    const logPublicKey = await ed.getPublicKeyAsync(logSigningKey);
    const storage = new InMemoryLogStorage();
    const log = createLog(storage, logSigningKey);

    // Build a log entry from the deletion event
    const commitment = bytesToHex(
      sha256(new TextEncoder().encode(`event_data||event-123||${crypto.randomUUID()}`)),
    );
    const logEntry: Omit<LogEntry, "index"> = {
      receiptId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      entityType: "event_data",
      commitment,
      deletionMethod: "crypto_shredding_2of3",
      thresholdSignatures: [
        bytesToHex(att1.signature),
        bytesToHex(att2.signature),
      ],
      scanHash: bytesToHex(sha256(new TextEncoder().encode("scan-clean"))),
      smtRoot: bytesToHex(sha256(new TextEncoder().encode("smt-root"))),
      operatorSignature: bytesToHex(att1.signature), // operator's attestation doubles as operator sig
    };

    const inclusionProof = await log.append(logEntry);

    // Verify inclusion
    expect(inclusionProof.logIndex).toBe(0);
    expect(inclusionProof.treeSize).toBe(1);

    const fullEntry: LogEntry = { ...logEntry, index: 0 };
    const leafHash = computeLeafHash(fullEntry);
    expect(await verifyInclusionProof(leafHash, inclusionProof)).toBe(true);

    // Verify tree head
    const head = await log.getTreeHead();
    expect(head.treeSize).toBe(1);
    expect(await verifyTreeHead(head, logPublicKey)).toBe(true);

    // Retrieve by receipt ID
    const retrieved = await log.getEntry(logEntry.receiptId);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.entityType).toBe("event_data");
    expect(retrieved!.commitment).toBe(commitment);
  });

  it("multiple deletions with consistency proof across modules", async () => {
    const logSigningKey = crypto.getRandomValues(new Uint8Array(32));
    const logPublicKey = await ed.getPublicKeyAsync(logSigningKey);
    const storage = new InMemoryLogStorage();
    const log = createLog(storage, logSigningKey);

    const holders = await Promise.all([
      createTestHolder("operator"),
      createTestHolder("oracle"),
      createTestHolder("auditor"),
    ]);
    const config: ThresholdConfig = {
      totalShares: 3,
      threshold: 2,
      holders: holders.map((h) => h.holder),
    };

    // Delete 3 entities, each with its own KEK
    const proofs = [];
    for (let i = 0; i < 3; i++) {
      const kek = await generateKEK();
      const data = new TextEncoder().encode(`entity-${i}-data`);
      await encrypt(data, kek, `entity-${i}`);

      const keyMaterial = await exportKeyMaterial(kek);
      const { shares } = await splitKey(keyMaterial, kek.id, config);

      // Create attestations from operator + oracle
      const att1 = await createDestructionAttestation(
        kek.id,
        shares[0].index,
        holders[0].holder,
        holders[0].privateKey,
      );
      const att2 = await createDestructionAttestation(
        kek.id,
        shares[1].index,
        holders[1].holder,
        holders[1].privateKey,
      );

      expect(await verifyThresholdDestruction([att1, att2], 2)).toBe(true);

      const entry: Omit<LogEntry, "index"> = {
        receiptId: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        entityType: "user_data",
        commitment: bytesToHex(
          sha256(new TextEncoder().encode(`user_data||entity-${i}||salt-${i}`)),
        ),
        deletionMethod: "crypto_shredding_2of3",
        thresholdSignatures: [
          bytesToHex(att1.signature),
          bytesToHex(att2.signature),
        ],
        scanHash: bytesToHex(sha256(new TextEncoder().encode(`scan-${i}`))),
        smtRoot: bytesToHex(sha256(new TextEncoder().encode(`smt-${i}`))),
        operatorSignature: bytesToHex(att1.signature),
      };

      proofs.push(await log.append(entry));
    }

    // All 3 inclusion proofs should verify against current tree
    for (let i = 0; i < 3; i++) {
      const currentProof = await log.getInclusionProof(i);
      const storedEntry = (await log.getEntries(i, 1))[0]!;
      const leafHash = computeLeafHash(storedEntry);
      expect(await verifyInclusionProof(leafHash, currentProof)).toBe(true);
    }

    // Tree head for size 3 should verify
    const head3 = await log.getTreeHead();
    expect(head3.treeSize).toBe(3);
    expect(await verifyTreeHead(head3, logPublicKey)).toBe(true);

    // Consistency: tree grew from 1→3, 2→3 should all be consistent
    const consistency1to3 = await log.getConsistencyProof(1, 3);
    expect(await verifyConsistencyProof(consistency1to3)).toBe(true);

    const consistency2to3 = await log.getConsistencyProof(2, 3);
    expect(await verifyConsistencyProof(consistency2to3)).toBe(true);

    // Add one more deletion and verify consistency 3→4
    const extraKek = await generateKEK();
    const extraMaterial = await exportKeyMaterial(extraKek);
    const { shares: extraShares } = await splitKey(extraMaterial, extraKek.id, config);
    const extraAtt = await createDestructionAttestation(
      extraKek.id,
      extraShares[0].index,
      holders[0].holder,
      holders[0].privateKey,
    );
    const extraAtt2 = await createDestructionAttestation(
      extraKek.id,
      extraShares[2].index,
      holders[2].holder,
      holders[2].privateKey,
    );

    await log.append({
      receiptId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      entityType: "event_rsvp",
      commitment: bytesToHex(sha256(new TextEncoder().encode("rsvp-commit"))),
      deletionMethod: "crypto_shredding_2of3",
      thresholdSignatures: [
        bytesToHex(extraAtt.signature),
        bytesToHex(extraAtt2.signature),
      ],
      scanHash: bytesToHex(sha256(new TextEncoder().encode("scan-extra"))),
      smtRoot: bytesToHex(sha256(new TextEncoder().encode("smt-extra"))),
      operatorSignature: bytesToHex(extraAtt.signature),
    });

    const consistency3to4 = await log.getConsistencyProof(3, 4);
    expect(await verifyConsistencyProof(consistency3to4)).toBe(true);

    const head4 = await log.getTreeHead();
    expect(head4.treeSize).toBe(4);
    expect(await verifyTreeHead(head4, logPublicKey)).toBe(true);
  });
});

// --- Helper: build a log entry from real crypto + threshold flow ---

async function buildLogEntryFromCrypto(
  holders: { holder: ShareHolder; privateKey: Uint8Array }[],
  config: ThresholdConfig,
  entityIndex: number,
): Promise<{
  entry: Omit<LogEntry, "index">;
}> {
  const kek = await generateKEK();
  const data = new TextEncoder().encode(`entity-${entityIndex}-data`);
  await encrypt(data, kek, `entity-${entityIndex}`);

  const keyMaterial = await exportKeyMaterial(kek);
  const { shares } = await splitKey(keyMaterial, kek.id, config);

  // Create attestations from first 2 holders (operator + oracle)
  const att1 = await createDestructionAttestation(
    kek.id,
    shares[0]!.index,
    holders[0]!.holder,
    holders[0]!.privateKey,
  );
  const att2 = await createDestructionAttestation(
    kek.id,
    shares[1]!.index,
    holders[1]!.holder,
    holders[1]!.privateKey,
  );

  expect(await verifyThresholdDestruction([att1, att2], 2)).toBe(true);

  const entry: Omit<LogEntry, "index"> = {
    receiptId: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    entityType: "event_data",
    commitment: bytesToHex(
      sha256(
        new TextEncoder().encode(
          `event_data||entity-${entityIndex}||salt-${entityIndex}`,
        ),
      ),
    ),
    deletionMethod: "crypto_shredding_2of3",
    thresholdSignatures: [
      bytesToHex(att1.signature),
      bytesToHex(att2.signature),
    ],
    scanHash: bytesToHex(
      sha256(new TextEncoder().encode(`scan-${entityIndex}`)),
    ),
    smtRoot: bytesToHex(
      sha256(new TextEncoder().encode(`smt-${entityIndex}`)),
    ),
    operatorSignature: bytesToHex(att1.signature),
  };

  return { entry };
}

describe("integration: new log features E2E", () => {
  it("full pipeline with batch: generate KEKs, threshold-split, batch-append, verify", async () => {
    // --- Setup: 3 holders, 2-of-3 threshold ---
    const [h1, h2, h3] = await Promise.all([
      createTestHolder("operator"),
      createTestHolder("oracle"),
      createTestHolder("auditor"),
    ]);
    const holders = [h1, h2, h3];
    const config: ThresholdConfig = {
      totalShares: 3,
      threshold: 2,
      holders: holders.map((h) => h.holder),
    };

    // --- Generate 5 KEKs, full crypto+threshold flow for each ---
    const entries: Omit<LogEntry, "index">[] = [];
    for (let i = 0; i < 5; i++) {
      const { entry } = await buildLogEntryFromCrypto(holders, config, i);
      entries.push(entry);
    }

    // --- Create log, batch-append all 5 ---
    const logSigningKey = crypto.getRandomValues(new Uint8Array(32));
    const logPublicKey = await ed.getPublicKeyAsync(logSigningKey);
    const storage = new InMemoryLogStorage();
    const log = createLog(storage, logSigningKey);

    const proofs = await log.appendBatch(entries);

    // --- Verify: all 5 inclusion proofs are valid ---
    expect(proofs).toHaveLength(5);
    for (let i = 0; i < 5; i++) {
      expect(proofs[i]!.logIndex).toBe(i);
      expect(proofs[i]!.treeSize).toBe(5);

      const storedEntry = (await log.getEntries(i, 1))[0]!;
      const leafHash = computeLeafHash(storedEntry);
      expect(await verifyInclusionProof(leafHash, proofs[i]!)).toBe(true);
    }

    // --- Verify: tree head is valid, treeSize === 5 ---
    const head = await log.getTreeHead();
    expect(head.treeSize).toBe(5);
    expect(await verifyTreeHead(head, logPublicKey)).toBe(true);

    // --- Verify: consistency proof from 0→5 is valid ---
    const consistency0to5 = await log.getConsistencyProof(0, 5);
    expect(await verifyConsistencyProof(consistency0to5)).toBe(true);
  });

  it("tree head history E2E: checkpoint after each append, verify chain", async () => {
    // --- Setup: 3 holders, 2-of-3 threshold ---
    const [h1, h2, h3] = await Promise.all([
      createTestHolder("operator"),
      createTestHolder("oracle"),
      createTestHolder("auditor"),
    ]);
    const holders = [h1, h2, h3];
    const config: ThresholdConfig = {
      totalShares: 3,
      threshold: 2,
      holders: holders.map((h) => h.holder),
    };

    const logSigningKey = crypto.getRandomValues(new Uint8Array(32));
    const logPublicKey = await ed.getPublicKeyAsync(logSigningKey);
    const storage = new InMemoryLogStorage();
    const log = createLog(storage, logSigningKey);

    // --- Append 4 entries one at a time, checkpointing after each ---
    for (let i = 0; i < 4; i++) {
      const { entry } = await buildLogEntryFromCrypto(holders, config, i);
      await log.append(entry);
      // Checkpoint: getTreeHead() stores head in storage via storeTreeHead
      await log.getTreeHead();
    }

    // --- Retrieve history: should have 4 heads, newest first ---
    const history = await log.getTreeHeadHistory(10);
    expect(history).toHaveLength(4);

    // Newest first: treeSizes should be 4, 3, 2, 1
    expect(history[0]!.treeSize).toBe(4);
    expect(history[1]!.treeSize).toBe(3);
    expect(history[2]!.treeSize).toBe(2);
    expect(history[3]!.treeSize).toBe(1);

    // --- Verify each head signature ---
    for (const head of history) {
      expect(await verifyTreeHead(head, logPublicKey)).toBe(true);
    }

    // --- Verify consistency between consecutive heads ---
    // history is newest-first, so history[i+1] is the smaller tree
    for (let i = 0; i < history.length - 1; i++) {
      const olderHead = history[i + 1]!;
      const newerHead = history[i]!;
      const consistencyProof = await log.getConsistencyProof(
        olderHead.treeSize,
        newerHead.treeSize,
      );
      expect(await verifyConsistencyProof(consistencyProof)).toBe(true);
    }
  });

  it("max size + concurrency E2E", async () => {
    // --- Setup: 3 holders, 2-of-3 threshold ---
    const [h1, h2, h3] = await Promise.all([
      createTestHolder("operator"),
      createTestHolder("oracle"),
      createTestHolder("auditor"),
    ]);
    const holders = [h1, h2, h3];
    const config: ThresholdConfig = {
      totalShares: 3,
      threshold: 2,
      holders: holders.map((h) => h.holder),
    };

    // --- Create log with maxTreeSize: 5 ---
    const logSigningKey = crypto.getRandomValues(new Uint8Array(32));
    const logPublicKey = await ed.getPublicKeyAsync(logSigningKey);
    const storage = new InMemoryLogStorage();
    const log = createLog(storage, logSigningKey, { maxTreeSize: 5 });

    // --- Build 8 log entries from real crypto+threshold flow ---
    const entries: Omit<LogEntry, "index">[] = [];
    for (let i = 0; i < 8; i++) {
      const { entry } = await buildLogEntryFromCrypto(holders, config, i);
      entries.push(entry);
    }

    // --- Fire 8 concurrent append calls ---
    const results = await Promise.allSettled(
      entries.map((entry) => log.append(entry)),
    );

    // --- Verify: exactly 5 succeeded, 3 failed ---
    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r) => r.status === "rejected");
    expect(fulfilled).toHaveLength(5);
    expect(rejected).toHaveLength(3);

    // --- Verify: tree size is 5 ---
    const head = await log.getTreeHead();
    expect(head.treeSize).toBe(5);

    // --- Verify: all 5 successful inclusion proofs are valid ---
    for (const result of fulfilled) {
      const proof = (result as PromiseFulfilledResult<any>).value;
      const storedEntry = (await log.getEntries(proof.logIndex, 1))[0]!;
      const leafHash = computeLeafHash(storedEntry);
      expect(await verifyInclusionProof(leafHash, proof)).toBe(true);
    }

    // --- Verify: tree head signature is valid ---
    expect(await verifyTreeHead(head, logPublicKey)).toBe(true);
  });
});
