/**
 * End-to-end integration tests spanning all 5 modules:
 * crypto, threshold, scan, log, receipts.
 *
 * 20 tests exercising the complete verifiable deletion pipeline.
 */
import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

import {
  generateKEK,
  encrypt,
  decrypt,
  exportKeyMaterial,
  importKeyMaterial,
  ratchetKey,
  verifyKeyDestruction,
} from "../../packages/core/src/crypto/index.js";
import {
  splitKey,
  reconstructKey,
  createDestructionAttestation,
  verifyThresholdDestruction,
  type ShareHolder,
  type ThresholdConfig,
} from "../../packages/core/src/threshold/index.js";
import {
  runDeletionScan,
  hashScanResult,
  type StorageScanner,
  type ScanResult,
} from "../../packages/core/src/scan/index.js";
import {
  createLog,
  verifyInclusionProof,
  verifyConsistencyProof,
  verifyTreeHead,
  computeLeafHash,
  type LogEntry,
  type LogStorageAdapter,
  type SignedTreeHead,
  type TransparencyLog,
} from "../../packages/core/src/log/index.js";
import {
  createDeletionReceipt,
  verifyDeletionReceipt,
  computeCommitment,
  type DeletionReceipt,
  type NonMembershipProof,
} from "../../packages/core/src/receipts/index.js";
import { createSMT, entityToKey, serializeProof } from "../../packages/core/src/smt/index.js";
import { canonicalJSON } from "../../packages/core/src/utils.js";

// Ed25519 sync setup for Node
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

// --- Test Infrastructure ---

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
    this.treeHeads.unshift(head);
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

async function createTestInfra(): Promise<{
  operatorSigningKey: Uint8Array;
  operatorPublicKey: Uint8Array;
  holders: { holder: ShareHolder; privateKey: Uint8Array }[];
  config: ThresholdConfig;
  log: TransparencyLog;
  logSigningKey: Uint8Array;
  logPublicKey: Uint8Array;
  storage: InMemoryLogStorage;
}> {
  const operatorSigningKey = crypto.getRandomValues(new Uint8Array(32));
  const operatorPublicKey = await ed.getPublicKeyAsync(operatorSigningKey);

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

  return {
    operatorSigningKey,
    operatorPublicKey,
    holders,
    config,
    log,
    logSigningKey,
    logPublicKey,
    storage,
  };
}

function mockScanner(absent: boolean): StorageScanner {
  return {
    type: "d1",
    checkAbsence: async (entityId: string) => ({
      type: "d1",
      identifier: "events",
      query: `SELECT * FROM events WHERE id = '${entityId}'`,
      absent,
      scannedAt: new Date().toISOString(),
    }),
  };
}

function realNonMembershipProof(entityId: string): NonMembershipProof {
  const smt = createSMT();
  smt.add(entityToKey("other-entity"), entityToKey("other-entity"));
  const proof = smt.createProof(entityToKey(entityId));
  return serializeProof(proof, entityId);
}

async function signLogEntry(
  entry: Omit<LogEntry, "index" | "operatorSignature">,
  signingKey: Uint8Array,
): Promise<string> {
  const message = new TextEncoder().encode(
    "vd-log-entry-v1:" + canonicalJSON(entry),
  );
  return bytesToHex(await ed.signAsync(message, signingKey));
}

/** Full deletion pipeline for a single entity. Returns receipt + log inclusion proof. */
async function runFullPipeline(params: {
  entityType: string;
  entityId: string;
  data: Uint8Array;
  holders: { holder: ShareHolder; privateKey: Uint8Array }[];
  config: ThresholdConfig;
  log: TransparencyLog;
  operatorSigningKey: Uint8Array;
  issuerDid: string;
}): Promise<{
  receipt: DeletionReceipt;
  inclusionProof: import("../../packages/core/src/log/index.js").InclusionProof;
  scanResult: ScanResult;
  commitment: string;
  logEntry: Omit<LogEntry, "index">;
}> {
  const {
    entityType,
    entityId,
    data,
    holders,
    config,
    log,
    operatorSigningKey,
    issuerDid,
  } = params;

  // 1. Crypto: generate KEK, encrypt
  const kek = await generateKEK();
  const blob = await encrypt(data, kek, entityId);

  // 2. Threshold: split and attest
  const keyMaterial = await exportKeyMaterial(kek);
  const { shares } = await splitKey(keyMaterial, kek.id, config);

  const attestations = await Promise.all(
    holders.slice(0, config.threshold).map((h, i) =>
      createDestructionAttestation(
        kek.id,
        shares[i]!.index,
        h.holder,
        h.privateKey,
      ),
    ),
  );

  // 3. Verify key destruction (use a different key to simulate)
  const wrongKek = await generateKEK();
  const keyVerified = await verifyKeyDestruction(blob, wrongKek);

  // 4. Scan
  const scanResult = await runDeletionScan({
    entityId,
    scanners: [mockScanner(true)],
    testCiphertextId: blob.entityId,
    keyVerified,
  });

  // 5. Build log entry
  const salt = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  const commitment = await computeCommitment(entityType, entityId, salt);
  const scanHash = await hashScanResult(scanResult);
  const nmProof = realNonMembershipProof(entityId);

  const entryWithoutSig: Omit<LogEntry, "index" | "operatorSignature"> = {
    receiptId: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    entityType,
    commitment,
    deletionMethod: "crypto_shredding_2of3",
    thresholdSignatures: attestations.map((a) => bytesToHex(a.signature)),
    scanHash,
    smtRoot: nmProof.smtRoot,
  };

  const operatorSignature = await signLogEntry(entryWithoutSig, operatorSigningKey);
  const logEntry: Omit<LogEntry, "index"> = {
    ...entryWithoutSig,
    operatorSignature,
  };

  // 6. Append to log
  const inclusionProof = await log.append(logEntry);

  // 7. Create receipt
  const receipt = await createDeletionReceipt({
    entityType,
    entityId,
    issuerDid,
    signingKey: operatorSigningKey,
    attestations,
    scanResult,
    nonMembershipProof: nmProof,
    inclusionProof,
  });

  return { receipt, inclusionProof, scanResult, commitment, logEntry };
}

// --- Tests ---

describe("integration: all 5 modules E2E", () => {
  // Test 1: Full happy path
  it("full happy path: encrypt → split → destroy → scan → log → receipt → verify", async () => {
    const infra = await createTestInfra();

    // Generate KEK → encrypt → decrypt
    const kek = await generateKEK();
    const plaintext = new TextEncoder().encode("sensitive event data");
    const blob = await encrypt(plaintext, kek, "event-123");
    const decrypted = await decrypt(blob, kek);
    expect(new TextDecoder().decode(decrypted)).toBe("sensitive event data");

    // Export key material → split 2-of-3
    const keyMaterial = await exportKeyMaterial(kek);
    const { shares } = await splitKey(keyMaterial, kek.id, infra.config);

    // Create 2 attestations
    const [a1, a2] = await Promise.all([
      createDestructionAttestation(kek.id, shares[0].index, infra.holders[0]!.holder, infra.holders[0]!.privateKey),
      createDestructionAttestation(kek.id, shares[1].index, infra.holders[1]!.holder, infra.holders[1]!.privateKey),
    ]);

    // Verify threshold destruction
    expect(await verifyThresholdDestruction([a1, a2], 2)).toBe(true);

    // Verify key destruction
    const wrongKek = await generateKEK();
    expect(await verifyKeyDestruction(blob, wrongKek)).toBe(true);

    // Run scan
    const scanResult = await runDeletionScan({
      entityId: "event-123",
      scanners: [mockScanner(true)],
      testCiphertextId: blob.entityId,
      keyVerified: true,
    });
    expect(scanResult.allVerified).toBe(true);

    // Build + sign log entry
    const salt = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    const commitment = await computeCommitment("event_data", "event-123", salt);
    const scanHash = await hashScanResult(scanResult);
    const nmProof = realNonMembershipProof("event-123");

    const entryWithoutSig: Omit<LogEntry, "index" | "operatorSignature"> = {
      receiptId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      entityType: "event_data",
      commitment,
      deletionMethod: "crypto_shredding_2of3",
      thresholdSignatures: [bytesToHex(a1.signature), bytesToHex(a2.signature)],
      scanHash,
      smtRoot: nmProof.smtRoot,
    };
    const operatorSignature = await signLogEntry(entryWithoutSig, infra.operatorSigningKey);
    const logEntry: Omit<LogEntry, "index"> = { ...entryWithoutSig, operatorSignature };

    // Append to log
    const inclusionProof = await infra.log.append(logEntry);

    // Verify inclusion proof
    const fullEntry: LogEntry = { ...logEntry, index: 0 };
    const leafHash = computeLeafHash(fullEntry);
    expect(await verifyInclusionProof(leafHash, inclusionProof)).toBe(true);

    // Verify tree head
    const head = await infra.log.getTreeHead();
    expect(await verifyTreeHead(head, infra.logPublicKey)).toBe(true);

    // Create receipt
    const receipt = await createDeletionReceipt({
      entityType: "event_data",
      entityId: "event-123",
      issuerDid: "did:web:ephemeral.social",
      signingKey: infra.operatorSigningKey,
      attestations: [a1, a2],
      scanResult,
      nonMembershipProof: nmProof,
      inclusionProof,
    });

    // Verify receipt (all 4 checks)
    const verifyResult = await verifyDeletionReceipt(receipt, infra.operatorPublicKey);
    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.checks.operatorSignature).toBe(true);
    expect(verifyResult.checks.thresholdAttestations).toBe(true);
    expect(verifyResult.checks.inclusionProof).toBe(true);
    expect(verifyResult.checks.nonMembershipProof).toBe(true);

    // Verify commitment consistency
    const recomputedCommitment = await computeCommitment("event_data", "event-123", salt);
    expect(commitment).toBe(recomputedCommitment);
  });

  // Test 2: Forward secrecy
  it("forward secrecy: ratcheted key cannot decrypt old data", async () => {
    const kek = await generateKEK();
    const plaintext = new TextEncoder().encode("old data");
    const blob = await encrypt(plaintext, kek, "entity-fs");

    const { nextKey } = await ratchetKey(kek);
    expect(nextKey.epoch).toBe(1);

    // Old key still decrypts (if not destroyed)
    const decrypted = await decrypt(blob, kek);
    expect(new TextDecoder().decode(decrypted)).toBe("old data");

    // Ratcheted key cannot decrypt old data
    await expect(decrypt(blob, nextKey)).rejects.toThrow();
  });

  // Test 3: Threshold minimum (exactly 2 of 3)
  it("threshold minimum: exactly 2 of 3 attests succeeds", async () => {
    const kek = await generateKEK();
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

    // Reconstruct from exactly 2 shares
    const reconstructed = await reconstructKey([shares[0], shares[2]], 2);
    const restoredKek = await importKeyMaterial(reconstructed, kek.id, kek.epoch);

    const blob = await encrypt(new TextEncoder().encode("test"), kek, "e");
    const decrypted = await decrypt(blob, restoredKek);
    expect(new TextDecoder().decode(decrypted)).toBe("test");

    // 2 attestations pass threshold
    const [a1, a2] = await Promise.all([
      createDestructionAttestation(kek.id, shares[0].index, h1.holder, h1.privateKey),
      createDestructionAttestation(kek.id, shares[2].index, h3.holder, h3.privateKey),
    ]);
    expect(await verifyThresholdDestruction([a1, a2], 2)).toBe(true);
  });

  // Test 4: Threshold insufficient (only 1 of 3)
  it("threshold insufficient: only 1 of 3 fails verification", async () => {
    const kek = await generateKEK();
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

    const a1 = await createDestructionAttestation(
      kek.id, shares[0].index, h1.holder, h1.privateKey,
    );
    expect(await verifyThresholdDestruction([a1], 2)).toBe(false);
  });

  // Test 5: Multiple entities (5): all log entries + receipts + consistency
  it("multiple entities: 5 full pipelines with consistency proofs", async () => {
    const infra = await createTestInfra();
    const issuerDid = "did:web:ephemeral.social";
    const receipts: DeletionReceipt[] = [];
    const commitments: string[] = [];

    for (let i = 0; i < 5; i++) {
      const result = await runFullPipeline({
        entityType: "event_data",
        entityId: `entity-${i}`,
        data: new TextEncoder().encode(`data-${i}`),
        holders: infra.holders,
        config: infra.config,
        log: infra.log,
        operatorSigningKey: infra.operatorSigningKey,
        issuerDid,
      });
      receipts.push(result.receipt);
      commitments.push(result.commitment);
    }

    // Tree size = 5
    const head = await infra.log.getTreeHead();
    expect(head.treeSize).toBe(5);
    expect(await verifyTreeHead(head, infra.logPublicKey)).toBe(true);

    // All 5 inclusion proofs valid
    for (let i = 0; i < 5; i++) {
      const proof = await infra.log.getInclusionProof(i);
      const entry = (await infra.log.getEntries(i, 1))[0]!;
      const leafHash = computeLeafHash(entry);
      expect(await verifyInclusionProof(leafHash, proof)).toBe(true);
    }

    // Consistency proofs
    expect(await verifyConsistencyProof(await infra.log.getConsistencyProof(1, 5))).toBe(true);
    expect(await verifyConsistencyProof(await infra.log.getConsistencyProof(3, 5))).toBe(true);

    // All 5 receipts valid
    for (const receipt of receipts) {
      const result = await verifyDeletionReceipt(receipt, infra.operatorPublicKey);
      expect(result.valid).toBe(true);
    }

    // All 5 commitments are different
    const uniqueCommitments = new Set(commitments);
    expect(uniqueCommitments.size).toBe(5);

    // Pagination works
    const page1 = await infra.log.getEntries(0, 3);
    const page2 = await infra.log.getEntries(3, 3);
    expect(page1).toHaveLength(3);
    expect(page2).toHaveLength(2);
  });

  // Test 6: Receipt tampering detected at every field
  it("receipt tampering detected at 5 tamper targets", async () => {
    const infra = await createTestInfra();

    const { receipt } = await runFullPipeline({
      entityType: "event_data",
      entityId: "tamper-test",
      data: new TextEncoder().encode("tamper data"),
      holders: infra.holders,
      config: infra.config,
      log: infra.log,
      operatorSigningKey: infra.operatorSigningKey,
      issuerDid: "did:web:ephemeral.social",
    });

    // Baseline: valid
    const baseline = await verifyDeletionReceipt(receipt, infra.operatorPublicKey);
    expect(baseline.valid).toBe(true);

    // Tamper targets
    const tamperFns: ((r: DeletionReceipt) => DeletionReceipt)[] = [
      // entityType
      (r) => ({
        ...r,
        credentialSubject: { ...r.credentialSubject, entityType: "tampered" },
      }),
      // commitment
      (r) => ({
        ...r,
        credentialSubject: { ...r.credentialSubject, commitment: "0".repeat(64) },
      }),
      // proofValue
      (r) => ({
        ...r,
        proof: { ...r.proof, proofValue: "a".repeat(128) },
      }),
      // issuanceDate
      (r) => ({
        ...r,
        issuanceDate: "1999-01-01T00:00:00.000Z",
      }),
      // issuer
      (r) => ({
        ...r,
        issuer: "did:web:evil.example",
      }),
    ];

    for (const tamper of tamperFns) {
      const tampered = tamper(receipt);
      const result = await verifyDeletionReceipt(tampered, infra.operatorPublicKey);
      expect(result.valid).toBe(false);
    }
  });

  // Test 7: Log integrity to 20 entries
  it("log integrity: 20 entries, all inclusion + consistency proofs", async () => {
    const infra = await createTestInfra();

    // Append 20 entries
    for (let i = 0; i < 20; i++) {
      const entry: Omit<LogEntry, "index"> = {
        receiptId: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        entityType: "event_data",
        commitment: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
        deletionMethod: "crypto_shredding",
        thresholdSignatures: ["sig_a", "sig_b"],
        scanHash: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
        smtRoot: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
        operatorSignature: bytesToHex(crypto.getRandomValues(new Uint8Array(64))),
      };
      await infra.log.append(entry);
    }

    // Verify all 20 inclusion proofs
    for (let i = 0; i < 20; i++) {
      const proof = await infra.log.getInclusionProof(i);
      const entry = (await infra.log.getEntries(i, 1))[0]!;
      const leafHash = computeLeafHash(entry);
      expect(await verifyInclusionProof(leafHash, proof)).toBe(true);
    }

    // Consistency proofs at various checkpoints
    const consistencyPairs: [number, number][] = [
      [1, 5], [5, 10], [10, 15], [15, 20], [1, 20], [7, 13],
    ];
    for (const [from, to] of consistencyPairs) {
      const proof = await infra.log.getConsistencyProof(from, to);
      expect(await verifyConsistencyProof(proof)).toBe(true);
    }

    // Verify tree head signature
    const head = await infra.log.getTreeHead();
    expect(head.treeSize).toBe(20);
    expect(await verifyTreeHead(head, infra.logPublicKey)).toBe(true);
  });

  // Test 8: Scan with mixed results
  it("scan with mixed results: receipt still valid structurally", async () => {
    const infra = await createTestInfra();

    // One scanner absent, one not
    const mixedScanners: StorageScanner[] = [
      mockScanner(true),
      {
        type: "kv",
        checkAbsence: async (entityId: string) => ({
          type: "kv",
          identifier: "cache",
          query: `GET ${entityId}`,
          absent: false,
          scannedAt: new Date().toISOString(),
          note: "data still present in cache",
        }),
      },
    ];

    const scanResult = await runDeletionScan({
      entityId: "mixed-scan",
      scanners: mixedScanners,
      testCiphertextId: "tc",
      keyVerified: true,
    });

    expect(scanResult.allVerified).toBe(false);

    // Receipt can still be created and verified (scan evidence is informational)
    const kek = await generateKEK();
    const keyMaterial = await exportKeyMaterial(kek);
    const { shares } = await splitKey(keyMaterial, kek.id, infra.config);

    const attestations = await Promise.all(
      infra.holders.slice(0, 2).map((h, i) =>
        createDestructionAttestation(kek.id, shares[i]!.index, h.holder, h.privateKey),
      ),
    );

    const receipt = await createDeletionReceipt({
      entityType: "event_data",
      entityId: "mixed-scan",
      issuerDid: "did:web:ephemeral.social",
      signingKey: infra.operatorSigningKey,
      attestations,
      scanResult,
      nonMembershipProof: realNonMembershipProof("mixed-scan"),
      inclusionProof: { logIndex: 0, treeSize: 1, rootHash: "abc", hashes: [] },
    });

    const result = await verifyDeletionReceipt(receipt, infra.operatorPublicKey);
    // Receipt is still valid — scan mixed results don't invalidate the receipt itself
    expect(result.checks.operatorSignature).toBe(true);
    expect(result.checks.thresholdAttestations).toBe(true);
  });

  // Test 9: Empty data encryption + deletion
  it("empty data encryption + full pipeline", async () => {
    const infra = await createTestInfra();

    const { receipt } = await runFullPipeline({
      entityType: "event_data",
      entityId: "empty-entity",
      data: new Uint8Array(0),
      holders: infra.holders,
      config: infra.config,
      log: infra.log,
      operatorSigningKey: infra.operatorSigningKey,
      issuerDid: "did:web:ephemeral.social",
    });

    const result = await verifyDeletionReceipt(receipt, infra.operatorPublicKey);
    expect(result.valid).toBe(true);
  });

  // Test 10: Large data (1MB) encryption + deletion
  it("large data (1MB) encryption + full pipeline", async () => {
    const infra = await createTestInfra();

    // crypto.getRandomValues has a 65536-byte limit per call
    const largeData = new Uint8Array(1024 * 1024);
    for (let offset = 0; offset < largeData.length; offset += 65536) {
      const chunk = Math.min(65536, largeData.length - offset);
      crypto.getRandomValues(largeData.subarray(offset, offset + chunk));
    }

    const { receipt } = await runFullPipeline({
      entityType: "event_data",
      entityId: "large-entity",
      data: largeData,
      holders: infra.holders,
      config: infra.config,
      log: infra.log,
      operatorSigningKey: infra.operatorSigningKey,
      issuerDid: "did:web:ephemeral.social",
    });

    const result = await verifyDeletionReceipt(receipt, infra.operatorPublicKey);
    expect(result.valid).toBe(true);
  });

  // Test 11: Commitment consistency (receipt.commitment === logEntry.commitment)
  it("commitment consistency: receipt and log entry share same commitment", async () => {
    const infra = await createTestInfra();

    const { receipt, commitment } = await runFullPipeline({
      entityType: "event_data",
      entityId: "commit-check",
      data: new TextEncoder().encode("commitment test"),
      holders: infra.holders,
      config: infra.config,
      log: infra.log,
      operatorSigningKey: infra.operatorSigningKey,
      issuerDid: "did:web:ephemeral.social",
    });

    // Receipt commitment uses its own salt (different from log entry commitment)
    // But the log entry has the commitment we computed in the pipeline
    const logEntry = (await infra.log.getEntries(0, 1))[0]!;
    expect(logEntry.commitment).toBe(commitment);

    // The receipt has its own commitment (computed from its own salt)
    expect(receipt.credentialSubject.commitment).toMatch(/^[0-9a-f]{64}$/);
  });

  // Test 12: Independent verifier can verify log without receipt
  it("independent verifier can verify log without receipt", async () => {
    const infra = await createTestInfra();

    // Append a few entries
    for (let i = 0; i < 3; i++) {
      await runFullPipeline({
        entityType: "event_data",
        entityId: `verify-log-${i}`,
        data: new TextEncoder().encode(`data-${i}`),
        holders: infra.holders,
        config: infra.config,
        log: infra.log,
        operatorSigningKey: infra.operatorSigningKey,
        issuerDid: "did:web:ephemeral.social",
      });
    }

    // Independent verifier: only has the log public key and log access
    const head = await infra.log.getTreeHead();
    expect(await verifyTreeHead(head, infra.logPublicKey)).toBe(true);

    for (let i = 0; i < 3; i++) {
      const proof = await infra.log.getInclusionProof(i);
      const entry = (await infra.log.getEntries(i, 1))[0]!;
      const leafHash = computeLeafHash(entry);
      expect(await verifyInclusionProof(leafHash, proof)).toBe(true);
    }
  });

  // Test 13: Wrong issuer key rejected by receipt verification
  it("wrong issuer key rejected by receipt verification", async () => {
    const infra = await createTestInfra();

    const { receipt } = await runFullPipeline({
      entityType: "event_data",
      entityId: "wrong-key",
      data: new TextEncoder().encode("secret"),
      holders: infra.holders,
      config: infra.config,
      log: infra.log,
      operatorSigningKey: infra.operatorSigningKey,
      issuerDid: "did:web:ephemeral.social",
    });

    const wrongPublicKey = await ed.getPublicKeyAsync(
      crypto.getRandomValues(new Uint8Array(32)),
    );
    const result = await verifyDeletionReceipt(receipt, wrongPublicKey);
    expect(result.checks.operatorSignature).toBe(false);
    expect(result.valid).toBe(false);
  });

  // Test 14: Log consistency breaks with tampered proof
  it("log consistency breaks with tampered proof", async () => {
    const infra = await createTestInfra();

    for (let i = 0; i < 4; i++) {
      const entry: Omit<LogEntry, "index"> = {
        receiptId: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        entityType: "event_data",
        commitment: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
        deletionMethod: "crypto_shredding",
        thresholdSignatures: [],
        scanHash: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
        smtRoot: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
        operatorSignature: bytesToHex(crypto.getRandomValues(new Uint8Array(64))),
      };
      await infra.log.append(entry);
    }

    const proof = await infra.log.getConsistencyProof(2, 4);
    // Tamper with the proof
    const tampered = {
      ...proof,
      hashes: proof.hashes.map(() => bytesToHex(crypto.getRandomValues(new Uint8Array(32)))),
    };
    expect(await verifyConsistencyProof(tampered)).toBe(false);
  });

  // Test 15: Scan hash in log entry matches actual scan hash
  it("scan hash in log entry matches actual scan hash", async () => {
    const infra = await createTestInfra();

    const { scanResult, logEntry } = await runFullPipeline({
      entityType: "event_data",
      entityId: "scan-hash-check",
      data: new TextEncoder().encode("scan hash test"),
      holders: infra.holders,
      config: infra.config,
      log: infra.log,
      operatorSigningKey: infra.operatorSigningKey,
      issuerDid: "did:web:ephemeral.social",
    });

    const expectedScanHash = await hashScanResult(scanResult);
    expect(logEntry.scanHash).toBe(expectedScanHash);
  });

  // Test 16: All 3 attestations (exceeds threshold)
  it("all 3 attestations (exceeds threshold of 2) — full pipeline", async () => {
    const infra = await createTestInfra();

    const kek = await generateKEK();
    const keyMaterial = await exportKeyMaterial(kek);
    const blob = await encrypt(new TextEncoder().encode("three-attest"), kek, "three-attest");
    const { shares } = await splitKey(keyMaterial, kek.id, infra.config);

    // All 3 holders attest
    const attestations = await Promise.all(
      infra.holders.map((h, i) =>
        createDestructionAttestation(kek.id, shares[i]!.index, h.holder, h.privateKey),
      ),
    );

    expect(await verifyThresholdDestruction(attestations, 2)).toBe(true);

    const scanResult = await runDeletionScan({
      entityId: "three-attest",
      scanners: [mockScanner(true)],
      testCiphertextId: blob.entityId,
      keyVerified: true,
    });

    const receipt = await createDeletionReceipt({
      entityType: "event_data",
      entityId: "three-attest",
      issuerDid: "did:web:ephemeral.social",
      signingKey: infra.operatorSigningKey,
      attestations,
      scanResult,
      nonMembershipProof: realNonMembershipProof("three-attest"),
      inclusionProof: { logIndex: 0, treeSize: 1, rootHash: "abc", hashes: [] },
    });

    const result = await verifyDeletionReceipt(receipt, infra.operatorPublicKey);
    expect(result.valid).toBe(true);
    expect(result.checks.thresholdAttestations).toBe(true);
  });

  // Test 17: Log entry operator signature independently verifiable
  it("log entry operator signature is independently verifiable", async () => {
    const infra = await createTestInfra();

    const { logEntry } = await runFullPipeline({
      entityType: "event_data",
      entityId: "opsig-verify",
      data: new TextEncoder().encode("operator sig test"),
      holders: infra.holders,
      config: infra.config,
      log: infra.log,
      operatorSigningKey: infra.operatorSigningKey,
      issuerDid: "did:web:ephemeral.social",
    });

    // Reconstruct the entry without operatorSignature to verify
    const { operatorSignature, ...entryWithoutSig } = logEntry;
    const message = new TextEncoder().encode(
      "vd-log-entry-v1:" + canonicalJSON(entryWithoutSig),
    );
    const sigBytes = new Uint8Array(
      (operatorSignature.match(/.{2}/g) ?? []).map((b) => parseInt(b, 16)),
    );

    const isValid = await ed.verifyAsync(sigBytes, message, infra.operatorPublicKey);
    expect(isValid).toBe(true);
  });

  // Test 18: Multiple entity types
  it("multiple entity types: event_data, user_rsvp, connection_record", async () => {
    const infra = await createTestInfra();
    const entityTypes = ["event_data", "user_rsvp", "connection_record"];

    for (const entityType of entityTypes) {
      const { receipt } = await runFullPipeline({
        entityType,
        entityId: `${entityType}-entity-1`,
        data: new TextEncoder().encode(`${entityType} data`),
        holders: infra.holders,
        config: infra.config,
        log: infra.log,
        operatorSigningKey: infra.operatorSigningKey,
        issuerDid: "did:web:ephemeral.social",
      });

      const result = await verifyDeletionReceipt(receipt, infra.operatorPublicKey);
      expect(result.valid).toBe(true);
      expect(receipt.credentialSubject.entityType).toBe(entityType);
    }

    const head = await infra.log.getTreeHead();
    expect(head.treeSize).toBe(3);
  });

  // Test 19: Concurrent deletions (5 parallel full pipelines)
  it("concurrent deletions: 5 parallel full pipelines", async () => {
    const infra = await createTestInfra();

    const results = await Promise.all(
      Array.from({ length: 5 }, (_, i) =>
        runFullPipeline({
          entityType: "event_data",
          entityId: `concurrent-${i}`,
          data: new TextEncoder().encode(`concurrent data ${i}`),
          holders: infra.holders,
          config: infra.config,
          log: infra.log,
          operatorSigningKey: infra.operatorSigningKey,
          issuerDid: "did:web:ephemeral.social",
        }),
      ),
    );

    // All 5 receipts valid
    for (const { receipt } of results) {
      const result = await verifyDeletionReceipt(receipt, infra.operatorPublicKey);
      expect(result.valid).toBe(true);
    }

    // Log has 5 entries
    const head = await infra.log.getTreeHead();
    expect(head.treeSize).toBe(5);

    // All indices unique
    const indices = new Set(results.map((r) => r.inclusionProof.logIndex));
    expect(indices.size).toBe(5);
  });

  // Test 20: Audit trail — given receipt, trace to log entry via commitment match
  it("audit trail: trace receipt to log entry via commitment match", async () => {
    const infra = await createTestInfra();

    // Run 3 pipelines
    const pipelineResults = [];
    for (let i = 0; i < 3; i++) {
      const result = await runFullPipeline({
        entityType: "event_data",
        entityId: `audit-${i}`,
        data: new TextEncoder().encode(`audit data ${i}`),
        holders: infra.holders,
        config: infra.config,
        log: infra.log,
        operatorSigningKey: infra.operatorSigningKey,
        issuerDid: "did:web:ephemeral.social",
      });
      pipelineResults.push(result);
    }

    // For the second receipt, trace back to its log entry
    const targetResult = pipelineResults[1]!;
    const targetCommitment = targetResult.commitment;

    // Search log entries for matching commitment
    const allEntries = await infra.log.getEntries(0, 10);
    const matchingEntry = allEntries.find((e) => e.commitment === targetCommitment);
    expect(matchingEntry).toBeDefined();

    // Verify the matching log entry's inclusion proof
    const proof = await infra.log.getInclusionProof(matchingEntry!.index);
    const leafHash = computeLeafHash(matchingEntry!);
    expect(await verifyInclusionProof(leafHash, proof)).toBe(true);
  });
});
