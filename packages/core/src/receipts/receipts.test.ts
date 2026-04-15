import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import {
  createDeletionReceipt,
  verifyDeletionReceipt,
  computeCommitment,
  type DeletionReceipt,
  type NonMembershipProof,
} from "./index.js";
import {
  createDestructionAttestation,
  type ShareHolder,
} from "../threshold/index.js";
import { createSMT, entityToKey, serializeProof } from "../smt/index.js";
import type { ScanResult } from "../scan/index.js";
import type { InclusionProof } from "../log/index.js";

// Ed25519 sync setup for Node
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
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

function mockScanResult(entityId: string): ScanResult {
  return {
    scanId: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    entityId,
    backends: [
      {
        type: "d1",
        identifier: "events",
        query: `SELECT * FROM events WHERE id = '${entityId}'`,
        absent: true,
        scannedAt: new Date().toISOString(),
      },
    ],
    keyVerification: {
      testCiphertextId: "test-ct-1",
      expectedFailure: true,
    },
    allVerified: true,
    caveats: [],
  };
}

function realNonMembershipProof(entityId: string): NonMembershipProof {
  const smt = createSMT();
  smt.add(entityToKey("other-entity"), entityToKey("other-entity"));
  const key = entityToKey(entityId);
  const proof = smt.createProof(key);
  return serializeProof(proof, entityId);
}

function mockInclusionProof(): InclusionProof {
  return {
    logIndex: 0,
    treeSize: 1,
    rootHash: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
    hashes: [],
  };
}

async function createTestReceipt(): Promise<{
  receipt: DeletionReceipt;
  signingKey: Uint8Array;
  publicKey: Uint8Array;
}> {
  const signingKey = crypto.getRandomValues(new Uint8Array(32));
  const publicKey = await ed.getPublicKeyAsync(signingKey);

  const [h1, h2] = await Promise.all([
    createTestHolder("operator"),
    createTestHolder("oracle"),
  ]);

  const kekId = crypto.randomUUID();
  const [a1, a2] = await Promise.all([
    createDestructionAttestation(kekId, 1, h1.holder, h1.privateKey),
    createDestructionAttestation(kekId, 2, h2.holder, h2.privateKey),
  ]);

  const receipt = await createDeletionReceipt({
    entityType: "event_data",
    entityId: "entity-test",
    issuerDid: "did:web:verifiabledelete.dev",
    signingKey,
    attestations: [a1, a2],
    scanResult: mockScanResult("entity-test"),
    nonMembershipProof: realNonMembershipProof("entity-test"),
    inclusionProof: mockInclusionProof(),
  });

  return { receipt, signingKey, publicKey };
}

describe("receipts", () => {
  // Test 1: valid W3C VC structure
  it("creates receipt with valid W3C VC structure", async () => {
    const { receipt } = await createTestReceipt();

    expect(receipt["@context"]).toEqual([
      "https://www.w3.org/ns/credentials/v2",
      "https://verifiabledelete.dev/ns/v1",
    ]);
    expect(receipt.type).toEqual(["VerifiableCredential", "DeletionReceipt"]);
    expect(receipt.id).toMatch(/^urn:uuid:/);
    expect(receipt.issuer).toBe("did:web:verifiabledelete.dev");
    expect(new Date(receipt.issuanceDate).getTime()).not.toBeNaN();
    expect(receipt.credentialSubject.entityType).toBe("event_data");
    expect(receipt.credentialSubject.deletionMethod).toBe("crypto_shredding");
    expect(receipt.credentialSubject.encryptionAlgorithm).toBe("AES-256-GCM");
    expect(receipt.credentialSubject.keyManagement).toBe("threshold_2_of_3");
    expect(receipt.credentialSubject.keyRatcheting).toBe("HKDF-SHA256");
    expect(receipt.proof.type).toBe("Ed25519Signature2020");
    expect(receipt.evidence).toHaveLength(4);
  });

  // Test 2: commitment matches computeCommitment
  it("receipt commitment matches recomputed commitment", async () => {
    const { receipt } = await createTestReceipt();

    const recomputed = await computeCommitment(
      receipt.credentialSubject.entityType,
      "entity-test",
      receipt.credentialSubject.salt,
    );
    expect(receipt.credentialSubject.commitment).toBe(recomputed);
  });

  // Test 3: all checks true for valid receipt
  it("verifyDeletionReceipt returns all checks true for valid receipt", async () => {
    const { receipt, publicKey } = await createTestReceipt();

    const result = await verifyDeletionReceipt(receipt, publicKey);
    expect(result.valid).toBe(true);
    expect(result.checks.operatorSignature).toBe(true);
    expect(result.checks.thresholdAttestations).toBe(true);
    expect(result.checks.inclusionProof).toBe(true);
    expect(result.checks.nonMembershipProof).toBe(true);
  });

  // Test 4: wrong issuer key → operatorSignature fails
  it("wrong issuer key → operatorSignature false, threshold still true", async () => {
    const { receipt } = await createTestReceipt();
    const wrongKey = await ed.getPublicKeyAsync(
      crypto.getRandomValues(new Uint8Array(32)),
    );

    const result = await verifyDeletionReceipt(receipt, wrongKey);
    expect(result.checks.operatorSignature).toBe(false);
    expect(result.checks.thresholdAttestations).toBe(true);
    expect(result.valid).toBe(false);
  });

  // Test 5: tampered credentialSubject → sig fails
  it("tampered credentialSubject → operatorSignature false", async () => {
    const { receipt, publicKey } = await createTestReceipt();

    const tampered: DeletionReceipt = {
      ...receipt,
      credentialSubject: {
        ...receipt.credentialSubject,
        entityType: "tampered_type",
      },
    };

    const result = await verifyDeletionReceipt(tampered, publicKey);
    expect(result.checks.operatorSignature).toBe(false);
    expect(result.valid).toBe(false);
  });

  // Test 6: tampered threshold attestation
  it("tampered threshold attestation → thresholdAttestations false", async () => {
    const { receipt, publicKey } = await createTestReceipt();

    const tampered = structuredClone(receipt) as DeletionReceipt;
    const thresholdEv = tampered.evidence.find((e) => e.type === "ThresholdAttestation");
    if (thresholdEv && "attestations" in thresholdEv && thresholdEv.attestations[0]) {
      // Tamper with the signature (now a hex string)
      thresholdEv.attestations[0].signature = bytesToHex(crypto.getRandomValues(new Uint8Array(64)));
    }

    const result = await verifyDeletionReceipt(tampered, publicKey);
    expect(result.checks.thresholdAttestations).toBe(false);
    // Operator sig also fails because evidence changed
    expect(result.valid).toBe(false);
  });

  // Test 7: missing evidence → all checks fail
  it("empty evidence → all evidence-based checks fail", async () => {
    const { receipt, publicKey } = await createTestReceipt();

    const tampered: DeletionReceipt = {
      ...receipt,
      evidence: [],
    };

    const result = await verifyDeletionReceipt(tampered, publicKey);
    expect(result.checks.thresholdAttestations).toBe(false);
    expect(result.checks.inclusionProof).toBe(false);
    expect(result.checks.nonMembershipProof).toBe(false);
    expect(result.valid).toBe(false);
  });

  // Test 8: computeCommitment deterministic
  it("computeCommitment is deterministic", async () => {
    const c1 = await computeCommitment("event_data", "entity-1", "salt-abc");
    const c2 = await computeCommitment("event_data", "entity-1", "salt-abc");
    expect(c1).toBe(c2);
  });

  // Test 9: computeCommitment sensitive to all inputs
  it("computeCommitment changes with different inputs", async () => {
    const base = await computeCommitment("event_data", "entity-1", "salt-abc");
    const diffType = await computeCommitment("user_rsvp", "entity-1", "salt-abc");
    const diffId = await computeCommitment("event_data", "entity-2", "salt-abc");
    const diffSalt = await computeCommitment("event_data", "entity-1", "salt-xyz");

    expect(base).not.toBe(diffType);
    expect(base).not.toBe(diffId);
    expect(base).not.toBe(diffSalt);
  });

  // Test 10: computeCommitment returns 64-char hex
  it("computeCommitment returns 64-char hex string", async () => {
    const c = await computeCommitment("event_data", "entity-1", "salt-1");
    expect(c).toMatch(/^[0-9a-f]{64}$/);
  });

  // Test 11: no witness signatures → still valid
  it("receipt without witness signatures is still valid", async () => {
    const signingKey = crypto.getRandomValues(new Uint8Array(32));
    const publicKey = await ed.getPublicKeyAsync(signingKey);

    const [h1, h2] = await Promise.all([
      createTestHolder("operator"),
      createTestHolder("oracle"),
    ]);
    const kekId = crypto.randomUUID();
    const [a1, a2] = await Promise.all([
      createDestructionAttestation(kekId, 1, h1.holder, h1.privateKey),
      createDestructionAttestation(kekId, 2, h2.holder, h2.privateKey),
    ]);

    const receipt = await createDeletionReceipt({
      entityType: "event_data",
      entityId: "no-witness",
      issuerDid: "did:web:verifiabledelete.dev",
      signingKey,
      attestations: [a1, a2],
      scanResult: mockScanResult("no-witness"),
      nonMembershipProof: realNonMembershipProof("no-witness"),
      inclusionProof: mockInclusionProof(),
      // No witnessSignatures
    });

    const logEvidence = receipt.evidence.find((e) => e.type === "TransparencyLogInclusion");
    expect(logEvidence && "witnessSignatures" in logEvidence ? logEvidence.witnessSignatures : []).toEqual([]);

    const result = await verifyDeletionReceipt(receipt, publicKey);
    expect(result.valid).toBe(true);
  });

  // Test 12: unique ID and salt per receipt
  it("two receipts with same params have different ID and salt", async () => {
    const signingKey = crypto.getRandomValues(new Uint8Array(32));

    const [h1, h2] = await Promise.all([
      createTestHolder("operator"),
      createTestHolder("oracle"),
    ]);
    const kekId = crypto.randomUUID();
    const [a1, a2] = await Promise.all([
      createDestructionAttestation(kekId, 1, h1.holder, h1.privateKey),
      createDestructionAttestation(kekId, 2, h2.holder, h2.privateKey),
    ]);

    const commonParams = {
      entityType: "event_data",
      entityId: "same-entity",
      issuerDid: "did:web:verifiabledelete.dev",
      signingKey,
      attestations: [a1, a2],
      scanResult: mockScanResult("same-entity"),
      nonMembershipProof: realNonMembershipProof("same-entity"),
      inclusionProof: mockInclusionProof(),
    };

    const receipt1 = await createDeletionReceipt(commonParams);
    const receipt2 = await createDeletionReceipt(commonParams);

    expect(receipt1.id).not.toBe(receipt2.id);
    expect(receipt1.credentialSubject.salt).not.toBe(receipt2.credentialSubject.salt);
  });

  // Test 13: malformed proofValue → operatorSignature fails
  it("malformed proofValue → operatorSignature false, no crash", async () => {
    const { receipt, publicKey } = await createTestReceipt();

    const tampered: DeletionReceipt = {
      ...receipt,
      proof: {
        ...receipt.proof,
        proofValue: "not-valid-hex-gggg",
      },
    };

    const result = await verifyDeletionReceipt(tampered, publicKey);
    expect(result.checks.operatorSignature).toBe(false);
    expect(result.valid).toBe(false);
  });

  // Test 14: receipt with 3 attestations (exceeds threshold) still valid
  it("receipt with 3 attestations (exceeds threshold of 2) is still valid", async () => {
    const signingKey = crypto.getRandomValues(new Uint8Array(32));
    const publicKey = await ed.getPublicKeyAsync(signingKey);

    const [h1, h2, h3] = await Promise.all([
      createTestHolder("operator"),
      createTestHolder("oracle"),
      createTestHolder("auditor"),
    ]);
    const kekId = crypto.randomUUID();
    const [a1, a2, a3] = await Promise.all([
      createDestructionAttestation(kekId, 1, h1.holder, h1.privateKey),
      createDestructionAttestation(kekId, 2, h2.holder, h2.privateKey),
      createDestructionAttestation(kekId, 3, h3.holder, h3.privateKey),
    ]);

    const receipt = await createDeletionReceipt({
      entityType: "event_data",
      entityId: "three-attest",
      issuerDid: "did:web:verifiabledelete.dev",
      signingKey,
      attestations: [a1, a2, a3],
      scanResult: mockScanResult("three-attest"),
      nonMembershipProof: realNonMembershipProof("three-attest"),
      inclusionProof: mockInclusionProof(),
    });

    const result = await verifyDeletionReceipt(receipt, publicKey);
    expect(result.valid).toBe(true);
    expect(result.checks.thresholdAttestations).toBe(true);
  });

  // Test 15: JSON round-trip preserves receipt validity (cross-verification)
  it("receipt survives JSON.stringify → JSON.parse round-trip", async () => {
    const { receipt, publicKey } = await createTestReceipt();

    // Serialize to JSON and back (simulates network transport / storage)
    const json = JSON.stringify(receipt);
    const parsed = JSON.parse(json) as DeletionReceipt;

    // Verify the parsed receipt passes all checks
    const result = await verifyDeletionReceipt(parsed, publicKey);
    expect(result.valid).toBe(true);
    expect(result.checks.operatorSignature).toBe(true);
    expect(result.checks.thresholdAttestations).toBe(true);
    expect(result.checks.inclusionProof).toBe(true);
    expect(result.checks.nonMembershipProof).toBe(true);
  });
});
