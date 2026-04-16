/**
 * W3C Verifiable Credential deletion receipts.
 *
 * Generates machine-verifiable deletion receipts following
 * W3C VC Data Model 2.0 with a custom deletion attestation vocabulary.
 *
 * @module receipts
 */

import { sha512 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as ed from "@noble/ed25519";
import { canonicalJSON, sha256hex } from "../utils.js";
import { verifyThresholdDestruction, type DestructionAttestation } from "../threshold/index.js";
import { hashScanResult, type ScanResult } from "../scan/index.js";
import type { InclusionProof } from "../log/index.js";
import { verifyNonMembershipProof as verifySMTProof } from "../smt/index.js";

// Ed25519 sync setup for Node
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

// --- Types ---

/** JSON-safe representation of a ShareHolder (publicKey as hex string). */
export interface SerializedShareHolder {
  id: string;
  label: string;
  publicKey: string; // hex
}

/** JSON-safe representation of a DestructionAttestation (binary fields as hex strings). */
export interface SerializedDestructionAttestation {
  kekId: string;
  shareIndex: number;
  holder: SerializedShareHolder;
  destroyedAt: string;
  signature: string; // hex
}

/** Non-membership proof from the Sparse Merkle Tree. */
export interface NonMembershipProof {
  /** The entity hash that was looked up. */
  entityHash: string;
  /** The SMT root hash at time of proof generation. */
  smtRoot: string;
  /** The proof siblings (base64 encoded). */
  proof: string;
  /** Whether the proof demonstrates non-membership. */
  nonMember: boolean;
}

/** The complete deletion receipt as a W3C VC. */
export interface DeletionReceipt {
  /** W3C VC context. */
  "@context": string[];
  /** Credential types. */
  type: string[];
  /** Receipt ID (random UUID). */
  id: string;
  /** Issuer DID. */
  issuer: string;
  /** ISO 8601 issuance timestamp. */
  issuanceDate: string;
  /** The deletion claims. */
  credentialSubject: {
    entityType: string;
    commitment: string;
    salt: string;
    deletionMethod: string;
    encryptionAlgorithm: string;
    keyManagement: string;
    keyRatcheting: string;
  };
  /** Evidence supporting the deletion claims. */
  evidence: Array<
    | ThresholdAttestationEvidence
    | StorageScanEvidence
    | NonMembershipEvidence
    | TransparencyLogEvidence
    | BackupCoverageEvidence
  >;
  /** Ed25519 proof over the entire credential. */
  proof: {
    type: string;
    verificationMethod: string;
    proofValue: string;
  };
}

export interface ThresholdAttestationEvidence {
  type: "ThresholdAttestation";
  participants: number;
  threshold: number;
  attestations: SerializedDestructionAttestation[];
}

export interface StorageScanEvidence {
  type: "StorageScan";
  scanHash: string;
  backendsChecked: number;
  allAbsent: boolean;
  keyVerified: boolean;
  note?: string;
}

export interface NonMembershipEvidence {
  type: "NonMembershipProof";
  entityHash: string;
  smtRoot: string;
  proof: string;
  nonMember: boolean;
}

export interface TransparencyLogEvidence {
  type: "TransparencyLogInclusion";
  logIndex: number;
  treeSize: number;
  treeRoot: string;
  inclusionProof: string[];
  witnessSignatures: Array<{ witness: string; signature: string }>;
}

export interface BackupCoverageEvidence {
  type: "BackupCoverage";
  method: "encryption_renders_backup_unreadable";
  keyManagement: "threshold_2_of_3";
  note: string;
}

// --- Serialization helpers ---

/** Serialize a DestructionAttestation to JSON-safe format (Uint8Array → hex). */
export function serializeAttestation(a: DestructionAttestation): SerializedDestructionAttestation {
  return {
    kekId: a.kekId,
    shareIndex: a.shareIndex,
    holder: {
      id: a.holder.id,
      label: a.holder.label,
      publicKey: bytesToHex(a.holder.publicKey),
    },
    destroyedAt: a.destroyedAt,
    signature: bytesToHex(a.signature),
  };
}

/** Deserialize a SerializedDestructionAttestation back to DestructionAttestation (hex → Uint8Array). */
export function deserializeAttestation(s: SerializedDestructionAttestation): DestructionAttestation {
  return {
    kekId: s.kekId,
    shareIndex: s.shareIndex,
    holder: {
      id: s.holder.id,
      label: s.holder.label,
      publicKey: hexToBytes(s.holder.publicKey),
    },
    destroyedAt: s.destroyedAt,
    signature: hexToBytes(s.signature),
  };
}

// --- Functions ---

/**
 * Compute the commitment for a deletion event.
 * commitment = SHA256("vd-commitment-v1:" + entityType + ":" + entityId + ":" + salt)
 */
export async function computeCommitment(
  entityType: string,
  entityId: string,
  salt: string,
): Promise<string> {
  return sha256hex(
    new TextEncoder().encode(`vd-commitment-v1:${entityType}:${entityId}:${salt}`),
  );
}

/**
 * Generate a deletion receipt with all evidence.
 */
export async function createDeletionReceipt(params: {
  entityType: string;
  entityId: string;
  issuerDid: string;
  signingKey: Uint8Array;
  attestations: DestructionAttestation[];
  scanResult: ScanResult;
  nonMembershipProof: NonMembershipProof;
  inclusionProof: InclusionProof;
  witnessSignatures?: Array<{ witness: string; signature: string }>;
  storageScanNote?: string;
}): Promise<DeletionReceipt> {
  const {
    entityType,
    entityId,
    issuerDid,
    signingKey,
    attestations,
    scanResult,
    nonMembershipProof,
    inclusionProof,
    witnessSignatures,
  } = params;

  // 1. Generate IDs
  const receiptId = crypto.randomUUID();
  const salt = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));

  // 2. Compute commitment
  const commitment = await computeCommitment(entityType, entityId, salt);

  // 3. Compute scan hash
  const scanHash = await hashScanResult(scanResult);

  // 4. Build evidence items
  const thresholdEvidence: ThresholdAttestationEvidence = {
    type: "ThresholdAttestation",
    participants: 3,
    threshold: 2,
    attestations: attestations.map(serializeAttestation),
  };

  const storageScanEvidence: StorageScanEvidence = {
    type: "StorageScan",
    scanHash,
    backendsChecked: scanResult.backends.length,
    allAbsent: scanResult.backends.every((b) => b.absent),
    keyVerified: scanResult.keyVerification.expectedFailure,
    ...(params.storageScanNote ? { note: params.storageScanNote } : {}),
  };

  const nonMembershipEvidence: NonMembershipEvidence = {
    type: "NonMembershipProof",
    entityHash: nonMembershipProof.entityHash,
    smtRoot: nonMembershipProof.smtRoot,
    proof: nonMembershipProof.proof,
    nonMember: nonMembershipProof.nonMember,
  };

  const transparencyLogEvidence: TransparencyLogEvidence = {
    type: "TransparencyLogInclusion",
    logIndex: inclusionProof.logIndex,
    treeSize: inclusionProof.treeSize,
    treeRoot: inclusionProof.rootHash,
    inclusionProof: inclusionProof.hashes,
    witnessSignatures: witnessSignatures ?? [],
  };

  // 5. Build evidence array (conditionally include BackupCoverage)
  const evidence: DeletionReceipt["evidence"] = [
    thresholdEvidence,
    storageScanEvidence,
    nonMembershipEvidence,
    transparencyLogEvidence,
  ];

  if (attestations.length > 0) {
    evidence.push({
      type: "BackupCoverage",
      method: "encryption_renders_backup_unreadable",
      keyManagement: "threshold_2_of_3",
      note: "Data encrypted with VD-managed threshold key; backups contain only ciphertext that is unreadable after key destruction",
    });
  }

  // 6. Build credential WITHOUT proof field
  const credentialWithoutProof = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://verifiabledelete.dev/ns/v1",
    ],
    type: ["VerifiableCredential", "DeletionReceipt"],
    id: `urn:uuid:${receiptId}`,
    issuer: issuerDid,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      entityType,
      commitment,
      salt,
      deletionMethod: "crypto_shredding",
      encryptionAlgorithm: "AES-256-GCM",
      keyManagement: "threshold_2_of_3",
      keyRatcheting: "HKDF-SHA256",
    },
    evidence,
  };

  // 7. Sign
  const message = new TextEncoder().encode(
    "vd-receipt-v1:" + canonicalJSON(credentialWithoutProof),
  );
  const signature = bytesToHex(await ed.signAsync(message, signingKey));

  // 8. Attach proof and return
  return {
    ...credentialWithoutProof,
    proof: {
      type: "Ed25519Signature2020",
      verificationMethod: `${issuerDid}#key-1`,
      proofValue: signature,
    },
  } satisfies DeletionReceipt;
}

/**
 * Verify all components of a deletion receipt.
 * Checks: operator signature, threshold attestation signatures,
 * Merkle inclusion proof (structural), SMT non-membership proof (structural).
 */
export async function verifyDeletionReceipt(
  receipt: DeletionReceipt,
  issuerPublicKey: Uint8Array,
): Promise<{
  valid: boolean;
  checks: {
    operatorSignature: boolean;
    thresholdAttestations: boolean;
    inclusionProof: boolean;
    nonMembershipProof: boolean;
  };
}> {
  // 1. Operator signature (FULL crypto)
  let operatorSignature = false;
  try {
    // Reconstruct the credential without proof
    const { proof: _proof, ...credentialWithoutProof } = receipt;
    const message = new TextEncoder().encode(
      "vd-receipt-v1:" + canonicalJSON(credentialWithoutProof),
    );
    const sigBytes = hexToBytes(receipt.proof.proofValue);
    operatorSignature = await ed.verifyAsync(sigBytes, message, issuerPublicKey);
  } catch {
    operatorSignature = false;
  }

  // 2. Threshold attestations (FULL crypto)
  let thresholdAttestations = false;
  try {
    const thresholdEvidence = receipt.evidence.find(
      (e): e is ThresholdAttestationEvidence => e.type === "ThresholdAttestation",
    );
    if (thresholdEvidence) {
      const deserialized = thresholdEvidence.attestations.map(deserializeAttestation);
      thresholdAttestations = await verifyThresholdDestruction(
        deserialized,
        thresholdEvidence.threshold,
      );
    }
  } catch {
    thresholdAttestations = false;
  }

  // 3. Inclusion proof (STRUCTURAL check)
  let inclusionProof = false;
  try {
    const logEvidence = receipt.evidence.find(
      (e): e is TransparencyLogEvidence => e.type === "TransparencyLogInclusion",
    );
    if (logEvidence) {
      inclusionProof =
        typeof logEvidence.logIndex === "number" &&
        logEvidence.logIndex >= 0 &&
        typeof logEvidence.treeSize === "number" &&
        logEvidence.treeSize > 0 &&
        typeof logEvidence.treeRoot === "string" &&
        logEvidence.treeRoot.length > 0 &&
        Array.isArray(logEvidence.inclusionProof);
    }
  } catch {
    inclusionProof = false;
  }

  // 4. Non-membership proof (CRYPTOGRAPHIC verification)
  let nonMembershipProof = false;
  try {
    const nmEvidence = receipt.evidence.find(
      (e): e is NonMembershipEvidence => e.type === "NonMembershipProof",
    );
    if (nmEvidence) {
      nonMembershipProof = verifySMTProof({
        entityHash: nmEvidence.entityHash,
        smtRoot: nmEvidence.smtRoot,
        proof: nmEvidence.proof,
        nonMember: nmEvidence.nonMember,
      });
    }
  } catch {
    nonMembershipProof = false;
  }

  const valid =
    operatorSignature && thresholdAttestations && inclusionProof && nonMembershipProof;

  return {
    valid,
    checks: {
      operatorSignature,
      thresholdAttestations,
      inclusionProof,
      nonMembershipProof,
    },
  };
}
