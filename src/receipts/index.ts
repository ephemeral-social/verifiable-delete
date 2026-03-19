/**
 * W3C Verifiable Credential deletion receipts.
 *
 * Generates machine-verifiable deletion receipts following
 * W3C VC Data Model 2.0 with a custom deletion attestation vocabulary.
 *
 * @module receipts
 */

import type { DestructionAttestation } from "../threshold/index.js";
import type { ScanResult } from "../scan/index.js";
import type { InclusionProof } from "../log/index.js";

// --- Types ---

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
  >;
  /** Ed25519 proof over the entire credential. */
  proof: {
    type: string;
    verificationMethod: string;
    proofValue: string;
  };
}

interface ThresholdAttestationEvidence {
  type: "ThresholdAttestation";
  participants: number;
  threshold: number;
  attestations: DestructionAttestation[];
}

interface StorageScanEvidence {
  type: "StorageScan";
  scanHash: string;
  backendsChecked: number;
  allAbsent: boolean;
  keyVerified: boolean;
}

interface NonMembershipEvidence {
  type: "NonMembershipProof";
  smtRoot: string;
  proof: string;
}

interface TransparencyLogEvidence {
  type: "TransparencyLogInclusion";
  logIndex: number;
  treeSize: number;
  treeRoot: string;
  inclusionProof: string[];
  witnessSignatures: Array<{ witness: string; signature: string }>;
}

// --- Functions ---

/**
 * Generate a deletion receipt with all evidence.
 */
export async function createDeletionReceipt(_params: {
  entityType: string;
  entityId: string;
  issuerDid: string;
  signingKey: Uint8Array;
  attestations: DestructionAttestation[];
  scanResult: ScanResult;
  nonMembershipProof: NonMembershipProof;
  inclusionProof: InclusionProof;
  witnessSignatures?: Array<{ witness: string; signature: string }>;
}): Promise<DeletionReceipt> {
  throw new Error("Not implemented");
}

/**
 * Verify all components of a deletion receipt.
 * Checks: operator signature, threshold attestation signatures,
 * Merkle inclusion proof, SMT non-membership proof.
 */
export async function verifyDeletionReceipt(
  _receipt: DeletionReceipt,
  _issuerPublicKey: Uint8Array,
): Promise<{
  valid: boolean;
  checks: {
    operatorSignature: boolean;
    thresholdAttestations: boolean;
    inclusionProof: boolean;
    nonMembershipProof: boolean;
  };
}> {
  throw new Error("Not implemented");
}

/**
 * Compute the commitment for a deletion event.
 * commitment = SHA256(entityType || entityId || salt)
 */
export async function computeCommitment(
  _entityType: string,
  _entityId: string,
  _salt: string,
): Promise<string> {
  throw new Error("Not implemented");
}
