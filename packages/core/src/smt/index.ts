/**
 * Sparse Merkle Tree utilities for verifiable non-membership proofs.
 *
 * Wraps @zk-kit/sparse-merkle-tree with SHA-256 hashing and
 * serialization helpers for the deletion receipt pipeline.
 *
 * @module smt
 */

import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import { SparseMerkleTree } from "@zk-kit/sparse-merkle-tree";
import type { ChildNodes, MerkleProof } from "@zk-kit/sparse-merkle-tree";
import type { NonMembershipProof } from "../receipts/index.js";

// btoa/atob exist in all target runtimes (Node 16+, Workers, Deno, browsers)
declare function btoa(data: string): string;
declare function atob(data: string): string;

/**
 * SHA-256 hash function for the SMT.
 * Concatenates child node hex strings and hashes them.
 */
export function smtHash(childNodes: ChildNodes): string {
  return bytesToHex(
    sha256(new TextEncoder().encode(childNodes.map(String).join(""))),
  );
}

/**
 * Create a new empty SparseMerkleTree using SHA-256 hashing.
 */
export function createSMT(): SparseMerkleTree {
  return new SparseMerkleTree(smtHash);
}

/**
 * Hash an entity ID to a 64-char hex key for SMT insertion/lookup.
 */
export function entityToKey(entityId: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(entityId)));
}

/**
 * Serialize a MerkleProof into a portable NonMembershipProof.
 * The proof siblings/entry/matchingEntry are base64-encoded JSON.
 */
export function serializeProof(
  proof: MerkleProof,
  entityId: string,
): NonMembershipProof {
  return {
    entityHash: entityToKey(entityId),
    smtRoot: proof.root as string,
    proof: btoa(
      JSON.stringify({
        entry: proof.entry,
        matchingEntry: proof.matchingEntry,
        siblings: proof.siblings,
      }),
    ),
    nonMember: !proof.membership,
  };
}

/**
 * Verify a serialized non-membership proof.
 * Reconstructs the MerkleProof and verifies it using a fresh SMT instance.
 *
 * Checks both the cryptographic hash path AND that the proof structure
 * actually represents non-membership (entry has no value/mark).
 */
export function verifyNonMembershipProof(proof: NonMembershipProof): boolean {
  if (proof.nonMember !== true) return false;
  try {
    const raw = JSON.parse(atob(proof.proof));
    // Structural check: a genuine non-membership proof has entry = [key] (no value).
    // A membership proof has entry = [key, value, mark] (length 3).
    // If entry[1] is defined, this is a membership proof disguised as non-membership.
    if (Array.isArray(raw.entry) && raw.entry.length >= 2 && raw.entry[1] !== undefined) {
      return false;
    }
    const merkleProof: MerkleProof = {
      entry: raw.entry,
      matchingEntry: raw.matchingEntry,
      siblings: raw.siblings,
      root: proof.smtRoot,
      membership: false,
    };
    const smt = createSMT();
    return smt.verifyProof(merkleProof);
  } catch {
    return false;
  }
}
