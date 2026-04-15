import { describe, it, expect } from "vitest";
import {
  smtHash,
  createSMT,
  entityToKey,
  serializeProof,
  verifyNonMembershipProof,
} from "./index.js";

describe("smt", () => {
  // Test 1: smtHash returns hex string
  it("smtHash returns 64-char hex string", () => {
    const result = smtHash(["abc", "def"]);
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });

  // Test 2: smtHash is deterministic
  it("smtHash is deterministic", () => {
    const a = smtHash(["foo", "bar"]);
    const b = smtHash(["foo", "bar"]);
    expect(a).toBe(b);
  });

  // Test 3: createSMT returns empty tree with root "0"
  it('createSMT returns empty tree with root "0"', () => {
    const smt = createSMT();
    expect(smt.root).toBe("0");
  });

  // Test 4: add entity, get returns value
  it("add entity, get returns value", () => {
    const smt = createSMT();
    const key = entityToKey("entity-1");
    smt.add(key, key);
    expect(smt.get(key)).toBe(key);
  });

  // Test 5: createProof on non-member returns membership=false
  it("createProof on non-member returns membership=false", () => {
    const smt = createSMT();
    smt.add(entityToKey("entity-1"), entityToKey("entity-1"));
    const proof = smt.createProof(entityToKey("entity-missing"));
    expect(proof.membership).toBe(false);
  });

  // Test 6: createProof on member returns membership=true
  it("createProof on member returns membership=true", () => {
    const smt = createSMT();
    const key = entityToKey("entity-1");
    smt.add(key, key);
    const proof = smt.createProof(key);
    expect(proof.membership).toBe(true);
  });

  // Test 7: verifyProof on valid non-membership proof
  it("verifyProof on valid non-membership proof returns true", () => {
    const smt = createSMT();
    smt.add(entityToKey("entity-1"), entityToKey("entity-1"));
    const proof = smt.createProof(entityToKey("entity-absent"));
    expect(smt.verifyProof(proof)).toBe(true);
  });

  // Test 8: delete entity, then non-membership proof valid
  it("delete entity, then non-membership proof valid", () => {
    const smt = createSMT();
    const key = entityToKey("entity-del");
    smt.add(key, key);
    expect(smt.get(key)).toBe(key);
    smt.delete(key);
    const proof = smt.createProof(key);
    expect(proof.membership).toBe(false);
    expect(smt.verifyProof(proof)).toBe(true);
  });

  // Test 9: entityToKey returns 64-char hex
  it("entityToKey returns 64-char hex, deterministic", () => {
    const a = entityToKey("my-entity");
    const b = entityToKey("my-entity");
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).toBe(b);
  });

  // Test 10: serializeProof round-trips through verifyNonMembershipProof
  it("serializeProof round-trips through verifyNonMembershipProof", () => {
    const smt = createSMT();
    // Add a different entity so the tree is non-empty
    smt.add(entityToKey("other-entity"), entityToKey("other-entity"));
    // Prove non-membership of absent entity
    const key = entityToKey("absent-entity");
    const proof = smt.createProof(key);
    expect(proof.membership).toBe(false);
    const serialized = serializeProof(proof, "absent-entity");
    expect(serialized.nonMember).toBe(true);
    expect(serialized.entityHash).toBe(key);
    expect(verifyNonMembershipProof(serialized)).toBe(true);
  });

  // Test 11: verifyNonMembershipProof rejects tampered proof
  it("verifyNonMembershipProof rejects tampered proof", () => {
    const smt = createSMT();
    smt.add(entityToKey("other-entity"), entityToKey("other-entity"));
    const proof = smt.createProof(entityToKey("absent-entity"));
    const serialized = serializeProof(proof, "absent-entity");

    // Tamper with the root hash — this makes the proof path invalid
    const tampered = {
      ...serialized,
      smtRoot: "a".repeat(64),
    };
    expect(verifyNonMembershipProof(tampered)).toBe(false);
  });

  // Test 12: verifyNonMembershipProof rejects membership proof presented as non-membership
  it("verifyNonMembershipProof rejects membership proof presented as non-membership", () => {
    const smt = createSMT();
    const key = entityToKey("existing-entity");
    smt.add(key, key);
    const proof = smt.createProof(key);
    expect(proof.membership).toBe(true);

    // Forge nonMember=true on a membership proof
    const serialized = serializeProof(proof, "existing-entity");
    const forged = {
      ...serialized,
      nonMember: true, // lie - this is actually a membership proof
    };
    expect(verifyNonMembershipProof(forged)).toBe(false);
  });
});
