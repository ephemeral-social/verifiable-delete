import { describe, it, expect } from "vitest";
import {
  generateKEK,
  encrypt,
  decrypt,
  exportKeyMaterial,
  importKeyMaterial,
  ratchetKey,
  verifyKeyDestruction,
} from "./index.js";

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

describe("crypto", () => {
  it("generateKEK returns valid VDKey", async () => {
    const key = await generateKEK();
    expect(key.cryptoKey).toBeDefined();
    expect(key.cryptoKey.type).toBe("secret");
    expect(key.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(key.epoch).toBe(0);
    expect(new Date(key.createdAt).getTime()).not.toBeNaN();
  });

  it("encrypt/decrypt round-trip", async () => {
    const kek = await generateKEK();
    const plaintext = new TextEncoder().encode("hello verifiable delete");
    const blob = await encrypt(plaintext, kek, "entity-1");
    const decrypted = await decrypt(blob, kek);
    expect(bytesEqual(decrypted, plaintext)).toBe(true);
    expect(blob.entityId).toBe("entity-1");
    expect(blob.kekId).toBe(kek.id);
  });

  it("decrypt with wrong KEK throws", async () => {
    const kek1 = await generateKEK();
    const kek2 = await generateKEK();
    const plaintext = new TextEncoder().encode("secret data");
    const blob = await encrypt(plaintext, kek1, "entity-2");
    await expect(decrypt(blob, kek2)).rejects.toThrow();
  });

  it("each encrypt uses unique DEK and nonce", async () => {
    const kek = await generateKEK();
    const data = new TextEncoder().encode("same data");
    const blob1 = await encrypt(data, kek, "e1");
    const blob2 = await encrypt(data, kek, "e2");

    expect(bytesEqual(blob1.wrappedDek, blob2.wrappedDek)).toBe(false);
    expect(bytesEqual(blob1.nonce, blob2.nonce)).toBe(false);
  });

  it("exportKeyMaterial/importKeyMaterial round-trip", async () => {
    const original = await generateKEK();
    const plaintext = new TextEncoder().encode("round-trip test");
    const blob = await encrypt(plaintext, original, "e3");

    const material = await exportKeyMaterial(original);
    expect(material).toBeInstanceOf(Uint8Array);
    expect(material.length).toBe(32);

    const restored = await importKeyMaterial(material, original.id, original.epoch);
    const decrypted = await decrypt(blob, restored);
    expect(bytesEqual(decrypted, plaintext)).toBe(true);
  });

  it("ratchetKey produces new key that cannot decrypt old data", async () => {
    const kek = await generateKEK();
    const plaintext = new TextEncoder().encode("pre-ratchet data");
    const blob = await encrypt(plaintext, kek, "e4");

    const { nextKey, epoch } = await ratchetKey(kek);
    expect(epoch).toBe(1);
    expect(nextKey.epoch).toBe(1);
    expect(nextKey.id).not.toBe(kek.id);

    // Old data cannot be decrypted with new key
    await expect(decrypt(blob, nextKey)).rejects.toThrow();

    // New key can encrypt/decrypt new data
    const newPlaintext = new TextEncoder().encode("post-ratchet data");
    const newBlob = await encrypt(newPlaintext, nextKey, "e5");
    const newDecrypted = await decrypt(newBlob, nextKey);
    expect(bytesEqual(newDecrypted, newPlaintext)).toBe(true);
  });

  it("verifyKeyDestruction returns true for wrong key", async () => {
    const kek1 = await generateKEK();
    const kek2 = await generateKEK();
    const blob = await encrypt(new Uint8Array([1, 2, 3]), kek1, "e6");

    const destroyed = await verifyKeyDestruction(blob, kek2);
    expect(destroyed).toBe(true);
  });

  it("verifyKeyDestruction returns false for correct key", async () => {
    const kek = await generateKEK();
    const blob = await encrypt(new Uint8Array([1, 2, 3]), kek, "e7");

    const destroyed = await verifyKeyDestruction(blob, kek);
    expect(destroyed).toBe(false);
  });

  it("encrypt handles empty data", async () => {
    const kek = await generateKEK();
    const empty = new Uint8Array(0);
    const blob = await encrypt(empty, kek, "e8");
    const decrypted = await decrypt(blob, kek);
    expect(decrypted.length).toBe(0);
    expect(bytesEqual(decrypted, empty)).toBe(true);
  });

  it("encrypt handles large data (1 MB)", async () => {
    const kek = await generateKEK();
    const large = new Uint8Array(1024 * 1024);
    // crypto.getRandomValues has a 65536-byte limit per call
    for (let offset = 0; offset < large.length; offset += 65536) {
      crypto.getRandomValues(large.subarray(offset, offset + 65536));
    }
    const blob = await encrypt(large, kek, "e9");
    const decrypted = await decrypt(blob, kek);
    expect(bytesEqual(decrypted, large)).toBe(true);
  });
});
