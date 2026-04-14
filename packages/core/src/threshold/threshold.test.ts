import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import {
  splitKey,
  reconstructKey,
  createDestructionAttestation,
  verifyDestructionAttestation,
  verifyThresholdDestruction,
  type ShareHolder,
  type ThresholdConfig,
} from "./index.js";
import {
  generateKEK,
  exportKeyMaterial,
  importKeyMaterial,
  encrypt,
  decrypt,
} from "../crypto/index.js";

// Ed25519 sync setup for Node
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
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

describe("threshold", () => {
  // --- splitKey ---

  it("splitKey splits into 3 shares", async () => {
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

    const result = await splitKey(keyMaterial, kek.id, config);

    expect(result.shares.length).toBe(3);
    expect(result.kekId).toBe(kek.id);

    // Indices are 1-based and unique
    const indices = result.shares.map((s) => s.index);
    expect(indices).toEqual([1, 2, 3]);

    // Each share has correct kekId and holder
    for (let i = 0; i < 3; i++) {
      expect(result.shares[i]!.kekId).toBe(kek.id);
      expect(result.shares[i]!.holder.id).toBe(config.holders[i]!.id);
      expect(result.shares[i]!.data.length).toBeGreaterThan(0);
    }

    // Shares are distinct
    expect(bytesEqual(result.shares[0].data, result.shares[1].data)).toBe(
      false,
    );
    expect(bytesEqual(result.shares[1].data, result.shares[2].data)).toBe(
      false,
    );
  });

  it("splitKey rejects invalid config", async () => {
    const keyMaterial = crypto.getRandomValues(new Uint8Array(32));
    const [h1, h2, h3] = await Promise.all([
      createTestHolder("a"),
      createTestHolder("b"),
      createTestHolder("c"),
    ]);

    // Wrong holder count
    await expect(
      splitKey(keyMaterial, "kek-1", {
        totalShares: 3,
        threshold: 2,
        holders: [h1.holder, h2.holder],
      }),
    ).rejects.toThrow();

    // Threshold < 2
    await expect(
      splitKey(keyMaterial, "kek-1", {
        totalShares: 3,
        threshold: 1,
        holders: [h1.holder, h2.holder, h3.holder],
      }),
    ).rejects.toThrow();

    // Threshold > totalShares
    await expect(
      splitKey(keyMaterial, "kek-1", {
        totalShares: 3,
        threshold: 4,
        holders: [h1.holder, h2.holder, h3.holder],
      }),
    ).rejects.toThrow();

    // keyMaterial not 32 bytes
    await expect(
      splitKey(new Uint8Array(16), "kek-1", {
        totalShares: 3,
        threshold: 2,
        holders: [h1.holder, h2.holder, h3.holder],
      }),
    ).rejects.toThrow();
  });

  // --- reconstructKey ---

  it("reconstructKey recovers original key from any 2 of 3 shares", async () => {
    const kek = await generateKEK();
    const keyMaterial = await exportKeyMaterial(kek);
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
    const { shares } = await splitKey(keyMaterial, kek.id, config);

    // All 3 combinations of 2 shares
    const combos = [
      [shares[0], shares[1]],
      [shares[0], shares[2]],
      [shares[1], shares[2]],
    ];
    for (const combo of combos) {
      const recovered = await reconstructKey(combo, 2);
      expect(bytesEqual(recovered, keyMaterial)).toBe(true);
    }
  });

  it("reconstructed key can decrypt data encrypted with original", async () => {
    const kek = await generateKEK();
    const plaintext = new TextEncoder().encode("threshold integration test");
    const blob = await encrypt(plaintext, kek, "entity-threshold");

    const keyMaterial = await exportKeyMaterial(kek);
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
    const { shares } = await splitKey(keyMaterial, kek.id, config);

    // Reconstruct from 2 shares
    const recovered = await reconstructKey([shares[0], shares[2]], 2);
    const restoredKek = await importKeyMaterial(recovered, kek.id, kek.epoch);
    const decrypted = await decrypt(blob, restoredKek);
    expect(bytesEqual(decrypted, plaintext)).toBe(true);
  });

  it("single share cannot reconstruct", async () => {
    const keyMaterial = crypto.getRandomValues(new Uint8Array(32));
    const holders = await Promise.all([
      createTestHolder("a"),
      createTestHolder("b"),
      createTestHolder("c"),
    ]);
    const config: ThresholdConfig = {
      totalShares: 3,
      threshold: 2,
      holders: holders.map((h) => h.holder),
    };
    const { shares } = await splitKey(keyMaterial, "kek-single", config);

    await expect(reconstructKey([shares[0]], 2)).rejects.toThrow(
      "insufficient shares",
    );
  });

  it("shares from different KEKs rejected", async () => {
    const holders = await Promise.all([
      createTestHolder("a"),
      createTestHolder("b"),
      createTestHolder("c"),
    ]);
    const config: ThresholdConfig = {
      totalShares: 3,
      threshold: 2,
      holders: holders.map((h) => h.holder),
    };

    const mat1 = crypto.getRandomValues(new Uint8Array(32));
    const mat2 = crypto.getRandomValues(new Uint8Array(32));
    const { shares: shares1 } = await splitKey(mat1, "kek-A", config);
    const { shares: shares2 } = await splitKey(mat2, "kek-B", config);

    await expect(
      reconstructKey([shares1[0], shares2[1]], 2),
    ).rejects.toThrow("shares must belong to the same KEK");
  });

  // --- createDestructionAttestation ---

  it("creates valid attestation", async () => {
    const { holder, privateKey } = await createTestHolder("operator");
    const attestation = await createDestructionAttestation(
      "kek-attest",
      1,
      holder,
      privateKey,
    );

    expect(attestation.kekId).toBe("kek-attest");
    expect(attestation.shareIndex).toBe(1);
    expect(attestation.holder.id).toBe(holder.id);
    expect(new Date(attestation.destroyedAt).getTime()).not.toBeNaN();
    expect(attestation.signature).toBeInstanceOf(Uint8Array);
    expect(attestation.signature.length).toBe(64);
  });

  // --- verifyDestructionAttestation ---

  it("returns true for valid attestation", async () => {
    const { holder, privateKey } = await createTestHolder("oracle");
    const attestation = await createDestructionAttestation(
      "kek-verify",
      2,
      holder,
      privateKey,
    );

    const valid = await verifyDestructionAttestation(attestation);
    expect(valid).toBe(true);
  });

  it("returns false for wrong public key", async () => {
    const { holder, privateKey } = await createTestHolder("oracle");
    const { holder: otherHolder } = await createTestHolder("imposter");

    const attestation = await createDestructionAttestation(
      "kek-wrong-pk",
      2,
      holder,
      privateKey,
    );

    // Replace holder with one that has a different public key
    const tampered = { ...attestation, holder: otherHolder };
    const valid = await verifyDestructionAttestation(tampered);
    expect(valid).toBe(false);
  });

  it("returns false for tampered kekId", async () => {
    const { holder, privateKey } = await createTestHolder("auditor");
    const attestation = await createDestructionAttestation(
      "kek-original",
      3,
      holder,
      privateKey,
    );

    const tampered = { ...attestation, kekId: "kek-tampered" };
    const valid = await verifyDestructionAttestation(tampered);
    expect(valid).toBe(false);
  });

  // --- verifyThresholdDestruction ---

  it("returns true with sufficient valid attestations", async () => {
    const holders = await Promise.all([
      createTestHolder("operator"),
      createTestHolder("oracle"),
      createTestHolder("auditor"),
    ]);

    const attestations = await Promise.all([
      createDestructionAttestation(
        "kek-threshold",
        1,
        holders[0].holder,
        holders[0].privateKey,
      ),
      createDestructionAttestation(
        "kek-threshold",
        2,
        holders[1].holder,
        holders[1].privateKey,
      ),
    ]);

    const valid = await verifyThresholdDestruction(attestations, 2);
    expect(valid).toBe(true);
  });

  it("returns false with insufficient attestations", async () => {
    const { holder, privateKey } = await createTestHolder("operator");
    const attestation = await createDestructionAttestation(
      "kek-insuff",
      1,
      holder,
      privateKey,
    );

    const valid = await verifyThresholdDestruction([attestation], 2);
    expect(valid).toBe(false);
  });

  it("returns false with duplicate share indices", async () => {
    const holders = await Promise.all([
      createTestHolder("operator"),
      createTestHolder("oracle"),
    ]);

    // Both attestations claim share index 1
    const attestations = await Promise.all([
      createDestructionAttestation(
        "kek-dup",
        1,
        holders[0].holder,
        holders[0].privateKey,
      ),
      createDestructionAttestation(
        "kek-dup",
        1,
        holders[1].holder,
        holders[1].privateKey,
      ),
    ]);

    const valid = await verifyThresholdDestruction(attestations, 2);
    expect(valid).toBe(false);
  });

  it("returns false with mismatched kekIds", async () => {
    const holders = await Promise.all([
      createTestHolder("operator"),
      createTestHolder("oracle"),
    ]);

    const attestations = await Promise.all([
      createDestructionAttestation(
        "kek-X",
        1,
        holders[0].holder,
        holders[0].privateKey,
      ),
      createDestructionAttestation(
        "kek-Y",
        2,
        holders[1].holder,
        holders[1].privateKey,
      ),
    ]);

    const valid = await verifyThresholdDestruction(attestations, 2);
    expect(valid).toBe(false);
  });

  it("returns false if any signature is invalid", async () => {
    const holders = await Promise.all([
      createTestHolder("operator"),
      createTestHolder("oracle"),
    ]);

    const attestations = await Promise.all([
      createDestructionAttestation(
        "kek-badsig",
        1,
        holders[0].holder,
        holders[0].privateKey,
      ),
      createDestructionAttestation(
        "kek-badsig",
        2,
        holders[1].holder,
        holders[1].privateKey,
      ),
    ]);

    // Flip a byte in the second attestation's signature
    const tamperedSig = new Uint8Array(attestations[1]!.signature);
    tamperedSig[0] = tamperedSig[0]! ^ 0xff;
    attestations[1] = { ...attestations[1]!, signature: tamperedSig };

    const valid = await verifyThresholdDestruction(attestations, 2);
    expect(valid).toBe(false);
  });
});
