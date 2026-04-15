import { describe, it, expect } from "vitest";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { bytesToHex } from "@noble/hashes/utils";
import { verifyDestructionAttestation, deserializeAttestation } from "@ephemeral-social/verifiable-delete";
import { KeyShareStorage, type SqlStorageLike } from "./key-share-storage.js";

// Ed25519 requires sha512 sync fallback
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

/**
 * In-memory mock of DO SqlStorage.
 * Pattern-matches on SQL strings and stores data in Maps.
 */
class MockSqlStorage implements SqlStorageLike {
  private keypair: { private_key: string; public_key: string } | null = null;
  private shares = new Map<string, { share_index: number; share_data: string }>();

  exec<T>(query: string, ...bindings: unknown[]): { toArray(): T[] } {
    const q = query.trim();

    if (q.startsWith("CREATE TABLE")) {
      return { toArray: () => [] as T[] };
    }

    if (q.includes("INSERT INTO keypair")) {
      this.keypair = {
        private_key: bindings[0] as string,
        public_key: bindings[1] as string,
      };
      return { toArray: () => [] as T[] };
    }

    if (q.includes("INSERT OR REPLACE INTO shares")) {
      this.shares.set(bindings[0] as string, {
        share_index: bindings[1] as number,
        share_data: bindings[2] as string,
      });
      return { toArray: () => [] as T[] };
    }

    if (q.includes("SELECT private_key, public_key FROM keypair")) {
      const result = this.keypair ? [this.keypair] : [];
      return { toArray: () => result as T[] };
    }

    if (q.includes("SELECT kek_id FROM shares WHERE")) {
      const kekId = bindings[0] as string;
      const share = this.shares.get(kekId);
      return { toArray: () => (share ? [{ kek_id: kekId }] : []) as T[] };
    }

    if (q.includes("SELECT share_index, share_data FROM shares WHERE")) {
      const kekId = bindings[0] as string;
      const share = this.shares.get(kekId);
      return { toArray: () => (share ? [share] : []) as T[] };
    }

    if (q.includes("DELETE FROM shares WHERE")) {
      this.shares.delete(bindings[0] as string);
      return { toArray: () => [] as T[] };
    }

    return { toArray: () => [] as T[] };
  }
}

describe("KeyShareStorage", () => {
  it("getOrCreateKeypair generates a 64-char hex public key on first call", async () => {
    const storage = new KeyShareStorage(new MockSqlStorage());
    const { publicKey } = await storage.getOrCreateKeypair();

    expect(typeof publicKey).toBe("string");
    expect(publicKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it("getOrCreateKeypair returns the same keypair on second call", async () => {
    const storage = new KeyShareStorage(new MockSqlStorage());
    const first = await storage.getOrCreateKeypair();
    const second = await storage.getOrCreateKeypair();

    expect(first.publicKey).toBe(second.publicKey);
    expect(bytesToHex(first.privateKey)).toBe(bytesToHex(second.privateKey));
  });

  it("getShareHolder returns a valid ShareHolder with id, label, and publicKey", async () => {
    const storage = new KeyShareStorage(new MockSqlStorage());
    const holder = await storage.getShareHolder("operator");

    expect(holder.id).toHaveLength(16);
    expect(holder.label).toBe("operator");
    expect(holder.publicKey).toBeInstanceOf(Uint8Array);
    expect(holder.publicKey.length).toBe(32);
  });

  it("storeShare persists share data — hasShare returns true", async () => {
    const storage = new KeyShareStorage(new MockSqlStorage());
    const shareData = crypto.getRandomValues(new Uint8Array(48));

    await storage.storeShare("kek-001", 1, shareData);

    expect(await storage.hasShare("kek-001")).toBe(true);
  });

  it("hasShare returns false for unknown kekId", async () => {
    const storage = new KeyShareStorage(new MockSqlStorage());

    expect(await storage.hasShare("kek-nonexistent")).toBe(false);
  });

  it("destroyShare deletes share from storage — hasShare returns false after", async () => {
    const storage = new KeyShareStorage(new MockSqlStorage());
    const shareData = crypto.getRandomValues(new Uint8Array(48));
    await storage.storeShare("kek-002", 2, shareData);

    await storage.destroyShare("kek-002", "operator");

    expect(await storage.hasShare("kek-002")).toBe(false);
  });

  it("destroyShare returns a SerializedDestructionAttestation with hex strings", async () => {
    const storage = new KeyShareStorage(new MockSqlStorage());
    const shareData = crypto.getRandomValues(new Uint8Array(48));
    await storage.storeShare("kek-003", 3, shareData);

    const attestation = await storage.destroyShare("kek-003", "oracle");

    expect(attestation.kekId).toBe("kek-003");
    expect(attestation.shareIndex).toBe(3);
    expect(typeof attestation.signature).toBe("string");
    expect(attestation.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(typeof attestation.holder.publicKey).toBe("string");
    expect(attestation.holder.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(attestation.holder.label).toBe("oracle");
    expect(attestation.destroyedAt).toBeTruthy();
  });

  it("destroyShare attestation is verifiable after deserialization", async () => {
    const storage = new KeyShareStorage(new MockSqlStorage());
    const shareData = crypto.getRandomValues(new Uint8Array(48));
    await storage.storeShare("kek-004", 1, shareData);

    const serialized = await storage.destroyShare("kek-004", "auditor");
    const attestation = deserializeAttestation(serialized);
    const valid = await verifyDestructionAttestation(attestation);

    expect(valid).toBe(true);
  });

  it("destroyShare on missing share throws 'No share found' error", async () => {
    const storage = new KeyShareStorage(new MockSqlStorage());

    await expect(storage.destroyShare("kek-missing", "operator")).rejects.toThrow(
      "No share found for kekId: kek-missing",
    );
  });

  it("storeShare overwrites existing share via INSERT OR REPLACE", async () => {
    const storage = new KeyShareStorage(new MockSqlStorage());
    const shareData1 = crypto.getRandomValues(new Uint8Array(48));
    const shareData2 = crypto.getRandomValues(new Uint8Array(48));

    await storage.storeShare("kek-005", 1, shareData1);
    await storage.storeShare("kek-005", 2, shareData2);

    // Should not throw, and the share should still exist
    expect(await storage.hasShare("kek-005")).toBe(true);
  });
});
