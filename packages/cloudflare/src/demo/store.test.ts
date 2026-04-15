import { describe, it, expect } from "vitest";
import { storeDemoData, deleteDemoData } from "./store.js";
import type { EncryptedBlob } from "@ephemeral-social/verifiable-delete";
import type { Env } from "../env.js";

function createMockEnv() {
  const calls: { target: string; method: string; args: unknown[] }[] = [];

  const env = {
    DB: {
      prepare: (sql: string) => ({
        bind: (...args: unknown[]) => ({
          run: async () => {
            calls.push({ target: "d1", method: "run", args: [sql, ...args] });
            return { success: true };
          },
        }),
      }),
    },
    KV: {
      put: async (key: string, value: string) => {
        calls.push({ target: "kv", method: "put", args: [key, value] });
      },
      delete: async (key: string) => {
        calls.push({ target: "kv", method: "delete", args: [key] });
      },
    },
    BUCKET: {
      put: async (key: string, value: unknown) => {
        calls.push({ target: "r2", method: "put", args: [key, value] });
      },
      delete: async (key: string) => {
        calls.push({ target: "r2", method: "delete", args: [key] });
      },
    },
  } as unknown as Env;

  return { env, calls };
}

function createTestBlob(): EncryptedBlob {
  return {
    ciphertext: new Uint8Array([1, 2, 3, 4]),
    nonce: new Uint8Array([5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
    wrappedDek: new Uint8Array([17, 18, 19, 20]),
    entityId: "test-entity",
    kekId: "kek-123",
  };
}

describe("storeDemoData", () => {
  it("writes to D1 with correct hex values", async () => {
    const { env, calls } = createMockEnv();
    const blob = createTestBlob();

    await storeDemoData(env, "test-entity", blob);

    const d1Call = calls.find((c) => c.target === "d1");
    expect(d1Call).toBeDefined();
    expect(d1Call!.args[0]).toContain("INSERT OR REPLACE INTO demo_data");
    // entity_id
    expect(d1Call!.args[1]).toBe("test-entity");
    // hex-encoded ciphertext: [1,2,3,4] -> "01020304"
    expect(d1Call!.args[2]).toBe("01020304");
    // hex-encoded nonce: [5..16] -> "05060708090a0b0c0d0e0f10"
    expect(d1Call!.args[3]).toBe("05060708090a0b0c0d0e0f10");
    // hex-encoded wrappedDek: [17,18,19,20] -> "11121314"
    expect(d1Call!.args[4]).toBe("11121314");
    // kekId
    expect(d1Call!.args[5]).toBe("kek-123");
  });

  it("writes to KV with correct key", async () => {
    const { env, calls } = createMockEnv();
    const blob = createTestBlob();

    await storeDemoData(env, "test-entity", blob);

    const kvCall = calls.find((c) => c.target === "kv");
    expect(kvCall).toBeDefined();
    expect(kvCall!.method).toBe("put");
    expect(kvCall!.args[0]).toBe("entity:test-entity");
    const value = JSON.parse(kvCall!.args[1] as string);
    expect(value.encrypted_blob).toBe("01020304");
    expect(value.kek_id).toBe("kek-123");
  });

  it("writes to R2 with correct key", async () => {
    const { env, calls } = createMockEnv();
    const blob = createTestBlob();

    await storeDemoData(env, "test-entity", blob);

    const r2Call = calls.find((c) => c.target === "r2");
    expect(r2Call).toBeDefined();
    expect(r2Call!.method).toBe("put");
    expect(r2Call!.args[0]).toBe("entity/test-entity");
    expect(r2Call!.args[1]).toEqual(new Uint8Array([1, 2, 3, 4]));
  });
});

describe("deleteDemoData", () => {
  it("removes from D1", async () => {
    const { env, calls } = createMockEnv();

    await deleteDemoData(env, "test-entity");

    const d1Call = calls.find((c) => c.target === "d1");
    expect(d1Call).toBeDefined();
    expect(d1Call!.args[0]).toContain("DELETE FROM demo_data");
    expect(d1Call!.args[1]).toBe("test-entity");
  });

  it("removes from KV", async () => {
    const { env, calls } = createMockEnv();

    await deleteDemoData(env, "test-entity");

    const kvCall = calls.find((c) => c.target === "kv");
    expect(kvCall).toBeDefined();
    expect(kvCall!.method).toBe("delete");
    expect(kvCall!.args[0]).toBe("entity:test-entity");
  });

  it("removes from R2", async () => {
    const { env, calls } = createMockEnv();

    await deleteDemoData(env, "test-entity");

    const r2Call = calls.find((c) => c.target === "r2");
    expect(r2Call).toBeDefined();
    expect(r2Call!.method).toBe("delete");
    expect(r2Call!.args[0]).toBe("entity/test-entity");
  });
});
