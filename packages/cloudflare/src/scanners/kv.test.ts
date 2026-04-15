import { describe, it, expect } from "vitest";
import { sha256hex } from "@ephemeral-social/verifiable-delete";
import { KVScanner } from "./kv.js";

function mockKV(value: string | null, shouldThrow = false): KVNamespace {
  return {
    get: async (_key: string) => {
      if (shouldThrow) throw new Error("KV unavailable");
      return value;
    },
  } as unknown as KVNamespace;
}

describe("KVScanner", () => {
  it("returns absent=true when get returns null", async () => {
    const scanner = new KVScanner(mockKV(null));
    const result = await scanner.checkAbsence("entity-123");
    expect(result.absent).toBe(true);
    expect(result.type).toBe("kv");
  });

  it("returns absent=false when get returns data", async () => {
    const scanner = new KVScanner(mockKV("some-data"));
    const result = await scanner.checkAbsence("entity-123");
    expect(result.absent).toBe(false);
  });

  it("includes eventual consistency caveat on both absent=true and absent=false", async () => {
    const scannerAbsent = new KVScanner(mockKV(null));
    const resultAbsent = await scannerAbsent.checkAbsence("entity-123");
    expect(resultAbsent.note).toContain("eventually consistent");

    const scannerPresent = new KVScanner(mockKV("data"));
    const resultPresent = await scannerPresent.checkAbsence("entity-123");
    expect(resultPresent.note).toContain("eventually consistent");
  });

  it("uses hashed entityId in key and query (privacy)", async () => {
    const scanner = new KVScanner(mockKV(null));
    const result = await scanner.checkAbsence("my-entity-456");
    const expectedHash = sha256hex(new TextEncoder().encode("my-entity-456"));
    expect(result.identifier).toBe(`entity:${expectedHash}`);
    expect(result.query).toContain(expectedHash);
    // Must NOT contain the raw entityId
    expect(result.identifier).not.toContain("my-entity-456");
    expect(result.query).not.toContain("my-entity-456");
  });

  it("handles KV error with absent=false and error note", async () => {
    const scanner = new KVScanner(mockKV(null, true));
    const result = await scanner.checkAbsence("entity-123");
    expect(result.absent).toBe(false);
    expect(result.note).toContain("KV error");
    expect(result.note).toContain("KV unavailable");
  });
});
