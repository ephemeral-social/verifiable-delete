import { describe, it, expect } from "vitest";
import { sha256hex } from "@ephemeral-social/verifiable-delete";
import { R2Scanner } from "./r2.js";

function mockR2(headResult: object | null, shouldThrow = false): R2Bucket {
  return {
    head: async (_key: string) => {
      if (shouldThrow) throw new Error("R2 unavailable");
      return headResult;
    },
  } as unknown as R2Bucket;
}

describe("R2Scanner", () => {
  it("returns absent=true when head returns null", async () => {
    const scanner = new R2Scanner(mockR2(null));
    const result = await scanner.checkAbsence("entity-123");
    expect(result.absent).toBe(true);
    expect(result.type).toBe("r2");
  });

  it("returns absent=false when head returns object", async () => {
    const scanner = new R2Scanner(mockR2({ size: 1024, httpEtag: "abc" }));
    const result = await scanner.checkAbsence("entity-123");
    expect(result.absent).toBe(false);
  });

  it("uses hashed entityId in key and query (privacy)", async () => {
    const scanner = new R2Scanner(mockR2(null));
    const result = await scanner.checkAbsence("my-entity-789");
    const expectedHash = sha256hex(new TextEncoder().encode("my-entity-789"));
    expect(result.identifier).toBe(`entity/${expectedHash}`);
    expect(result.query).toContain(expectedHash);
    // Must NOT contain the raw entityId
    expect(result.identifier).not.toContain("my-entity-789");
    expect(result.query).not.toContain("my-entity-789");
  });

  it("handles R2 error with absent=false and error note", async () => {
    const scanner = new R2Scanner(mockR2(null, true));
    const result = await scanner.checkAbsence("entity-123");
    expect(result.absent).toBe(false);
    expect(result.note).toContain("R2 error");
    expect(result.note).toContain("R2 unavailable");
  });

  it("returns a valid ISO 8601 scannedAt timestamp", async () => {
    const scanner = new R2Scanner(mockR2(null));
    const result = await scanner.checkAbsence("entity-123");
    const parsed = new Date(result.scannedAt);
    expect(parsed.toISOString()).toBe(result.scannedAt);
  });
});
