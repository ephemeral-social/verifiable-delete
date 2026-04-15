import { describe, it, expect } from "vitest";
import { D1Scanner } from "./d1.js";

function mockD1(result: { count: number } | null, shouldThrow = false): D1Database {
  return {
    prepare: (_sql: string) => ({
      bind: (..._args: unknown[]) => ({
        first: async () => {
          if (shouldThrow) throw new Error("D1 unavailable");
          return result;
        },
      }),
    }),
  } as unknown as D1Database;
}

describe("D1Scanner", () => {
  it("returns absent=true when COUNT returns 0", async () => {
    const scanner = new D1Scanner(mockD1({ count: 0 }));
    const result = await scanner.checkAbsence("entity-123");
    expect(result.absent).toBe(true);
    expect(result.type).toBe("d1");
  });

  it("returns absent=false when COUNT > 0", async () => {
    const scanner = new D1Scanner(mockD1({ count: 3 }));
    const result = await scanner.checkAbsence("entity-123");
    expect(result.absent).toBe(false);
  });

  it("includes D1 Time Travel caveat when data is present", async () => {
    const scanner = new D1Scanner(mockD1({ count: 1 }));
    const result = await scanner.checkAbsence("entity-123");
    expect(result.note).toContain("Time Travel");
  });

  it("includes correct table and entity_id in query", async () => {
    const scanner = new D1Scanner(mockD1({ count: 0 }), "my_table");
    const result = await scanner.checkAbsence("entity-456");
    expect(result.query).toContain("my_table");
    expect(result.identifier).toBe("my_table");
  });

  it("handles D1 error with absent=false and error note", async () => {
    const scanner = new D1Scanner(mockD1(null, true));
    const result = await scanner.checkAbsence("entity-123");
    expect(result.absent).toBe(false);
    expect(result.note).toContain("D1 query error");
    expect(result.note).toContain("D1 unavailable");
  });
});
