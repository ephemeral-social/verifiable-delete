import { describe, it, expect } from "vitest";
import {
  runDeletionScan,
  hashScanResult,
  type StorageScanner,
  type BackendScanResult,
  type ScanResult,
} from "./index.js";

function makeScanner(
  type: string,
  absent: boolean,
  note?: string,
  delay?: number,
): StorageScanner {
  return {
    type,
    checkAbsence: async (entityId: string): Promise<BackendScanResult> => {
      if (delay !== undefined) {
        await new Promise((r) => setTimeout(r, delay));
      }
      return {
        type,
        identifier: `table_${type}`,
        query: `SELECT * FROM ${type} WHERE entity_id = '${entityId}'`,
        absent,
        scannedAt: new Date().toISOString(),
        ...(note !== undefined ? { note } : {}),
      };
    },
  };
}

function makeThrowingScanner(type: string, errorMessage: string): StorageScanner {
  return {
    type,
    checkAbsence: async () => {
      throw new Error(errorMessage);
    },
  };
}

describe("scan", () => {
  // Test 1: all backends absent + key verified
  it("all backends absent + key verified → allVerified true, empty caveats", async () => {
    const result = await runDeletionScan({
      entityId: "entity-1",
      scanners: [makeScanner("d1", true), makeScanner("kv", true)],
      testCiphertextId: "test-ct-1",
      keyVerified: true,
    });

    expect(result.allVerified).toBe(true);
    expect(result.caveats).toEqual([]);
    expect(result.backends).toHaveLength(2);
    expect(result.backends.every((b) => b.absent)).toBe(true);
    expect(result.entityId).toBe("entity-1");
    expect(result.scanId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(result.keyVerification.testCiphertextId).toBe("test-ct-1");
    expect(result.keyVerification.expectedFailure).toBe(true);
  });

  // Test 2: one backend not absent
  it("one backend not absent → allVerified false", async () => {
    const result = await runDeletionScan({
      entityId: "entity-2",
      scanners: [makeScanner("d1", true), makeScanner("kv", false)],
      testCiphertextId: "test-ct-2",
      keyVerified: true,
    });

    expect(result.allVerified).toBe(false);
  });

  // Test 3: key not verified
  it("key not verified → allVerified false, caveat present", async () => {
    const result = await runDeletionScan({
      entityId: "entity-3",
      scanners: [makeScanner("d1", true)],
      testCiphertextId: "test-ct-3",
      keyVerified: false,
      keyError: "decryption succeeded unexpectedly",
    });

    expect(result.allVerified).toBe(false);
    expect(result.caveats.length).toBeGreaterThanOrEqual(1);
    expect(result.caveats.some((c) => c.includes("Key verification failed"))).toBe(true);
    expect(result.caveats.some((c) => c.includes("decryption succeeded unexpectedly"))).toBe(true);
  });

  // Test 4: zero scanners + key verified → vacuously true
  it("zero scanners + key verified → allVerified true", async () => {
    const result = await runDeletionScan({
      entityId: "entity-4",
      scanners: [],
      testCiphertextId: "test-ct-4",
      keyVerified: true,
    });

    expect(result.allVerified).toBe(true);
    expect(result.backends).toHaveLength(0);
    expect(result.caveats).toEqual([]);
  });

  // Test 5: zero scanners + key not verified
  it("zero scanners + key not verified → allVerified false", async () => {
    const result = await runDeletionScan({
      entityId: "entity-5",
      scanners: [],
      testCiphertextId: "test-ct-5",
      keyVerified: false,
    });

    expect(result.allVerified).toBe(false);
  });

  // Test 6: scanner error handled gracefully
  it("scanner error → absent false + error note", async () => {
    const result = await runDeletionScan({
      entityId: "entity-6",
      scanners: [makeThrowingScanner("r2", "Connection timeout")],
      testCiphertextId: "test-ct-6",
      keyVerified: true,
    });

    expect(result.allVerified).toBe(false);
    expect(result.backends).toHaveLength(1);
    expect(result.backends[0]!.absent).toBe(false);
    expect(result.backends[0]!.note).toContain("Connection timeout");
  });

  // Test 7: notes in caveats (absent=true with note)
  it("absent backend with note → allVerified true, caveat present", async () => {
    const result = await runDeletionScan({
      entityId: "entity-7",
      scanners: [makeScanner("kv", true, "eventual consistency: may appear for ~60s")],
      testCiphertextId: "test-ct-7",
      keyVerified: true,
    });

    expect(result.allVerified).toBe(true);
    expect(result.caveats.length).toBe(1);
    expect(result.caveats[0]).toContain("eventual consistency");
  });

  // Test 8: hashScanResult deterministic
  it("hashScanResult is deterministic", async () => {
    const scanResult: ScanResult = {
      scanId: "fixed-id",
      timestamp: "2024-01-01T00:00:00.000Z",
      entityId: "entity-8",
      backends: [],
      keyVerification: { testCiphertextId: "tc-8", expectedFailure: true },
      allVerified: true,
      caveats: [],
    };

    const hash1 = await hashScanResult(scanResult);
    const hash2 = await hashScanResult(scanResult);
    expect(hash1).toBe(hash2);
  });

  // Test 9: hashScanResult changes with different input
  it("hashScanResult changes with different entityId", async () => {
    const base: ScanResult = {
      scanId: "fixed-id",
      timestamp: "2024-01-01T00:00:00.000Z",
      entityId: "entity-A",
      backends: [],
      keyVerification: { testCiphertextId: "tc", expectedFailure: true },
      allVerified: true,
      caveats: [],
    };

    const modified: ScanResult = { ...base, entityId: "entity-B" };

    const hash1 = await hashScanResult(base);
    const hash2 = await hashScanResult(modified);
    expect(hash1).not.toBe(hash2);
  });

  // Test 10: hashScanResult returns 64-char hex
  it("hashScanResult returns 64-char hex string", async () => {
    const scanResult: ScanResult = {
      scanId: "some-id",
      timestamp: "2024-01-01T00:00:00.000Z",
      entityId: "entity-10",
      backends: [],
      keyVerification: { testCiphertextId: "tc", expectedFailure: true },
      allVerified: true,
      caveats: [],
    };

    const hash = await hashScanResult(scanResult);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  // Test 11: scanners run concurrently
  it("scanners run concurrently (total time < sum of delays)", async () => {
    const delayMs = 50;
    const scanners = [
      makeScanner("d1", true, undefined, delayMs),
      makeScanner("kv", true, undefined, delayMs),
      makeScanner("r2", true, undefined, delayMs),
    ];

    const start = Date.now();
    await runDeletionScan({
      entityId: "entity-11",
      scanners,
      testCiphertextId: "tc-11",
      keyVerified: true,
    });
    const elapsed = Date.now() - start;

    // If sequential, would take ~150ms. Concurrent should be ~50ms.
    // Use generous threshold to avoid flaky tests.
    expect(elapsed).toBeLessThan(delayMs * 2.5);
  });

  // Test 12: hashScanResult ignores field order (canonical JSON)
  it("hashScanResult produces same hash regardless of field order", async () => {
    const scanResult1: ScanResult = {
      scanId: "id-12",
      timestamp: "2024-06-01T00:00:00.000Z",
      entityId: "entity-12",
      backends: [],
      keyVerification: { testCiphertextId: "tc", expectedFailure: true },
      allVerified: true,
      caveats: [],
    };

    // Construct with reordered keys via Object.assign
    const scanResult2 = {} as ScanResult;
    Object.assign(scanResult2, {
      caveats: [],
      entityId: "entity-12",
      allVerified: true,
      scanId: "id-12",
      backends: [],
      keyVerification: { expectedFailure: true, testCiphertextId: "tc" },
      timestamp: "2024-06-01T00:00:00.000Z",
    });

    const hash1 = await hashScanResult(scanResult1);
    const hash2 = await hashScanResult(scanResult2);
    expect(hash1).toBe(hash2);
  });
});
