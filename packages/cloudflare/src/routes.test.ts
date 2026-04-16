/**
 * Worker route tests.
 *
 * Tests the fetch handler with a mock Env, verifying status codes,
 * content types, and basic response structure.
 */
import { describe, it, expect } from "vitest";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { bytesToHex } from "@noble/hashes/utils";
import type { Env } from "./env.js";
import {
  createSMT,
  entityToKey,
  serializeProof,
  type InclusionProof,
  type SignedTreeHead,
  type LogEntry,
} from "@ephemeral-social/verifiable-delete";

// Ed25519 sync setup
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

// Import the default export (worker)
import worker from "./index.js";

// --- Mock Env ---

function createMockEnv(): Env {
  const logSigningKey = crypto.getRandomValues(new Uint8Array(32));
  const mockEntries: LogEntry[] = [
    {
      index: 0,
      receiptId: "test-receipt-1",
      timestamp: new Date().toISOString(),
      entityType: "demo_data",
      commitment: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
      deletionMethod: "crypto_shredding_2of3",
      thresholdSignatures: [],
      scanHash: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
      smtRoot: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
      operatorSignature: bytesToHex(crypto.getRandomValues(new Uint8Array(64))),
    },
  ];

  return {
    DB: {
      prepare: () => ({
        bind: () => ({
          run: async () => ({ success: true }),
          first: async () => ({ count: 0 }),
        }),
      }),
      exec: async () => ({}),
    } as unknown as D1Database,

    KV: {
      put: async () => {},
      get: async () => null,
      delete: async () => {},
    } as unknown as KVNamespace,

    BUCKET: {
      put: async () => {},
      head: async () => null,
      delete: async () => {},
    } as unknown as R2Bucket,

    KEY_SHARE_DO: {
      idFromName: (name: string) => ({ toString: () => name }),
      get: () =>
        new Proxy(
          {},
          {
            get: (_target, prop: string) => {
              if (prop === "getShareHolder") {
                return async (label: string) => {
                  const pk = crypto.getRandomValues(new Uint8Array(32));
                  const publicKey = await ed.getPublicKeyAsync(pk);
                  return { id: bytesToHex(publicKey).slice(0, 16), label, publicKey };
                };
              }
              if (prop === "storeShare") return async () => {};
              if (prop === "destroyShare") {
                return async (kekId: string, holderLabel: string) => {
                  const pk = crypto.getRandomValues(new Uint8Array(32));
                  const publicKey = await ed.getPublicKeyAsync(pk);
                  const destroyedAt = new Date().toISOString();
                  const msg = new TextEncoder().encode(
                    `vd-destroy-v1:${kekId}:1:${destroyedAt}`,
                  );
                  const signature = await ed.signAsync(msg, pk);
                  return {
                    kekId,
                    shareIndex: 1,
                    holder: { id: bytesToHex(publicKey).slice(0, 16), label: holderLabel, publicKey: bytesToHex(publicKey) },
                    destroyedAt,
                    signature: bytesToHex(new Uint8Array(signature)),
                  };
                };
              }
              return undefined;
            },
          },
        ),
    } as unknown as Env["KEY_SHARE_DO"],

    TRANSPARENCY_LOG_DO: {
      idFromName: () => ({ toString: () => "main" }),
      get: () => ({
        append: async (): Promise<InclusionProof> => ({
          logIndex: 0,
          treeSize: 1,
          rootHash: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
          hashes: [],
        }),
        getTreeHead: async (): Promise<SignedTreeHead> => {
          const timestamp = new Date().toISOString();
          const rootHash = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
          const msg = new TextEncoder().encode(
            `vd-tree-head-v1:1:${rootHash}:${timestamp}`,
          );
          const signature = bytesToHex(await ed.signAsync(msg, logSigningKey));
          return { treeSize: 1, rootHash, timestamp, signature };
        },
        getInclusionProof: async (index: number): Promise<InclusionProof> => {
          if (index >= mockEntries.length) throw new Error("Index out of range");
          return {
            logIndex: index,
            treeSize: mockEntries.length,
            rootHash: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
            hashes: [],
          };
        },
        getConsistencyProof: async () => ({
          fromSize: 0,
          toSize: 1,
          fromRoot: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
          toRoot: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
          hashes: [],
        }),
        getEntry: async (receiptId: string) =>
          mockEntries.find((e) => e.receiptId === receiptId) ?? null,
        getEntries: async (offset: number, limit: number) =>
          mockEntries.slice(offset, offset + limit),
      }),
    } as unknown as Env["TRANSPARENCY_LOG_DO"],

    SMT_DO: (() => {
      const smt = createSMT();
      return {
        idFromName: () => ({ toString: () => "main" }),
        get: () => ({
          addEntity: async (entityId: string) => {
            const key = entityToKey(entityId);
            smt.add(key, key);
            return smt.root as string;
          },
          removeEntity: async (entityId: string) => {
            const key = entityToKey(entityId);
            smt.delete(key);
            const proof = smt.createProof(key);
            return serializeProof(proof, entityId);
          },
          getRoot: async () => smt.root as string,
        }),
      };
    })() as unknown as Env["SMT_DO"],
  };
}

function makeRequest(path: string, method = "GET", body?: unknown): Request {
  const opts: RequestInit = { method };
  if (body) {
    opts.headers = { "Content-Type": "application/json" };
    opts.body = JSON.stringify(body);
  }
  return new Request(`http://localhost${path}`, opts);
}

// --- Tests ---

function createMockEnvWithOperatorKey(operatorKey: string): Env {
  const base = createMockEnv();
  return { ...base, OPERATOR_SIGNING_KEY: operatorKey };
}

describe("worker routes", () => {
  it("GET / returns HTML with Content-Type text/html", async () => {
    const env = createMockEnv();
    const res = await worker.fetch(makeRequest("/"), env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("text/html");
    const html = await res.text();
    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("Verifiable Delete");
    expect(html).toContain("tab-receipts");
    expect(html).toContain("inspector-panel");
  });

  it("POST /demo/delete returns SSE Content-Type", async () => {
    const env = createMockEnv();
    const res = await worker.fetch(
      makeRequest("/demo/delete", "POST", { data: "test" }),
      env,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("text/event-stream");
  });

  it("GET /log returns JSON with treeSize", async () => {
    const env = createMockEnv();
    const res = await worker.fetch(makeRequest("/log"), env);
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("application/json");
    const data = await res.json();
    expect(data).toHaveProperty("treeSize");
    expect(data).toHaveProperty("rootHash");
    expect(data).toHaveProperty("signature");
  });

  it("GET /log/entries respects offset/limit", async () => {
    const env = createMockEnv();
    const res = await worker.fetch(makeRequest("/log/entries?offset=0&limit=10"), env);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(Array.isArray(data)).toBe(true);
  });

  it("GET /log/entry/unknown returns 404", async () => {
    const env = createMockEnv();
    const res = await worker.fetch(makeRequest("/log/entry/nonexistent-id"), env);
    expect(res.status).toBe(404);
    const data = await res.json();
    expect(data).toHaveProperty("error");
  });

  it("GET /.well-known/vd-operator-key returns 503 when secret not configured", async () => {
    const env = createMockEnv();
    const res = await worker.fetch(makeRequest("/.well-known/vd-operator-key"), env);
    expect(res.status).toBe(503);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Operator signing key not configured");
  });

  it("GET /.well-known/vd-operator-key returns valid public key when secret is set", async () => {
    const privateKey = crypto.getRandomValues(new Uint8Array(32));
    const expectedPublicKey = bytesToHex(await ed.getPublicKeyAsync(privateKey));
    const env = createMockEnvWithOperatorKey(bytesToHex(privateKey));
    const res = await worker.fetch(makeRequest("/.well-known/vd-operator-key"), env);
    expect(res.status).toBe(200);
    const data = (await res.json()) as {
      keys: Array<{ id: string; publicKey: string; algorithm: string; activeFrom: string; activeTo: string | null }>;
      verificationMethod: string;
    };
    expect(data.keys).toHaveLength(1);
    const key = data.keys[0]!;
    expect(key.publicKey).toBe(expectedPublicKey);
    expect(key.algorithm).toBe("Ed25519");
    expect(key.id).toBe("operator-key-1");
    expect(key.activeFrom).toBe("2020-01-01T00:00:00.000Z");
    expect(key.activeTo).toBeNull();
    expect(data.verificationMethod).toBe("did:web:verifiabledelete.dev#key-1");
  });

  it("unknown route returns 404", async () => {
    const env = createMockEnv();
    const res = await worker.fetch(makeRequest("/nonexistent"), env);
    expect(res.status).toBe(404);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe("Not found");
  });

  it("/v1/ without auth returns 401", async () => {
    const env = createMockEnv();
    const res = await worker.fetch(makeRequest("/v1/entities", "POST", { entityId: "x", entityType: "x" }), env);
    expect(res.status).toBe(401);
  });

  it("/admin/ without VD_ADMIN_SECRET returns 401", async () => {
    const env = createMockEnv();
    const res = await worker.fetch(makeRequest("/admin/customers"), env);
    expect(res.status).toBe(401);
  });
});
