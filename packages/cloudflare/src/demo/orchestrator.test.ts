/**
 * Orchestrator tests — parse SSE stream and verify pipeline events.
 */
import { describe, it, expect } from "vitest";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { bytesToHex } from "@noble/hashes/utils";
import {
  createDestructionAttestation,
  serializeAttestation,
  createSMT,
  entityToKey,
  serializeProof,
  type ShareHolder,
  type InclusionProof,
  type SignedTreeHead,
} from "@ephemeral-social/verifiable-delete";
import { runDemoDeletion } from "./orchestrator.js";
import type { Env } from "../env.js";

// Ed25519 sync setup
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

// --- Mock infrastructure ---

interface SSEEvent {
  event: string;
  data: Record<string, unknown>;
}

async function parseSSEStream(response: Response): Promise<SSEEvent[]> {
  const text = await response.text();
  const events: SSEEvent[] = [];
  const lines = text.split("\n");
  let currentEvent = "";
  let currentData = "";

  for (const line of lines) {
    if (line.startsWith("event: ")) {
      currentEvent = line.slice(7);
    } else if (line.startsWith("data: ")) {
      currentData = line.slice(6);
    } else if (line === "" && currentEvent && currentData) {
      events.push({ event: currentEvent, data: JSON.parse(currentData) });
      currentEvent = "";
      currentData = "";
    }
  }

  return events;
}

async function createMockHolder(label: string): Promise<{
  holder: ShareHolder;
  privateKey: Uint8Array;
}> {
  const privateKey = crypto.getRandomValues(new Uint8Array(32));
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return {
    holder: {
      id: bytesToHex(publicKey).slice(0, 16),
      label,
      publicKey,
    },
    privateKey,
  };
}

function createMockEnv(options?: { throwOnD1?: boolean; operatorSigningKey?: string }): Env {
  // Track stored data for scanner reads
  const d1Data = new Map<string, boolean>();
  const kvData = new Map<string, string>();
  const r2Data = new Map<string, boolean>();

  // Holders + attestation state
  const holderState = new Map<
    string,
    {
      holder: ShareHolder | null;
      privateKey: Uint8Array | null;
      shares: Map<string, { index: number; data: Uint8Array }>;
    }
  >();

  for (const label of ["operator", "oracle", "auditor"]) {
    holderState.set(label, {
      holder: null,
      privateKey: null,
      shares: new Map(),
    });
  }

  // Log state
  let logIndex = 0;
  const logSigningKey = crypto.getRandomValues(new Uint8Array(32));

  const env: Env = {
    DB: {
      prepare: (sql: string) => ({
        bind: (...args: unknown[]) => ({
          run: async () => {
            if (options?.throwOnD1) throw new Error("D1 unavailable");
            const entityId = args[0] as string;
            if (sql.includes("INSERT")) {
              d1Data.set(entityId, true);
            } else if (sql.includes("DELETE")) {
              d1Data.delete(entityId);
            }
            return { success: true };
          },
          first: async () => {
            if (options?.throwOnD1) throw new Error("D1 unavailable");
            const entityId = args[0] as string;
            return { count: d1Data.has(entityId) ? 1 : 0 };
          },
        }),
      }),
    } as unknown as D1Database,

    KV: {
      put: async (key: string, value: string) => {
        kvData.set(key, value);
      },
      get: async (key: string) => kvData.get(key) ?? null,
      delete: async (key: string) => {
        kvData.delete(key);
      },
    } as unknown as KVNamespace,

    BUCKET: {
      put: async (key: string) => {
        r2Data.set(key, true);
      },
      head: async (key: string) => (r2Data.has(key) ? {} : null),
      delete: async (key: string) => {
        r2Data.delete(key);
      },
    } as unknown as R2Bucket,

    KEY_SHARE_DO: {
      idFromName: (name: string) => ({ toString: () => name }),
      get: (_id: unknown) => {
        // Return a stub proxy that routes to holderState based on the label
        return new Proxy(
          {},
          {
            get: (_target, prop: string) => {
              if (prop === "getShareHolder") {
                return async (label: string) => {
                  const state = holderState.get(label)!;
                  if (!state.holder) {
                    const { holder, privateKey } = await createMockHolder(label);
                    state.holder = holder;
                    state.privateKey = privateKey;
                  }
                  return state.holder;
                };
              }
              if (prop === "storeShare") {
                return async (kekId: string, shareIndex: number, shareData: Uint8Array) => {
                  // Find which holder this DO represents by checking all states
                  // We use the kekId to find which shares map to put in
                  for (const [, state] of holderState) {
                    // Store in the current stub's state (we use closure)
                    if (!state.shares.has(kekId)) {
                      state.shares.set(kekId, { index: shareIndex, data: shareData });
                      break;
                    }
                  }
                };
              }
              if (prop === "destroyShare") {
                return async (kekId: string, holderLabel: string) => {
                  const state = holderState.get(holderLabel)!;
                  const share = state.shares.get(kekId);
                  if (!share) throw new Error(`No share found for kekId: ${kekId}`);
                  state.shares.delete(kekId);

                  if (!state.holder || !state.privateKey) {
                    const { holder, privateKey } = await createMockHolder(holderLabel);
                    state.holder = holder;
                    state.privateKey = privateKey;
                  }

                  const attestation = await createDestructionAttestation(
                    kekId,
                    share.index,
                    state.holder,
                    state.privateKey,
                  );
                  return serializeAttestation(attestation);
                };
              }
              return undefined;
            },
          },
        );
      },
    } as unknown as Env["KEY_SHARE_DO"],

    TRANSPARENCY_LOG_DO: {
      idFromName: () => ({ toString: () => "main" }),
      get: () => ({
        append: async (_entry: Record<string, unknown>): Promise<InclusionProof> => {
          const idx = logIndex++;
          return {
            logIndex: idx,
            treeSize: idx + 1,
            rootHash: bytesToHex(crypto.getRandomValues(new Uint8Array(32))),
            hashes: [],
          };
        },
        getTreeHead: async (): Promise<SignedTreeHead> => {
          const timestamp = new Date().toISOString();
          const rootHash = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
          const msg = new TextEncoder().encode(
            `vd-tree-head-v1:${logIndex}:${rootHash}:${timestamp}`,
          );
          const signature = bytesToHex(await ed.signAsync(msg, logSigningKey));
          return { treeSize: logIndex, rootHash, timestamp, signature };
        },
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

  if (options?.operatorSigningKey) {
    (env as unknown as Record<string, unknown>).OPERATOR_SIGNING_KEY = options.operatorSigningKey;
  }

  return env;
}

// --- Tests ---

describe("demo orchestrator", () => {
  it("returns Response with Content-Type text/event-stream", () => {
    const env = createMockEnv();
    const response = runDemoDeletion(env, "test data", { delayMs: 0 });
    expect(response.headers.get("Content-Type")).toBe("text/event-stream");
  });

  it("stream contains 9 step events with complete status", async () => {
    const env = createMockEnv();
    const response = runDemoDeletion(env, "test data", { delayMs: 0 });
    const events = await parseSSEStream(response);

    const completeSteps = events.filter(
      (e) => e.event === "step" && (e.data as { status: string }).status === "complete",
    );
    expect(completeSteps).toHaveLength(9);
  });

  it("steps arrive in correct order (1-9)", async () => {
    const env = createMockEnv();
    const response = runDemoDeletion(env, "test data", { delayMs: 0 });
    const events = await parseSSEStream(response);

    const completeSteps = events
      .filter((e) => e.event === "step" && (e.data as { status: string }).status === "complete")
      .map((e) => (e.data as { step: number }).step);

    expect(completeSteps).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });

  it("each step has running then complete status (18 step events total)", async () => {
    const env = createMockEnv();
    const response = runDemoDeletion(env, "test data", { delayMs: 0 });
    const events = await parseSSEStream(response);

    const stepEvents = events.filter((e) => e.event === "step");
    expect(stepEvents).toHaveLength(18);

    // Every pair should be running then complete
    for (let i = 0; i < 18; i += 2) {
      const running = stepEvents[i]!.data as { step: number; status: string };
      const complete = stepEvents[i + 1]!.data as { step: number; status: string };
      expect(running.status).toBe("running");
      expect(complete.status).toBe("complete");
      expect(running.step).toBe(complete.step);
    }
  });

  it("step 1 (KEK) includes kekId and algorithm", async () => {
    const env = createMockEnv();
    const response = runDemoDeletion(env, "test data", { delayMs: 0 });
    const events = await parseSSEStream(response);

    const step1Complete = events.find(
      (e) =>
        e.event === "step" &&
        (e.data as { step: number; status: string }).step === 1 &&
        (e.data as { status: string }).status === "complete",
    );
    expect(step1Complete).toBeDefined();
    const data = step1Complete!.data as { data: { kekId: string; algorithm: string } };
    expect(data.data.kekId).toBeDefined();
    expect(data.data.algorithm).toBe("AES-256-GCM");
  });

  it("step 9 (receipt) includes W3C VC structure", async () => {
    const env = createMockEnv();
    const response = runDemoDeletion(env, "test data", { delayMs: 0 });
    const events = await parseSSEStream(response);

    const step9Complete = events.find(
      (e) =>
        e.event === "step" &&
        (e.data as { step: number; status: string }).step === 9 &&
        (e.data as { status: string }).status === "complete",
    );
    expect(step9Complete).toBeDefined();
    const data = step9Complete!.data as { data: { credentialType: string[]; evidenceCount: number } };
    expect(data.data.credentialType).toContain("DeletionReceipt");
    expect(data.data.evidenceCount).toBe(4);
  });

  it("done event contains receipt + operatorPublicKey", async () => {
    const env = createMockEnv();
    const response = runDemoDeletion(env, "test data", { delayMs: 0 });
    const events = await parseSSEStream(response);

    const doneEvent = events.find((e) => e.event === "done");
    expect(doneEvent).toBeDefined();
    const data = doneEvent!.data as {
      receipt: { type: string[]; proof: object };
      operatorPublicKey: string;
    };
    expect(data.receipt).toBeDefined();
    expect(data.receipt.type).toContain("DeletionReceipt");
    expect(data.receipt.proof).toBeDefined();
    expect(data.operatorPublicKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it("uses persistent operator key when OPERATOR_SIGNING_KEY is set", async () => {
    const privateKey = crypto.getRandomValues(new Uint8Array(32));
    const expectedPublicKey = bytesToHex(await ed.getPublicKeyAsync(privateKey));
    const env = createMockEnv({ operatorSigningKey: bytesToHex(privateKey) });
    const response = runDemoDeletion(env, "test data", { delayMs: 0 });
    const events = await parseSSEStream(response);

    const doneEvent = events.find((e) => e.event === "done");
    expect(doneEvent).toBeDefined();
    const data = doneEvent!.data as { operatorPublicKey: string };
    expect(data.operatorPublicKey).toBe(expectedPublicKey);
  });

  it("error in pipeline emits error event", async () => {
    const env = createMockEnv({ throwOnD1: true });
    const response = runDemoDeletion(env, "test data", { delayMs: 0 });
    const events = await parseSSEStream(response);

    const errorEvent = events.find((e) => e.event === "error");
    expect(errorEvent).toBeDefined();
    expect((errorEvent!.data as { message: string }).message).toContain("D1 unavailable");
  });

  it("emits 9 inspector events, one per step", async () => {
    const env = createMockEnv();
    const response = runDemoDeletion(env, "test data", { delayMs: 0 });
    const events = await parseSSEStream(response);

    const inspectorEvents = events.filter((e) => e.event === "inspector");
    expect(inspectorEvents).toHaveLength(9);
  });

  it("inspector phases arrive in correct order", async () => {
    const env = createMockEnv();
    const response = runDemoDeletion(env, "test data", { delayMs: 0 });
    const events = await parseSSEStream(response);

    const phases = events
      .filter((e) => e.event === "inspector")
      .map((e) => (e.data as { phase: string }).phase);

    expect(phases).toEqual([
      "plaintext",
      "encrypted",
      "key_split",
      "key_destroyed",
      "data_deleted",
      "verified",
      "smt_proven",
      "logged",
      "receipted",
    ]);
  });
});
