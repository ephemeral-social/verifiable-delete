/**
 * Deletion orchestrator tests.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { bytesToHex } from "@noble/hashes/utils";
import {
  canonicalJSON,
} from "@ephemeral-social/verifiable-delete";
import { handleDeletionsRoute } from "./deletions.js";
import { createApiMockEnv, makeRequest } from "./test-helpers.js";
import type { AuthContext } from "./types.js";

// Ed25519 sync setup
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

const AUTH: AuthContext = { customerId: "cust_001", keyId: "key_001" };

// Helper: register an entity in the SMT and DB
async function setupEntityInSMT(env: ReturnType<typeof createApiMockEnv>, entityId: string): Promise<void> {
  const smtId = env.SMT_DO.idFromName(`smt-${AUTH.customerId}`);
  const smtDO = env.SMT_DO.get(smtId) as { addEntity: (id: string) => Promise<string> };
  await smtDO.addEntity(entityId);
}

// Helper: register a key in D1
async function setupKey(env: ReturnType<typeof createApiMockEnv>, kekId: string): Promise<void> {
  env.mockDB._execute(
    "INSERT INTO key_registrations (id, customer_id, kek_id, status, created_at, destroyed_at) VALUES (?, ?, ?, ?, ?, ?)",
    [crypto.randomUUID(), AUTH.customerId, kekId, "active", new Date().toISOString(), null],
  );
}

// Helper: register an agent in D1
async function setupAgent(
  env: ReturnType<typeof createApiMockEnv>,
  callbackUrl: string,
  publicKeyHex: string,
): Promise<string> {
  const agentId = crypto.randomUUID();
  env.mockDB._execute(
    "INSERT INTO agents (id, customer_id, callback_url, public_key_hex, status, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
    [agentId, AUTH.customerId, callbackUrl, publicKeyHex, "active", new Date().toISOString()],
  );
  return agentId;
}

// Helper: create mock agent response with valid signature
async function mockAgentResponse(
  agentPrivateKey: Uint8Array,
  requestId: string,
  absent = true,
): Promise<Response> {
  const results = [{
    entityId: "test-entity",
    backends: [{ type: "database", identifier: "database:test:users.user_id", absent, scannedAt: new Date().toISOString(), note: null }],
    allAbsent: absent,
  }];
  const timestamp = new Date().toISOString();

  // Sign using the same format as the real scanner agent
  const signMessage = new TextEncoder().encode(
    "vd-scan-result-v1:" + canonicalJSON(results),
  );
  const signature = bytesToHex(await ed.signAsync(signMessage, agentPrivateKey));

  return new Response(
    JSON.stringify({ requestId, results, timestamp, signature }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("deletions endpoints", () => {
  it("POST /v1/deletions missing entityId returns 400", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/deletions", "POST", { entityType: "user" });
    const res = await handleDeletionsRoute(req, env, "/v1/deletions", AUTH);

    expect(res.status).toBe(400);
  });

  it("POST /v1/deletions entity not in SMT returns 404", async () => {
    const env = createApiMockEnv();
    // Setup a key so we pass the KEY_REQUIRED check
    await setupKey(env, "kek-notfound");

    const req = makeRequest("/v1/deletions", "POST", {
      entityId: "nonexistent",
      entityType: "user",
    });
    const res = await handleDeletionsRoute(req, env, "/v1/deletions", AUTH);

    expect(res.status).toBe(404);
    const data = await res.json() as { error: { code: string } };
    expect(data.error.code).toBe("ENTITY_NOT_FOUND");
  });

  it("POST /v1/deletions no key returns 400 KEY_REQUIRED", async () => {
    const env = createApiMockEnv();
    await setupEntityInSMT(env, "user-123");

    const req = makeRequest("/v1/deletions", "POST", {
      entityId: "user-123",
      entityType: "user",
    });
    const res = await handleDeletionsRoute(req, env, "/v1/deletions", AUTH);

    expect(res.status).toBe(400);
    const data = await res.json() as { error: { code: string } };
    expect(data.error.code).toBe("KEY_REQUIRED");
  });

  it("POST /v1/deletions with agent calls callback with X-VD-Signature", async () => {
    const env = createApiMockEnv();
    const agentKey = crypto.getRandomValues(new Uint8Array(32));
    const agentPubKey = bytesToHex(await ed.getPublicKeyAsync(agentKey));
    await setupAgent(env, "https://scanner.example.com/scan", agentPubKey);
    await setupKey(env, "kek-sig");
    await setupEntityInSMT(env, "user-agent-1");

    let capturedHeaders: Headers | null = null;
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      capturedHeaders = new Headers(init.headers as HeadersInit);
      const body = JSON.parse(init.body as string) as { requestId: string };
      return mockAgentResponse(agentKey, body.requestId);
    });

    const req = makeRequest("/v1/deletions", "POST", {
      entityId: "user-agent-1",
      entityType: "user",
    });
    const res = await handleDeletionsRoute(req, env, "/v1/deletions", AUTH);

    expect(res.status).toBe(201);
    expect(capturedHeaders).not.toBeNull();
    expect(capturedHeaders!.get("X-VD-Signature")).toBeTruthy();
    expect(capturedHeaders!.get("X-VD-Request-Id")).toBeTruthy();
  });

  it("agent timeout returns 502 AGENT_UNREACHABLE", async () => {
    const env = createApiMockEnv();
    const agentKey = crypto.getRandomValues(new Uint8Array(32));
    const agentPubKey = bytesToHex(await ed.getPublicKeyAsync(agentKey));
    await setupAgent(env, "https://scanner.example.com/scan", agentPubKey);
    await setupKey(env, "kek-timeout");
    await setupEntityInSMT(env, "user-timeout");

    vi.stubGlobal("fetch", async () => {
      throw new DOMException("The operation was aborted", "AbortError");
    });

    const req = makeRequest("/v1/deletions", "POST", {
      entityId: "user-timeout",
      entityType: "user",
    });
    const res = await handleDeletionsRoute(req, env, "/v1/deletions", AUTH);

    expect(res.status).toBe(502);
    const data = await res.json() as { error: { code: string } };
    expect(data.error.code).toBe("AGENT_UNREACHABLE");
  });

  it("agent non-200 returns 502 AGENT_ERROR", async () => {
    const env = createApiMockEnv();
    const agentKey = crypto.getRandomValues(new Uint8Array(32));
    const agentPubKey = bytesToHex(await ed.getPublicKeyAsync(agentKey));
    await setupAgent(env, "https://scanner.example.com/scan", agentPubKey);
    await setupKey(env, "kek-500");
    await setupEntityInSMT(env, "user-500");

    vi.stubGlobal("fetch", async () => {
      return new Response("Internal Server Error", { status: 500 });
    });

    const req = makeRequest("/v1/deletions", "POST", {
      entityId: "user-500",
      entityType: "user",
    });
    const res = await handleDeletionsRoute(req, env, "/v1/deletions", AUTH);

    expect(res.status).toBe(502);
    const data = await res.json() as { error: { code: string } };
    expect(data.error.code).toBe("AGENT_ERROR");
  });

  it("agent invalid signature returns 502 AGENT_SIGNATURE_INVALID", async () => {
    const env = createApiMockEnv();
    const agentKey = crypto.getRandomValues(new Uint8Array(32));
    const agentPubKey = bytesToHex(await ed.getPublicKeyAsync(agentKey));
    await setupAgent(env, "https://scanner.example.com/scan", agentPubKey);
    await setupKey(env, "kek-badsig");
    await setupEntityInSMT(env, "user-badsig");

    // Respond with a DIFFERENT key's signature (wrong key)
    const wrongKey = crypto.getRandomValues(new Uint8Array(32));
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      const body = JSON.parse(init.body as string) as { requestId: string };
      return mockAgentResponse(wrongKey, body.requestId);
    });

    const req = makeRequest("/v1/deletions", "POST", {
      entityId: "user-badsig",
      entityType: "user",
    });
    const res = await handleDeletionsRoute(req, env, "/v1/deletions", AUTH);

    expect(res.status).toBe(502);
    const data = await res.json() as { error: { code: string } };
    expect(data.error.code).toBe("AGENT_SIGNATURE_INVALID");
  });

  it("agent reports data present returns 409 DATA_STILL_PRESENT", async () => {
    const env = createApiMockEnv();
    const agentKey = crypto.getRandomValues(new Uint8Array(32));
    const agentPubKey = bytesToHex(await ed.getPublicKeyAsync(agentKey));
    await setupAgent(env, "https://scanner.example.com/scan", agentPubKey);
    await setupKey(env, "kek-present");
    await setupEntityInSMT(env, "user-present");

    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      const body = JSON.parse(init.body as string) as { requestId: string };
      return mockAgentResponse(agentKey, body.requestId, false); // absent=false
    });

    const req = makeRequest("/v1/deletions", "POST", {
      entityId: "user-present",
      entityType: "user",
    });
    const res = await handleDeletionsRoute(req, env, "/v1/deletions", AUTH);

    expect(res.status).toBe(409);
    const data = await res.json() as { error: { code: string } };
    expect(data.error.code).toBe("DATA_STILL_PRESENT");
  });

  it("full pipeline with agent scan → receipt returned with BackupCoverage", async () => {
    const env = createApiMockEnv();
    const agentKey = crypto.getRandomValues(new Uint8Array(32));
    const agentPubKey = bytesToHex(await ed.getPublicKeyAsync(agentKey));
    await setupAgent(env, "https://scanner.example.com/scan", agentPubKey);
    await setupKey(env, "kek-full-1");
    await setupEntityInSMT(env, "user-full-1");

    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      const body = JSON.parse(init.body as string) as { requestId: string };
      return mockAgentResponse(agentKey, body.requestId);
    });

    const req = makeRequest("/v1/deletions", "POST", {
      entityId: "user-full-1",
      entityType: "user_account",
    });
    const res = await handleDeletionsRoute(req, env, "/v1/deletions", AUTH);

    expect(res.status).toBe(201);
    const data = await res.json() as { deletion: Record<string, unknown>; receipt: { evidence: Array<{ type: string }> } };
    expect(data.deletion.status).toBe("completed");
    expect(data.receipt).toBeDefined();
    const types = data.receipt.evidence.map((e) => e.type);
    expect(types).toContain("BackupCoverage");
  });

  it("full pipeline with VD key + agent → receipt has attestation + scan", async () => {
    const env = createApiMockEnv();
    const agentKey = crypto.getRandomValues(new Uint8Array(32));
    const agentPubKey = bytesToHex(await ed.getPublicKeyAsync(agentKey));
    await setupAgent(env, "https://scanner.example.com/scan", agentPubKey);
    await setupKey(env, "kek-full-1");
    await setupEntityInSMT(env, "user-full-2");

    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      const body = JSON.parse(init.body as string) as { requestId: string };
      return mockAgentResponse(agentKey, body.requestId);
    });

    const req = makeRequest("/v1/deletions", "POST", {
      entityId: "user-full-2",
      entityType: "user_account",
    });
    const res = await handleDeletionsRoute(req, env, "/v1/deletions", AUTH);

    expect(res.status).toBe(201);
    const data = await res.json() as { receipt: { evidence: Array<{ type: string }> } };
    const types = data.receipt.evidence.map((e) => e.type);
    expect(types).toContain("ThresholdAttestation");
    expect(types).toContain("StorageScan");
    expect(types).toContain("NonMembershipProof");
    expect(types).toContain("TransparencyLogInclusion");
    expect(types).toContain("BackupCoverage");
  });

  it("full pipeline with VD key only (no agent) → receipt has StorageScan note and BackupCoverage", async () => {
    const env = createApiMockEnv();
    await setupKey(env, "kek-noagent");
    await setupEntityInSMT(env, "user-keyonly");

    const req = makeRequest("/v1/deletions", "POST", {
      entityId: "user-keyonly",
      entityType: "user_account",
    });
    const res = await handleDeletionsRoute(req, env, "/v1/deletions", AUTH);

    expect(res.status).toBe(201);
    const data = await res.json() as { receipt: { evidence: Array<{ type: string; note?: string }> } };
    expect(data.receipt).toBeDefined();

    const types = data.receipt.evidence.map((e) => e.type);
    expect(types).toContain("BackupCoverage");

    const storageScan = data.receipt.evidence.find((e) => e.type === "StorageScan");
    expect(storageScan).toBeDefined();
    expect(storageScan!.note).toContain("No Scanner Agent registered");
  });

  it("idempotency: same entity twice returns cached receipt", async () => {
    const env = createApiMockEnv();
    await setupKey(env, "kek-idem");
    await setupEntityInSMT(env, "user-idem");

    const req1 = makeRequest("/v1/deletions", "POST", {
      entityId: "user-idem",
      entityType: "user_account",
    });
    const res1 = await handleDeletionsRoute(req1, env, "/v1/deletions", AUTH);
    expect(res1.status).toBe(201);
    const data1 = await res1.json() as { receipt: { id: string } };

    // Second request — entity already deleted, should return cached
    const req2 = makeRequest("/v1/deletions", "POST", {
      entityId: "user-idem",
      entityType: "user_account",
    });
    const res2 = await handleDeletionsRoute(req2, env, "/v1/deletions", AUTH);
    expect(res2.status).toBe(200);
    const data2 = await res2.json() as { receipt: { id: string } };
    expect(data2.receipt.id).toBe(data1.receipt.id);
  });

  it("deletion status updated after completion", async () => {
    const env = createApiMockEnv();
    await setupKey(env, "kek-status");
    await setupEntityInSMT(env, "user-status");

    const req = makeRequest("/v1/deletions", "POST", {
      entityId: "user-status",
      entityType: "user_account",
    });
    await handleDeletionsRoute(req, env, "/v1/deletions", AUTH);

    const deletions = env.mockDB.tables.get("deletions") ?? [];
    const completed = deletions.find((d) => d.status === "completed");
    expect(completed).toBeDefined();
  });

  it("usage counter incremented after deletion", async () => {
    const env = createApiMockEnv();
    await setupKey(env, "kek-usage");
    await setupEntityInSMT(env, "user-usage");

    const req = makeRequest("/v1/deletions", "POST", {
      entityId: "user-usage",
      entityType: "user_account",
    });
    await handleDeletionsRoute(req, env, "/v1/deletions", AUTH);

    const usage = env.mockDB.tables.get("usage") ?? [];
    expect(usage.length).toBeGreaterThan(0);
  });

  it("GET /v1/deletions/:id returns deletion with receipt", async () => {
    const env = createApiMockEnv();
    await setupKey(env, "kek-get");
    await setupEntityInSMT(env, "user-get");

    const createReq = makeRequest("/v1/deletions", "POST", {
      entityId: "user-get",
      entityType: "user_account",
    });
    const createRes = await handleDeletionsRoute(createReq, env, "/v1/deletions", AUTH);
    const created = await createRes.json() as { deletion: { id: string } };

    const getReq = makeRequest(`/v1/deletions/${created.deletion.id}`, "GET");
    const res = await handleDeletionsRoute(getReq, env, `/v1/deletions/${created.deletion.id}`, AUTH);

    expect(res.status).toBe(200);
    const data = await res.json() as Record<string, unknown>;
    expect(data.status).toBe("completed");
    expect(data.receipt).toBeDefined();
  });

  it("GET /v1/receipts/:receiptId returns public receipt", async () => {
    const env = createApiMockEnv();
    await setupKey(env, "kek-receipt");
    await setupEntityInSMT(env, "user-receipt");

    const createReq = makeRequest("/v1/deletions", "POST", {
      entityId: "user-receipt",
      entityType: "user_account",
    });
    const createRes = await handleDeletionsRoute(createReq, env, "/v1/deletions", AUTH);
    const created = await createRes.json() as { receipt: { id: string } };
    const receiptId = (created.receipt.id as string).replace("urn:uuid:", "");

    const getReq = makeRequest(`/v1/receipts/${receiptId}`, "GET");
    const res = await handleDeletionsRoute(getReq, env, `/v1/receipts/${receiptId}`, null);

    expect(res.status).toBe(200);
    const data = await res.json() as Record<string, unknown>;
    expect(data.type).toContain("DeletionReceipt");
  });
});
