/**
 * Agent endpoint tests.
 */
import { describe, it, expect } from "vitest";
import { handleAgentsRoute } from "./agents.js";
import { createApiMockEnv, makeRequest } from "./test-helpers.js";
import type { AuthContext } from "./types.js";
import { bytesToHex } from "@noble/hashes/utils";

const AUTH: AuthContext = { customerId: "cust_001", keyId: "key_001" };
const VALID_PUBKEY = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));

describe("agents endpoints", () => {
  it("POST /v1/agents registers agent", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/agents", "POST", {
      callbackUrl: "https://scanner.example.com/scan",
      publicKey: VALID_PUBKEY,
    });
    const res = await handleAgentsRoute(req, env, "/v1/agents", AUTH);

    expect(res.status).toBe(201);
    const data = await res.json() as Record<string, unknown>;
    expect(data.id).toBeTruthy();
    expect(data.callbackUrl).toBe("https://scanner.example.com/scan");
    expect(data.publicKey).toBe(VALID_PUBKEY);
    expect(data.status).toBe("active");
  });

  it("POST /v1/agents with invalid publicKey returns 400", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/agents", "POST", {
      callbackUrl: "https://scanner.example.com/scan",
      publicKey: "tooshort",
    });
    const res = await handleAgentsRoute(req, env, "/v1/agents", AUTH);

    expect(res.status).toBe(400);
    const data = await res.json() as { error: { code: string } };
    expect(data.error.code).toBe("INVALID_PUBLIC_KEY");
  });

  it("GET /v1/agents lists customer agents", async () => {
    const env = createApiMockEnv();
    // Register an agent
    const createReq = makeRequest("/v1/agents", "POST", {
      callbackUrl: "https://scanner.example.com/scan",
      publicKey: VALID_PUBKEY,
    });
    await handleAgentsRoute(createReq, env, "/v1/agents", AUTH);

    const listReq = makeRequest("/v1/agents", "GET");
    const res = await handleAgentsRoute(listReq, env, "/v1/agents", AUTH);

    expect(res.status).toBe(200);
    const data = await res.json() as { agents: Array<Record<string, unknown>> };
    expect(data.agents.length).toBe(1);
  });

  it("DELETE /v1/agents/:id removes agent", async () => {
    const env = createApiMockEnv();
    const createReq = makeRequest("/v1/agents", "POST", {
      callbackUrl: "https://scanner.example.com/scan",
      publicKey: VALID_PUBKEY,
    });
    const createRes = await handleAgentsRoute(createReq, env, "/v1/agents", AUTH);
    const created = await createRes.json() as Record<string, unknown>;
    const agentId = created.id as string;

    const deleteReq = makeRequest(`/v1/agents/${agentId}`, "DELETE");
    const res = await handleAgentsRoute(deleteReq, env, `/v1/agents/${agentId}`, AUTH);

    expect(res.status).toBe(200);
    const data = await res.json() as Record<string, unknown>;
    expect(data.status).toBe("deleted");
  });

  it("DELETE /v1/agents/:id wrong customer returns 404", async () => {
    const env = createApiMockEnv();
    const createReq = makeRequest("/v1/agents", "POST", {
      callbackUrl: "https://scanner.example.com/scan",
      publicKey: VALID_PUBKEY,
    });
    const createRes = await handleAgentsRoute(createReq, env, "/v1/agents", AUTH);
    const created = await createRes.json() as Record<string, unknown>;
    const agentId = created.id as string;

    // Different customer
    const otherAuth: AuthContext = { customerId: "cust_other", keyId: "key_other" };
    const deleteReq = makeRequest(`/v1/agents/${agentId}`, "DELETE");
    const res = await handleAgentsRoute(deleteReq, env, `/v1/agents/${agentId}`, otherAuth);

    expect(res.status).toBe(404);
  });

  it("deleted agent not returned in listing", async () => {
    const env = createApiMockEnv();
    const createReq = makeRequest("/v1/agents", "POST", {
      callbackUrl: "https://scanner.example.com/scan",
      publicKey: VALID_PUBKEY,
    });
    const createRes = await handleAgentsRoute(createReq, env, "/v1/agents", AUTH);
    const created = await createRes.json() as Record<string, unknown>;
    const agentId = created.id as string;

    // Delete
    const deleteReq = makeRequest(`/v1/agents/${agentId}`, "DELETE");
    await handleAgentsRoute(deleteReq, env, `/v1/agents/${agentId}`, AUTH);

    // List
    const listReq = makeRequest("/v1/agents", "GET");
    const res = await handleAgentsRoute(listReq, env, "/v1/agents", AUTH);
    const data = await res.json() as { agents: Array<Record<string, unknown>> };
    expect(data.agents.length).toBe(0);
  });
});
