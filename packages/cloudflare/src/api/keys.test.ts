/**
 * Key registration endpoint tests.
 */
import { describe, it, expect } from "vitest";
import { bytesToHex } from "@noble/hashes/utils";
import { handleKeysRoute } from "./keys.js";
import { createApiMockEnv, makeRequest } from "./test-helpers.js";
import type { AuthContext } from "./types.js";

const AUTH: AuthContext = { customerId: "cust_001", keyId: "key_001" };

describe("keys endpoints", () => {
  it("POST /v1/keys stores share and returns registration", async () => {
    const env = createApiMockEnv();
    const shareData = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    const req = makeRequest("/v1/keys", "POST", {
      kekId: "kek-001",
      shareData,
      shareIndex: 0,
      entityId: "user-123",
    });
    const res = await handleKeysRoute(req, env, "/v1/keys", AUTH);

    expect(res.status).toBe(201);
    const data = await res.json() as Record<string, unknown>;
    expect(data.kekId).toBe("kek-001");
    expect(data.status).toBe("active");
  });

  it("GET /v1/keys/:kekId returns active status", async () => {
    const env = createApiMockEnv();
    // Register key first
    const shareData = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    const regReq = makeRequest("/v1/keys", "POST", {
      kekId: "kek-002",
      shareData,
      shareIndex: 0,
    });
    await handleKeysRoute(regReq, env, "/v1/keys", AUTH);

    const getReq = makeRequest("/v1/keys/kek-002", "GET");
    const res = await handleKeysRoute(getReq, env, "/v1/keys/kek-002", AUTH);

    expect(res.status).toBe(200);
    const data = await res.json() as Record<string, unknown>;
    expect(data.status).toBe("active");
  });

  it("GET /v1/keys/:kekId returns 404 for unknown key", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/keys/nonexistent", "GET");
    const res = await handleKeysRoute(req, env, "/v1/keys/nonexistent", AUTH);

    expect(res.status).toBe(404);
  });

  it("POST /v1/keys with missing fields returns 400", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/keys", "POST", { kekId: "kek-003" });
    const res = await handleKeysRoute(req, env, "/v1/keys", AUTH);

    expect(res.status).toBe(400);
  });
});
