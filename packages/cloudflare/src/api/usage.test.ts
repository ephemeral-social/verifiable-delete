/**
 * Usage endpoint tests.
 */
import { describe, it, expect } from "vitest";
import { handleUsageRoute } from "./usage.js";
import { createApiMockEnv, makeRequest } from "./test-helpers.js";
import type { AuthContext } from "./types.js";

const AUTH: AuthContext = { customerId: "cust_001", keyId: "key_001" };

describe("usage endpoints", () => {
  it("GET /v1/usage returns current and history", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/usage", "GET");
    const res = await handleUsageRoute(req, env, "/v1/usage", AUTH);

    expect(res.status).toBe(200);
    const data = await res.json() as Record<string, unknown>;
    expect(data.current).toBeDefined();
    expect(data.history).toBeDefined();
  });

  it("empty usage returns zeroes", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/usage", "GET");
    const res = await handleUsageRoute(req, env, "/v1/usage", AUTH);

    const data = await res.json() as {
      current: { entities_registered: number; deletions_completed: number; api_calls: number };
    };
    expect(data.current.entities_registered).toBe(0);
    expect(data.current.deletions_completed).toBe(0);
    expect(data.current.api_calls).toBe(0);
  });
});
