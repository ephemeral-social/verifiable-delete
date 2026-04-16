/**
 * Auth middleware tests.
 */
import { describe, it, expect } from "vitest";
import { authenticateRequest, authenticateAdmin, incrementUsage } from "./auth.js";
import { createApiMockEnv, seedCustomerAndKey, makeRequest } from "./test-helpers.js";

const TEST_API_KEY = "vd_live_abc123def456ghi789jkl012";
const TEST_CUSTOMER_ID = "cust_test_001";

describe("authenticateRequest", () => {
  it("returns null when no auth header", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/test");
    const result = await authenticateRequest(req, env);
    expect(result).toBeNull();
  });

  it("returns null when wrong prefix (not vd_)", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/test", "GET", undefined, {
      Authorization: "Bearer sk_live_abc123",
    });
    const result = await authenticateRequest(req, env);
    expect(result).toBeNull();
  });

  it("returns null for unknown key hash", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/test", "GET", undefined, {
      Authorization: "Bearer vd_live_unknown_key",
    });
    const result = await authenticateRequest(req, env);
    expect(result).toBeNull();
  });

  it("returns null for revoked key", async () => {
    const env = createApiMockEnv();
    await seedCustomerAndKey(env.mockDB, TEST_CUSTOMER_ID, TEST_API_KEY);
    // Revoke the key
    const keys = env.mockDB.tables.get("api_keys")!;
    keys[0]!.revoked_at = new Date().toISOString();

    const req = makeRequest("/v1/test", "GET", undefined, {
      Authorization: `Bearer ${TEST_API_KEY}`,
    });
    const result = await authenticateRequest(req, env);
    expect(result).toBeNull();
  });

  it("returns null for suspended customer", async () => {
    const env = createApiMockEnv();
    await seedCustomerAndKey(env.mockDB, TEST_CUSTOMER_ID, TEST_API_KEY);
    // Suspend customer
    const customers = env.mockDB.tables.get("customers")!;
    customers[0]!.status = "suspended";

    const req = makeRequest("/v1/test", "GET", undefined, {
      Authorization: `Bearer ${TEST_API_KEY}`,
    });
    const result = await authenticateRequest(req, env);
    expect(result).toBeNull();
  });

  it("returns AuthContext for valid key", async () => {
    const env = createApiMockEnv();
    await seedCustomerAndKey(env.mockDB, TEST_CUSTOMER_ID, TEST_API_KEY);

    const req = makeRequest("/v1/test", "GET", undefined, {
      Authorization: `Bearer ${TEST_API_KEY}`,
    });
    const result = await authenticateRequest(req, env);
    expect(result).not.toBeNull();
    expect(result!.customerId).toBe(TEST_CUSTOMER_ID);
    expect(result!.keyId).toBeTruthy();
  });
});

describe("authenticateAdmin", () => {
  it("returns true for correct secret", () => {
    const env = createApiMockEnv({ adminSecret: "my-secret" });
    const req = makeRequest("/admin/test", "GET", undefined, {
      Authorization: "Bearer my-secret",
    });
    expect(authenticateAdmin(req, env)).toBe(true);
  });

  it("returns false for wrong secret", () => {
    const env = createApiMockEnv({ adminSecret: "my-secret" });
    const req = makeRequest("/admin/test", "GET", undefined, {
      Authorization: "Bearer wrong-secret",
    });
    expect(authenticateAdmin(req, env)).toBe(false);
  });

  it("returns false when no admin secret configured", () => {
    const env = createApiMockEnv();
    env.VD_ADMIN_SECRET = undefined;
    const req = makeRequest("/admin/test", "GET", undefined, {
      Authorization: "Bearer anything",
    });
    expect(authenticateAdmin(req, env)).toBe(false);
  });
});

describe("incrementUsage", () => {
  it("creates or increments usage row", async () => {
    const env = createApiMockEnv();
    await seedCustomerAndKey(env.mockDB, TEST_CUSTOMER_ID, TEST_API_KEY);

    await incrementUsage(env, TEST_CUSTOMER_ID, "api_calls");

    const usage = env.mockDB.tables.get("usage");
    expect(usage).toBeDefined();
    expect(usage!.length).toBeGreaterThan(0);
  });
});
