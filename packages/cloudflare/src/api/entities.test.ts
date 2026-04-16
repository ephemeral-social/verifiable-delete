/**
 * Entity registration endpoint tests.
 */
import { describe, it, expect } from "vitest";
import { handleEntitiesRoute } from "./entities.js";
import { createApiMockEnv, makeRequest } from "./test-helpers.js";
import type { AuthContext } from "./types.js";

const AUTH: AuthContext = { customerId: "cust_001", keyId: "key_001" };

describe("entities endpoints", () => {
  it("POST /v1/entities registers entity and returns SMT root", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/entities", "POST", {
      entityId: "user-123",
      entityType: "user_account",
    });
    const res = await handleEntitiesRoute(req, env, "/v1/entities", AUTH);

    expect(res.status).toBe(201);
    const data = await res.json() as Record<string, unknown>;
    expect(data.entityId).toBe("user-123");
    expect(data.smtRoot).toBeTruthy();
    expect(data.registered).toBe(true);
  });

  it("POST /v1/entities/batch registers multiple entities", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/entities/batch", "POST", {
      entities: [
        { entityId: "user-1", entityType: "user" },
        { entityId: "user-2", entityType: "user" },
        { entityId: "user-3", entityType: "user" },
      ],
    });
    const res = await handleEntitiesRoute(req, env, "/v1/entities/batch", AUTH);

    expect(res.status).toBe(201);
    const data = await res.json() as { results: Array<Record<string, unknown>> };
    expect(data.results.length).toBe(3);
    expect(data.results[0]!.entityId).toBe("user-1");
  });

  it("POST /v1/entities/batch > 100 returns 400", async () => {
    const env = createApiMockEnv();
    const entities = Array.from({ length: 101 }, (_, i) => ({
      entityId: `user-${i}`,
      entityType: "user",
    }));
    const req = makeRequest("/v1/entities/batch", "POST", { entities });
    const res = await handleEntitiesRoute(req, env, "/v1/entities/batch", AUTH);

    expect(res.status).toBe(400);
    const data = await res.json() as { error: { code: string } };
    expect(data.error.code).toBe("BATCH_LIMIT_EXCEEDED");
  });

  it("POST /v1/entities without required fields returns 400", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/entities", "POST", { entityId: "user-1" });
    const res = await handleEntitiesRoute(req, env, "/v1/entities", AUTH);

    expect(res.status).toBe(400);
  });

  it("increments usage counter", async () => {
    const env = createApiMockEnv();
    const req = makeRequest("/v1/entities", "POST", {
      entityId: "user-456",
      entityType: "user",
    });
    await handleEntitiesRoute(req, env, "/v1/entities", AUTH);

    const usage = env.mockDB.tables.get("usage");
    expect(usage).toBeDefined();
    expect(usage!.length).toBeGreaterThan(0);
  });
});
