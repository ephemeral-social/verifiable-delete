/**
 * Admin endpoint tests.
 */
import { describe, it, expect } from "vitest";
import { handleAdminRoute } from "./admin.js";
import { createApiMockEnv, makeRequest } from "./test-helpers.js";

const ADMIN_SECRET = "test-admin-secret";

function adminHeaders(): Record<string, string> {
  return { Authorization: `Bearer ${ADMIN_SECRET}` };
}

describe("admin endpoints", () => {
  it("POST /admin/customers creates a customer", async () => {
    const env = createApiMockEnv({ adminSecret: ADMIN_SECRET });
    const req = makeRequest("/admin/customers", "POST", { name: "Acme", email: "a@acme.com" }, adminHeaders());
    const res = await handleAdminRoute(req, env, "/admin/customers");

    expect(res.status).toBe(201);
    const data = await res.json() as Record<string, unknown>;
    expect(data.name).toBe("Acme");
    expect(data.email).toBe("a@acme.com");
    expect(data.status).toBe("active");
    expect(data.id).toBeTruthy();
  });

  it("POST /admin/customers without name returns 400", async () => {
    const env = createApiMockEnv({ adminSecret: ADMIN_SECRET });
    const req = makeRequest("/admin/customers", "POST", { email: "a@acme.com" }, adminHeaders());
    const res = await handleAdminRoute(req, env, "/admin/customers");

    expect(res.status).toBe(400);
  });

  it("GET /admin/customers/:id returns customer detail", async () => {
    const env = createApiMockEnv({ adminSecret: ADMIN_SECRET });
    // Create customer first
    const createReq = makeRequest("/admin/customers", "POST", { name: "Acme", email: "a@acme.com" }, adminHeaders());
    const createRes = await handleAdminRoute(createReq, env, "/admin/customers");
    const created = await createRes.json() as Record<string, unknown>;
    const custId = created.id as string;

    const getReq = makeRequest(`/admin/customers/${custId}`, "GET", undefined, adminHeaders());
    const res = await handleAdminRoute(getReq, env, `/admin/customers/${custId}`);

    expect(res.status).toBe(200);
    const data = await res.json() as Record<string, unknown>;
    expect(data.name).toBe("Acme");
    expect(data.keys).toBeDefined();
    expect(data.agents).toBeDefined();
  });

  it("GET /admin/customers/:id returns 404 for unknown", async () => {
    const env = createApiMockEnv({ adminSecret: ADMIN_SECRET });
    const req = makeRequest("/admin/customers/nonexistent", "GET", undefined, adminHeaders());
    const res = await handleAdminRoute(req, env, "/admin/customers/nonexistent");

    expect(res.status).toBe(404);
  });

  it("POST /admin/customers/:id/keys issues an API key with vd_live_ prefix", async () => {
    const env = createApiMockEnv({ adminSecret: ADMIN_SECRET });
    // Create customer
    const createReq = makeRequest("/admin/customers", "POST", { name: "Acme", email: "a@acme.com" }, adminHeaders());
    const createRes = await handleAdminRoute(createReq, env, "/admin/customers");
    const created = await createRes.json() as Record<string, unknown>;
    const custId = created.id as string;

    const keyReq = makeRequest(`/admin/customers/${custId}/keys`, "POST", { label: "dev" }, adminHeaders());
    const keyRes = await handleAdminRoute(keyReq, env, `/admin/customers/${custId}/keys`);

    expect(keyRes.status).toBe(201);
    const keyData = await keyRes.json() as Record<string, unknown>;
    expect((keyData.apiKey as string).startsWith("vd_live_")).toBe(true);
    expect(keyData.keyPrefix).toBeTruthy();
    expect(keyData.label).toBe("dev");
  });

  it("GET /admin/customers/:id shows key prefixes not hashes", async () => {
    const env = createApiMockEnv({ adminSecret: ADMIN_SECRET });
    // Create customer + key
    const createReq = makeRequest("/admin/customers", "POST", { name: "Acme", email: "a@acme.com" }, adminHeaders());
    const createRes = await handleAdminRoute(createReq, env, "/admin/customers");
    const created = await createRes.json() as Record<string, unknown>;
    const custId = created.id as string;

    const keyReq = makeRequest(`/admin/customers/${custId}/keys`, "POST", { label: "dev" }, adminHeaders());
    await handleAdminRoute(keyReq, env, `/admin/customers/${custId}/keys`);

    const getReq = makeRequest(`/admin/customers/${custId}`, "GET", undefined, adminHeaders());
    const res = await handleAdminRoute(getReq, env, `/admin/customers/${custId}`);
    const data = await res.json() as Record<string, unknown>;
    const keys = data.keys as Array<Record<string, unknown>>;

    expect(keys.length).toBe(1);
    expect(keys[0]!.key_prefix).toBeTruthy();
    // Should NOT expose key_hash
    expect(keys[0]!.key_hash).toBeUndefined();
  });

  it("POST /admin/customers/:id/suspend changes status", async () => {
    const env = createApiMockEnv({ adminSecret: ADMIN_SECRET });
    const createReq = makeRequest("/admin/customers", "POST", { name: "Acme", email: "a@acme.com" }, adminHeaders());
    const createRes = await handleAdminRoute(createReq, env, "/admin/customers");
    const created = await createRes.json() as Record<string, unknown>;
    const custId = created.id as string;

    const suspendReq = makeRequest(`/admin/customers/${custId}/suspend`, "POST", undefined, adminHeaders());
    const suspendRes = await handleAdminRoute(suspendReq, env, `/admin/customers/${custId}/suspend`);

    expect(suspendRes.status).toBe(200);
    const data = await suspendRes.json() as Record<string, unknown>;
    expect(data.status).toBe("suspended");
  });

  it("POST /admin/customers/:id/activate changes status", async () => {
    const env = createApiMockEnv({ adminSecret: ADMIN_SECRET });
    const createReq = makeRequest("/admin/customers", "POST", { name: "Acme", email: "a@acme.com" }, adminHeaders());
    const createRes = await handleAdminRoute(createReq, env, "/admin/customers");
    const created = await createRes.json() as Record<string, unknown>;
    const custId = created.id as string;

    // Suspend then activate
    const suspendReq = makeRequest(`/admin/customers/${custId}/suspend`, "POST", undefined, adminHeaders());
    await handleAdminRoute(suspendReq, env, `/admin/customers/${custId}/suspend`);

    const activateReq = makeRequest(`/admin/customers/${custId}/activate`, "POST", undefined, adminHeaders());
    const activateRes = await handleAdminRoute(activateReq, env, `/admin/customers/${custId}/activate`);

    expect(activateRes.status).toBe(200);
    const data = await activateRes.json() as Record<string, unknown>;
    expect(data.status).toBe("active");
  });

  it("all admin endpoints without VD_ADMIN_SECRET return 401", async () => {
    const env = createApiMockEnv({ adminSecret: ADMIN_SECRET });
    const req = makeRequest("/admin/customers", "GET");
    const res = await handleAdminRoute(req, env, "/admin/customers");

    expect(res.status).toBe(401);
  });

  it("GET /admin/customers lists all customers", async () => {
    const env = createApiMockEnv({ adminSecret: ADMIN_SECRET });
    // Create 2 customers
    await handleAdminRoute(
      makeRequest("/admin/customers", "POST", { name: "A", email: "a@a.com" }, adminHeaders()),
      env,
      "/admin/customers",
    );
    await handleAdminRoute(
      makeRequest("/admin/customers", "POST", { name: "B", email: "b@b.com" }, adminHeaders()),
      env,
      "/admin/customers",
    );

    const req = makeRequest("/admin/customers", "GET", undefined, adminHeaders());
    const res = await handleAdminRoute(req, env, "/admin/customers");

    expect(res.status).toBe(200);
    const data = await res.json() as { customers: CustomerRow[] };
    expect(data.customers.length).toBe(2);
  });
});

interface CustomerRow {
  id: string;
  name: string;
  email: string;
  plan: string;
  status: string;
  created_at: string;
}
