/**
 * Admin endpoints for customer and API key management.
 * All require Authorization: Bearer {VD_ADMIN_SECRET}.
 * @module api/admin
 */

import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import type { Env } from "../env.js";
import { authenticateAdmin } from "./auth.js";
import { errorResponse, jsonResponse } from "./errors.js";
import type { CustomerRow, ApiKeyRow, AgentRow } from "./types.js";

function sha256hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

export async function handleAdminRoute(
  request: Request,
  env: Env,
  path: string,
): Promise<Response> {
  if (!authenticateAdmin(request, env)) {
    return errorResponse(401, "UNAUTHORIZED", "Invalid or missing admin credentials");
  }

  // POST /admin/customers
  if (path === "/admin/customers" && request.method === "POST") {
    return createCustomer(request, env);
  }

  // GET /admin/customers
  if (path === "/admin/customers" && request.method === "GET") {
    return listCustomers(env);
  }

  // GET /admin/customers/:id
  const customerDetailMatch = path.match(/^\/admin\/customers\/([^/]+)$/);
  if (customerDetailMatch && request.method === "GET") {
    return getCustomer(env, customerDetailMatch[1]!);
  }

  // POST /admin/customers/:id/keys
  const keysMatch = path.match(/^\/admin\/customers\/([^/]+)\/keys$/);
  if (keysMatch && request.method === "POST") {
    return issueApiKey(request, env, keysMatch[1]!);
  }

  // POST /admin/customers/:id/suspend
  const suspendMatch = path.match(/^\/admin\/customers\/([^/]+)\/suspend$/);
  if (suspendMatch && request.method === "POST") {
    return setCustomerStatus(env, suspendMatch[1]!, "suspended");
  }

  // POST /admin/customers/:id/activate
  const activateMatch = path.match(/^\/admin\/customers\/([^/]+)\/activate$/);
  if (activateMatch && request.method === "POST") {
    return setCustomerStatus(env, activateMatch[1]!, "active");
  }

  return errorResponse(404, "NOT_FOUND", "Admin route not found");
}

async function createCustomer(request: Request, env: Env): Promise<Response> {
  let body: { name?: string; email?: string; plan?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return errorResponse(400, "INVALID_JSON", "Request body must be valid JSON");
  }

  if (!body.name || !body.email) {
    return errorResponse(400, "MISSING_FIELDS", "name and email are required");
  }

  const id = `cust_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
  const now = new Date().toISOString();
  const plan = body.plan ?? "standard";

  await env.DB.prepare(
    "INSERT INTO customers (id, name, email, plan, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
  )
    .bind(id, body.name, body.email, plan, "active", now)
    .run();

  return jsonResponse({ id, name: body.name, email: body.email, plan, status: "active", created_at: now }, 201);
}

async function listCustomers(env: Env): Promise<Response> {
  const result = await env.DB.prepare(
    "SELECT id, name, email, plan, status, created_at FROM customers ORDER BY created_at",
  )
    .all<CustomerRow>();

  return jsonResponse({ customers: result.results });
}

async function getCustomer(env: Env, customerId: string): Promise<Response> {
  const customer = await env.DB.prepare(
    "SELECT id, name, email, plan, status, created_at FROM customers WHERE id = ?",
  )
    .bind(customerId)
    .first<CustomerRow>();

  if (!customer) {
    return errorResponse(404, "NOT_FOUND", "Customer not found");
  }

  // Get API keys (prefix only, not hash)
  const keys = await env.DB.prepare(
    "SELECT id, key_prefix, label, created_at, revoked_at FROM api_keys WHERE customer_id = ?",
  )
    .bind(customerId)
    .all<Pick<ApiKeyRow, "id" | "key_prefix" | "label" | "created_at" | "revoked_at">>();

  // Get agents
  const agents = await env.DB.prepare(
    "SELECT id, callback_url, public_key_hex, status, registered_at FROM agents WHERE customer_id = ?",
  )
    .bind(customerId)
    .all<Pick<AgentRow, "id" | "callback_url" | "public_key_hex" | "status" | "registered_at">>();

  return jsonResponse({
    ...customer,
    keys: keys.results,
    agents: agents.results,
  });
}

async function issueApiKey(request: Request, env: Env, customerId: string): Promise<Response> {
  // Verify customer exists
  const customer = await env.DB.prepare(
    "SELECT id FROM customers WHERE id = ?",
  )
    .bind(customerId)
    .first<Pick<CustomerRow, "id">>();

  if (!customer) {
    return errorResponse(404, "NOT_FOUND", "Customer not found");
  }

  let body: { label?: string } = {};
  try {
    body = (await request.json()) as typeof body;
  } catch {
    // No body is fine, label is optional
  }

  // Generate API key
  const raw = crypto.getRandomValues(new Uint8Array(16));
  const apiKey = "vd_live_" + bytesToHex(raw);
  const keyHash = sha256hex(new TextEncoder().encode(apiKey));
  const keyPrefix = apiKey.slice(0, 12);
  const keyId = crypto.randomUUID();
  const now = new Date().toISOString();

  await env.DB.prepare(
    "INSERT INTO api_keys (id, customer_id, key_hash, key_prefix, label, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(keyId, customerId, keyHash, keyPrefix, body.label ?? null, now, null)
    .run();

  // Return the raw key — this is the only time it's shown
  return jsonResponse({
    id: keyId,
    apiKey,
    keyPrefix,
    label: body.label ?? null,
    created_at: now,
  }, 201);
}

async function setCustomerStatus(
  env: Env,
  customerId: string,
  status: string,
): Promise<Response> {
  const customer = await env.DB.prepare(
    "SELECT id FROM customers WHERE id = ?",
  )
    .bind(customerId)
    .first<Pick<CustomerRow, "id">>();

  if (!customer) {
    return errorResponse(404, "NOT_FOUND", "Customer not found");
  }

  await env.DB.prepare("UPDATE customers SET status = ? WHERE id = ?")
    .bind(status, customerId)
    .run();

  return jsonResponse({ id: customerId, status });
}
