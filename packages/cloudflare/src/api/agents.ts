/**
 * Scanner agent registration endpoints.
 * No shared_secret — VD authenticates via operator key signature.
 * @module api/agents
 */

import type { Env } from "../env.js";
import type { AuthContext, AgentRow } from "./types.js";
import { errorResponse, jsonResponse } from "./errors.js";
import { incrementUsage } from "./auth.js";

export async function handleAgentsRoute(
  request: Request,
  env: Env,
  path: string,
  auth: AuthContext,
): Promise<Response> {
  if (path === "/v1/agents" && request.method === "POST") {
    return registerAgent(request, env, auth);
  }

  if (path === "/v1/agents" && request.method === "GET") {
    return listAgents(env, auth);
  }

  const deleteMatch = path.match(/^\/v1\/agents\/([^/]+)$/);
  if (deleteMatch && request.method === "DELETE") {
    return deregisterAgent(env, auth, deleteMatch[1]!);
  }

  return errorResponse(404, "NOT_FOUND", "Agent route not found");
}

async function registerAgent(
  request: Request,
  env: Env,
  auth: AuthContext,
): Promise<Response> {
  let body: { callbackUrl?: string; publicKey?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return errorResponse(400, "INVALID_JSON", "Request body must be valid JSON");
  }

  if (!body.callbackUrl || !body.publicKey) {
    return errorResponse(400, "MISSING_FIELDS", "callbackUrl and publicKey are required");
  }

  // Validate publicKey is 64 hex chars (Ed25519 public key)
  if (!/^[0-9a-fA-F]{64}$/.test(body.publicKey)) {
    return errorResponse(400, "INVALID_PUBLIC_KEY", "publicKey must be 64 hex characters (Ed25519 public key)");
  }

  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await env.DB.prepare(
    "INSERT INTO agents (id, customer_id, callback_url, public_key_hex, status, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
  )
    .bind(id, auth.customerId, body.callbackUrl, body.publicKey, "active", now)
    .run();

  await incrementUsage(env, auth.customerId, "api_calls");

  return jsonResponse(
    {
      id,
      callbackUrl: body.callbackUrl,
      publicKey: body.publicKey,
      status: "active",
      registered_at: now,
    },
    201,
  );
}

async function listAgents(env: Env, auth: AuthContext): Promise<Response> {
  const result = await env.DB.prepare(
    "SELECT id, callback_url, public_key_hex, status, registered_at FROM agents WHERE customer_id = ? AND status = ?",
  )
    .bind(auth.customerId, "active")
    .all<Pick<AgentRow, "id" | "callback_url" | "public_key_hex" | "status" | "registered_at">>();

  return jsonResponse({ agents: result.results });
}

async function deregisterAgent(
  env: Env,
  auth: AuthContext,
  agentId: string,
): Promise<Response> {
  // Verify ownership
  const agent = await env.DB.prepare(
    "SELECT id, customer_id FROM agents WHERE id = ? AND customer_id = ?",
  )
    .bind(agentId, auth.customerId)
    .first<Pick<AgentRow, "id" | "customer_id">>();

  if (!agent) {
    return errorResponse(404, "NOT_FOUND", "Agent not found");
  }

  await env.DB.prepare("UPDATE agents SET status = ? WHERE id = ?")
    .bind("deleted", agentId)
    .run();

  return jsonResponse({ id: agentId, status: "deleted" });
}
