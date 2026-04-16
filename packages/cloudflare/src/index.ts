/**
 * Verifiable Delete — Cloudflare Worker entry point.
 *
 * Routes:
 * - GET  /              → Demo UI
 * - POST /demo/delete   → SSE deletion pipeline
 * - GET  /log           → Signed tree head
 * - GET  /log/entries   → Paginated entries
 * - GET  /log/entry/:id → Entry by receipt ID
 * - GET  /log/proof/:i  → Inclusion proof by index
 * - GET  /log/consistency → Consistency proof
 * - GET  /.well-known/vd-operator-key → Operator public key
 * - POST /init          → Initialize D1 schema
 * - /admin/*            → Admin endpoints (requires VD_ADMIN_SECRET)
 * - /v1/*               → Authenticated API (requires API key)
 *
 * @packageDocumentation
 */

import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import type { Env } from "./env.js";
import { runDemoDeletion } from "./demo/orchestrator.js";
import { getUIHtml } from "./ui/html.js";
import { handleAdminRoute } from "./api/admin.js";
import { authenticateRequest } from "./api/auth.js";
import { handleEntitiesRoute } from "./api/entities.js";
import { handleAgentsRoute } from "./api/agents.js";
import { handleKeysRoute } from "./api/keys.js";
import { handleUsageRoute } from "./api/usage.js";
import { handleDeletionsRoute } from "./api/deletions.js";
import { errorResponse } from "./api/errors.js";

// Ed25519 sync setup
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

export { KeyShareDO } from "./durable-objects/key-share.js";
export { TransparencyLogDO } from "./durable-objects/transparency-log.js";
export { SparseMerkleTreeDO } from "./durable-objects/sparse-merkle-tree.js";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

function getLogDO(env: Env) {
  const id = env.TRANSPARENCY_LOG_DO.idFromName("main");
  return env.TRANSPARENCY_LOG_DO.get(id);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // --- Demo UI ---
    if (path === "/" && request.method === "GET") {
      return new Response(getUIHtml(), {
        headers: { "Content-Type": "text/html; charset=utf-8", ...CORS_HEADERS },
      });
    }

    // --- Demo deletion pipeline ---
    if (path === "/demo/delete" && request.method === "POST") {
      let plaintextInput = "demo data";
      try {
        const body = (await request.json()) as { data?: string };
        if (body.data) plaintextInput = body.data;
      } catch {
        // Use default
      }
      const delayMs = url.searchParams.get("nodelay") === "1" ? 0 : 2000;
      return runDemoDeletion(env, plaintextInput, { delayMs });
    }

    // --- Transparency Log API ---
    if (path === "/log" && request.method === "GET") {
      const logDO = getLogDO(env);
      const head = await logDO.getTreeHead();
      return json(head);
    }

    if (path === "/log/entries" && request.method === "GET") {
      const offset = Math.max(0, parseInt(url.searchParams.get("offset") ?? "0", 10) || 0);
      const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") ?? "20", 10) || 20));
      const logDO = getLogDO(env);
      const entries = await logDO.getEntries(offset, limit);
      return json(entries);
    }

    // Entry by receipt ID
    const entryMatch = path.match(/^\/log\/entry\/(.+)$/);
    if (entryMatch && request.method === "GET") {
      const receiptId = decodeURIComponent(entryMatch[1]!);
      const logDO = getLogDO(env);
      const entry = await logDO.getEntry(receiptId);
      if (!entry) {
        return json({ error: "Entry not found" }, 404);
      }
      return json(entry);
    }

    // Inclusion proof by index
    const proofMatch = path.match(/^\/log\/proof\/(\d+)$/);
    if (proofMatch && request.method === "GET") {
      const index = parseInt(proofMatch[1]!, 10);
      const logDO = getLogDO(env);
      try {
        const proof = await logDO.getInclusionProof(index);
        return json(proof);
      } catch (err) {
        return json({ error: err instanceof Error ? err.message : String(err) }, 400);
      }
    }

    // Consistency proof
    if (path === "/log/consistency" && request.method === "GET") {
      const from = parseInt(url.searchParams.get("from") ?? "0", 10);
      const to = parseInt(url.searchParams.get("to") ?? "0", 10);
      const logDO = getLogDO(env);
      try {
        const proof = await logDO.getConsistencyProof(from, to);
        return json(proof);
      } catch (err) {
        return json({ error: err instanceof Error ? err.message : String(err) }, 400);
      }
    }

    // --- Schema init (updated to include all tables) ---
    if (path === "/init" && request.method === "POST") {
      try {
        // D1 exec handles multiple semicolon-separated statements
        await env.DB.exec(
          "CREATE TABLE IF NOT EXISTS demo_data (entity_id TEXT PRIMARY KEY, encrypted_blob TEXT NOT NULL, nonce TEXT NOT NULL, wrapped_dek TEXT NOT NULL, kek_id TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')));"
          + "CREATE TABLE IF NOT EXISTS customers (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'standard', status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL);"
          + "CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, key_hash TEXT NOT NULL, key_prefix TEXT NOT NULL, label TEXT, created_at TEXT NOT NULL, revoked_at TEXT);"
          + "CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);"
          + "CREATE INDEX IF NOT EXISTS idx_api_keys_customer ON api_keys(customer_id);"
          + "CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, callback_url TEXT NOT NULL, public_key_hex TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', registered_at TEXT NOT NULL);"
          + "CREATE INDEX IF NOT EXISTS idx_agents_customer ON agents(customer_id);"
          + "CREATE TABLE IF NOT EXISTS key_registrations (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, kek_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, destroyed_at TEXT);"
          + "CREATE INDEX IF NOT EXISTS idx_key_registrations_customer ON key_registrations(customer_id);"
          + "CREATE INDEX IF NOT EXISTS idx_key_registrations_kek ON key_registrations(kek_id);"
          + "CREATE TABLE IF NOT EXISTS deletions (id TEXT PRIMARY KEY, customer_id TEXT NOT NULL, entity_id TEXT NOT NULL, entity_type TEXT NOT NULL, entity_hash TEXT NOT NULL, kek_id TEXT, status TEXT NOT NULL DEFAULT 'pending', receipt_id TEXT, receipt_json TEXT, scan_result_json TEXT, error TEXT, created_at TEXT NOT NULL, completed_at TEXT);"
          + "CREATE INDEX IF NOT EXISTS idx_deletions_customer ON deletions(customer_id);"
          + "CREATE INDEX IF NOT EXISTS idx_deletions_entity ON deletions(customer_id, entity_hash);"
          + "CREATE INDEX IF NOT EXISTS idx_deletions_receipt ON deletions(receipt_id);"
          + "CREATE TABLE IF NOT EXISTS usage (customer_id TEXT NOT NULL, month TEXT NOT NULL, entities_registered INTEGER NOT NULL DEFAULT 0, deletions_completed INTEGER NOT NULL DEFAULT 0, api_calls INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (customer_id, month));"
        );
        return json({ success: true });
      } catch (err) {
        return json({ error: err instanceof Error ? err.message : String(err) }, 500);
      }
    }

    // --- Operator public key ---
    if (path === "/.well-known/vd-operator-key" && request.method === "GET") {
      if (!env.OPERATOR_SIGNING_KEY) {
        return json({ error: "Operator signing key not configured" }, 503);
      }
      const publicKey = bytesToHex(
        await ed.getPublicKeyAsync(hexToBytes(env.OPERATOR_SIGNING_KEY)),
      );
      return json({
        keys: [
          {
            id: "operator-key-1",
            publicKey,
            algorithm: "Ed25519",
            activeFrom: "2020-01-01T00:00:00.000Z",
            activeTo: null,
          },
        ],
        verificationMethod: "did:web:verifiabledelete.dev#key-1",
      });
    }

    // --- Admin API ---
    if (path.startsWith("/admin/")) {
      return handleAdminRoute(request, env, path);
    }

    // --- Public receipt endpoints (no auth required) ---
    if (path.match(/^\/v1\/receipts\/[^/]+(\/verify)?$/)) {
      return handleDeletionsRoute(request, env, path, null);
    }

    // --- Authenticated V1 API ---
    if (path.startsWith("/v1/")) {
      const auth = await authenticateRequest(request, env);
      if (!auth) {
        return errorResponse(401, "UNAUTHORIZED", "Invalid or missing API key");
      }

      // Route to appropriate handler
      if (path.startsWith("/v1/entities")) {
        return handleEntitiesRoute(request, env, path, auth);
      }
      if (path.startsWith("/v1/agents")) {
        return handleAgentsRoute(request, env, path, auth);
      }
      if (path.startsWith("/v1/keys")) {
        return handleKeysRoute(request, env, path, auth);
      }
      if (path.startsWith("/v1/usage")) {
        return handleUsageRoute(request, env, path, auth);
      }
      if (path.startsWith("/v1/deletions")) {
        return handleDeletionsRoute(request, env, path, auth);
      }

      return errorResponse(404, "NOT_FOUND", "API route not found");
    }

    // --- 404 ---
    return json({ error: "Not found" }, 404);
  },
};
