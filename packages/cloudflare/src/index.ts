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
 *
 * @packageDocumentation
 */

import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import type { Env } from "./env.js";
import { runDemoDeletion } from "./demo/orchestrator.js";
import { getUIHtml } from "./ui/html.js";

// Ed25519 sync setup
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

export { KeyShareDO } from "./durable-objects/key-share.js";
export { TransparencyLogDO } from "./durable-objects/transparency-log.js";
export { SparseMerkleTreeDO } from "./durable-objects/sparse-merkle-tree.js";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
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

    // --- Schema init ---
    if (path === "/init" && request.method === "POST") {
      try {
        await env.DB.exec(
          `CREATE TABLE IF NOT EXISTS demo_data (
            entity_id TEXT PRIMARY KEY,
            encrypted_blob TEXT NOT NULL,
            nonce TEXT NOT NULL,
            wrapped_dek TEXT NOT NULL,
            kek_id TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
          )`
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
        publicKey,
        algorithm: "Ed25519",
        verificationMethod: "did:web:verifiabledelete.dev#key-1",
      });
    }

    // --- 404 ---
    return json({ error: "Not found" }, 404);
  },
};
