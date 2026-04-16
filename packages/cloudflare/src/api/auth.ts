/**
 * API key authentication and admin auth for the VD multi-tenant API.
 * @module api/auth
 */

import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import type { Env } from "../env.js";
import type { AuthContext, ApiKeyRow, CustomerRow } from "./types.js";

function sha256hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

/**
 * Authenticate an API request using the Authorization: Bearer vd_live_... header.
 * Returns AuthContext if valid, null otherwise.
 */
export async function authenticateRequest(
  request: Request,
  env: Env,
): Promise<AuthContext | null> {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader) return null;

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") return null;

  const apiKey = parts[1]!;
  if (!apiKey.startsWith("vd_")) return null;

  const keyHash = sha256hex(new TextEncoder().encode(apiKey));

  // Look up key hash in api_keys table
  const keyRow = await env.DB.prepare(
    "SELECT id, customer_id, revoked_at FROM api_keys WHERE key_hash = ?",
  )
    .bind(keyHash)
    .first<Pick<ApiKeyRow, "id" | "customer_id" | "revoked_at">>();

  if (!keyRow) return null;
  if (keyRow.revoked_at) return null;

  // Check customer status
  const customer = await env.DB.prepare(
    "SELECT status FROM customers WHERE id = ?",
  )
    .bind(keyRow.customer_id)
    .first<Pick<CustomerRow, "status">>();

  if (!customer || customer.status !== "active") return null;

  return { customerId: keyRow.customer_id, keyId: keyRow.id };
}

/**
 * Authenticate an admin request using VD_ADMIN_SECRET.
 */
export function authenticateAdmin(request: Request, env: Env): boolean {
  if (!env.VD_ADMIN_SECRET) return false;

  const authHeader = request.headers.get("Authorization");
  if (!authHeader) return false;

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") return false;

  return parts[1] === env.VD_ADMIN_SECRET;
}

/**
 * Increment a usage counter for the current month.
 */
export async function incrementUsage(
  env: Env,
  customerId: string,
  field: "entities_registered" | "deletions_completed" | "api_calls",
): Promise<void> {
  const month = new Date().toISOString().slice(0, 7); // YYYY-MM

  // Upsert: insert or increment
  await env.DB.prepare(
    `INSERT OR REPLACE INTO usage (customer_id, month, entities_registered, deletions_completed, api_calls)
     VALUES (?, ?,
       COALESCE((SELECT entities_registered FROM usage WHERE customer_id = ? AND month = ?), 0) + ?,
       COALESCE((SELECT deletions_completed FROM usage WHERE customer_id = ? AND month = ?), 0) + ?,
       COALESCE((SELECT api_calls FROM usage WHERE customer_id = ? AND month = ?), 0) + ?
     )`,
  )
    .bind(
      customerId,
      month,
      customerId,
      month,
      field === "entities_registered" ? 1 : 0,
      customerId,
      month,
      field === "deletions_completed" ? 1 : 0,
      customerId,
      month,
      field === "api_calls" ? 1 : 0,
    )
    .run();
}
