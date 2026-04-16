/**
 * Key registration endpoints (threshold key shares managed by VD).
 *
 * Each customer's KEK is split into 3 shares stored in separate DOs:
 * - {customerId}-{kekId}-operator
 * - {customerId}-{kekId}-oracle
 * - {customerId}-{kekId}-auditor
 *
 * @module api/keys
 */

import { hexToBytes } from "@noble/hashes/utils";
import type { Env } from "../env.js";
import type { AuthContext, KeyRegistrationRow } from "./types.js";
import { errorResponse, jsonResponse } from "./errors.js";
import { incrementUsage } from "./auth.js";

export const KEY_HOLDERS = ["operator", "oracle", "auditor"] as const;

export async function handleKeysRoute(
  request: Request,
  env: Env,
  path: string,
  auth: AuthContext,
): Promise<Response> {
  if (path === "/v1/keys" && request.method === "POST") {
    return registerKey(request, env, auth);
  }

  const keyStatusMatch = path.match(/^\/v1\/keys\/([^/]+)$/);
  if (keyStatusMatch && request.method === "GET") {
    return getKeyStatus(env, auth, keyStatusMatch[1]!);
  }

  return errorResponse(404, "NOT_FOUND", "Key route not found");
}

async function registerKey(
  request: Request,
  env: Env,
  auth: AuthContext,
): Promise<Response> {
  let body: { kekId?: string; shareData?: string; shareIndex?: number; entityId?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return errorResponse(400, "INVALID_JSON", "Request body must be valid JSON");
  }

  if (!body.kekId || !body.shareData || body.shareIndex === undefined) {
    return errorResponse(400, "MISSING_FIELDS", "kekId, shareData, and shareIndex are required");
  }

  // Store share in holder-specific DO
  const holderLabel = KEY_HOLDERS[body.shareIndex % KEY_HOLDERS.length]!;
  const doName = `${auth.customerId}-${body.kekId}-${holderLabel}`;
  const doId = env.KEY_SHARE_DO.idFromName(doName);
  const keyDO = env.KEY_SHARE_DO.get(doId);

  const shareBytes = hexToBytes(body.shareData);
  await keyDO.storeShare(body.kekId, body.shareIndex, shareBytes);

  // Record registration in D1 (only once per kekId)
  const existing = await env.DB.prepare(
    "SELECT id FROM key_registrations WHERE customer_id = ? AND kek_id = ?",
  )
    .bind(auth.customerId, body.kekId)
    .first<{ id: string }>();

  if (!existing) {
    const regId = crypto.randomUUID();
    const now = new Date().toISOString();
    await env.DB.prepare(
      "INSERT INTO key_registrations (id, customer_id, kek_id, status, created_at, destroyed_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
      .bind(regId, auth.customerId, body.kekId, "active", now, null)
      .run();
  }

  await incrementUsage(env, auth.customerId, "api_calls");

  return jsonResponse({
    kekId: body.kekId,
    shareIndex: body.shareIndex,
    holder: holderLabel,
    status: "active",
  }, 201);
}

async function getKeyStatus(
  env: Env,
  auth: AuthContext,
  kekId: string,
): Promise<Response> {
  const reg = await env.DB.prepare(
    "SELECT id, kek_id, status, created_at, destroyed_at FROM key_registrations WHERE customer_id = ? AND kek_id = ?",
  )
    .bind(auth.customerId, kekId)
    .first<Pick<KeyRegistrationRow, "id" | "kek_id" | "status" | "created_at" | "destroyed_at">>();

  if (!reg) {
    return errorResponse(404, "NOT_FOUND", "Key registration not found");
  }

  return jsonResponse({
    id: reg.id,
    kekId: reg.kek_id,
    status: reg.status,
    created_at: reg.created_at,
    destroyed_at: reg.destroyed_at,
  });
}
