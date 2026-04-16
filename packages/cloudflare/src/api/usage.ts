/**
 * Usage tracking endpoint.
 * @module api/usage
 */

import type { Env } from "../env.js";
import type { AuthContext, UsageRow } from "./types.js";
import { errorResponse, jsonResponse } from "./errors.js";

export async function handleUsageRoute(
  _request: Request,
  env: Env,
  path: string,
  auth: AuthContext,
): Promise<Response> {
  if (path === "/v1/usage" && _request.method === "GET") {
    return getUsage(env, auth);
  }

  return errorResponse(404, "NOT_FOUND", "Usage route not found");
}

async function getUsage(env: Env, auth: AuthContext): Promise<Response> {
  const result = await env.DB.prepare(
    "SELECT customer_id, month, entities_registered, deletions_completed, api_calls FROM usage WHERE customer_id = ? ORDER BY month",
  )
    .bind(auth.customerId)
    .all<UsageRow>();

  const currentMonth = new Date().toISOString().slice(0, 7);
  const current = result.results.find((r) => r.month === currentMonth) ?? {
    customer_id: auth.customerId,
    month: currentMonth,
    entities_registered: 0,
    deletions_completed: 0,
    api_calls: 0,
  };

  // Last 12 months history
  const history = result.results.slice(-12);

  return jsonResponse({ current, history });
}
