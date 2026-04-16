/**
 * Entity registration endpoints.
 * @module api/entities
 */

import type { Env } from "../env.js";
import type { AuthContext } from "./types.js";
import { errorResponse, jsonResponse } from "./errors.js";
import { incrementUsage } from "./auth.js";

export async function handleEntitiesRoute(
  request: Request,
  env: Env,
  path: string,
  auth: AuthContext,
): Promise<Response> {
  if (path === "/v1/entities" && request.method === "POST") {
    return registerEntity(request, env, auth);
  }

  if (path === "/v1/entities/batch" && request.method === "POST") {
    return registerEntityBatch(request, env, auth);
  }

  return errorResponse(404, "NOT_FOUND", "Entity route not found");
}

async function registerEntity(
  request: Request,
  env: Env,
  auth: AuthContext,
): Promise<Response> {
  let body: { entityId?: string; entityType?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return errorResponse(400, "INVALID_JSON", "Request body must be valid JSON");
  }

  if (!body.entityId || !body.entityType) {
    return errorResponse(400, "MISSING_FIELDS", "entityId and entityType are required");
  }

  // Add to customer-scoped SMT
  const smtId = env.SMT_DO.idFromName(`smt-${auth.customerId}`);
  const smtDO = env.SMT_DO.get(smtId);
  const root = await smtDO.addEntity(body.entityId);

  await incrementUsage(env, auth.customerId, "entities_registered");
  await incrementUsage(env, auth.customerId, "api_calls");

  return jsonResponse({
    entityId: body.entityId,
    entityType: body.entityType,
    smtRoot: root,
    registered: true,
  }, 201);
}

async function registerEntityBatch(
  request: Request,
  env: Env,
  auth: AuthContext,
): Promise<Response> {
  let body: { entities?: Array<{ entityId: string; entityType: string }> };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return errorResponse(400, "INVALID_JSON", "Request body must be valid JSON");
  }

  if (!body.entities || !Array.isArray(body.entities)) {
    return errorResponse(400, "MISSING_FIELDS", "entities array is required");
  }

  if (body.entities.length > 100) {
    return errorResponse(400, "BATCH_LIMIT_EXCEEDED", "Maximum 100 entities per batch");
  }

  const smtId = env.SMT_DO.idFromName(`smt-${auth.customerId}`);
  const smtDO = env.SMT_DO.get(smtId);

  const results = [];
  for (const entity of body.entities) {
    const root = await smtDO.addEntity(entity.entityId);
    results.push({
      entityId: entity.entityId,
      entityType: entity.entityType,
      smtRoot: root,
      registered: true,
    });
  }

  await incrementUsage(env, auth.customerId, "entities_registered");
  await incrementUsage(env, auth.customerId, "api_calls");

  return jsonResponse({ results }, 201);
}
