/**
 * Deletion orchestrator — the critical pipeline.
 * Handles entity deletion with agent scanning, key destruction, and receipt generation.
 * @module api/deletions
 */

import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  computeCommitment,
  hashScanResult,
  createDeletionReceipt,
  verifyDeletionReceipt,
  deserializeAttestation,
  canonicalJSON,
  sha256hex,
  type ScanResult,
  type BackendScanResult,
  type LogEntry,
  type SerializedDestructionAttestation,
  type DeletionReceipt,
} from "@ephemeral-social/verifiable-delete";
import type { Env } from "../env.js";
import type { AuthContext, AgentRow, DeletionRow, AgentScanResponse, KeyRegistrationRow } from "./types.js";
import { errorResponse, jsonResponse } from "./errors.js";
import { incrementUsage } from "./auth.js";

// Ed25519 sync setup
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

export async function handleDeletionsRoute(
  request: Request,
  env: Env,
  path: string,
  auth: AuthContext | null,
): Promise<Response> {
  // Public routes (no auth)
  const receiptVerifyMatch = path.match(/^\/v1\/receipts\/([^/]+)\/verify$/);
  if (receiptVerifyMatch && request.method === "GET") {
    return verifyReceipt(env, receiptVerifyMatch[1]!);
  }

  const receiptMatch = path.match(/^\/v1\/receipts\/([^/]+)$/);
  if (receiptMatch && request.method === "GET") {
    return getReceipt(env, receiptMatch[1]!);
  }

  // Authenticated routes
  if (!auth) {
    return errorResponse(401, "UNAUTHORIZED", "Authentication required");
  }

  if (path === "/v1/deletions" && request.method === "POST") {
    return createDeletion(request, env, auth);
  }

  if (path === "/v1/deletions/batch" && request.method === "POST") {
    return createDeletionBatch(request, env, auth);
  }

  const deletionDetailMatch = path.match(/^\/v1\/deletions\/([^/]+)$/);
  if (deletionDetailMatch && request.method === "GET") {
    return getDeletion(env, auth, deletionDetailMatch[1]!);
  }

  return errorResponse(404, "NOT_FOUND", "Deletion route not found");
}

// --- Core Deletion Pipeline ---

async function createDeletion(
  request: Request,
  env: Env,
  auth: AuthContext,
): Promise<Response> {
  let body: { entityId?: string; entityType?: string; customerAttestation?: string };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return errorResponse(400, "INVALID_JSON", "Request body must be valid JSON");
  }

  if (!body.entityId || !body.entityType) {
    return errorResponse(400, "MISSING_FIELDS", "entityId and entityType are required");
  }

  const result = await runDeletionPipeline(env, auth, body.entityId, body.entityType, body.customerAttestation);
  return result;
}

async function createDeletionBatch(
  request: Request,
  env: Env,
  auth: AuthContext,
): Promise<Response> {
  let body: { deletions?: Array<{ entityId: string; entityType: string; customerAttestation?: string }> };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return errorResponse(400, "INVALID_JSON", "Request body must be valid JSON");
  }

  if (!body.deletions || !Array.isArray(body.deletions)) {
    return errorResponse(400, "MISSING_FIELDS", "deletions array is required");
  }

  if (body.deletions.length > 100) {
    return errorResponse(400, "BATCH_LIMIT_EXCEEDED", "Maximum 100 deletions per batch");
  }

  const results = [];
  for (const del of body.deletions) {
    const res = await runDeletionPipeline(env, auth, del.entityId, del.entityType, del.customerAttestation);
    const data = await res.json();
    results.push({ status: res.status, data });
  }

  return jsonResponse({ results });
}

async function runDeletionPipeline(
  env: Env,
  auth: AuthContext,
  entityId: string,
  entityType: string,
  _customerAttestation?: string,
): Promise<Response> {
  if (!env.OPERATOR_SIGNING_KEY) {
    return errorResponse(503, "NOT_CONFIGURED", "Operator signing key not configured");
  }

  const operatorKey = hexToBytes(env.OPERATOR_SIGNING_KEY);
  const entityHash = sha256hex(new TextEncoder().encode(entityId));

  // Step 0: Idempotency check
  const existing = await env.DB.prepare(
    "SELECT id, receipt_id, receipt_json, status FROM deletions WHERE customer_id = ? AND entity_hash = ? AND status = ?",
  )
    .bind(auth.customerId, entityHash, "completed")
    .first<Pick<DeletionRow, "id" | "receipt_id" | "receipt_json" | "status">>();

  if (existing?.receipt_json) {
    const receipt = JSON.parse(existing.receipt_json) as DeletionReceipt;
    return jsonResponse({ deletion: { id: existing.id, status: "completed" }, receipt });
  }

  // Step 1: Verify entity in customer's SMT
  const smtId = env.SMT_DO.idFromName(`smt-${auth.customerId}`);
  const smtDO = env.SMT_DO.get(smtId);
  const entityExists = await smtDO.hasEntity(entityId);

  if (!entityExists) {
    return errorResponse(404, "ENTITY_NOT_FOUND", "Entity not found in registry");
  }

  // Check verification methods
  const agents = await env.DB.prepare(
    "SELECT id, callback_url, public_key_hex FROM agents WHERE customer_id = ? AND status = ? ORDER BY registered_at DESC",
  )
    .bind(auth.customerId, "active")
    .all<Pick<AgentRow, "id" | "callback_url" | "public_key_hex">>();

  const hasAgent = agents.results.length > 0;

  const keyReg = await env.DB.prepare(
    "SELECT id, kek_id, status FROM key_registrations WHERE customer_id = ? AND status = ?",
  )
    .bind(auth.customerId, "active")
    .first<Pick<KeyRegistrationRow, "id" | "kek_id" | "status">>();

  const hasKey = !!keyReg;

  if (!hasKey) {
    return errorResponse(400, "KEY_REQUIRED",
      "A VD-managed threshold key must be registered before deletion. Register key shares via POST /v1/keys");
  }

  // Step 2: Create deletion record
  const deletionId = crypto.randomUUID();
  const now = new Date().toISOString();

  await env.DB.prepare(
    "INSERT INTO deletions (id, customer_id, entity_id, entity_type, entity_hash, kek_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(deletionId, auth.customerId, entityId, entityType, entityHash, keyReg?.kek_id ?? null, "pending", now)
    .run();

  // Step 3: Call Scanner Agent (if registered)
  let scanResult: ScanResult;
  const backends: BackendScanResult[] = [];

  if (hasAgent) {
    const agent = agents.results[0]!;
    const agentResult = await callScannerAgent(env, operatorKey, agent, entityId, entityHash);

    if (agentResult.error) {
      // Update deletion status with error
      await env.DB.prepare("UPDATE deletions SET status = ?, error = ? WHERE id = ?")
        .bind("failed", agentResult.error.message, deletionId)
        .run();
      return errorResponse(agentResult.error.status, agentResult.error.code, agentResult.error.message);
    }

    backends.push(...agentResult.backends);

    // Check all entities absent (empty backends = no verification performed = not absent)
    const allAbsent = backends.length > 0 && backends.every((b) => b.absent);
    if (!allAbsent) {
      await env.DB.prepare("UPDATE deletions SET status = ?, error = ? WHERE id = ?")
        .bind("failed", "Data still present in storage", deletionId)
        .run();
      return errorResponse(409, "DATA_STILL_PRESENT", "Scanner agent reports data is still present in storage");
    }
  }

  // Step 4: Key destruction (if VD-managed key exists)
  const attestations: SerializedDestructionAttestation[] = [];
  if (hasKey) {
    // Destroy 2 of 3 holder-specific DOs (operator, oracle; keep auditor)
    const holdersToDestroy = ["operator", "oracle"] as const;
    for (const holder of holdersToDestroy) {
      const doName = `${auth.customerId}-${keyReg!.kek_id}-${holder}`;
      const doId = env.KEY_SHARE_DO.idFromName(doName);
      const keyDO = env.KEY_SHARE_DO.get(doId);
      const att = await keyDO.destroyShare(keyReg!.kek_id, holder);
      attestations.push(att);
    }

    // Update key registration
    await env.DB.prepare("UPDATE key_registrations SET status = ?, destroyed_at = ? WHERE id = ?")
      .bind("destroyed", new Date().toISOString(), keyReg!.id)
      .run();
  }

  // Build scan result
  const storageScanNote = !hasAgent
    ? "No Scanner Agent registered — storage scan not performed. Deletion relies on threshold key destruction; register an agent for independent storage verification."
    : undefined;

  scanResult = {
    scanId: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    entityId,
    backends,
    keyVerification: {
      testCiphertextId: entityId,
      expectedFailure: hasKey,
    },
    allVerified: backends.every((b) => b.absent) && hasKey,
    caveats: [],
  };

  // Step 5: Remove from SMT, get non-membership proof
  const nonMembershipProof = await smtDO.removeEntity(entityId);

  // Step 6: Build log entry and append
  const salt = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  const commitment = await computeCommitment(entityType, entityId, salt);
  const scanHash = await hashScanResult(scanResult);

  const entryWithoutSig: Omit<LogEntry, "index" | "operatorSignature"> = {
    receiptId: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    entityType,
    commitment,
    deletionMethod: hasKey ? "crypto_shredding_2of3" : "agent_verified",
    thresholdSignatures: attestations.map((a) => a.signature),
    scanHash,
    smtRoot: nonMembershipProof.smtRoot,
  };

  const message = new TextEncoder().encode(
    "vd-log-entry-v1:" + canonicalJSON(entryWithoutSig),
  );
  const operatorSignature = bytesToHex(await ed.signAsync(message, operatorKey));

  const logEntry: Omit<LogEntry, "index"> = {
    ...entryWithoutSig,
    operatorSignature,
  };

  const logDOId = env.TRANSPARENCY_LOG_DO.idFromName("main");
  const logDO = env.TRANSPARENCY_LOG_DO.get(logDOId);
  const inclusionProof = await logDO.append(logEntry);

  // Step 7: Create W3C VC receipt
  const receipt = await createDeletionReceipt({
    entityType,
    entityId,
    issuerDid: "did:web:verifiabledelete.dev",
    signingKey: operatorKey,
    attestations: attestations.map(deserializeAttestation),
    scanResult,
    nonMembershipProof,
    inclusionProof,
    storageScanNote,
  });

  // Step 8: Store receipt and update status
  const receiptId = receipt.id.replace("urn:uuid:", "");

  await env.DB.prepare(
    "UPDATE deletions SET status = ?, receipt_id = ?, receipt_json = ?, scan_result_json = ?, completed_at = ? WHERE id = ?",
  )
    .bind("completed", receiptId, JSON.stringify(receipt), JSON.stringify(scanResult), new Date().toISOString(), deletionId)
    .run();

  await incrementUsage(env, auth.customerId, "deletions_completed");
  await incrementUsage(env, auth.customerId, "api_calls");

  return jsonResponse({
    deletion: {
      id: deletionId,
      entityId,
      entityType,
      status: "completed",
    },
    receipt,
  }, 201);
}

// --- Agent Communication ---

async function callScannerAgent(
  _env: Env,
  operatorKey: Uint8Array,
  agent: Pick<AgentRow, "id" | "callback_url" | "public_key_hex">,
  entityId: string,
  entityHash: string,
): Promise<{
  backends: BackendScanResult[];
  error?: { status: number; code: string; message: string };
}> {
  const requestBody = {
    requestId: crypto.randomUUID(),
    entities: [{ entityId, entityHash }],
    timestamp: new Date().toISOString(),
  };

  // Use canonicalJSON for body so the sent bytes match the signed bytes
  const bodyStr = canonicalJSON(requestBody);

  // Sign request with operator key
  const signMessage = new TextEncoder().encode(
    "vd-scan-request-v1:" + bodyStr,
  );
  const signature = bytesToHex(await ed.signAsync(signMessage, operatorKey));

  let response: Response;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    response = await fetch(agent.callback_url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-VD-Signature": signature,
        "X-VD-Request-Id": requestBody.requestId,
      },
      body: bodyStr,
      signal: controller.signal,
    });

    clearTimeout(timeout);
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      return { backends: [], error: { status: 502, code: "AGENT_UNREACHABLE", message: "Scanner agent timed out" } };
    }
    return { backends: [], error: { status: 502, code: "AGENT_UNREACHABLE", message: `Failed to reach scanner agent: ${err instanceof Error ? err.message : String(err)}` } };
  }

  if (!response.ok) {
    return { backends: [], error: { status: 502, code: "AGENT_ERROR", message: `Scanner agent returned ${response.status}` } };
  }

  let agentResponse: AgentScanResponse;
  try {
    agentResponse = (await response.json()) as AgentScanResponse;
  } catch {
    return { backends: [], error: { status: 502, code: "AGENT_ERROR", message: "Invalid JSON response from scanner agent" } };
  }

  // Verify agent signature (agent signs: "vd-scan-result-v1:" + canonicalJSON(results))
  const agentVerifyMessage = new TextEncoder().encode(
    "vd-scan-result-v1:" + canonicalJSON(agentResponse.results),
  );

  let sigValid = false;
  try {
    sigValid = await ed.verifyAsync(
      hexToBytes(agentResponse.signature),
      agentVerifyMessage,
      hexToBytes(agent.public_key_hex),
    );
  } catch {
    sigValid = false;
  }

  if (!sigValid) {
    return { backends: [], error: { status: 502, code: "AGENT_SIGNATURE_INVALID", message: "Scanner agent response signature verification failed" } };
  }

  // Flatten per-entity backend results from the agent response
  const backends: BackendScanResult[] = [];
  for (const entityResult of agentResponse.results) {
    for (const b of entityResult.backends) {
      backends.push({
        type: b.type,
        identifier: b.identifier,
        query: `agent-scan:${b.type}`,
        absent: b.absent,
        scannedAt: b.scannedAt,
      });
    }
  }

  return { backends };
}

// --- Read Operations ---

async function getDeletion(
  env: Env,
  auth: AuthContext,
  deletionId: string,
): Promise<Response> {
  const deletion = await env.DB.prepare(
    "SELECT id, entity_id, entity_type, status, receipt_id, receipt_json, created_at, completed_at FROM deletions WHERE id = ? AND customer_id = ?",
  )
    .bind(deletionId, auth.customerId)
    .first<Pick<DeletionRow, "id" | "entity_id" | "entity_type" | "status" | "receipt_id" | "receipt_json" | "created_at" | "completed_at">>();

  if (!deletion) {
    return errorResponse(404, "NOT_FOUND", "Deletion not found");
  }

  const result: Record<string, unknown> = {
    id: deletion.id,
    entityId: deletion.entity_id,
    entityType: deletion.entity_type,
    status: deletion.status,
    created_at: deletion.created_at,
    completed_at: deletion.completed_at,
  };

  if (deletion.receipt_json) {
    result.receipt = JSON.parse(deletion.receipt_json);
  }

  return jsonResponse(result);
}

async function getReceipt(env: Env, receiptId: string): Promise<Response> {
  const deletion = await env.DB.prepare(
    "SELECT receipt_json FROM deletions WHERE receipt_id = ?",
  )
    .bind(receiptId)
    .first<Pick<DeletionRow, "receipt_json">>();

  if (!deletion?.receipt_json) {
    return errorResponse(404, "NOT_FOUND", "Receipt not found");
  }

  return jsonResponse(JSON.parse(deletion.receipt_json));
}

async function verifyReceipt(env: Env, receiptId: string): Promise<Response> {
  if (!env.OPERATOR_SIGNING_KEY) {
    return errorResponse(503, "NOT_CONFIGURED", "Operator signing key not configured");
  }

  const deletion = await env.DB.prepare(
    "SELECT receipt_json FROM deletions WHERE receipt_id = ?",
  )
    .bind(receiptId)
    .first<Pick<DeletionRow, "receipt_json">>();

  if (!deletion?.receipt_json) {
    return errorResponse(404, "NOT_FOUND", "Receipt not found");
  }

  const receipt = JSON.parse(deletion.receipt_json) as DeletionReceipt;
  const publicKey = await ed.getPublicKeyAsync(hexToBytes(env.OPERATOR_SIGNING_KEY));
  const verification = await verifyDeletionReceipt(receipt, publicKey);

  return jsonResponse({ receiptId, verification });
}
