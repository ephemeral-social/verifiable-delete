/**
 * Shared types for the VD multi-tenant API.
 * @module api/types
 */

/** Authenticated request context. */
export interface AuthContext {
  customerId: string;
  keyId: string;
}

/** Agent scan response received from a customer's scanner agent. */
export interface AgentScanResponse {
  requestId: string;
  results: Array<{
    entityId: string;
    backends: Array<{
      type: string;
      identifier: string;
      absent: boolean;
      scannedAt: string;
      note: string | null;
    }>;
    allAbsent: boolean;
  }>;
  signature: string;
  timestamp: string;
}

/** Deletion request body. */
export interface DeletionRequest {
  entityId: string;
  entityType: string;
  customerAttestation?: string;
}

// --- D1 Row Types ---

export interface CustomerRow {
  id: string;
  name: string;
  email: string;
  plan: string;
  status: string;
  created_at: string;
}

export interface ApiKeyRow {
  id: string;
  customer_id: string;
  key_hash: string;
  key_prefix: string;
  label: string | null;
  created_at: string;
  revoked_at: string | null;
}

export interface AgentRow {
  id: string;
  customer_id: string;
  callback_url: string;
  public_key_hex: string;
  status: string;
  registered_at: string;
}

export interface DeletionRow {
  id: string;
  customer_id: string;
  entity_id: string;
  entity_type: string;
  entity_hash: string;
  kek_id: string | null;
  status: string;
  receipt_id: string | null;
  receipt_json: string | null;
  scan_result_json: string | null;
  error: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface KeyRegistrationRow {
  id: string;
  customer_id: string;
  kek_id: string;
  status: string;
  created_at: string;
  destroyed_at: string | null;
}

export interface UsageRow {
  customer_id: string;
  month: string;
  entities_registered: number;
  deletions_completed: number;
  api_calls: number;
}
