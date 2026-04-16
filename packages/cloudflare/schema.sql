-- Demo data table for verifiable-delete Cloudflare adapter.
-- Stores encrypted blobs for demonstration purposes.
-- All binary data stored as hex strings (D1 BLOB handling is unreliable).

CREATE TABLE IF NOT EXISTS demo_data (
  entity_id TEXT PRIMARY KEY,
  encrypted_blob TEXT NOT NULL,
  nonce TEXT NOT NULL,
  wrapped_dek TEXT NOT NULL,
  kek_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ==========================================================================
-- MULTI-TENANT API TABLES
-- ==========================================================================

-- Customer accounts
CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'standard',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL
);

-- API keys (SHA-256 hashed, prefix for display)
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  label TEXT,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_customer ON api_keys(customer_id);

-- Scanner agents registered by customers
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  callback_url TEXT NOT NULL,
  public_key_hex TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  registered_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agents_customer ON agents(customer_id);

-- KEK registrations (threshold key shares managed by VD)
CREATE TABLE IF NOT EXISTS key_registrations (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  kek_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  destroyed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_key_registrations_customer ON key_registrations(customer_id);
CREATE INDEX IF NOT EXISTS idx_key_registrations_kek ON key_registrations(kek_id);

-- Deletion records with receipt storage
CREATE TABLE IF NOT EXISTS deletions (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_hash TEXT NOT NULL,
  kek_id TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  receipt_id TEXT,
  receipt_json TEXT,
  scan_result_json TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_deletions_customer ON deletions(customer_id);
CREATE INDEX IF NOT EXISTS idx_deletions_entity ON deletions(customer_id, entity_hash);
CREATE INDEX IF NOT EXISTS idx_deletions_receipt ON deletions(receipt_id);

-- Monthly usage tracking
CREATE TABLE IF NOT EXISTS usage (
  customer_id TEXT NOT NULL,
  month TEXT NOT NULL,
  entities_registered INTEGER NOT NULL DEFAULT 0,
  deletions_completed INTEGER NOT NULL DEFAULT 0,
  api_calls INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (customer_id, month)
);
