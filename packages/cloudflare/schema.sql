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
