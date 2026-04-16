/**
 * Cloudflare Worker environment bindings.
 *
 * @module env
 */

export interface Env {
  KEY_SHARE_DO: DurableObjectNamespace<
    import("./durable-objects/key-share.js").KeyShareDO
  >;
  TRANSPARENCY_LOG_DO: DurableObjectNamespace<
    import("./durable-objects/transparency-log.js").TransparencyLogDO
  >;
  SMT_DO: DurableObjectNamespace<
    import("./durable-objects/sparse-merkle-tree.js").SparseMerkleTreeDO
  >;
  DB: D1Database;
  KV: KVNamespace;
  BUCKET: R2Bucket;
  OPERATOR_SIGNING_KEY?: string; // hex-encoded Ed25519 private key (32 bytes → 64 hex chars)
  VD_ADMIN_SECRET?: string; // bearer token for /admin/* endpoints
}
