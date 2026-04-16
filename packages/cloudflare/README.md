# @ephemeral-social/verifiable-delete-cloudflare

Cloudflare Workers/Durable Objects adapter for [Verifiable Delete](https://github.com/ephemeral-social/verifiable-delete).

> **Status: complete.** Full API, Durable Objects, and deletion orchestration. Production-deployed and verified with 78 E2E assertions.

## What this package provides

**API Routes** (Hono-based Workers):
- Customer management, API key authentication, usage tracking
- Entity registration (Sparse Merkle Tree backed)
- Threshold key share registration (2-of-3 Shamir)
- Scanner agent registration with Ed25519 signature verification
- Full deletion orchestration: key destruction → agent scan → receipt generation → log append
- Batch deletion support
- Receipt verification endpoint
- Public transparency log browsing (signed tree heads, Merkle proofs)
- Operator key endpoint (`/.well-known/vd-operator-key`)

**Durable Objects**:
- `KeyShareDO`: Threshold key share storage with destruction attestation (Ed25519 signed)
- `SparseMerkleTreeDO`: Entity registration and non-membership proof generation
- `TransparencyLogDO`: Append-only Merkle tree with signed tree heads and inclusion proofs

**Storage**:
- D1 for relational data (customers, API keys, agents, entities, deletions, receipts)
- KV for operator key caching
- R2 for receipt storage

## Architecture

```
Client → Workers API → D1 (auth, entities)
                     → KeyShareDO (key destruction + attestations)
                     → Scanner Agent (external, Ed25519-verified scan)
                     → SparseMerkleTreeDO (non-membership proof)
                     → TransparencyLogDO (append + inclusion proof)
                     → Receipt generation (W3C VC, Ed25519 signed)
                     → R2 + D1 (receipt storage)
```

## Deployment

```bash
npx wrangler deploy
wrangler secret put OPERATOR_SIGNING_KEY    # Ed25519 private key (hex)
wrangler secret put VD_ADMIN_SECRET         # Admin API bearer token
wrangler d1 execute vd-demo --file=schema.sql --remote
```

## License

MIT. See [LICENSE](../../LICENSE) for details.
