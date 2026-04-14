# @ephemeral-social/verifiable-delete-cloudflare

Cloudflare Workers/Durable Objects adapter for [Verifiable Delete](https://github.com/ephemeral-social/verifiable-delete).

> **Status: scaffold only.** Implementation coming soon.

## What this package provides

- `DurableObjectLogStorage`: `LogStorageAdapter` implementation using Durable Object transactional SQLite
- `DurableObjectKeyShareStore`: Threshold key share storage with destruction attestation
- `D1Scanner`, `KVScanner`, `R2Scanner`: `StorageScanner` implementations for Cloudflare storage backends
- `TransparencyLogDO`: Durable Object class for the append-only Merkle tree log
- `VerificationOracleWorker`: Worker with public API endpoints for browsing and verifying

## License

MIT. See [LICENSE](../../LICENSE) for details.
