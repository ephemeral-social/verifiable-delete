# verifiable-delete

**Verifiable data deletion for the internet.**

An open-source TypeScript framework that combines threshold crypto-shredding, W3C Verifiable Credential deletion receipts, a public append-only Merkle tree transparency log, and automated post-deletion scanning. Every deletion is attested by independent parties, logged in a tamper-evident public ledger, and verified through cryptographic proofs of data absence.

> **Status: core library and Cloudflare adapter complete.** 255 tests across core library (118), Cloudflare adapter (117), and E2E integration suite (20). Deployed on Cloudflare Workers. Public transparency log live at [verifiabledelete.dev](https://verifiabledelete.dev). The reference integration is [Ephemeral Events](https://github.com/ephemeral-social/events).

## The problem

Every service that promises to delete user data faces the same gap: the API returns a success code confirming the *request was accepted*. Nobody can prove the data is actually gone.

- **GDPR Article 17** creates a legal obligation for erasure but no technical verification mechanism. The EDPB's 2026 Coordinated Enforcement report found systemic compliance failures across 764 controllers in 32 DPAs.
- **Cloud providers** return `Promise<void>` or `HTTP 204`, confirming request acceptance, not deletion completion.
- **Enterprise compliance tools** (OneTrust, Transcend, BigID) orchestrate deletion commands but verify nothing. They confirm "we sent the API call," not "the data is actually gone."
- **Existing academic approaches** require trusted hardware (TPMs, Intel SGX) or blockchain infrastructure, and none produce a reusable software library.

## The approach

**Threshold crypto-shredding + multi-party attestation + public transparency log + post-deletion verification.**

1. **Encrypt all data at the application layer** using per-entity envelope encryption (AES-256-GCM via Web Crypto API) with forward-secret key ratcheting (HKDF).
2. **Split encryption keys across independent parties** using 2-of-3 Shamir secret sharing. No single party holds a complete key.
3. **Delete by coordinated key destruction.** At least two independent parties destroy their shares. The encryption key becomes irrecoverable. Encrypted data is computationally inaccessible regardless of physical persistence.
4. **Scan all storage backends** to confirm data absence. Attempt decryption with the destroyed key to confirm it no longer works.
5. **Generate a deletion receipt** as a W3C Verifiable Credential containing: threshold attestation signatures, storage scan results, a Sparse Merkle Tree non-membership proof, and a Merkle tree inclusion proof.
6. **Append the receipt to a public transparency log**: a Merkle tree with signed tree heads and external witness anchoring. Anyone can browse the log, click any entry, and verify the receipt.

The result: multi-party attested, publicly auditable, cryptographically verified proof that specific data has been rendered permanently inaccessible.

## Architecture

```
+---------------------------------------------------------------+
|                      Your Application                          |
|                                                                |
|  Data --> Encrypt (DEK, AES-256-GCM) --> Store encrypted blob  |
|                                                                |
|  DEK --> Wrap (KEK) --> Split KEK (2-of-3 Shamir)             |
|                                                                |
|  Share 1 --> Operator key store (Durable Object)               |
|  Share 2 --> Verification Oracle (independent DO)              |
|  Share 3 --> Third party (customer, auditor, or VD node)       |
+-------------------------------+-------------------------------+
                                |
                    On TTL expiry or deletion request:
                                |
          +---------------------v----------------------+
          |  Coordinated key destruction (2-of-3)      |
          |                                            |
          |  Share holder 1: destroy share, sign att.  |
          |  Share holder 2: destroy share, sign att.  |
          |  (Any two of three, key irrecoverable)     |
          +---------------------+----------------------+
                                |
          +---------------------v----------------------+
          |  Post-deletion verification scan           |
          |                                            |
          |  - Query all storage: confirmed absent     |
          |  - Attempt decryption: confirmed failure   |
          +---------------------+----------------------+
                                |
          +---------------------v----------------------+
          |  Generate deletion receipt (W3C VC)        |
          |                                            |
          |  - Threshold attestation signatures        |
          |  - Storage scan results                    |
          |  - SMT non-membership proof + root hash    |
          |  - Timestamp chain                         |
          |  - Ed25519 operator signature              |
          +---------------------+----------------------+
                                |
          +---------------------v----------------------+
          |  Append to public transparency log         |
          |                                            |
          |  - Merkle tree in Durable Object           |
          |  - Signed tree head (Ed25519)              |
          |  - Inclusion proof returned                |
          |  - Tree head anchored to external witness  |
          +--------------------------------------------+
```

## What makes this different

**Threshold key destruction** breaks the self-attestation problem. In every existing system, the operator attests to their own deletion. Verifiable Delete requires independent parties to co-sign key destruction. No single entity is the actor, the witness, and the record-keeper.

**Public transparency log** makes deletion auditable by anyone. Browse the log, click any entry, verify the receipt. Count total deletions. Check Merkle tree consistency. No authentication required. Log entries use cryptographic commitments (blinded): they reveal that a deletion occurred without revealing whose data or which specific entity.

**Sparse Merkle Tree non-membership proofs** provide cryptographic evidence of data absence. After deletion, a proof is generated showing the entity no longer exists in the data index. Any verifier can check this proof against the published SMT root without accessing the operator's systems. No enterprise deletion tool provides this today.

**Post-deletion scanning** transforms the receipt from "we executed a deletion command" to "we confirmed data is absent across all storage systems and the encryption key no longer works."

**Forward-secret key ratcheting** derives each epoch's key from the previous via HKDF, then deletes old key material. Combined with threshold splitting, keys are never held by a single party, automatically evolve to make old states irrecoverable, and require multi-party coordination to destroy.

## Public log entries

Every deletion produces a publicly browsable log entry:

| Field | Description | Privacy |
|-------|-------------|---------|
| Receipt ID | Random UUID | Reveals nothing |
| Timestamp | When deletion occurred | Public |
| Entity type | General category (e.g. "event_data", "user_rsvp") | Public |
| Commitment | `SHA256(entity_type \|\| entity_id \|\| salt)` | Blinded (identity hidden) |
| Deletion method | e.g. "crypto-shredding, AES-256-GCM, threshold 2-of-3" | Public |
| Threshold signatures | Co-signatures from share holders | Verifiable |
| Scan hash | Hash of post-deletion scan results | Verifiable |
| SMT proof | Non-membership proof + root hash | Verifiable |
| Inclusion proof | Merkle tree proof for this entry | Verifiable |
| Operator signature | Ed25519 signature over the full entry | Verifiable |

Click any entry to view the full deletion receipt.

## Deliverables

### `@ephemeral-social/verifiable-delete` (MIT)
Platform-agnostic core library. Envelope encryption (AES-256-GCM, DEK/KEK), Shamir threshold key management, forward-secret key ratcheting (HKDF), W3C VC deletion receipts, Sparse Merkle Tree proofs, Merkle tree transparency log. Works in any JavaScript runtime with Web Crypto API. Published on npm. 118 unit tests.

### `@ephemeral-social/verifiable-delete-cloudflare` (MIT)
Cloudflare Workers edge adapter. Full API with customer management, API key authentication, entity registration, deletion orchestration, and receipt verification. Durable Objects for key share storage (with destruction attestation), Sparse Merkle Tree state, and append-only transparency log. D1 for relational data (customers, API keys, agents, key registrations, deletions, usage). 117 tests. Deployed and production-tested.

### [`@ephemeral-social/verifiable-delete-scanner-agent`](https://github.com/ephemeral-social/verifiable-delete-scanner-agent) (MIT)
Independent scanner agent that verifies data absence across storage backends after deletion. Supports PostgreSQL, MySQL/MariaDB, MSSQL, MongoDB, Redis, Elasticsearch, S3-compatible stores, and Cloudflare D1/KV/R2. Cryptographically signs scan results with Ed25519. Deployed as a standalone service that the VD operator calls during the deletion pipeline.

### Public transparency log
Live at [verifiabledelete.dev](https://verifiabledelete.dev). Browse all deletion entries, click any entry to view the full W3C VC receipt, verify receipts independently. Real-time polling for new entries.

### Reference integration
[Ephemeral Events](https://github.com/ephemeral-social/events) — production app with deletion-by-default architecture. Integration in progress.

## API

### Public (no authentication)

```
GET  /.well-known/vd-operator-key            Operator public key (keys array format)
GET  /log                                    Current signed tree head (signed, Ed25519)
GET  /log/entries?offset=0&limit=50          Paginated log entries
GET  /log/entry/{id}                         Log entry by receipt ID
GET  /log/proof/{index}                      Merkle inclusion proof
GET  /log/consistency?from=X&to=Y            Merkle consistency proof between tree sizes
GET  /v1/receipts/{id}                       Full W3C VC deletion receipt
GET  /v1/receipts/{id}/verify                Independent receipt verification (4 checks)
```

### Customer API (API key authentication)

```
POST /v1/entities                            Register entity in Sparse Merkle Tree
POST /v1/entities/batch                      Batch entity registration (max 100)
POST /v1/keys                                Register threshold key shares (2-of-3 Shamir)
GET  /v1/keys/{kekId}                        Key registration status
POST /v1/agents                              Register scanner agent (callback URL + Ed25519 public key)
GET  /v1/agents                              List registered agents
DELETE /v1/agents/{id}                       Deregister scanner agent
POST /v1/deletions                           Trigger full deletion pipeline, returns W3C VC receipt
POST /v1/deletions/batch                     Batch deletion (max 100)
GET  /v1/deletions/{id}                      Deletion status and receipt
GET  /v1/usage                               Usage statistics (current month + 12-month history)
```

### Admin API

```
POST /admin/customers                        Create customer account
GET  /admin/customers                        List all customers
GET  /admin/customers/{id}                   Customer details with keys and agents
POST /admin/customers/{id}/keys              Issue API key
POST /admin/customers/{id}/suspend           Suspend customer account
POST /admin/customers/{id}/activate          Activate customer account
```

## Prior art

- **Hao, Clarke, Zorzo (IEEE TDSC, 2016)**: TPM-based proof-of-concept. Requires hardware not available in cloud environments.
- **Yang, Tao, Zhao (2019)** and **SevDel (Li & Ni, 2023)**: Blockchain-based. Privacy paradox, prohibitive costs, infrastructure dependency.
- **Darwish, Markatou, Smaragdakis (EuroSec 2025)**: Bounded Merkle Hash Trees and Global Merkle Forests for multi-cloud verification. Closest to this project. Requires cloud HSMs and secure enclaves.
- **Perito & Tsudik (2010)**: Proofs of Secure Erasure. Memory-bounded embedded devices only.
- **Broadbent & Islam (TCC 2020)**: Quantum certified deletion. Information-theoretic guarantees, requires quantum hardware.

This project provides: software-only, no blockchain, multi-party threshold attestation, public transparency log, cryptographic proofs of data absence, as a reusable npm library. This combination does not exist.

## Honest limitations

**Computational inaccessibility, not physical absence.** Crypto-shredding renders data computationally inaccessible by destroying the encryption key. Encrypted ciphertext may persist in storage backends or backup systems. This is the strongest achievable software-only guarantee.

**Classical impossibility.** Broadbent & Islam (2020) proved certified deletion is impossible with classical computing. This system provides the strongest achievable accountability for deletion procedures, not mathematical proof that no copy exists.

**Trust boundary.** The infrastructure provider (e.g. Cloudflare) remains in the trust boundary. Threshold distribution across providers mitigates but does not eliminate this.

**Completeness.** The log proves logged deletions were logged. It does not guarantee every deletion was logged. External witness anchoring prevents retroactive modification but not selective omission.

## References

- Reardon, Basin, Capkun. "SoK: Secure Data Deletion" (IEEE S&P 2013)
- Hao, Clarke, Zorzo. "Deleting Secret Data with Public Verifiability" (IEEE TDSC 2016)
- Darwish, Markatou, Smaragdakis. "Provable Co-Owned Data Deletion" (EuroSec 2025)
- Broadbent, Islam. "Quantum Encryption with Certified Deletion" (TCC 2020)
- Green, Miers. "Forward Secure Asynchronous Messaging from Puncturable Encryption" (IEEE S&P 2015)
- W3C Verifiable Credentials Data Model 2.0 (Recommendation 2025)
- NIST SP 800-88 Rev. 2, Guidelines for Media Sanitization (2025)
- NIST IR 8214C, First Call for Multi-Party Threshold Schemes (2026)
- EDPB Coordinated Enforcement Report on Right to Erasure (2026)

## Status

| Component | Status | Tests |
|-----------|--------|-------|
| Architecture design | Complete | — |
| Core: envelope encryption (AES-256-GCM, DEK/KEK) | Complete | 10 unit |
| Core: Shamir threshold key management | Complete | 15 unit |
| Core: forward-secret key ratcheting (HKDF) | Complete | (included in crypto) |
| Core: W3C VC deletion receipts | Complete | 18 unit |
| Core: Sparse Merkle Tree non-membership proofs | Complete | 12 unit |
| Core: Merkle tree transparency log | Complete | 46 unit |
| Core: post-deletion scanning | Complete | 12 unit |
| Core: integration (cross-module) | Complete | 5 unit |
| Cloudflare adapter: API routes & auth | Complete | 117 unit |
| Cloudflare adapter: Durable Objects (KeyShare, SMT, Log) | Complete | (included above) |
| Cloudflare adapter: deletion orchestration | Complete | (included above) |
| Scanner agent (7 backend types + 3 Cloudflare) | Complete | separate repo |
| E2E integration (full pipeline) | Complete | 20 tests |
| Production deployment (Cloudflare Workers) | Complete | verified |
| Public transparency log (verifiabledelete.dev) | Complete | — |
| Reference integration (Ephemeral Events) | In progress | — |

## Related

- [verifiabledelete.dev](https://verifiabledelete.dev) — Public transparency log (browse entries, view receipts, verify independently)
- [Scanner Agent](https://github.com/ephemeral-social/verifiable-delete-scanner-agent) — Independent deletion verification agent (10 backend types)
- [Ephemeral Events](https://github.com/ephemeral-social/events) — Production app with deletion-by-default architecture
- [ephemeralsocial.com](https://ephemeralsocial.com) — Project website

## License

MIT. See [LICENSE](LICENSE) for details.
