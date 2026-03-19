# verifiable-delete

**Verifiable data deletion for the internet.**

An open-source TypeScript framework that combines threshold crypto-shredding, W3C Verifiable Credential deletion receipts, a public append-only Merkle tree transparency log, and automated post-deletion scanning. Every deletion is attested by independent parties, logged in a tamper-evident public ledger, and verified through cryptographic proofs of data absence.

> **Status: implementation in progress.** The architecture is complete. The reference integration is [Ephemeral Events](https://github.com/ephemeral-social/events) (live at [ephemeralsocial.com/events](https://ephemeralsocial.com/events)).

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
Platform-agnostic core library. Envelope encryption (AES-256-GCM, DEK/KEK), Shamir threshold key management, forward-secret key ratcheting (HKDF), W3C VC deletion receipts, Sparse Merkle Tree proofs, Merkle tree transparency log. Works in any JavaScript runtime with Web Crypto API.

### `@ephemeral-social/verifiable-delete-cloudflare` (MIT)
Reference edge adapter. Durable Objects key store and transparency log, Workers orchestration, post-deletion scanning across KV, R2, and D1.

### Verification Oracle API
Public API for browsing the transparency log and verifying deletion receipts. Independent verification service for enterprise customers.

### Reference integration
Integrated into [Ephemeral Events](https://github.com/ephemeral-social/events). Every deleted event page serves its deletion receipt with links to the public log. Live at [ephemeralsocial.com/events](https://ephemeralsocial.com/events).

## API

### Public (no authentication)

```
GET  /log                                    Current signed tree head
GET  /log/entries?offset=0&limit=50          Paginated log entries
GET  /log/entry/{receipt-id}                 Full deletion receipt with all proofs
GET  /log/proof/{receipt-id}                 Merkle inclusion proof
GET  /log/consistency?from={size}&to={size}  Consistency proof (append-only verification)
```

### Authenticated (paid)

```
POST /delete                                 Trigger deletion, returns receipt
POST /verify                                 Submit receipt for independent verification
GET  /log/entries?api_key=...                Customer-filtered log view
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

| Component | Status |
|-----------|--------|
| Architecture design | Complete |
| Core: envelope encryption (AES-256-GCM, DEK/KEK) | In progress |
| Core: Shamir threshold key management | Planned |
| Core: forward-secret key ratcheting (HKDF) | Planned |
| Deletion receipt W3C VC schema | Planned |
| Sparse Merkle Tree non-membership proofs | Planned |
| Merkle tree transparency log | Planned |
| Post-deletion scanning | Planned |
| Cloudflare adapter (Durable Objects, KV, R2, D1) | Planned |
| Verification Oracle API | Planned |
| Reference integration (Ephemeral Events) | Planned |

## Related

- [Ephemeral Events](https://github.com/ephemeral-social/events) — Production app with deletion-by-default architecture
- [ephemeralsocial.com](https://ephemeralsocial.com) — Project website

## License

MIT. See [LICENSE](LICENSE) for details.
