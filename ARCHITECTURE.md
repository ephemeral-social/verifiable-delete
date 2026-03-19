# Architecture

This document specifies the technical architecture of Verifiable Delete. It is intended for contributors, security reviewers, and integration developers.

## Design principles

1. **Multi-party trust.** No single entity attests to its own deletion. Every deletion requires coordinated action from independent parties.
2. **Public auditability.** The deletion log is publicly browsable. Anyone can verify any entry without authentication.
3. **Platform-agnostic core.** The core library depends only on Web Crypto API. No Node.js native modules, no platform-specific dependencies.
4. **Honest guarantees.** The system provides computational inaccessibility, not physical absence. This distinction is stated clearly in all documentation and receipts.

## Components

### 1. Envelope encryption (AES-256-GCM, DEK/KEK)

Every piece of data is encrypted at the application layer before reaching any storage backend.

**Data Encryption Key (DEK):** generated per entity using `crypto.getRandomValues()`. Used once for a single encryption operation (eliminates nonce reuse risk). 256 bits.

**Key Encryption Key (KEK):** wraps the DEK. The KEK is the target of threshold splitting and destruction. 256 bits.

**Encryption flow:**
1. Generate random DEK (256 bits)
2. Encrypt data with DEK using AES-256-GCM (96-bit random nonce, Web Crypto API)
3. Wrap DEK with KEK using AES-KW (Web Crypto API)
4. Store encrypted blob + wrapped DEK in application storage
5. Split KEK into shares (see threshold key management)

**Nonce safety:** each DEK is used exactly once. The birthday collision risk with 96-bit random nonces (50% at ~2^48 messages per key) is eliminated because each key encrypts exactly one message.

### 2. Forward-secret key ratcheting (HKDF)

KEKs evolve per epoch to provide forward secrecy. Old key material is automatically irrecoverable.

**Ratchet step:**
```
next_kek = HKDF-SHA256(
  ikm: current_kek || fresh_randomness,
  salt: epoch_counter,
  info: "vd-kek-ratchet-v1"
)
```

After derivation, `current_kek` is deleted. This uses the native Web Crypto `deriveBits` operation with HKDF, requiring no external dependencies.

**Epoch triggers:** configurable per deployment. For Ephemeral Events, the epoch is the event lifecycle (creation to TTL expiry). For the paid API, epochs are time-based (configurable interval).

### 3. Shamir threshold key management (2-of-3)

The KEK is split into three shares using Shamir's Secret Sharing over GF(2^8). Any two shares reconstruct the key. No single share reveals any information about the key.

**Library:** `shamir-secret-sharing` by Privy. Zero-dependency, pure TypeScript, Web Crypto API only. Audited by Cure53 and Zellic.

**Share distribution:**
- Share 1: operator's key store (Durable Object in reference implementation)
- Share 2: Verification Oracle (separate Durable Object, independent account)
- Share 3: third party (customer-controlled for enterprise, or independent VD node)

**Key destruction protocol:**
1. Deletion is triggered (TTL expiry, user request, or API call)
2. Operator sends destruction request to at least one other share holder
3. Each participating share holder:
   a. Destroys their share from storage (transactional delete)
   b. Signs a destruction attestation with their Ed25519 key
   c. Returns the signed attestation
4. Operator destroys their own share
5. Operator collects at least 2 attestation signatures
6. Key is irrecoverable (any 1 share reveals nothing)

**Share integrity:** the `shamir-secret-sharing` library does not verify shares on reconstruction. The system validates key destruction by attempting decryption of a retained test ciphertext. Decryption failure confirms key destruction.

### 4. Post-deletion verification scanning

After key destruction, automated scans confirm data absence across all storage backends.

**Scan operations (Cloudflare reference):**
- D1: `SELECT COUNT(*) FROM [table] WHERE entity_id = ?` (expect 0)
- KV: `get(key)` (expect null)
- R2: `head(key)` (expect null/404)
- Test decryption: attempt to decrypt retained test ciphertext with destroyed key (expect failure)

**KV consistency delay:** KV is eventually consistent with up to 60 seconds propagation delay. Scans wait a configurable delay (default: 90 seconds) before checking KV.

**D1 Time Travel caveat:** D1 retains WAL data for 30 days (point-in-time recovery). Encrypted data persists in Time Travel backups but is computationally inaccessible without the destroyed key. The scan result notes this: "D1 record absent from live database. Encrypted remnants may persist in PITR backups for up to 30 days but are inaccessible without the destroyed encryption key."

**Scan result format:**
```json
{
  "scan_id": "uuid",
  "timestamp": "ISO 8601",
  "backends": [
    { "type": "d1", "table": "events", "query": "entity_id = abc123", "result": "absent" },
    { "type": "kv", "key": "event:abc123", "result": "absent" },
    { "type": "r2", "key": "photos/abc123/", "result": "absent" }
  ],
  "key_verification": {
    "test_ciphertext_id": "uuid",
    "decryption_result": "expected_failure",
    "error": "OperationError: key does not exist"
  },
  "d1_time_travel_note": "Encrypted remnants may persist in PITR backups for up to 30 days."
}
```

### 5. Sparse Merkle Tree (non-membership proofs)

A Sparse Merkle Tree tracks all active entities. After deletion, the entity is removed from the SMT and a non-membership proof is generated.

**Library:** `@zk-kit/sparse-merkle-tree` (Privacy & Scaling Explorations, Ethereum Foundation). TypeScript implementation supporting SHA-256 and Poseidon hash functions.

**Hash function:** SHA-256 (via `@noble/hashes`). Chosen for universality and NIST standardization over Poseidon (which is optimized for ZK circuits we don't currently use).

**Operations:**
- On data creation: `smt.add(entity_hash, value_hash)`
- On deletion: `smt.delete(entity_hash)`, then `proof = smt.createProof(entity_hash)`
- The proof demonstrates non-membership: the entity hash maps to an empty leaf
- Any verifier: `smt.verifyProof(proof)` returns true if the proof is valid against the published root

**SMT root** is published in every deletion receipt and in the transparency log. The root evolves with each add/delete operation.

### 6. Deletion receipt (W3C Verifiable Credential)

Each deletion produces a receipt formatted as a W3C VC (Data Model 2.0).

**Receipt structure:**
```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://ephemeralsocial.com/ns/deletion/v1"
  ],
  "type": ["VerifiableCredential", "DeletionReceipt"],
  "issuer": "did:web:ephemeralsocial.com",
  "issuanceDate": "2026-04-13T14:32:00Z",
  "credentialSubject": {
    "entityType": "event_data",
    "commitment": "SHA256(event_data||abc123||random_salt)",
    "salt": "random_salt_hex",
    "deletionMethod": "crypto-shredding",
    "encryptionAlgorithm": "AES-256-GCM",
    "keyManagement": "shamir-2-of-3",
    "keyRatcheting": "HKDF-SHA256"
  },
  "evidence": [
    {
      "type": "ThresholdAttestation",
      "participants": 3,
      "threshold": 2,
      "attestations": [
        { "holder": "did:web:ephemeralsocial.com#key-1", "signature": "..." },
        { "holder": "did:web:oracle.ephemeralsocial.com#key-1", "signature": "..." }
      ]
    },
    {
      "type": "StorageScan",
      "scanHash": "SHA256 of scan result document",
      "backendsChecked": 3,
      "allAbsent": true,
      "keyVerified": true
    },
    {
      "type": "NonMembershipProof",
      "smtRoot": "hex",
      "proof": "base64 encoded SMT proof"
    },
    {
      "type": "TransparencyLogInclusion",
      "logIndex": 4271,
      "treeSize": 4272,
      "treeRoot": "hex",
      "inclusionProof": ["hex", "hex", "..."],
      "witnessSignatures": [
        { "witness": "sigsum.example.com", "signature": "..." }
      ]
    }
  ],
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:web:ephemeralsocial.com#key-1",
    "proofValue": "..."
  }
}
```

### 7. Transparency log (append-only Merkle tree)

A publicly browsable, append-only log of all deletion events.

**Implementation:** Merkle tree stored in a Durable Object's transactional SQLite storage. Single-threaded execution eliminates distributed consensus. Ed25519-signed tree heads.

**Log entry (public, blinded):**
```json
{
  "index": 4271,
  "receiptId": "uuid",
  "timestamp": "2026-04-13T14:32:00Z",
  "entityType": "event_data",
  "commitment": "SHA256(event_data||abc123||salt)",
  "deletionMethod": "crypto-shredding, AES-256-GCM, threshold 2-of-3",
  "thresholdSignatures": ["sig1", "sig2"],
  "scanHash": "SHA256 of scan results",
  "smtRoot": "hex",
  "operatorSignature": "Ed25519 signature over this entry"
}
```

**Merkle tree operations:**
- Append: add leaf hash, recompute path to root, sign new tree head
- Inclusion proof: return sibling hashes from leaf to root
- Consistency proof: prove tree at size N is a prefix of tree at size M

**Signed tree head:**
```json
{
  "treeSize": 4272,
  "rootHash": "hex",
  "timestamp": "2026-04-13T14:32:01Z",
  "signature": "Ed25519 signature by log operator"
}
```

**External witness anchoring:** tree heads are periodically cross-posted to external witnesses for split-view protection. If the operator shows different tree roots to different verifiers, witnesses detect the inconsistency. Options:
- Sigsum litewitness (lightweight, SQLite-backed, open-source)
- Azure Confidential Ledger (hardware-backed, tamper-proof, ~$3/day)

### 8. Verification Oracle API

The public interface for browsing the log and verifying receipts.

**Public endpoints (no auth):**

`GET /log` returns the current signed tree head.

`GET /log/entries?offset=0&limit=50` returns paginated log entries. Each entry contains all fields listed above. Browsable by anyone.

`GET /log/entry/{receipt-id}` returns the full deletion receipt (W3C VC) with all evidence, proofs, and scan results.

`GET /log/proof/{receipt-id}` returns just the Merkle inclusion proof for lightweight verification.

`GET /log/consistency?from={size}&to={size}` returns a consistency proof proving the log is append-only between two tree sizes.

**Authenticated endpoints (paid API):**

`POST /delete` triggers a deletion through the VD system. Accepts entity identifiers, coordinates threshold key destruction, runs scans, generates receipt, appends to log, returns the complete receipt.

`POST /verify` submits a receipt for independent verification. The Oracle checks all signatures, verifies Merkle proofs, confirms threshold attestations, validates SMT non-membership proof, and returns a verification result.

`GET /log/entries?api_key=...` returns entries filtered to the authenticated customer's deletions.

## Cloudflare reference implementation

The `@ephemeral-social/verifiable-delete-cloudflare` package maps the abstract architecture to Cloudflare infrastructure:

| Component | Cloudflare primitive |
|-----------|---------------------|
| KEK share store (operator) | Durable Object (transactional SQLite) |
| KEK share store (oracle) | Separate Durable Object (independent account) |
| Transparency log | Durable Object (single-threaded, globally unique) |
| SMT state | Durable Object storage |
| Post-deletion scans | Worker function querying D1, KV, R2 |
| Deletion orchestration | Worker (alarm-triggered or HTTP-triggered) |
| Verification Oracle API | Worker (public HTTP endpoints) |
| Encrypted data storage | D1 (relational), R2 (blobs), KV (key-value) |

**Constraints:**
- 128 MB memory per Worker invocation
- 30 second CPU time (paid plan)
- Web Crypto API only (no native modules)
- D1 Time Travel: 30-day mandatory PITR retention (cannot be disabled)
- KV: 60-second eventual consistency
- No hardware TEE or HSM attestation available

All dependencies (`shamir-secret-sharing`, `@noble/hashes`, `@noble/ed25519`, `@zk-kit/sparse-merkle-tree`) are pure JavaScript/TypeScript with Web Crypto API only. Verified compatible with Workers runtime.

## Security model

**Threat model:**
- Honest-but-curious infrastructure provider (Cloudflare): has theoretical access to decrypted request data during processing. Threshold distribution across multiple providers mitigates.
- Malicious operator: cannot fabricate threshold attestations from independent parties. Cannot retroactively modify log entries (Merkle tree + witness anchoring). Can selectively omit deletions from the log (completeness limitation).
- Colluding threshold parties: if 2-of-3 parties collude before destruction, they can reconstruct and retain the key. Mitigated by choosing genuinely independent parties.
- Key remanence: key material may persist in V8 isolate memory after "deletion." Managed runtime (JavaScript) prevents `explicit_bzero()`-style secure erasure. Mitigated by: per-entity DEKs (limits exposure), forward-secret ratcheting (old epochs irrecoverable), and the short-lived nature of Worker invocations.

**What the system proves:**
- Multiple independent parties attested to key destruction (threshold attestation)
- Data was confirmed absent from all live storage systems (scan results)
- The entity no longer exists in the data index (SMT non-membership proof)
- This deletion event was recorded in a tamper-evident log (Merkle inclusion proof)
- The log has not been retroactively modified (consistency proofs + witness anchoring)

**What the system does not prove:**
- Physical absence of encrypted ciphertext (impossible without hardware attestation)
- That every deletion was logged (completeness, inherent limitation)
- That no party retained a copy before deletion (classical impossibility, Broadbent & Islam 2020)
