# verifiable-delete

**Verifiable data deletion for web and cloud applications.**

An open-source TypeScript framework that combines crypto-shredding with W3C Verifiable Credential-formatted deletion receipts and Sigstore Rekor transparency log integration: cryptographically signed, machine-verifiable, independently auditable proof that data has been rendered permanently inaccessible.

> **This project is in the design phase.** Architecture and specification are being developed. Implementation is planned as part of an [NLnet NGI Zero Commons Fund](https://nlnet.nl/commonsfund/) grant application. See [Architecture](#architecture) below for the technical approach.

## The Problem

Every service that promises to delete user data faces the same gap: the API returns a success code confirming the *request was accepted*. Nobody can prove the data is actually gone.

- **GDPR Article 17** creates a legal obligation for erasure but no technical verification mechanism. Compliance today means trust, not proof.
- **Cloud providers** return `Promise<void>` or `HTTP 204`, confirming request acceptance, not deletion completion
- **Existing academic approaches** require trusted hardware (TPMs, Intel SGX) or blockchain infrastructure, and none produce a reusable software library
- **Edge and multi-region infrastructure** replicates data across hundreds of locations with mixed consistency models, making verification especially hard

## The Approach

**Crypto-shredding + verifiable attestation + transparency logging.**

Instead of trying to prove data was physically erased from every storage location (classically impossible without trusted hardware), we:

1. **Encrypt all data at the application layer** before it reaches any storage backend, using per-entity envelope encryption (AES-256-GCM via Web Crypto API)
2. **Manage encryption keys in a strongly consistent store** (reference implementation uses Cloudflare Durable Objects, with documented interfaces for PostgreSQL, Redis, and SQLite), separate from the encrypted data
3. **Delete by destroying the encryption key.** Once the key is gone, encrypted data is computationally inaccessible regardless of physical persistence
4. **Generate a deletion receipt** as a W3C Verifiable Credential, a cryptographically signed attestation recording what was deleted, when, and confirmation of key destruction
5. **Submit the deletion receipt to a Sigstore Rekor transparency log**, an independent, append-only, publicly queryable ledger. The operator cannot skip, backdate, or retract deletion receipts.
6. **Expose a third-party verification endpoint** allowing external auditors, regulators, or users to independently confirm data inaccessibility and co-sign the deletion receipt

The result: machine-verifiable proof that specific data has been rendered permanently inaccessible, even if encrypted remnants persist in caches, WAL logs, or backup systems. The transparency log ensures the operator cannot selectively omit deletions.

## Architecture

```
+---------------------------------------------------------+
|                    Your Application                      |
|                                                          |
|   Data --> Encrypt (DEK) --> Store encrypted blob        |
|                                                          |
|   DEK --> Wrap (KEK) --> Store wrapped DEK               |
|                                                          |
|   KEK --> Strongly consistent key store                  |
|           (e.g., Durable Objects, PostgreSQL, Redis)     |
+----------------------------+----------------------------+
                             |
                       On TTL expiry:
                             |
                      +------v-------+
                      | Destroy KEK  |
                      | in key store |
                      +------+-------+
                             |
                +------------v------------+
                |  Generate deletion      |
                |  receipt (W3C VC):      |
                |                         |
                |  - Issuer identity      |
                |  - Content hash         |
                |  - Timestamp            |
                |  - Key destruction      |
                |    confirmation         |
                |  - Ed25519 signature    |
                +------------+------------+
                             |
                +------------v------------+
                |  Submit to Sigstore     |
                |  Rekor transparency log |
                +------------+------------+
                             |
                +------------v------------+
                |  Third-party            |
                |  verification endpoint  |
                |  (auditors, regulators, |
                |   users can query)      |
                +-------------------------+
```

## Planned Deliverables

### `@ephemeral-social/verifiable-delete` (MIT)
Platform-agnostic core library. Envelope encryption, key lifecycle, deletion receipts as W3C Verifiable Credentials, Sigstore Rekor submission. Usable by any developer on any platform.

### `@ephemeral-social/verifiable-delete-cloudflare` (MIT)
Reference edge adapter. Durable Objects key store, Workers orchestration, cache purge verification across KV (eventually consistent), R2 (strongly consistent), and D1 (strongly consistent with 30-day Time Travel). Portable pattern: documentation covers building adapters for Deno Deploy, AWS Lambda@Edge, and self-hosted environments.

### Reference Integration
The library is integrated into [Ephemeral Events](https://github.com/ephemeral-social/events), a production SvelteKit application with deletion-by-default architecture, serving as a real-world demonstration.

### Standards Contributions
Draft IETF informational document specifying the verifiable deletion protocol. Deletion attestation VC profile submitted to W3C Credentials Community Group.

## Prior Art & Why This Gap Exists

Academic research on verifiable deletion spans over a decade but has not produced a deployable, general-purpose software library:

- **Hao, Clarke, Zorzo (IEEE TDSC, 2016)**: TPM-based Java Card proof-of-concept with published source code. Requires dedicated tamper-resistant hardware not available in cloud, edge, or serverless environments. Last commit 2014.
- **Yang, Tao, Zhao (2019)** and **SevDel (Li & Ni, 2023)**: Blockchain-based verification. Three structural problems: (a) privacy paradox, an immutable public ledger of deletion events conflicts with the right to be forgotten, (b) per-transaction costs are prohibitive at application scale, (c) blockchain infrastructure dependency. SevDel additionally requires Intel SGX, deprecated for consumer CPUs.
- **Proofs of Secure Erasure** (Perito & Tsudik, 2010): Only applicable to memory-bounded embedded devices
- **Vanish** (USENIX Security 2009): Broken by Sybil attacks within months of publication
- **Quantum certified deletion** (Broadbent & Islam, TCC 2020): Information-theoretic guarantees, but requires quantum hardware

This project provides: software-only (no TPM/SGX), no blockchain dependency, transparency log auditability via existing free infrastructure (Sigstore Rekor), W3C standard credentials, packaged as a reusable npm library. This combination does not exist.

## References

- Reardon, Basin, Capkun. "SoK: Secure Data Deletion" (IEEE S&P 2013)
- Hao, Clarke, Zorzo. "Deleting Secret Data with Public Verifiability" (IEEE TDSC 2016)
- Yang, Tao, Zhao. "Publicly verifiable data transfer and deletion scheme for cloud storage" (2019)
- Li, Ni. "SevDel: Accelerating Secure and Verifiable Data Deletion in Cloud Storage via SGX and Blockchain" (2023)
- W3C Verifiable Credentials Data Model 2.0 (Recommendation 2025)
- NIST SP 800-88 Rev. 2, Guidelines for Media Sanitization (2025)
- Sigstore Rekor transparency log documentation
- Cloudflare Durable Objects documentation, consistency model and transactional storage

## Status

| Component | Status |
|-----------|--------|
| Architecture design | Complete |
| Deletion receipt VC schema | In progress |
| Core library | Planned |
| Cloudflare adapter | Planned |
| Sigstore Rekor integration | Planned |
| Third-party verification endpoint | Planned |
| Reference integration | Planned |
| IETF informational draft | Planned |
| W3C CG submission | Planned |

## Related

- [Ephemeral Events](https://github.com/ephemeral-social/events) - The production application where this library will be integrated
- [ephemeralsocial.com](https://ephemeralsocial.com) - Project website

## License

MIT. See [LICENSE](LICENSE) for details.
