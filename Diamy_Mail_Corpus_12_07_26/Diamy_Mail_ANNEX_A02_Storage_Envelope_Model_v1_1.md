# Diamy Mail — ANNEX A02: Storage & Multi-Device Envelope Model

**Document title:** Diamy Mail — ANNEX A02: Storage & Multi-Device Envelope Model
**Version:** 1.0
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)
**Sibling dependencies:** A17 (IAM Integration Contract v1.1), A24 (Identity & Address Normalization v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: storage components, cryptographic model (per-message AES-256-GCM, ML-KEM-768 envelope wrapping with HKDF labels), server data model (blob store, catalogue, envelope directory, encrypted summary records, journal), field classification, write/read paths (frontier, client submission, Diamy↔Diamy), device lifecycle incl. delegated re-wrap protocol, deletion semantics, quotas, failure model, test scenarios, common AI errors |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: hardened envelope HKDF `info` to bind `device_id` (domain separation, A02-CRY-4); stated nonce-independence requirement explicitly (A02-CRY-1b); resolved a metadata-privacy gap — `recipients_canonical[]` on a stored per-principal message leaks the full recipient set to the server for every co-recipient, added A02-DM-4 restricting it to the routing-necessary subset + BCC non-disclosure rule; added `k_msg` re-derivation-resistance note (server cannot brute-force short summaries — summary is not a low-entropy oracle) as A02-CRY-3 clarification; added envelope fan-out DoS bound cross-ref; added AI error #12 (recipient-set leakage) |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies the server-side storage model of Diamy Mail and the multi-device envelope mechanism: how a message is encrypted once and made readable by N authorized devices, how devices are added and revoked, and what the server stores, byte for byte.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

Inherited invariants (restated for locality, owned by A00): STO-1..STO-5, CDM-ENC-1..3, API-3, SEC-CRYPT-1..4. Device key provenance and directory are owned by A17 (§5); this annex consumes them.

## 1.1 Out of scope

Client-side storage (encrypted SQLite catalogue, blob cache) is A03. The sync wire protocol is A04. Blind Index derivation is A05 (inputs defined in A24 §5). The gateway hold queue for zero-device recipients is A01 (requirement fixed in A17-DIR-5).

------

# 2. Storage Components

```
┌─────────────────────────────────────────────────────────────┐
│  diamy-maild storage plane                                   │
│                                                              │
│  ┌────────────────┐   ┌──────────────────┐  ┌────────────┐  │
│  │ BLOB STORE     │   │ CATALOGUE (SQL)  │  │ ENVELOPE   │  │
│  │ (object store, │   │ - message entries│  │ DIRECTORY  │  │
│  │  S3-compatible)│   │ - summary records│  │ (SQL)      │  │
│  │ - message blobs│   │ - folders/flags  │  │ - per      │  │
│  │ - attachment   │   │ - sync journal   │  │   (msg ×   │  │
│  │   blobs        │   │                  │  │   device)  │  │
│  │ ciphertext only│   │ no plaintext     │  │   wraps    │  │
│  └────────────────┘   └──────────────────┘  └────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ BLIND INDEX STORE (webmail-enabled users only, A05)    │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

- **A02-CMP-1**: The blob store MUST be object storage (S3-compatible). Blobs are immutable after write; any content change is a new blob ID. Blob IDs are UUIDv7 (CDM-ID-1), NOT content hashes — content-addressing would leak equality of ciphertexts across users if deduplicated, and deduplication across security boundaries is FORBIDDEN (see A02-CRY-6).
- **A02-CMP-2**: The catalogue and envelope directory reside in PostgreSQL. The physical DDL (A21) is the source of truth over this document's logical descriptions (CDM-NULL-2).
- **A02-CMP-3**: Backups of all three stores inherit the same guarantee: they contain ciphertext and metadata only. A backup restore MUST NOT require any key material that a storage compromise would also yield (A00 §3.2).

------

# 3. Cryptographic Model

## 3.1 Message encryption

- **A02-CRY-1**: Each message is encrypted exactly once with a fresh random 32-byte message key `k_msg` (CSPRNG), using **AES-256-GCM** with a unique 12-byte nonce per blob. GCM provides the integrity required by SEC-CRYPT-3 for the frontier path, where no sender signature is available.
- **A02-CRY-1b**: Every GCM encryption under `k_msg` (each blob and the summary) MUST use an **independent CSPRNG nonce**. Nonces MUST NOT be counters derived from blob order (a re-encryption with the same layout would collide). The number of encryptions under one `k_msg` is small (blobs + summary), so random 96-bit nonces have negligible collision probability; implementations MUST NOT reuse a nonce across two encryptions under the same key under any circumstance.
- **A02-CRY-2**: A message consists of 1..N blobs: one **body blob** (full RFC 5322 / MIME source, headers included) and zero or more **attachment blobs** (one per extracted attachment). All blobs of one message are encrypted under the same `k_msg`, each with its own nonce. AAD for each blob is `"mailblob:" + message_id + ":" + blob_id` (binary UUIDs, per CDM-ID-2 discipline; AAD components immutable per A17-ENC-3).
- **A02-CRY-3**: A compact **summary record** (subject, sender display form, date, first-line snippet, attachment count/names) is built while plaintext is available (frontier zone for inbound; client for outbound), serialized as JSON, and encrypted under `k_msg` with AAD `"mailsum:" + message_id`. It is stored in the catalogue as `CIPHERTEXT` bytes so clients can render list views after fetching only catalogue pages, never full blobs. The server MUST NOT be able to read it. Note: `summary_ct` is encrypted under the full-entropy `k_msg` (never a content-derived key), so a low-entropy summary (e.g. a one-word subject) is NOT a brute-force oracle — the server cannot confirm a guessed plaintext without `k_msg`, which it never holds.

## 3.2 Envelope wrapping

- **A02-CRY-4**: For each authorized recipient device, the frontier (or sending client) performs ML-KEM-768 encapsulation against the device's mail public key (A17-KEY-2/3):

```
(kem_ct, ss)   = ML-KEM-768.Encaps(device_mail_pk)
k_wrap         = HKDF-SHA256(IKM = ss, salt = empty,
                             info = "diamy_mail_env_v1"
                                    || message_id_bytes(16)
                                    || device_id_bytes(16),
                             L = 32)
wrapped_key    = AES-256-GCM(key = k_wrap, nonce = random 12B,
                             plaintext = k_msg,
                             AAD = "mailenv:" + message_id + ":" + device_id)
envelope       = { message_id, device_id, kem_ct, wrapped_key, nonce, alg_version }
```

`device_id` is bound into the HKDF `info` for domain separation (defense in depth): although `ss` already differs per device because encapsulation is against a distinct device public key, binding `device_id` guarantees `k_wrap` is cryptographically scoped to exactly one (message, device) pair even if an implementation error ever reused `ss`.

- **A02-CRY-5**: `ss` and `k_wrap` MUST be zeroized immediately after wrapping (per corpus zeroization discipline). `k_msg` MUST be zeroized at the end of frontier processing (A00 SEC-FC-2 path) or client submission. The seed/secret-direct-use prohibition (SEC-CRYPT-4) applies: `ss` is never used directly as the wrap key.
- **A02-CRY-6**: Convergent tricks are FORBIDDEN: no content-derived keys, no cross-user deduplication, no ciphertext reuse. Two identical inbound messages to two recipients MUST produce two independent `k_msg` and two unrelated ciphertexts.
- **A02-CRY-7**: `alg_version` (envelope) and `blob_alg_version` (blob) are REQUIRED fields, value `1` for the suite above. Any future suite change increments the version; readers MUST dispatch on it and MUST reject unknown versions rather than guessing.

## 3.3 Authenticity by path

| Path | Confidentiality | Integrity/authenticity |
| ---- | --------------- | ---------------------- |
| Internet → Diamy (frontier) | AES-256-GCM under `k_msg` | GCM AEAD; origin authenticity is NOT cryptographic — it is the trust engine's SPF/DKIM/DMARC verdict stored as metadata (A06) |
| Diamy → Diamy (client-side) | Same envelope model, sender-side | Sender device MUST sign the (message_id, blob digests, recipient set) manifest with its ML-DSA-65 identity key; recipients MUST verify before rendering (aligned with messaging segment signing) |
| Client "Sent" copy | Same, wrapped for the sender's own devices | Same manifest signature |

------

# 4. Server Data Model (logical)

## 4.1 Catalogue — `mail.messages`

| Field | Class (CDM-ENC-1) | Status | Notes |
| ----- | ----------------- | ------ | ----- |
| `message_id` UUIDv7 | PLAINTEXT_METADATA | REQUIRED | Internal ID (CDM-ID-3) |
| `rfc5322_message_id_hash` | PLAINTEXT_METADATA | OPTIONAL | Hash of external Message-ID for dedup/threading; NEVER the raw value (it can embed plaintext hints) |
| `principal_id` UUIDv7 | PLAINTEXT_METADATA | REQUIRED | Owner (A17-RES) — FK per CDM-ADDR-2 |
| `tenant_id` UUIDv7 | PLAINTEXT_METADATA | REQUIRED | |
| `direction` | PLAINTEXT_METADATA | REQUIRED | `inbound` / `outbound` / `internal` |
| `sender_canonical` | PLAINTEXT_METADATA | REQUIRED (inbound) | Routing metadata (A00 §3.3); A24 canonical form |
| `recipients_canonical[]` | PLAINTEXT_METADATA | REQUIRED | Routing/delivery metadata — MINIMIZED per A02-DM-4 (not the full multi-recipient set; BCC never here) |
| `received_at` / `sent_at` | PLAINTEXT_METADATA | REQUIRED | CDM-TS-1 |
| `size_bytes` | PLAINTEXT_METADATA | REQUIRED | Sum of blob sizes |
| `summary_ct` BYTEA | CIPHERTEXT | REQUIRED | Encrypted summary record (A02-CRY-3) |
| `trust_metadata` JSONB | PLAINTEXT_METADATA | REQUIRED (inbound) | A06/A07 verdicts, scores, flags — needs no decryption by design (CMP-BND-1/2) |
| `folder_id` UUIDv7 | PLAINTEXT_METADATA | REQUIRED | FK to `mail.folders` |
| `state_flags` | PLAINTEXT_METADATA | REQUIRED | read / answered / flagged / deleted-tombstone |
| `blob_alg_version` | PLAINTEXT_METADATA | REQUIRED | A02-CRY-7 |

- **A02-DM-1**: Folder **names** are user content: `mail.folders.name_ct` is CIPHERTEXT (encrypted client-side under a per-principal folder key defined in A03; the server sees folder UUIDs and hierarchy only). System folders (Inbox, Sent, Drafts, Trash) are well-known UUIDs requiring no name.
- **A02-DM-2**: `state_flags` are server-visible by necessity (multi-device sync arbitration, A04). This is declared in A00 §3.3 (sync service row) and MUST NOT silently expand to content-bearing fields.
- **A02-DM-4** (recipient-set minimization): A stored message belongs to ONE principal (the mailbox owner). `recipients_canonical[]` on that stored row MUST contain only what routing/threading requires for THIS mailbox, not the full multi-recipient set of the original message. Specifically: (a) the owner's own address is always present; (b) other To/Cc recipients MAY be stored to support reply-all and thread display, but this is user content and SHOULD live inside the CIPHERTEXT `summary_ct`, not in a server-visible column, UNLESS the tenant accepts the metadata exposure for server-side features; (c) **BCC recipients MUST NEVER appear in any recipient's stored metadata except the sender's own Sent copy** — leaking a BCC address to a co-recipient's server row would break the fundamental BCC guarantee. The routing-time recipient set (needed transiently by the frontier to produce envelopes) is NOT the same as the persisted per-mailbox recipient metadata; the former is destroyed with the plaintext, the latter is minimized per this rule. The default V1 posture SHOULD be: server-visible `recipients_canonical[]` holds only the owner + envelope-To domain-routing needs; full recipient display lists live in `summary_ct`.

## 4.2 Blob references — `mail.blobs`

| Field | Class | Status |
| ----- | ----- | ------ |
| `blob_id` UUIDv7 | PLAINTEXT_METADATA | REQUIRED |
| `message_id` | PLAINTEXT_METADATA | REQUIRED |
| `kind` (`body` / `attachment`) | PLAINTEXT_METADATA | REQUIRED |
| `object_key` | PLAINTEXT_METADATA | REQUIRED (opaque storage locator) |
| `nonce` | PLAINTEXT_METADATA | REQUIRED |
| `size_bytes` | PLAINTEXT_METADATA | REQUIRED |
| `sha512_ct` | PLAINTEXT_METADATA | REQUIRED — digest of the **ciphertext** for storage integrity checks; a plaintext digest MUST NOT be stored (equality oracle) |

## 4.3 Envelope directory — `mail.envelopes`

| Field | Class | Status |
| ----- | ----- | ------ |
| `message_id` | PLAINTEXT_METADATA | REQUIRED |
| `device_id` | PLAINTEXT_METADATA | REQUIRED |
| `kem_ct` BYTEA (1088 B) | PLAINTEXT_METADATA¹ | REQUIRED |
| `wrapped_key` BYTEA | PLAINTEXT_METADATA¹ | REQUIRED |
| `wrap_nonce` | PLAINTEXT_METADATA | REQUIRED |
| `alg_version` | PLAINTEXT_METADATA | REQUIRED |
| `origin` (`frontier` / `sender_device` / `rewrap:<device_id>`) | PLAINTEXT_METADATA | REQUIRED — provenance audit |

¹ `kem_ct` and `wrapped_key` are cryptographically opaque to the server (it holds no ML-KEM private keys) but are classified metadata, not CIPHERTEXT, because the server must serve them per device without decryption semantics.

- **A02-DM-3**: Primary key is (`message_id`, `device_id`). At most one active envelope per pair; re-wrap replaces atomically.

## 4.4 Sync journal — `mail.journal`

Append-only event stream consumed by A04 cursors: `message_added`, `message_deleted`, `flags_changed`, `folder_changed`, `envelope_added`, `envelope_revoked`. Events carry IDs and flags only — NEVER content (API-5). Retention: events MAY be compacted once all registered devices' cursors have passed them, with a floor of 30 days for device-recovery scenarios.

------

# 5. Write Paths

## 5.1 Inbound (frontier)

1. `diamy-mxd` completes reception + trust analysis (A01/A06/A07) while plaintext is in RAM.
2. Builds summary record; generates `k_msg`; encrypts body blob, attachment blobs, summary (A02-CRY-1..3).
3. Resolves recipient principal (A17-RES) → active device bundles (A17-DIR-2). Zero devices → hold queue (A17-DIR-5, mechanics in A01).
4. Produces one envelope per active device (A02-CRY-4).
5. Writes blobs to object store, then catalogue row + envelopes + journal event **in one transaction**; blob writes MUST precede the transaction and orphan blobs from failed transactions MUST be garbage-collected (A02-FAIL-2).
6. Zeroizes `k_msg` and plaintext (SEC-FC-2). If any step 2–5 fails: no plaintext is retained, delivery is tempfailed upstream, nothing partial is served.

## 5.2 Outbound (client submission)

1. Client composes, builds summary record, generates `k_msg`, encrypts blobs locally.
2. Client wraps `k_msg` for **its principal's own active devices** (Sent copy) and signs the manifest (A02-CRY §3.3).
3. Client uploads blobs + catalogue entry + envelopes via A04; `diamy-submitd` handles SMTP emission from the **plaintext the client transmits for emission** over the submission channel (TLS + mail-plane token) — the platform emits RFC 5322 to the Internet, so submission necessarily carries emission plaintext transiently in `diamy-submitd` RAM; this is the outbound mirror of the frontier exception and MUST be declared as such (A00 §3.2 transparency duty). No persistent plaintext: the stored Sent copy is the client-encrypted one.
4. Diamy↔Diamy (both on platform): the sender client SHOULD additionally wrap `k_msg` for the recipient's active devices (recipient bundles fetched from the A17 directory) and deliver ciphertext platform-internally, skipping SMTP and the frontier entirely (A00 §3.4). Fallback to the SMTP path is permitted when recipient bundles are unavailable.

## 5.3 Drafts

Drafts follow the Sent-copy model (client-encrypted, own devices only) with `kind = draft` state; the server never sees draft plaintext.

------

# 6. Read Path

1. Client lists catalogue pages (paginated, API-4): metadata + `summary_ct`.
2. Client fetches its envelope for a message, `ML-KEM-768.Decaps(kem_ct)` with its OS-secure-store private key, derives `k_wrap` (same HKDF labels), unwraps `k_msg`.
3. Client decrypts `summary_ct` for list rendering; fetches blobs on open (lazy), verifies GCM tags and — for Diamy↔Diamy — the sender manifest signature before rendering (fail-closed to safe representation per SEC-FC-3).
4. The server never returns plaintext and never inlines blob bytes in catalogue JSON (API-3).

------

# 7. Device Lifecycle

## 7.1 Add device (forward)

On bundle publication (A17-DIR-3), the frontier and sending clients start including the device in new envelope production. No historical access is implied.

## 7.2 Delegated re-wrap (historical access)

Trust rule owned by A17-KEY-4; mechanics:

- **A02-RW-1**: Re-wrap is initiated by explicit user approval on an **existing active device** D_old for a target device D_new. D_old fetches its own envelopes in batches (RECOMMENDED 500/batch), unwraps each `k_msg`, immediately re-wraps for D_new's public bundle (fresh KEM encapsulation per message), uploads envelopes with `origin = rewrap:D_old`, and zeroizes each `k_msg` after its re-wrap. Plaintext blobs are NEVER fetched for re-wrap — only keys are processed.
- **A02-RW-2**: The job MUST be resumable: server tracks a re-wrap cursor per (principal, D_new); duplicate uploads are idempotent on (`message_id`, `device_id`).
- **A02-RW-3**: Rate limits apply (server-side cap on envelope-write rate) so a compromised device cannot use re-wrap as an amplification primitive; the job is audit-logged start/end with counts.
- **A02-RW-4**: If D_new is revoked mid-job, the job MUST abort and already-written envelopes for D_new MUST be marked revoked in the same pass as A17-DIR-4 handling.

## 7.3 Revoke device

- **A02-RV-1**: On revocation (A17-DIR-4): stop producing envelopes for the device; mark existing envelopes `revoked` (they are not served anymore); terminate its live sessions (A17-TOK-5). Existing envelopes MAY be physically deleted by a background job; their persistence grants nothing without the device's private key, but deletion reduces exposure surface and is RECOMMENDED within 24 h.
- **A02-RV-2**: Optional key rotation (STO-4): user MAY trigger re-encryption of future traffic only; historical `k_msg` rotation (decrypt-reencrypt of all blobs) is NOT offered in V1 — cost is unbounded and the revoked device already had historical access while trusted. This limitation MUST be documented to tenants.

------

# 8. Deletion, Tombstones, Retention

- **A02-DEL-1**: User deletion is two-phase: move to Trash (folder change, journal event), then purge (explicit or per tenant retention policy). Purge deletes catalogue row, all envelopes, and blobs, and emits `message_deleted`; other devices reconcile via journal.
- **A02-DEL-2**: Blob deletion in object storage MUST be verified (delete + existence check); backup copies expire per the tenant's backup retention window, which MUST be disclosed (a purged message may persist in encrypted backups until backup rotation — stated plainly, not hidden).
- **A02-DEL-3**: Tombstones (`state_flags.deleted`) are kept until all device cursors pass the purge event, then compacted (§4.4).
- **A02-DEL-4**: Tenant offboarding: all principals' messages, envelopes, blobs, and Blind Index entries are purged within a contractual window (RECOMMENDED ≤ 30 days), audit-logged.

------

# 9. Quotas and Limits

- **A02-QOS-1**: Per-principal storage quota (tenant-configurable). Enforcement at frontier: over-quota inbound MUST tempfail (4xx `mailbox full`) — never silently drop; the principal and tenant admin are notified.
- **A02-QOS-2**: Bounded sizes, enforced and rejected explicitly: max message size (tenant-configurable, RECOMMENDED default 50 MB), max attachment count (RECOMMENDED 100), max envelope fan-out per message (devices × recipients; hard cap RECOMMENDED 10 000 with alerting).

------

# 10. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Object store unavailable at ingest | Frontier tempfails upstream (4xx); nothing partial persisted; no plaintext retained |
| Transaction fails after blob write | Orphan blobs swept by GC (**A02-FAIL-2**: GC deletes blobs unreferenced for > 24 h, audit-logged) |
| Envelope missing for a requesting device | Client surfaces "no access on this device" and offers re-wrap flow; server MUST NOT fabricate access |
| GCM tag verification fails on read | Client discards, reports `blob_corrupt`, retries once from store; on second failure marks message damaged (visible state) — never renders unauthenticated plaintext |
| Re-wrap source device goes offline mid-job | Job pauses at cursor; resumable (A02-RW-2) |
| Journal compaction races a dormant device | Floor of 30 days (§4.4); a device dormant beyond journal retention MUST full-resync (A04 defines the resync handshake) |

------

# 11. Observability Contract

Per A00 §11:

- counters: `mail_messages_stored_total{direction}`, `mail_envelopes_written_total{origin}`, `mail_blob_gc_swept_total`, `mail_rewrap_jobs_total{result}`, `mail_purges_total`, `mail_quota_tempfails_total`
- gauges: blob store usage per tenant, journal depth, oldest un-passed cursor age
- latency: `frontier_encrypt_duration` (p99 target < 150 ms for 1 MB message), `envelope_fanout_duration`, `catalogue_page_duration`
- audit (OBS-3): re-wrap job start/end, device revocation envelope handling, purges, tenant offboarding

------

# 12. Test Scenarios (Normative)

1. **Single-encrypt invariant**: send one message to a principal with 3 devices → exactly 1 body blob, 1 summary, N attachment blobs, 3 envelopes; all envelopes unwrap to the same `k_msg`; ciphertexts differ from a second identical send (A02-CRY-6).
2. **Envelope isolation**: device A's private key MUST fail to unwrap device B's envelope (AAD binds device_id).
3. **Add device**: publish bundle → new messages readable on D_new; historical unreadable until re-wrap; run re-wrap of 10 000 messages with a forced interruption at 4 200 → resume completes, no duplicates, D_new reads full history.
4. **Revoke device**: revoke D_old mid-session → WSS severed ≤ 10 s, envelopes stop, other devices unaffected; re-wrap job in progress from D_old aborts.
5. **Tamper**: flip one byte in a stored blob → client rejects on GCM tag, message flagged damaged, no partial render.
6. **Purge propagation**: purge on device A → tombstone journal event → device B removes locally; blobs and envelopes gone server-side; GC leaves no orphans.
7. **Quota**: fill quota → inbound tempfail 4xx with `mailbox full`, notification emitted, no silent drop.

------

# 13. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Deriving the wrap key by using the KEM shared secret `ss` directly instead of through HKDF with the `diamy_mail_env_v1` label (SEC-CRYPT-4, A02-CRY-4).
2. ❌ Building AAD from UUID **strings** instead of 16-byte binary forms (CDM-ID-2) — envelopes become non-interoperable between Rust and TS.
3. ❌ Content-addressing or deduplicating blobs across users "for efficiency" (A02-CRY-6 — equality oracle).
4. ❌ Storing a plaintext digest of the message for integrity instead of the ciphertext digest (§4.2 — equality oracle on content).
5. ❌ Reusing one nonce across the body and attachment blobs of a message because they share `k_msg` — every blob has its own random nonce.
6. ❌ Fetching plaintext blobs during re-wrap; re-wrap processes keys only (A02-RW-1).
7. ❌ Making re-wrap non-resumable or non-idempotent, so an interruption forces restart-from-zero or duplicates envelopes (A02-RW-2).
8. ❌ Serving `summary_ct` decrypted "for the webmail case" server-side — webmail decrypts in the browser (A00 component map); the server never holds `k_msg`.
9. ❌ Emitting journal events that embed subject/snippet content instead of IDs and flags (API-5).
10. ❌ Treating the outbound submission plaintext window in `diamy-submitd` as license to log or persist message content — it is a transient exception mirroring the frontier, with the same destruction duty (§5.2).
11. ❌ Deleting the catalogue row on purge but leaving envelopes or blobs (or vice versa) — purge is all-or-nothing with GC as the safety net (A02-DEL-1, A02-FAIL-2).
12. ❌ Storing the full To/Cc/BCC recipient set as server-visible metadata on every recipient's mailbox row — this leaks the recipient graph and, for BCC, breaks the blind-copy guarantee. Full recipient display lists belong in `summary_ct`; BCC appears only in the sender's Sent copy (A02-DM-4).

------

# 14. Deferred Items

- Attachment-level lazy envelopes (separate keys per attachment for partial-access policies, interacting with A07 tiered attachment access) — V1 uses one `k_msg` per message; revisit with A07.
- Cross-tenant Diamy↔Diamy delivery trust model (with A01/A17 deferred item).
- Server-assisted search over encrypted summaries — explicitly rejected in V1 (contradicts SRCH-1/2); recorded here so it is not re-proposed casually.
- Historical `k_msg` rotation offering (A02-RV-2) — revisit if a compliance requirement emerges.

------

*End of document.*
