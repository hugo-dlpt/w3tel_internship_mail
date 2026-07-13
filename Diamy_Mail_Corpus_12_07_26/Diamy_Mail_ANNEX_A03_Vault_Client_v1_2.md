# Diamy Mail — ANNEX A03: Vault Client Architecture

**Document title:** Diamy Mail — ANNEX A03: Vault Client Architecture
**Version:** 1.2
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)
**Sibling dependencies:** A02 (Storage & Envelope Model v1.1), A04 (Native Sync API), A05 (Search & Local AI), A17 (IAM Integration Contract v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: local-first vault model, encrypted SQLite catalogue (SQLCipher), local blob store, OS-secure-store key hierarchy (device mail private key, catalogue key, per-principal folder key), decrypt/render read path, offline operation, intelligent cache policy, multi-device state model, conflict-resolution decision (LWW + per-field), draft/compose handling, security posture, failure model, test scenarios, common AI errors |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: closed a plaintext-at-rest gap — the local FTS index MUST be encrypted equal to the catalogue, not a separate plaintext SQLite file (A03-STO-4); added offboarding-vs-revocation local-data disposition rule (A03-SEC-5, enterprise/GDPR retention); noted the IAM-provisioned `k_folder` option would be an IAM extension not a Mail-invented mechanism (A03-KEY-3); fixed "coffee-fort"→"coffre-fort" typo; added AI error #13 |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Coherence fix following review of the Diamy IAM – Integration Specification v1.6: softened A03-SEC-4's unqualified "IAM epoch bump" language to reference A17-TOK-2's flagged (unconfirmed) revocation mechanism, consistent with the corpus-wide correction applied across A04/A17/A20/A25/A26. |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies the Diamy Mail **vault client**: the local-first desktop and mobile application that stores messages encrypted on-device, operates fully offline, decrypts and renders locally, and consumes the sync API (A04). It is the counterpart of the server storage model (A02): where A02 defines what the server holds, this defines what the device holds and how.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Out of scope

The sync wire protocol (A04). Search internals and local AI keyword extraction (A05). HTML→Tiptap conversion (A08) and rendering sandbox (A09) — this annex only states where they sit in the read path. The webmail client (browser, no local storage) is a separate surface governed by A00 §4 and A05; it is NOT a vault client.

## 1.2 The vault principle (inherited from A00)

- The client is a **coffre-fort**, not an IMAP cache: it holds the authoritative local copy of already-synced content, works with no network, and never depends on a permanent server connection (A00 OPS-OFF-1).
- Plaintext exists only on the device (A00 §3.1 zone 1). Private keys never leave the OS secure store (A00 STO-5).

------

# 2. Local Data Model

## 2.1 Two-tier storage

- **A03-STO-1**: The client MUST separate a **catalogue** (encrypted SQLite) from a **blob store** (encrypted message/attachment objects on the local filesystem or platform object store). The catalogue holds metadata, summary plaintext (post-decryption, see §2.3), folder structure, flags, sync cursors, and local indices. Full message bodies and attachments are NOT stored in SQLite — they are blob-store objects referenced by ID. (Same separation principle as A02, applied locally; keeps the catalogue small and fast for list/search.)
- **A03-STO-2**: The catalogue database MUST be encrypted at rest with SQLCipher (or an equivalent whole-database page-level encryption). The catalogue encryption key (`k_cat`) MUST be protected by the OS secure store (§3), NOT stored in a file, NOT hard-coded, NOT derived from a user password alone without a secure-store-bound factor.
- **A03-STO-3**: Local blob objects MUST be encrypted at rest. A blob MAY be stored still-enveloped (as received from sync: ciphertext under `k_msg`, plus the device envelope) OR re-encrypted under a local blob key; in both cases the plaintext blob is NEVER written to disk. The RECOMMENDED model is to keep the server-form ciphertext (blob under `k_msg`) plus the unwrapped-locally `k_msg` cached in memory only, decrypting on open — this avoids a second at-rest key hierarchy.
- **A03-STO-4**: The local full-text search index (A05) MUST have the same at-rest protection as the catalogue. If it is a separate SQLite FTS5 file rather than a table inside the SQLCipher catalogue, that file MUST be equally encrypted (SQLCipher or equivalent) under a secure-store-protected key. A plaintext FTS index would defeat the entire on-device encryption model — it would be a searchable plaintext copy of every message's content sitting unprotected on disk. The RECOMMENDED approach is to keep FTS as tables **inside** the single SQLCipher catalogue database, so one encryption boundary covers everything.

## 2.2 Catalogue contents

The catalogue mirrors the server catalogue (A02 §4.1) plus client-local state:

| Category | Fields |
| -------- | ------ |
| Message metadata | message_id, principal_id, folder_id, direction, sender_canonical, received/sent_at, size, trust_metadata, state_flags, blob refs |
| Decrypted summary | subject, snippet, sender display, attachment names (from `summary_ct`, decrypted once and cached — §2.3) |
| Folder tree | folder_id, parent_id, decrypted name, well-known-system-folder marker |
| Sync state | per-folder cursors, last-sync watermark, pending-outbound queue, re-wrap progress |
| Local indices | FTS index over decrypted content (A05), address index |
| Cache metadata | blob presence, last-accessed, pin/favorite markers, cache tier |

- **A03-CAT-1**: Because the whole catalogue is SQLCipher-encrypted, decrypted summary and decrypted folder names MAY reside in it as ordinary columns — the at-rest protection is the database encryption, not per-field encryption. This is the client analogue of the server's `CIPHERTEXT` classification: on the server the summary is opaque; on the device, inside the encrypted catalogue, it is usable plaintext.

## 2.3 Summary decryption caching

- **A03-CAT-2**: On first sync of a message, the client fetches `summary_ct` (A02-CRY-3), unwraps `k_msg` via its device envelope, decrypts the summary, and stores the plaintext summary fields in the (encrypted) catalogue for fast list rendering. The client MUST NOT need to re-decrypt on every list view. `k_msg` itself is NOT persisted in the catalogue; it is re-derived from the envelope when a full blob is opened, or held in a short-lived in-memory cache.

------

# 3. Key Hierarchy and OS Secure Store

- **A03-KEY-1**: The **device mail private key** (ML-KEM-768, A17-KEY-2) MUST reside in the OS secure store and MUST NOT be exportable to application memory in raw form where the platform offers non-exportable key handles (Secure Enclave, Android Keystore StrongBox, TPM-backed CNG). Where the platform cannot perform ML-KEM operations inside the secure element (likely in V1, since PQC secure-element support is nascent), the private key MUST be stored as a secure-store-protected blob, loaded into memory only for decapsulation, and zeroized immediately after. This limitation MUST be documented per platform.
- **A03-KEY-2**: `k_cat` (SQLCipher key) MUST be generated on device, stored in the OS secure store (DPAPI / Keychain / Keystore / Secure Enclave-wrapped), and retrieved at app unlock. It MUST NOT be derived from the user's password alone; if a password/biometric gates access, it gates *release of the secure-store item*, it is not the sole entropy of `k_cat`.
- **A03-KEY-3**: The **per-principal folder key** (`k_folder`, encrypts folder names client-side so the server sees only UUIDs, A02-DM-1) MUST be derived/stored such that all of a principal's devices can obtain it (it is shared across the user's devices, unlike the per-device mail key). RECOMMENDED: `k_folder` is itself distributed device-to-device inside the envelope mechanism (wrapped like a message key) or derived from a principal-level secret provisioned at enrollment via IAM (the latter would be a new IAM extension, submitted per A17 §1.1, not a Mail-invented key mechanism). The exact provisioning is fixed in A04/A05 where folder sync is defined; this annex mandates only that folder names are never server-visible plaintext and that `k_folder` never reaches the server.
- **A03-KEY-4**: OS secure store items for Diamy Mail MUST be scoped to the app and, where supported, require user presence (biometric/PIN) for release on mobile. All keys loaded into memory MUST be zeroized after use (corpus zeroization discipline).

------

# 4. Read Path (local)

```
1  User opens a message in a list (rendered from cached summary)
2  Catalogue → blob refs + device envelope for message_id
3  Blob present locally?  no → fetch via A04 (online) or show "not downloaded" (offline)
4  ML-KEM-768.Decaps(kem_ct) with device private key (secure store) → ss → k_wrap → k_msg
5  Decrypt body/attachment blobs (AES-256-GCM), verify GCM tags (A02)
6  For Diamy↔Diamy: verify sender ML-DSA-65 manifest signature before rendering
7  Body is RFC5322/MIME plaintext → parse → HTML→Tiptap conversion (A08)
8  Render Tiptap JSON via the app's own renderer (never raw HTML — SEC-RENDER-1)
9  Zeroize k_msg / decrypted plaintext when the view closes (best-effort on GC'd platforms)
```

- **A03-READ-1**: Rendering MUST use the Tiptap closed-schema pipeline by default (A00 SEC-RENDER-1); the "view original" sandbox (A09) is an explicit, non-default user action.
- **A03-READ-2**: If GCM verification (step 5) or manifest verification (step 6) fails, the client MUST degrade to a safe representation and mark the message damaged — NEVER render unauthenticated plaintext (A00 SEC-FC-3, A02 failure model).
- **A03-READ-3**: On platforms with managed memory (JS/TS, Kotlin, Swift) where true zeroization is not guaranteed, the client MUST minimize plaintext lifetime (decrypt on open, drop references on close) and MUST NOT hold decrypted bodies in long-lived caches. This is a best-effort obligation, explicitly weaker than the server's `zeroize`-crate guarantee, and MUST be documented as such.

------

# 5. Offline Operation

- **A03-OFF-1**: With no network, the client MUST remain fully functional for already-synced content: reading (blobs present in cache), local search (A05 local index), composing, saving drafts, filing/tagging/flagging, deleting. All such actions are recorded as **pending sync operations** in the catalogue and replayed on reconnection (A04).
- **A03-OFF-2**: Actions on not-yet-downloaded content MUST be clearly bounded: the client MAY queue a flag/move on a message whose blob is absent (metadata is present), but MUST clearly indicate a message body is "not downloaded" rather than showing an empty body as if it were the content.
- **A03-OFF-3**: The pending-outbound queue (composed messages awaiting submission) MUST survive app restart (persisted in the encrypted catalogue as client-encrypted drafts, A02 §5.3 model) and MUST be submitted in order on reconnection, with idempotency so a crash between send and ack does not double-send (A04 defines the idempotency key).

------

# 6. Intelligent Cache Policy

The client cannot always hold every blob (mailboxes reach tens of GB). Metadata is always fully synced; blobs are cached selectively.

- **A03-CACHE-1**: Message **metadata + decrypted summary** for the full mailbox MUST be synced and retained (this is what makes list views and local metadata search instant offline). Only **blobs** (full bodies, attachments) are subject to eviction.
- **A03-CACHE-2**: The default cache policy is a **hybrid** of: always-keep for pinned/favorite folders and flagged messages; recency window (RECOMMENDED: last N months, tenant/user-configurable); and LRU eviction beyond a size quota (user-configurable disk budget). The exact default (age vs size vs LRU weighting) is a client-tunable parameter; this annex fixes that a policy MUST exist and MUST be transparent to the user (show cache size, allow "download all" and "clear cache").
- **A03-CACHE-3**: Evicting a blob MUST retain its metadata and summary (the message does not disappear from the list; it becomes "not downloaded"). Re-opening an evicted message re-fetches the blob (A04) when online.
- **A03-CACHE-4**: Attachments MAY have a distinct, tighter cache policy than bodies (attachments dominate size). Opened attachments MAY be cached briefly; large unopened attachments SHOULD NOT be pre-fetched by default (bandwidth/disk), only their metadata.

*(This closes A00 Open Decision #4 — cache purge policy — as: hybrid pinned + recency + LRU-under-quota, user-transparent, metadata never evicted.)*

------

# 7. Multi-Device State Model

Each device has its own catalogue, its own blob cache, its own device keys (A00 §8). State flags (read/answered/flagged/tags/folder placement) are shared truth and sync between devices (A02 §4, A04).

## 7.1 Conflict resolution

- **A03-SYNC-1**: State-flag conflicts (two devices change the same message's flags/folder while one is offline) MUST resolve by **per-field last-writer-wins (LWW)** using a server-assigned monotonic sequence per journal event, NOT last-writer-wins on the whole message record. Rationale: device A marking read and device B moving to a folder are non-conflicting edits to different fields; whole-record LWW would lose one. Per-field LWW keeps both. Where two devices edit the *same* field, the higher journal sequence wins.
- **A03-SYNC-2**: `read`/`answered`/`flagged` are booleans/enums where LWW is acceptable (losing a stale toggle is low-harm). Folder placement conflicts (moved to two different folders) resolve by higher-sequence LWW, with the losing move recorded in a local "recently reconciled" log so the user can notice a surprising move. Tag sets MUST merge (union) rather than LWW, since tags are additive and losing a tag is more surprising than gaining one — a removed tag re-added by a concurrent device is acceptable.
- **A03-SYNC-3**: Deletion vs edit conflict: a purge (A02-DEL) always wins over a concurrent flag/move (you cannot flag a purged message). A move-to-Trash concurrent with a flag resolves normally (Trash is a folder); a hard purge is terminal.

*(This closes A00 Open Decision #3 — conflict resolution — as: per-field LWW by journal sequence, tag-set union, purge-wins.)*

## 7.2 New-device bootstrap

- **A03-SYNC-4**: A newly enrolled device (A17-DIR-3) syncs the full catalogue metadata + summaries immediately (fast, small), then lazily fetches blobs per cache policy. Historical blob **access** requires the delegated re-wrap (A02-RW) to have produced envelopes for this device; until then, historical messages show metadata + summary but bodies are "awaiting access" (re-wrap in progress). The client MUST show re-wrap progress rather than presenting historical messages as broken.

------

# 8. Compose and Draft Handling

- **A03-COMP-1**: Composition uses the Tiptap editor (A00 §5.6.3): Unicode emoji as codepoints, NFC normalization before signing/encryption/storage (CDM-I18N-9). The composed body is converted to the emission RFC 5322/MIME form at submission.
- **A03-COMP-2**: Drafts are client-encrypted for the principal's own devices only and synced as `kind=draft` (A02 §5.3); the server never sees draft plaintext. Auto-save drafts MUST also follow this (no plaintext autosave to disk).
- **A03-COMP-3**: On send, the client builds the summary, generates `k_msg`, encrypts blobs, wraps for own devices (Sent copy), signs the manifest, and enqueues submission (A02 §5.2, A04). For Diamy↔Diamy the client SHOULD additionally wrap for recipient devices (A02 §5.2 step 4).

------

# 9. Security Posture (client-specific)

- **A03-SEC-1**: The app MUST lock (require biometric/PIN to release `k_cat` and device key access) after a configurable inactivity period; locking MUST drop decrypted plaintext and key material from memory (best-effort per A03-READ-3).
- **A03-SEC-2**: The client MUST NOT export plaintext to unmanaged locations: no plaintext to system clipboard beyond user-initiated copy, no plaintext to unencrypted app logs, no plaintext in crash reports (scrub before upload), no plaintext screenshots in the app switcher on mobile (screen-privacy flag where supported).
- **A03-SEC-3**: Tokens (mail-plane, A17) live in memory only, never in the catalogue or any persistent store (A17-TOK-3). The catalogue stores sync cursors and message data, never credentials.
- **A03-SEC-4**: On session revocation (mechanism per A17-TOK-2 — confirmation pending) or device revocation affecting this device, the client MUST stop, drop keys and tokens, and require re-authentication; a revoked device's local catalogue MAY be wiped on next launch per tenant policy (remote-wipe-on-revoke is a tenant option, since the local data is already at-rest-encrypted the urgency is lower, but MUST be offered).
- **A03-SEC-5** (offboarding vs revocation): Entitlement removal / user offboarding (the server-side purge is A02-DEL-4) is distinct from single-device revocation. On offboarding, the local vault on ALL of the user's devices holds at-rest-encrypted company mail that a tenant may be contractually or legally required to remove (GDPR erasure, employee departure). The client MUST honor a tenant-policy local-data disposition on offboarding: RECOMMENDED default is local wipe of catalogue + blobs on next authenticated launch after entitlement loss is detected. Because the local data is at-rest-encrypted and the keys become unreleasable once the secure-store items are revoked, a tenant MAY accept "key destruction" (render undecryptable) as equivalent to wipe; this equivalence MUST be stated in the tenant's retention policy, not assumed silently.

------

# 10. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Secure store unavailable (locked device, biometric fail) | App stays locked; no catalogue decryption; retry on unlock; never fall back to an unprotected key |
| Catalogue corruption | Detect (SQLCipher integrity), attempt local repair; if unrecoverable, full re-sync from server (metadata+summaries fast; blobs lazy) — no data loss since server holds ciphertext of record |
| Blob missing locally, offline | Show "not downloaded"; queue fetch for reconnection; never show empty as content |
| GCM/manifest verification fails on open | Mark message damaged, safe representation, offer re-fetch once (A03-READ-2) |
| Historical blob has no envelope for this device | "Awaiting access" state; trigger/await re-wrap (A02-RW); not an error |
| Pending outbound send interrupted by crash | Resume from persisted queue with idempotency key; no double-send (A03-OFF-3) |
| Clock skew affecting draft/sync ordering | Use server journal sequence as ordering authority, not local clock (A03-SYNC-1) |

------

# 11. Observability (client-side, privacy-preserving)

- **A03-OBS-1**: Client telemetry MUST be privacy-preserving: it MAY report aggregate health (sync success rate, cache hit rate, crash-free rate, decryption-error counts) but MUST NOT report message content, subjects, addresses, or anything derived from plaintext. Opt-in per tenant policy.
- **A03-OBS-2**: Local diagnostic logs (for user-initiated support) MUST scrub plaintext and addresses by default; exporting a diagnostic bundle MUST warn the user and MUST NOT include catalogue contents or keys.

------

# 12. Test Scenarios (Normative)

1. **Offline full function**: airplane mode → read cached message, local-search, compose+save draft, flag+move, delete → all succeed; reconnect → pending ops replay, server state matches.
2. **Summary caching**: first sync decrypts `summary_ct` once; subsequent list renders do zero decryption of summaries (assert no envelope unwrap on list scroll).
3. **Cache eviction**: fill disk budget → LRU evicts oldest unpinned blobs; pinned folder blobs retained; evicted message still lists with summary, re-opens by re-fetch.
4. **Per-field conflict**: device A marks read offline; device B moves to folder offline; both reconnect → message is both read AND in the new folder (no lost edit); tag added on A and different tag on B → union of both tags.
5. **Purge-wins**: device A purges; device B flags same message offline → after sync, message is gone on both; B's flag discarded.
6. **New device**: enroll → metadata+summaries appear immediately; historical bodies "awaiting access" until re-wrap completes → then readable; assert no historical body was shown as broken.
7. **Damaged blob**: corrupt a local blob → open → GCM fail → damaged state + re-fetch offer; corrected after re-fetch.
8. **Lock/wipe**: inactivity lock drops keys; revoke device via IAM → next launch requires re-auth, optional local wipe per policy.

------

# 13. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Storing full message bodies/attachments in SQLite instead of the separate blob store — bloats the catalogue, destroys list/search performance (A03-STO-1).
2. ❌ Deriving `k_cat` from the user password alone, with no OS-secure-store-bound factor — a stolen device with a weak password decrypts everything (A03-STO-2, A03-KEY-2).
3. ❌ Writing decrypted plaintext blobs to disk "for caching" instead of caching server-form ciphertext + in-memory `k_msg` (A03-STO-3).
4. ❌ Whole-record last-writer-wins on state flags, silently losing a concurrent non-conflicting edit — MUST be per-field, tags union (A03-SYNC-1/2).
5. ❌ Rendering raw HTML instead of the Tiptap pipeline in the read path (A03-READ-1, SEC-RENDER-1).
6. ❌ Rendering a message whose GCM or manifest signature failed to verify (A03-READ-2).
7. ❌ Showing an evicted/not-downloaded message's empty body as if it were the actual (empty) content (A03-OFF-2, A03-CACHE-3).
8. ❌ Persisting mail-plane tokens in the catalogue or any store instead of memory-only (A03-SEC-3, A17-TOK-3).
9. ❌ Double-sending on crash because the outbound queue lacks an idempotency key (A03-OFF-3).
10. ❌ Persisting decrypted draft plaintext to disk on autosave instead of the client-encrypted draft model (A03-COMP-2).
11. ❌ Using local wall-clock for sync/draft ordering instead of the server journal sequence (A03-SYNC-1, clock-skew failure row).
12. ❌ Uploading crash reports / diagnostics containing plaintext, subjects, or addresses (A03-OBS-2, A03-SEC-2).
13. ❌ Building the local FTS search index as a separate unencrypted SQLite file — a plaintext searchable copy of all mail content at rest, defeating the whole model; the index MUST share the catalogue's encryption boundary (A03-STO-4).

------

# 14. Deferred Items

- Exact `k_folder` provisioning mechanism (device-to-device wrap vs IAM-provisioned principal secret) — fixed in A04/A05 where folder sync is specified; A03 mandates only the invariant (never server-visible, all devices can obtain it).
- Shared-mailbox local model (multi-principal access on one device) — depends on the IAM entitlement extension deferred in A17 §12.
- PQC secure-element storage of the ML-KEM private key once platform support matures (A03-KEY-1 currently allows secure-store-blob + in-memory decapsulation).
- Precise default cache weighting (age vs size vs LRU) — tunable, to be calibrated on real mailbox-size telemetry.

------

*End of document.*
