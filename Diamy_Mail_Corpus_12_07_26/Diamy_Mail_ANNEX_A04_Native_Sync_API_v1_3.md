# Diamy Mail — ANNEX A04: Native Sync API

**Document title:** Diamy Mail — ANNEX A04: Native Sync API
**Version:** 1.4
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)
**Sibling dependencies:** A02 (Storage & Envelope Model v1.1), A03 (Vault Client v1.1), A17 (IAM Integration Contract v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.4     | Jul 17th 2026 | Written by: session Claude Code — decided directly with Hugo DELEPORTE (in-session; not escalated to Cédric, since this closes an implementation-detail gap within already-decided direction rather than an invariant conflict, A25 Constitution rule 4 threshold) | **Closed a gap this annex left open**: §5.3's table described `/state/flags`'s fields as "read/answered/flagged/tags" only, with no field covering IMAP's reversible `\Deleted`-before-`EXPUNGE` toggle, while `/state/delete` was described only as the trash-move/purge *action* — neither literally accommodated a reversible pre-purge tombstone, and no "undelete" operation existed anywhere in this annex. Resolved: **`deleted` is now an explicit boolean field of `/state/flags`** (§5.3 table + A04-EP-4bis), participating in the same per-field LWW/journal-sequence discipline as read/answered/flagged (A03-SYNC-1/2) and emitting `flags_changed` — fully reversible by re-sending `deleted:false`, unlike `/state/delete` which remains a one-way terminal action. Rationale: A21-JRN-1's event catalogue (`message_added/deleted`, `flags_changed`, `folder_changed`, ...) has no dedicated tombstone-toggle or undelete event, so routing a reversible flag through `flags_changed` — the event type already designed for exactly this kind of per-field, reversible metadata change — fits the existing model better than inventing a new event or overloading `/state/delete` with a reversal it was never specified to support. Also recorded: the reference implementation (`diamy-bridged`) exercises `/state/delete` in **hard-purge mode only** on IMAP `EXPUNGE` (soft/Trash-move remains a valid mode of this endpoint per §5.3 but is not exercised — the bridge is single-folder, no Trash folder is wired). |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: native sync protocol (NOT IMAP), transport (WSS + HTTPS), authentication binding to mail-plane token, journal-cursor sync model, endpoint catalogue (catalogue pages, blob fetch, envelope fetch, submission, state ops, folder ops, key-directory publication), pagination rules, notification signals (no content push), idempotency + outbound queue, conflict inputs (per-field LWW feed), request signing, full-resync handshake, failure model, observability, test scenarios, common AI errors |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Coherence update: the Bridge (A20) is now a committed, specified feature — updated §1 and deferred-items to reference A20 as shipped (IMAP/SMTP/CalDAV via the client SDK on top of this native API, no protocol change) rather than "deferred". |
| 1.3     | Jul 4th 2026 | Cédric BORNECQUE | Corrected A04-TR-2 after reviewing the Diamy IAM – Integration Specification v1.6: every request now correctly requires TWO independently-validated credentials — the Tier 2 Diamy Mail AppKey (local, AppKey-first per A17-APPKEY-5) and the mail-plane token — previously conflated as one undifferentiated header set. Renamed `ERR_EPOCH_REVOKED` to the mechanism-neutral `ERR_SESSION_REVOKED` and added `ERR_APPKEY_INVALID`, consistent with A17-TOK-2's flagged (unconfirmed) revocation mechanism — the 10 s bound (A04-TR-4) is now stated as a target pending that confirmation, not an implemented fact. Added test scenarios #10–11 and AI errors #14–16 for the AppKey model. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: fixed orphaned section numbering (§2.4→§2.3); tightened outbound emission-plaintext handling — `diamy-submitd` MUST zeroize emission plaintext after emission, not merely "not persist" (A04-EP-6, mirrors A01-DESTROY); clarified Diamy↔Diamy shared-blob authorization so an internal-delivery recipient can fetch the sender-uploaded blob referenced by the recipient's own catalogue row (A04-EP-3b); hedged the request-timestamp window (RECOMMENDED ±120 s, no over-claim of exact IAM-SED alignment); added AI error #13 |

------

# Table of contents

[toc]

------

# 1. Scope

This annex defines the **native Diamy Mail sync API**: the wire protocol between the vault client (A03) and `diamy-maild`, and between the client and `diamy-submitd` for outbound. It is explicitly NOT IMAP/POP3/SMTP (A00 API-1); IMAP/SMTP/CalDAV compatibility for third-party clients is provided by the Bridge (A20), which sits on top of this native API via the client SDK (A19), not by changing this protocol.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Out of scope

Storage internals and the server data model (A02). Client local storage (A03). Search / Blind Index query endpoints (A05 owns the search endpoints; this annex owns catalogue/blob/state sync). Key-directory internal storage (A17 §5.2); this annex owns only the client-facing publish/fetch endpoints.

## 1.2 Design inheritance

- **Pull model, signals-only notifications** (A00 API-5): the server never pushes content; it signals, the client fetches. (Precedent: messaging pull model.)
- **Paginated, bounded** (A00 API-4): no unbounded scans.
- **JSON bodies, blobs by reference** (A00 API-3): ciphertext blobs are discrete objects fetched by ID, never inlined base64 in catalogue JSON.
- **Typed errors** (A00 API-6), **observability contract** (A00 API-7).

------

# 2. Transport and Authentication

- **A04-TR-1**: The sync API MUST be available over two transports: **WSS** (persistent, for live notification signals and streaming sync) and **HTTPS** (request/response, for catalogue pages, blob fetch, submission). Both MUST use TLS 1.3 (1.2 minimum). A client MAY operate HTTPS-only (polling) where a persistent socket is impractical; WSS is an optimization for latency, not a requirement for correctness.
- **A04-TR-2** (two independent credentials — corrected): Every request MUST carry **both**, independently validated (A17-APPKEY-5): (a) a valid **mail-plane token** (A17 §4, authenticates the user/session) and (b) Diamy Mail's own **Tier 2 AppKey header set** — `X-App-Key`, `X-App-Name`, `X-App-Platform`, `X-App-Version` (A17 §4.2bis, authenticates the client application). These are NOT the same X-App-* headers Diamy Mail's backend sends to IAM (Tier 1, A17-TOK-4) — a client never sees or sends a Tier 1 credential. `diamy-maild` validates the AppKey first (local lookup, no IAM call), then the mail-plane token (signature + expiry + revocation state, A17-TOK-1), on WSS register and on every HTTPS request/reconnection.
- **A04-TR-3**: The data plane is NOT SED-chained (A17-SED-2). Instead, each request MUST be signed per §2.4 and MUST be idempotent where it mutates state (§6). Rationale is fixed in A17-SED-2 (SED serialization is incompatible with parallel blob sync; payloads are already ciphertext).
- **A04-TR-4** (revocation timing — flagged, per A17-TOK-2): On session revocation, `diamy-maild` MUST terminate live WSS connections for the affected principal/device and reject subsequent requests until re-authentication, targeting the 10 s bound of A17-TOK-5. **This bound is currently unverified** against the actual IAM revocation mechanism (A17-TOK-2 flags a discrepancy between this annex's epoch-bump assumption and the JTI-cache-with-optional-webhook model described in the reviewed IAM Integration Specification v1.6). This annex's requirement stands as a target pending that confirmation; do not treat 10 s as a proven SLA until A17-TOK-2 is resolved.

## 2.3 Request signing

- **A04-SIG-1**: Each mutating request MUST include a request signature binding (method, path, body hash, nonce, timestamp) to prevent replay and tampering within the TLS channel (defense in depth). The signing key is derived from the mail-plane session, NOT the SED chain. The canonical form and derivation MUST follow the same HKDF discipline as the corpus (explicit `info` label, never a raw secret as MAC key — SEC-CRYPT-4).
- **A04-SIG-2**: Timestamp skew tolerance is RECOMMENDED ±120 s. Outside the window → `ERR_TIMESTAMP_INVALID`, client resends with fresh timestamp/nonce, same request-id (idempotent). The exact value SHOULD be harmonized with the IAM session timestamp tolerance at implementation time rather than assumed here.

------

# 3. Sync Model — Journal Cursors

Sync is driven by the append-only server journal (A02 §4.4). Each client tracks a cursor; the server streams or returns events after the cursor.

- **A04-SYNC-1**: The client maintains a **per-principal sync cursor** (an opaque, monotonic journal position). On connect/poll, it presents its cursor; the server returns journal events after it (`message_added`, `message_deleted`, `flags_changed`, `folder_changed`, `envelope_added`, `envelope_revoked`), paginated (§4), each event carrying IDs and flags only — NEVER content (A00 API-5).
- **A04-SYNC-2**: The client applies events to its catalogue, then fetches the referenced objects it wants (summary via catalogue page, blobs lazily per cache policy A03-CACHE). Advancing the cursor MUST be durable only after the client has persisted the corresponding catalogue changes, so a crash re-delivers un-applied events (at-least-once event delivery; client application MUST be idempotent per event).
- **A04-SYNC-3**: Notification signals over WSS are **cursor-advance hints**: "new events exist past your cursor". They carry no content and are not authoritative — the client always reconciles by reading journal events, never by trusting the signal payload. A missed signal is harmless (next poll/connect catches up).
- **A04-SYNC-4** (full resync): If a client's cursor is older than the journal retention floor (A02 §4.4, 30 days) or the server cannot honor it (compaction passed it), the server MUST respond `ERR_CURSOR_EXPIRED` and the client MUST perform a **full resync handshake**: fetch the complete current catalogue snapshot (metadata + summary_ct references, paginated) and reset its cursor to the current head. Blobs are re-fetched lazily. No message data is lost (server holds ciphertext of record); only the incremental delta is unavailable, replaced by a snapshot.

------

# 4. Pagination (Normative)

- **A04-PAGE-1**: All list endpoints (journal events, catalogue pages, folder listings, search results in A05) MUST be paginated with **cursor-based** pagination (opaque continuation token), NOT offset-based. Page size MUST be bounded (RECOMMENDED default 200, hard max 1000); a request exceeding the max is clamped, not rejected.
- **A04-PAGE-2**: Unbounded full-table scans MUST be rejected (A00 API-4). A catalogue snapshot (full resync) is delivered as a paginated stream of bounded pages, never a single unbounded response.
- **A04-PAGE-3**: Pagination continuation tokens MUST be stable across the page sequence (a concurrent insert MUST NOT cause a page to skip or duplicate an item beyond at-least-once semantics the client already tolerates).

------

# 5. Endpoint Catalogue

All paths are prefixed `/mail/v1`. All bodies JSON unless noted. All endpoints require mail-plane token + X-App-* + request signature (§2).

## 5.1 Sync and catalogue

| Method | Path | Purpose |
| ------ | ---- | ------- |
| POST | `/sync/events` | Present cursor → paginated journal events after it |
| GET | `/catalogue/messages` | Paginated catalogue page (metadata + `summary_ct` refs) for a folder or since a watermark |
| GET | `/catalogue/message/{message_id}` | Single message catalogue entry (metadata + `summary_ct` + blob refs + this device's envelope) |
| GET | `/folders` | Folder tree (UUIDs + encrypted `name_ct` + hierarchy) |

- **A04-EP-1**: `/catalogue/message/{id}` returns the requesting device's envelope (A02 §4.3) inline (it is small, per-device metadata), but NEVER the blob bytes — blobs are fetched separately (§5.2). If no envelope exists for this device (historical, pre-re-wrap), the response marks `envelope_status: awaiting_rewrap` (A03-SYNC-4), not an error.

## 5.2 Blob fetch

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET | `/blob/{blob_id}` | Fetch one ciphertext blob (body or attachment), streamed |

- **A04-EP-2**: `/blob/{id}` returns raw ciphertext bytes (not base64-in-JSON, A00 API-3), with the `nonce` and `blob_alg_version` in response headers (or already known from the catalogue entry). The server serves ciphertext without any decryption semantics; it holds no `k_msg`. Range requests MUST be supported for large attachments (resumable download); a truncated transfer is re-requested, never weakening encryption (the blob is atomic ciphertext, GCM-verified on the client after full assembly).
- **A04-EP-3**: Blob fetch MUST be authorized: the server verifies the requesting principal owns a catalogue row referencing this blob. A device MUST NOT fetch a blob for a message it does not own (cross-principal blob access is forbidden even though the blob is ciphertext — metadata-level access control).
- **A04-EP-3b** (Diamy↔Diamy shared blob): For platform-internal delivery (A02 §5.2 step 4), the sender uploads ONE ciphertext blob and provides envelopes for both the sender's and the recipient's devices (one `k_msg`, multiple envelopes — this is the intended model, NOT cross-user deduplication forbidden by A02-CRY-6, which concerns different messages). Internal delivery therefore creates a catalogue row **for the recipient** that references the sender-uploaded blob. The authorization check (A04-EP-3) MUST treat this recipient row as valid ownership: the recipient can fetch the shared blob because their own catalogue row references it. Implementers MUST NOT make the shared blob unreachable by scoping blob ownership solely to the uploader.

## 5.3 State operations (mutating, idempotent)

| Method | Path | Purpose |
| ------ | ---- | ------- |
| POST | `/state/flags` | Set read/answered/flagged/**deleted**/tags on message(s) |
| POST | `/state/move` | Move message(s) to a folder |
| POST | `/state/delete` | Move to Trash (soft) or purge (hard) |
| POST | `/folders/create` | Create a folder (client supplies `name_ct`) |
| POST | `/folders/rename` | Rename (`name_ct`) / reparent |
| POST | `/folders/delete` | Delete folder (messages handled per request policy) |

- **A04-EP-4**: Every mutating state op MUST carry a client-generated **idempotency key** (§6) and MUST be safe to retry. The server records the op in the journal with a monotonic sequence; that sequence is the authority for per-field LWW conflict resolution (A03-SYNC-1). The response returns the assigned sequence so the client can order local state.
- **A04-EP-4bis** (`deleted` as a reversible flag — added v1.4): `deleted` is a boolean field of `/state/flags`, resolved per-field-LWW exactly like `read`/`answered`/`flagged` (A03-SYNC-1/2) and emitting `flags_changed`, NOT `message_deleted`. Setting it MUST be fully reversible (a subsequent `deleted:false` undoes it) — this is the IMAP `\Deleted`-before-`EXPUNGE` semantics: a client marks a message for deletion, may still unmark it, and only `/state/delete` (a separate, one-way call) performs the actual Trash-move or purge. A client MUST NOT infer that setting `deleted:true` via `/state/flags` has moved or purged anything — those effects only happen via an explicit `/state/delete` call.
- **A04-EP-5**: `tags` operations MUST be expressed as add/remove deltas, not full-set replacement, so the server journal reflects the union-merge semantics (A03-SYNC-2). A full-set replacement would race-clobber a concurrent device's tag.

## 5.4 Outbound submission

| Method | Path | Purpose |
| ------ | ---- | ------- |
| POST | `/submit` | Submit a composed message for emission + store the client-encrypted Sent copy |

- **A04-EP-6**: `/submit` carries: the client-encrypted Sent-copy blobs + envelopes (for the sender's own devices, A02 §5.2), the summary_ct, the recipient set, and — for emission — the RFC 5322 form the platform must send to the Internet. `diamy-submitd` resolves the tenant's outbound sending allocation (A23 / OPS-SEND-5), emits, and stores only the client-encrypted Sent copy. The emission plaintext is the **outbound mirror of the frontier exception** (A02 §5.2): it exists transiently in `diamy-submitd` RAM only for the duration of emission, MUST NOT be persisted, MUST NOT be logged, and MUST be **zeroized immediately after emission completes** (same destruction discipline as A01-DESTROY-1, non-eliding zeroization). The submission is idempotent on the idempotency key (§6): a retry after a crash MUST NOT double-emit.
- **A04-EP-7**: For Diamy↔Diamy, the client MAY additionally supply recipient-device envelopes (A02 §5.2 step 4); `diamy-submitd`/`diamy-maild` deliver platform-internally, skipping SMTP. If recipient bundles are stale/unavailable, fall back to SMTP emission.

## 5.5 Key-directory (client-facing)

| Method | Path | Purpose |
| ------ | ---- | ------- |
| POST | `/keydir/publish` | Publish this device's signed ML-KEM-768 bundle (A17-DIR-3) |
| GET | `/keydir/{principal_id}` | Fetch active device bundles for a principal (Diamy↔Diamy send) |
| POST | `/keydir/rewrap` | Upload re-wrapped envelopes for a target device (A02-RW) |

- **A04-EP-8**: `/keydir/publish` is a **SED-protected control-plane call** (A17-SED-1), not a data-plane call — it changes the device's security posture. The server verifies the Dilithium signature against the IAM key directory before accepting (A17-DIR-1/3). This is the one endpoint family in this annex that crosses into the SED-chained control plane.
- **A04-EP-9**: `/keydir/rewrap` uploads envelopes with `origin=rewrap:<D_old>` (A02-RW-1); the server enforces the re-wrap rate limit (A02-RW-3) and idempotency on (`message_id`, `device_id`).

------

# 6. Idempotency and the Outbound Queue

- **A04-IDEM-1**: Every mutating request (state ops, submit, rewrap) MUST carry a client-generated idempotency key (UUIDv7). The server MUST deduplicate: a repeated key returns the original result (including the assigned journal sequence) without re-applying the effect. Idempotency records MUST be retained at least as long as the client's plausible retry window (RECOMMENDED ≥ 24 h).
- **A04-IDEM-2**: The client's pending-outbound queue (A03-OFF-3) submits in order; each entry keeps its idempotency key across retries so a crash between send and ack never double-emits (A04-EP-6). The client advances the queue only on a durable success response.
- **A04-IDEM-3**: Ordering: state ops are commutative under per-field LWW (A03-SYNC), so strict ordering is not required for them. Submissions SHOULD preserve user-visible order (the order the user hit send), but MUST NOT block the whole queue on one stuck submission indefinitely — a submission failing permanently (e.g. recipient rejected) surfaces to the user and is skipped, not head-of-line-blocking.

------

# 7. Error Model (Normative)

Typed, stable machine-readable codes (A00 API-6):

| Code | Meaning | Client action |
| ---- | ------- | ------------- |
| `ERR_TOKEN_INVALID` | Mail-plane token bad/expired | Re-mint from IAM session |
| `ERR_SESSION_REVOKED` | Principal/device session revoked (mechanism TBC — epoch, JTI cache, or other, per A17-TOK-2) | Re-authenticate; possibly device revoked |
| `ERR_APPKEY_INVALID` | Tier 2 AppKey missing/invalid/revoked/platform-mismatched (A17-APPKEY-5) | Not user-recoverable — app misconfiguration; surface to operator, not end user |
| `ERR_TIMESTAMP_INVALID` | Signature timestamp outside ±120 s | Resend with fresh timestamp, same request-id |
| `ERR_SIGNATURE_INVALID` | Request signature mismatch | Do NOT retry blindly; likely a bug — surface |
| `ERR_CURSOR_EXPIRED` | Cursor older than journal retention | Full resync handshake (A04-SYNC-4) |
| `ERR_NOT_ENTITLED` | Mail entitlement removed | Stop; offboarding path (A03-SEC-5) |
| `ERR_BLOB_NOT_FOUND` | Blob purged/GC'd | Mark message damaged, reconcile via journal |
| `ERR_QUOTA_EXCEEDED` | Storage quota (submit/store) | Surface to user (A02-QOS-1) |
| `ERR_RATE_LIMITED` | Rate limit hit (incl. re-wrap, submit) | Backoff with `retry_after` |
| `ERR_PAGE_TOO_LARGE` | Requested page > hard max | Clamp handled server-side; informational |
| `ERR_VALIDATION` | Malformed request body | Surface — bug |

- **A04-ERR-1**: Every error response MUST include a stable `code`, a human-readable `message`, and where applicable a `retry_after` (seconds) or `request_id` for correlation. Error responses MUST NOT leak plaintext or another principal's existence.
- **A04-ERR-2**: `ERR_APPKEY_INVALID` MUST be returned generically (per A17-APPKEY-5's step-1 discipline) without revealing which specific check failed (missing/hash-mismatch/revoked/platform-mismatch/version-out-of-range) — this is a client/app misconfiguration signal, not a user-facing error, and MUST be surfaced to the operator/developer channel rather than the end user (mirrors the IAM Integration Specification's own `appkey_invalid` → generic-500-to-user handling).
- **A04-ERR-3** (naming is provisional): `ERR_SESSION_REVOKED` deliberately avoids the word "epoch" in its wire name, since A17-TOK-2 has not confirmed whether the underlying mechanism is epoch-based. Do not rename this code to `ERR_EPOCH_REVOKED` (or otherwise assume epoch semantics) until that confirmation lands.

------

# 8. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| WSS drops mid-sync | Client reconnects, presents cursor, resumes from last durable position; no data loss (journal replay) |
| Client crash mid-event-apply | Cursor not advanced past un-applied events → re-delivered on reconnect; idempotent apply (A04-SYNC-2) |
| Submit ack lost (crash after emit) | Idempotency key dedup on retry → no double-emit (A04-IDEM-2) |
| Cursor expired (dormant device) | `ERR_CURSOR_EXPIRED` → full resync (A04-SYNC-4) |
| Blob fetch truncated | Range-resume; GCM verify after full assembly; corrupt → re-fetch once then damaged (A03 failure model) |
| Concurrent state edits | Server sequences all ops; per-field LWW + tag union resolves (A03-SYNC-1/2) |
| Session revoked mid-session | WSS severed, target ≤10 s pending A17-TOK-2 confirmation (A04-TR-4); requests rejected `ERR_SESSION_REVOKED` until re-auth |
| Invalid/revoked Tier 2 AppKey | Rejected `ERR_APPKEY_INVALID` before any token/session processing (A17-APPKEY-5) |
| Server overload | `ERR_RATE_LIMITED` with `retry_after`; client exponential backoff; MUST NOT hot-retry |

------

# 9. Observability Contract

Per A00 §11:

- counters: `sync_events_served_total`, `catalogue_pages_served_total`, `blob_fetches_total{result}`, `submits_total{result}`, `state_ops_total{op,result}`, `idempotency_dedup_hits_total`, `cursor_expired_resyncs_total`, `keydir_publishes_total{result}`
- latency: `sync_events_duration`, `blob_fetch_duration` (p99 by size bucket), `submit_duration`, `catalogue_page_duration` (p99 < 100 ms target)
- gauges: active WSS connections, per-principal journal lag (events behind head), outbound queue depth (server-side accepted-but-not-emitted)
- audit (OBS-3): submissions (metadata only), key-directory publications, hard purges, entitlement-denied requests

------

# 10. Test Scenarios (Normative)

1. **Cursor sync round-trip**: two devices; device A flags a message → journal event → device B's next `/sync/events` returns it → B applies, cursors advance; no content in the event payload (assert).
2. **Crash mid-apply**: kill client after receiving events but before persisting → restart → same events re-delivered (cursor not advanced) → idempotent apply, no duplicate local rows.
3. **Idempotent submit**: submit with key K, kill client after server emitted but before ack → retry with same K → server dedups, no second emission (assert single Internet emission).
4. **Cursor expired**: dormant device 40 days (> 30-day floor) → reconnect → `ERR_CURSOR_EXPIRED` → full resync snapshot → catalogue matches other devices; lazy blob re-fetch.
5. **Blob range resume**: fetch a 40 MB attachment, interrupt at 60% → range-resume → full assembly → GCM verifies.
6. **Tag union**: device A adds tag X, device B adds tag Y to same message offline → both sync → message has {X, Y} (delta semantics, A04-EP-5).
7. **Session revocation**: revoke a session mid-WSS (via the confirmed mechanism, A17-TOK-2) → connection severed, target ≤10 s pending that confirmation → next request `ERR_SESSION_REVOKED` (renamed from `ERR_EPOCH_REVOKED` pending A17-TOK-2's resolution — do not hard-code an epoch-specific error code until the mechanism is confirmed).
8. **Blob authorization**: device requests a blob referenced only by another principal's message → `ERR_BLOB_NOT_FOUND`/403 (no cross-principal access), assert no ciphertext served.
9. **Pagination stability**: paginate a 5000-message folder while inserts happen → no item skipped/duplicated beyond at-least-once; page size clamped at hard max.
10. **AppKey required and independent**: request with a valid mail-plane token but no/invalid AppKey → rejected before token processing (A17-APPKEY-5); request with a valid AppKey but expired token → rejected for the token reason at step 2, not conflated (A04-TR-2).
11. **Tier confusion rejected**: a request presenting a Tier 1 IAM AppKey value as the Tier 2 `X-App-Key` → rejected — the two are validated against different stores and MUST NOT be interchangeable (A04-TR-2, A17-TOK-4).

------

# 11. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Implementing sync as IMAP or an IMAP-like stateful mailbox protocol instead of the journal-cursor pull model (A00 API-1, A04-SYNC).
2. ❌ Pushing message content in WSS notifications instead of signals-only cursor-advance hints (A04-SYNC-3, API-5).
3. ❌ Inlining blob bytes as base64 in catalogue/message JSON instead of separate `/blob/{id}` fetch (A04-EP-2, API-3).
4. ❌ Advancing the sync cursor before the client durably persisted the applied events, losing events on crash (A04-SYNC-2).
5. ❌ Offset-based pagination that skips/duplicates rows under concurrent inserts instead of stable cursor pagination (A04-PAGE-1/3).
6. ❌ Non-idempotent submit, so a lost-ack retry double-emits to the Internet (A04-IDEM-2, A04-EP-6).
7. ❌ Full-set tag replacement instead of add/remove deltas, race-clobbering a concurrent device's tags (A04-EP-5).
8. ❌ SED-chaining the data plane (serializes blob sync, destroys throughput) — data plane uses request signing + idempotency, only `/keydir/publish` and webmail-enable are SED (A04-TR-3, A17-SED).
9. ❌ Serving a blob without verifying the requesting principal owns a referencing catalogue row (A04-EP-3 — cross-principal ciphertext access).
10. ❌ Treating `ERR_CURSOR_EXPIRED` as a fatal error instead of triggering the full-resync handshake (A04-SYNC-4).
11. ❌ Head-of-line-blocking the entire outbound queue on one permanently-failing submission instead of surfacing and skipping it (A04-IDEM-3).
12. ❌ Retrying on `ERR_SIGNATURE_INVALID` or `ERR_VALIDATION` in a hot loop instead of surfacing a bug (A04-ERR-1).
13. ❌ Persisting or failing to zeroize the emission plaintext in `diamy-submitd` after emission (A04-EP-6), or scoping shared Diamy↔Diamy blob ownership to the uploader so the recipient cannot fetch it (A04-EP-3b).
14. ❌ Treating the mail-plane token alone as sufficient authentication, omitting the Tier 2 AppKey check, or validating them in the wrong order (AppKey MUST be checked first, locally, before the token) (A04-TR-2, A17-APPKEY-5).
15. ❌ Sending or accepting a Tier 1 IAM AppKey value where a Tier 2 Diamy Mail AppKey is expected, or vice versa (A04-TR-2, A17-TOK-4) — the two tiers authenticate different things and use different stores.
16. ❌ Hard-coding `ERR_EPOCH_REVOKED` or assuming the epoch-bump mechanism is implemented fact before A17-TOK-2 is resolved (A04-TR-4) — use a mechanism-neutral error/behavior until confirmed.

------

# 12. Deferred Items

- WSS multiplexing / backpressure tuning for very large mailboxes syncing on a metered connection — operational, revisit with A18/A22.
- Delta-sync of `summary_ct` changes (rare: summaries are immutable once written; only relevant if a future feature edits summaries) — not needed in V1.
- Push-notification bridge (APNs/FCM) carrying signal-only wakeups when WSS is not held open on mobile — the payload rule (signals only, A04-SYNC-3) already applies; the exact APNs/FCM envelope is a client-platform detail for A19.
- Bridge (A20) translation of this API to IMAP/SMTP/CalDAV for third-party clients is specified in A20; it consumes this native API through the client SDK (A19) and requires no change to this protocol.

------

*End of document.*
