# Diamy Mail — ANNEX A05: Search & Local AI Keyword Extraction

**Document title:** Diamy Mail — ANNEX A05: Search & Local AI Keyword Extraction
**Version:** 1.0
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)
**Sibling dependencies:** A02 (Storage v1.1), A03 (Vault Client v1.1), A04 (Native Sync API v1.1), A17 (IAM Integration v1.1), A24 (Identity & Address Normalization v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: local-first search model, local FTS index (encrypted), local AI keyword extraction (on-device), webmail-only Blind Index sync with strict data-minimization, Blind Index derivation (keyword + address), server search endpoints (webmail only), partial-sync result completeness signaling, hidden-content exclusion, per-user keys, enablement/disablement lifecycle, failure model, test scenarios, common AI errors. Closes A00 Open Decision #2 (remote search scope). |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: added the webmail query flow (browser computes the query token locally, sends token not plaintext — §6.5) and the webmail key-exposure tradeoff (webmail necessarily brings per-user Blind-Index keys into the browser, a weaker boundary than the OS secure store — must be disclosed, §6.6); made the exact-token limitation's user-visible effect explicit (plural/inflection misses on webmail, A05-BI-4); added AI error #13 (sending the plaintext query to the server from webmail) |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies how a user searches their mail: the **local-first** default (full-text over decrypted content on-device), the **on-device AI keyword extraction**, and the **opt-in webmail** path that syncs Blind-Index tokens to enable server-side search when no local store exists. It fixes the exact data-minimization boundary (what leaves the device, and only when).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Closes Open Decision #2

A00 §14 Open Decision #2 asked whether server-side Blind-Index search activates only under webmail, or also for partially-synced native clients. **This annex fixes: Blind-Index sync to the server happens ONLY when webmail is enabled for the user. A native client without webmail never uploads keyword indices** (A00 SRCH-2, data minimization). A partially-synced native client searches locally over what it has and clearly signals incompleteness (§7) — it does NOT fall back to a server keyword query. (Address Blind Index for routing is separate — see §5.)

## 1.2 Out of scope

Local storage/encryption of the index (A03-STO-4 owns "the index must be encrypted"; this annex owns its content and use). Sync transport (A04). The keyword-extraction *model* internals (A19/deployment); this annex fixes the contract, privacy boundary, and I/O.

------

# 2. Search Model Overview

Three search surfaces, three capability levels:

| Surface | Local store? | Search mechanism | Scope |
| ------- | ------------ | ---------------- | ----- |
| Native client, full-synced | Yes | Local FTS over decrypted content + metadata | Full content search, instant, offline |
| Native client, partially-synced | Partial | Local FTS over synced subset; incompleteness signaled | Subset; NEVER a server keyword query |
| Webmail (opt-in) | No | Server-side Blind-Index over synced keyword tokens | Keyword + address equality only (not full-text) |

- **A05-MODEL-1**: Local search is the default and the richest. It runs entirely on-device over decrypted content, returns instantly, and works offline (A00 SRCH-1). No server round-trip, no query leaves the device.
- **A05-MODEL-2**: Webmail search is a **degraded** surface by design: it can match indexed keywords and canonical addresses, not arbitrary full-text substrings, because only derived keyword tokens (not content) are ever synced (A05-BI). This limitation MUST be disclosed to webmail users ("webmail search covers senders, recipients, and key terms; full-text search requires the app").

------

# 3. Local Full-Text Search

- **A05-LOC-1**: The native client MUST maintain a local full-text index (SQLite FTS5 or equivalent) over the decrypted content of synced messages: subject, body text (post-Tiptap-conversion plain text, A08), sender/recipient display and canonical forms, attachment filenames, and extracted attachment text where the client extracts it. The index MUST be encrypted at rest at the same level as the catalogue (A03-STO-4) — RECOMMENDED as FTS tables inside the single SQLCipher catalogue.
- **A05-LOC-2**: Indexing happens **after** decryption and Tiptap conversion, on-device, in the same trust boundary as rendering. Hidden source content (A00 SEC-RENDER-3: `display:none`, zero-size, background-colored text) MUST NOT be indexed — it is excluded at conversion (A08) and therefore never reaches the index. This prevents an attacker from poisoning search results with content invisible to the user.
- **A05-LOC-3**: Local search MUST support at least: free-text terms, phrase match, sender/recipient filter (by canonical address, A24), folder/date/flag filters, has-attachment and attachment-name match. Results MUST be ranked and returned incrementally for responsiveness.
- **A05-LOC-4**: Indexing MUST be incremental (new messages indexed on sync) and MUST be rebuildable from the local decrypted store if the index is lost or corrupted (no server dependency — the content of record is locally decryptable via envelopes).

------

# 4. On-Device AI Keyword Extraction

- **A05-AI-1**: A local AI agent (on-device model, A19/deployment) MAY extract a compact set of **keywords** from each message's subject and body at index time. The agent runs entirely on-device; message plaintext MUST NOT leave the device for extraction (A00 SRCH-4). This is the same trust boundary as local rendering and indexing.
- **A05-AI-2**: Keywords are an **abstraction/summary** of content, not the content itself. The extractor MUST operate only on the **visible** content (post-A08, hidden content excluded per A05-LOC-2 / SEC-RENDER-3), so hidden text cannot inject misleading keywords (A00 SEC-RENDER-3).
- **A05-AI-3**: Extracted keywords have two uses: (a) improving **local** search/ranking and enabling local semantic features — always available on-device; (b) feeding the **webmail Blind Index** — ONLY if webmail is enabled (§6). Use (a) never requires anything to leave the device.
- **A05-AI-4**: The extractor MUST be deterministic enough that the same message yields a stable keyword set across a device's re-index (so local search is consistent), but cross-device keyword identity is NOT required for local search (each device indexes independently). Cross-device identity IS required only for the webmail Blind Index, which is derived on whichever device syncs it (§6) — the server matches tokens, so the derivation input (keyword string) must be normalized consistently (§6.3).

------

# 5. Address Blind Index (routing/metadata — always)

Distinct from keyword search, sender/recipient **address** equality lookup uses a Blind Index that exists regardless of webmail, because address metadata is already server-visible for routing (A00 SRCH-3, §3.3).

- **A05-ADDR-1**: The sender/recipient address Blind Index is `BI_addr = HMAC-SHA256(k_bi_addr_user, canonical_address)` where `canonical_address` is the A24 canonical form (A24-BI-1/2) and `k_bi_addr_user` is a per-user key (§8). This lets the server answer "all messages from `x@y.fr`" for the webmail surface without storing plaintext addresses beyond routing needs.
- **A05-ADDR-2**: In the native client, address search runs locally (the canonical addresses are in the local catalogue); the address Blind Index is used **server-side only for the webmail surface**. Its derivation input is fixed by A24 (single normalization function), preventing the divergence that would silently break matching (A24-CONF, CDM-ADDR-3).

------

# 6. Webmail Blind Index (opt-in keyword sync)

This section applies **only when webmail is enabled** for the user. When disabled, none of it executes and nothing here is uploaded.

## 6.1 Enablement gate

- **A05-BI-1**: Keyword Blind-Index sync MUST be gated on an explicit webmail-enabled flag for the user. Enabling/disabling webmail is a **SED-protected, audited control-plane action** (A17-SED-3, A00 OBS-3). While disabled, the client MUST NOT compute or upload keyword Blind-Index tokens (data minimization, A00 SRCH-2). Address Blind Index (§5) is likewise uploaded only when webmail is enabled.

## 6.2 Derivation

- **A05-BI-2**: For each extracted keyword `kw`, the token is `BI_kw = HMAC-SHA256(k_bi_kw_user, normalize_kw(kw))` where `k_bi_kw_user` is the per-user keyword Blind-Index key (§8), separate from the address key (§5) and from any other key (key separation). The server stores `{message_id, BI_kw}` rows and can answer "messages whose keyword set contains token T" by matching `BI_kw` — never seeing `kw`.
- **A05-BI-3**: The client computes tokens **on-device** (it has the plaintext and the key) and uploads only the tokens via the sync API (A04), associated to `message_id`. The plaintext keyword MUST NOT be uploaded. Upload happens at index time for new messages and as a backfill when webmail is first enabled (§6.4).

## 6.3 Keyword normalization (shared, deterministic)

- **A05-BI-4**: `normalize_kw()` MUST be a single shared function (Rust + TS, byte-identical, like A24) applied before HMAC: Unicode NFC, casefold, trim, and a defined tokenization (word boundaries). Divergent normalization between the syncing device and any future re-derivation would make tokens non-matchable. Test vectors MUST pin its behavior. It MUST NOT apply stemming or language-specific lemmatization in V1 (locale-dependent, non-deterministic across libraries) — exact-token matching only; richer matching stays a local-search feature. User-visible consequence: on the webmail surface, `invoice` will NOT match `invoices` and accented/inflected variants match only if identical after normalization. This is an inherent limitation of the minimal webmail index and MUST be disclosed (A05-MODEL-2); the native app's local FTS does not have this limitation.

## 6.4 Enablement backfill / disablement purge

- **A05-BI-5**: On webmail **enable**: the client backfills Blind-Index tokens for existing messages (bounded, rate-limited, resumable like A02-RW), so webmail search covers history. The backfill processes on-device plaintext; only tokens upload.
- **A05-BI-6**: On webmail **disable**: the server MUST purge all of the user's Blind-Index tokens (keyword and address) within a bounded window (RECOMMENDED ≤ 24 h), audit-logged. Disabling is a data-minimization action and MUST actually remove server-side index data, not merely hide it. New messages stop producing uploaded tokens immediately.

## 6.5 Webmail query flow (token, not plaintext)

- **A05-BI-7**: When a webmail user searches, the query MUST be tokenized in the browser, NOT sent as plaintext. Flow: (1) browser applies `normalize_kw()` to each query term and computes `BI_kw = HMAC-SHA256(k_bi_kw_user, term)` locally; (2) browser sends the **token(s)** to the server search endpoint (A04-family, webmail scope); (3) server matches tokens against stored `{message_id, BI_kw}` rows and returns matching `message_id`s (paginated); (4) browser fetches those messages' catalogue entries + blobs + its envelope, decrypts in-browser (WebCrypto), and renders. The server never receives the plaintext query term, only the token. Address search is identical using `BI_addr` (§5).
- **A05-BI-8**: The webmail search endpoint MUST accept only tokens (fixed-length HMAC outputs) and MUST reject anything that looks like a plaintext term, as a defense against a client bug leaking the query. It returns `message_id`s and match metadata only — never content.

## 6.6 Webmail key-exposure tradeoff (must be disclosed)

- **A05-BI-9**: Webmail necessarily brings the per-user Blind-Index keys (`k_bi_kw_user`, `k_bi_addr_user`) and the device decryption key into the **browser** environment, which is a weaker protection boundary than the OS secure store used by the native client (A03-KEY). The keys live in browser memory for the session, never in `localStorage`/`sessionStorage`/IndexedDB (A00 artifact storage prohibition applies to any browser-side Diamy code), and are dropped on session end. Nonetheless, enabling webmail is a **security-posture downgrade** relative to native-only operation: it exposes key material to the browser attack surface and creates server-side Blind-Index tokens. This tradeoff MUST be disclosed to the user/admin at the point of enabling webmail (it is already a SED-protected, audited action, A05-BI-1), and tenants MUST be able to disable webmail organization-wide (native-only enforcement).
- **A05-BI-10**: Because webmail is an explicit opt-in with disclosed tradeoffs, a tenant that never enables it has: no server-side keyword/address Blind Index, no key material in any browser, and search that is exclusively local and offline. This is the maximum-privacy default posture and MUST be the out-of-the-box configuration.

------

# 7. Partial-Sync Result Completeness

- **A05-PART-1**: A native client that has not fully synced (new device mid-backfill, or cache-evicted blobs whose text was never indexed) MUST clearly signal when local search results MAY be incomplete, rather than silently returning a partial set as if complete (A00 SRCH-5). The UI MUST distinguish "no results" from "no results in the X% of your mailbox indexed so far".
- **A05-PART-2**: A partially-synced native client MUST NOT compensate by issuing a server-side keyword Blind-Index query — that path exists only for webmail (A05-BI-1, closes Open Decision #2). Instead it completes indexing in the background (fetching/decrypting/indexing missing messages per A03 cache and A04 sync) and updates results as coverage grows.
- **A05-PART-3**: Metadata search (sender/recipient/date/folder/flags) is ALWAYS complete on a native client even when bodies are not all downloaded, because full metadata + decrypted summaries are always synced (A03-CACHE-1). Only **body/attachment full-text** can be incomplete. The client SHOULD make this distinction visible (metadata matches are authoritative; body matches may be partial).

------

# 8. Keys

- **A05-KEY-1**: Blind-Index keys are **per-user**, distinct per purpose: `k_bi_addr_user` (address, §5) and `k_bi_kw_user` (keyword, §6), plus any future purpose gets its own key (key separation; a single key across purposes would allow cross-correlating address and keyword indices).
- **A05-KEY-2**: These keys MUST be available to all of the user's devices (so any device can derive matching tokens) but MUST NEVER reach the server (the server matches tokens, it does not derive them). They are provisioned/distributed by the same mechanism as `k_folder` (A03-KEY-3) — device-to-device wrap or an IAM-provisioned principal secret (the latter an IAM extension). The server storing a Blind-Index token is fine; the server storing the *key* would break the scheme (it could then dictionary-attack the tokens).
- **A05-KEY-3**: Because the server never holds the key, an offline dictionary attack against `BI_kw` requires guessing both the key and the keyword; the key's full entropy protects low-entropy keywords. This is the same property that makes the summary non-oracle (A02-CRY-3) — Blind Index security rests on the secrecy of the per-user key.

------

# 9. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Local index corrupted | Rebuild from local decrypted store (A05-LOC-4); no server dependency; search degraded to metadata-only until rebuilt, signaled (A05-PART) |
| AI extractor unavailable/fails on a message | Message still indexed for FTS (keywords are additive); message flagged `keywords_pending`; retried; search works without keywords |
| Webmail enabled but backfill incomplete | Webmail search signals partial coverage (mirror of A05-PART-1) until backfill completes |
| Blind-Index key unavailable on a device | That device cannot produce webmail tokens; it still searches locally; token production waits for key provisioning (A05-KEY-2) |
| Keyword normalization mismatch across versions | Version the normalizer; a version change requires token re-derivation on next backfill; mismatched tokens simply fail to match (safe: missed match, never wrong match) |
| Webmail disable purge fails | Retry until complete; the user's data-minimization request is not satisfied until tokens are gone — surface/alert if purge cannot complete (A05-BI-6) |

------

# 10. Observability Contract

Per A00 §11 (privacy-preserving, A03-OBS-1 — never content):

- counters: `local_index_ops_total{op}`, `ai_keyword_extractions_total{result}`, `bi_tokens_uploaded_total` (webmail only), `bi_backfill_jobs_total{result}`, `bi_disable_purges_total{result}`, `search_queries_total{surface}` (surface = local/webmail; NEVER the query text)
- latency: `local_search_duration` (p99 target < 50 ms), `bi_query_duration` (webmail), `keyword_extraction_duration`
- audit (OBS-3): webmail enable/disable (already A17-SED-3), Blind-Index purge completion
- **A05-OBS-1**: Search telemetry MUST NEVER include query terms, keywords, addresses, or any content-derived string. Only counts, latencies, and result-count buckets.

------

# 11. Test Scenarios (Normative)

1. **Local-only default**: native client, webmail disabled → full-text search works offline; assert zero network egress during search and zero Blind-Index tokens ever uploaded.
2. **Hidden-content exclusion**: message with `display:none` text containing "URGENT WIRE" → search "URGENT WIRE" returns nothing (hidden text never indexed, A05-LOC-2); the visible content is searchable.
3. **Partial-sync signaling**: new device mid-backfill → search returns subset with explicit "indexed X% so far" signal; NO server keyword query issued (assert); metadata search is complete.
4. **Webmail enable/backfill**: enable webmail (SED, audited) → backfill uploads tokens (rate-limited, resumable); webmail search now matches historical keywords; only tokens left the device (assert no plaintext keyword uploaded).
5. **Webmail disable purge**: disable → all address+keyword tokens purged server-side ≤ 24 h, audit-logged; webmail search returns nothing afterward.
6. **Key separation**: verify `BI_addr` and `BI_kw` use different keys (a token from one cannot be matched in the other's index).
7. **Normalization determinism**: `normalize_kw()` produces identical tokens for the same keyword on Rust and TS (shared test vectors); NFC-equivalent inputs collapse to one token.
8. **Address Blind Index consistency**: `café@société.fr` (A24 canonical) produces the same `BI_addr` as its NFC-variant input (A24 vector #5 property carried into the index).
9. **Webmail query is tokenized**: webmail user searches "invoice" → assert the server receives an HMAC token, never the string "invoice"; server returns message_ids; browser fetches + decrypts in-WebCrypto and renders; assert no plaintext query in any server log.
10. **Webmail exact-token limit**: webmail search "invoice" does NOT return a message whose only match is "invoices" (documented limitation); the native app's local FTS DOES return it.

------

# 12. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Uploading keyword Blind-Index tokens (or address tokens) when webmail is disabled — violates data minimization and Open Decision #2 (A05-BI-1, closes A00 #2).
2. ❌ Letting a partially-synced native client fall back to a server keyword query instead of signaling incompleteness and indexing in the background (A05-PART-2).
3. ❌ Indexing hidden source content (`display:none`, zero-size, background-colored) so search matches text the user cannot see — enables search-poisoning (A05-LOC-2, SEC-RENDER-3).
4. ❌ Building the local FTS index as an unencrypted separate file (A03-STO-4 cross-ref) — plaintext searchable copy at rest.
5. ❌ Uploading plaintext keywords instead of HMAC Blind-Index tokens (A05-BI-3).
6. ❌ Sending message plaintext off-device for AI keyword extraction instead of running the model on-device (A05-AI-1, SRCH-4).
7. ❌ Reusing one Blind-Index key for both address and keyword indices, enabling cross-correlation (A05-KEY-1).
8. ❌ Storing the Blind-Index key server-side, enabling an offline dictionary attack on tokens (A05-KEY-2/3).
9. ❌ Diverging keyword normalization between client implementations or versions without re-derivation, silently breaking webmail matches (A05-BI-4).
10. ❌ Applying stemming/lemmatization to Blind-Index tokens (locale-dependent, non-deterministic) instead of exact-token matching (A05-BI-4).
11. ❌ On webmail disable, hiding tokens instead of actually purging them server-side (A05-BI-6).
12. ❌ Emitting search telemetry containing query terms or keywords (A05-OBS-1).
13. ❌ Sending the webmail user's plaintext query term to the server instead of computing the Blind-Index token in the browser and sending only the token (A05-BI-7/8); or persisting webmail Blind-Index/device keys in browser `localStorage`/`sessionStorage`/IndexedDB instead of session memory only (A05-BI-9).

------

# 13. Deferred Items

- Semantic / vector search on-device (embeddings over decrypted content) — a local-only feature that never changes the server boundary; revisit as an enhancement once base search ships.
- Language-aware ranking/lemmatization for **local** search (permitted locally since it never affects server tokens) — a client enhancement, not a protocol concern.
- Encrypted-search schemes stronger than Blind Index (SSE with richer query support) for webmail — explicitly out of V1 scope; the local-first posture makes the webmail surface intentionally minimal.
- `k_bi_*` provisioning mechanism finalization — shares the A03-KEY-3 / A05-KEY-2 open item (device-wrap vs IAM extension).

------

*End of document.*
