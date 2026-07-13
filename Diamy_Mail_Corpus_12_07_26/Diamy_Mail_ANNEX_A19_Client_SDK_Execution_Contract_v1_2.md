# Diamy Mail — ANNEX A19: Client SDK & Execution Contract

**Document title:** Diamy Mail — ANNEX A19: Client SDK & Execution Contract
**Version:** 1.2
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.3 (A00)
**Sibling dependencies:** A03 (Vault Client v1.1), A04 (Native Sync API v1.1), A05 (Search v1.1), A08 (HTML→Tiptap v1.1), A18 (Server Implementation Guide v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: client SDK architecture and execution contract — protocol-engine invariants, platform targets (desktop/mobile/webmail), shared vs platform-specific layers, cryptographic operation placement, secure-store abstraction, best-effort zeroization on managed runtimes, offline/sync state machine, rendering pipeline contract, key-parity with server (A24/A05 shared functions), testing/conformance, forbidden patterns, deferred items. Client-side counterpart of A18. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: clarified the native-vs-webmail device-key placement — native clients hold the ML-KEM private key in the OS secure store; webmail has NO secure store, so its device-key material is in-session browser memory only (never browser storage), a disclosed weaker posture consistent with A05-BI-9 (A19-CRY-1b). Verified parity-by-shared-code approach reuses the A18 server crates. |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Coherence extension for the Tier 2 AppKey model (A17 v1.4 §4.2bis): added A19-STORE-4 — the SDK holds its own Diamy Mail AppKey in secure storage (native) or in-session memory (webmail, no exemption), distinct from the mail-plane token and unrelated to any Tier 1/IAM-side credential, which the SDK never sees. Added forbidden-pattern #15. |

------

# Table of contents

[toc]

------

# 1. Scope

This annex is the **client-side implementation contract**, the counterpart of A18 (server). It fixes how the vault client (A03) and its sync/search/render behaviors are built across platforms so the security and correctness invariants hold on the device side, where the runtime is often managed (JS/TS, Kotlin, Swift) and the guarantees differ from Rust's.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Platform targets

- Desktop (Electron or native shell) and mobile (iOS/Android) native clients — the **vault clients** (A03), full local store, offline.
- Webmail (browser) — a **thin** client: no local store, in-session key material, WebCrypto decrypt (A05 §6.6, A00 §4). Governed here for its crypto/no-storage rules.

## 1.2 Design tension (managed runtimes)

- **A19-RT-1**: Unlike the server (A18, Rust, strong zeroization), client runtimes are frequently **managed/GC'd** (JS/TS, Kotlin/JVM, Swift/ARC). True memory zeroization is not guaranteed (A03-READ-3). The client contract therefore mandates **best-effort** minimization plus **structural** protections (short plaintext lifetime, no long-lived plaintext caches, secure-store-held keys), and is explicit that this is weaker than the server guarantee — documented, not hidden.

## 1.3 Out of scope

Server conventions (A18). The sync wire protocol (A04). The Tiptap schema (A08). This annex fixes the *client execution* of those, not their definitions.

------

# 2. SDK Architecture

- **A19-SDK-1**: A **shared core SDK** MUST encapsulate the protocol logic that MUST be identical across platforms: sync state machine (A04 cursors, idempotency), envelope decryption orchestration, conflict resolution (A03-SYNC per-field LWW), catalogue/cache management (A03), Blind-Index token derivation (A05, webmail), and the shared normalization functions. The platform layer (UI, secure-store binding, OS integration) wraps the core.
- **A19-SDK-2** (language): The shared core SHOULD be one implementation reused across platforms where feasible — RECOMMENDED **Rust compiled to the platform** (WASM for web, native lib via UniFFI/JNI/Swift bridging for mobile/desktop), so the byte-exact shared functions (A24 `diamy_addr_canon`, A05 `normalize_kw`) are literally the same code as the server crate (A18-TOP-1), not a re-implementation that could drift. Where a full shared-core is impractical on a platform, the drift-sensitive functions (normalization, Blind-Index derivation, conflict resolution) MUST still be shared or conformance-tested against the same vectors (A19-TEST).
- **A19-SDK-3**: Platform layers MUST NOT duplicate protocol logic; a bug fixed in the core must not need re-fixing per platform. UI and OS integration are the only per-platform code.

------

# 3. Cryptographic Operation Placement

- **A19-CRY-1**: The device ML-KEM-768 private key lives in the OS secure store (A03-KEY-1); decapsulation happens in the core SDK, key loaded transiently, best-effort zeroized (A19-RT-1). Where a platform offers non-exportable key handles usable for the operation, use them; where PQC is not yet supported in the secure element, store as a secure-store-protected blob and operate in-memory (A03-KEY-1, documented per platform).
- **A19-CRY-1b** (native vs webmail key placement): A19-CRY-1 describes **native** clients (desktop/mobile), which have an OS secure store. **Webmail** has no OS secure store: a webmail session's device-key and Blind-Index key material lives in **in-session browser memory only**, never in browser storage (A19-STORE-2, A05-BI-9), and is dropped at session end. Webmail is therefore a "device" whose key material is ephemeral and browser-resident — a **disclosed weaker posture** than native (A05-BI-9): it MUST be surfaced when webmail is enabled, and tenants MUST be able to forbid webmail org-wide to keep all key material in native secure stores. An implementer MUST NOT assume a secure store exists in the webmail build, nor persist any key to browser storage as a "cache".
- **A19-CRY-2**: The client uses vetted crypto — the shared Rust core's audited primitives via WASM/native (A19-SDK-2), or, where a platform path uses native crypto (WebCrypto for webmail AES-GCM), a vetted platform API. Hand-rolled crypto is FORBIDDEN (mirrors A18-CRY-1).
- **A19-CRY-3** (HKDF/nonce parity): HKDF labels and nonce discipline (independent CSPRNG nonces, A02-CRY-1b/4) MUST match the server exactly — the shared core guarantees this. A client that derives keys or nonces differently from the server breaks interop; this is why the shared-core approach (A19-SDK-2) is strongly preferred.
- **A19-CRY-4** (Diamy↔Diamy signing): For internal messages the sending client signs the manifest with its ML-DSA-65 identity key (A02 §5.2); the receiving client MUST verify before rendering (A03-READ, A02). The identity key handling follows the IAM client contract (A17), never reused for encryption (A17 separation).

------

# 4. Secure Store Abstraction

- **A19-STORE-1**: The SDK MUST expose a uniform secure-store interface backed per platform: Keychain/Secure Enclave (iOS/macOS), Android Keystore/StrongBox, DPAPI/TPM-CNG (Windows), libsecret/Keychain (Linux/desktop). It holds: the device mail private key, `k_cat` (SQLCipher key, A03-KEY-2), and the shared per-user keys (`k_folder`, `k_bi_*`) obtained per A03-KEY-3/A05-KEY-2.
- **A19-STORE-2** (browser exception): Webmail has no OS secure store; in-session key material lives in **memory only**, NEVER in `localStorage`/`sessionStorage`/IndexedDB (A00 artifact-storage prohibition, A05-BI-9), dropped on session end. The SDK's browser build MUST enforce this — any attempt to persist keys in browser storage is a forbidden pattern (§11).
- **A19-STORE-3**: Secure-store release SHOULD require user presence (biometric/PIN) on mobile per app-lock policy (A03-SEC-1); the SDK surfaces lock/unlock to the platform layer.
- **A19-STORE-4** (Tier 2 AppKey — implements A17-APPKEY): The SDK MUST hold the client's own Diamy Mail Tier 2 AppKey (A17 §4.2bis) in the same secure store as other long-lived material (A19-STORE-1), distinct from the mail-plane token (which stays memory-only, A19-ZERO-2, A17-TOK-3). The AppKey is long-lived (not re-minted per session) and sent as the `X-App-Key`/`X-App-Name`/`X-App-Platform`/`X-App-Version` header set on every request (A04-TR-2) — it is unrelated to, and MUST NOT be confused with, any IAM-side (Tier 1) credential, which the SDK never sees or handles (Tier 1 is backend-only, A17-TOK-4). On the webmail build, the AppKey follows the same in-session-memory-only rule as other webmail key material (A19-STORE-2) — it is not exempted merely because it's an "app" credential rather than a decryption key.

------

# 5. Offline & Sync State Machine

- **A19-SYNC-1**: The core SDK implements the A04 sync state machine: cursor tracking, at-least-once event application with idempotent local apply (A04-SYNC-2), full-resync handshake on `ERR_CURSOR_EXPIRED` (A04-SYNC-4), signals-only notification handling (never trusting signal payloads for content, A04-SYNC-3). Cursor advance MUST be durable only after local persistence (A04-SYNC-2) — a crash re-delivers un-applied events.
- **A19-SYNC-2** (offline): All A03-OFF operations (read cached, local search, compose, draft, flag/move/delete offline) queue as pending sync ops and replay in order on reconnect, with the idempotency key preserved across retries so a crash never double-sends (A03-OFF-3, A04-IDEM-2).
- **A19-SYNC-3** (conflict): The SDK applies per-field LWW by server journal sequence, tag-set union, purge-wins (A03-SYNC-1/2/3) — deterministically, so all devices converge. This is shared-core logic (A19-SDK-1); property-tested for convergence regardless of event order (A19-TEST).
- **A19-SYNC-4** (ordering authority): The SDK MUST use the server journal `seq` as the ordering authority, NEVER local wall-clock (A03-SYNC-1, clock-skew failure). Local timestamps are display-only.

------

# 6. Rendering Pipeline Contract (client)

- **A19-REND-1**: The SDK/client MUST render via the Tiptap closed-schema pipeline by default (A03-READ-1, A08, SEC-RENDER-1), never raw HTML. HTML→Tiptap conversion (A08) runs client-side; the SDK provides or invokes the conversion and the plain-text projection for local index/AI (A08-OUT).
- **A19-REND-2**: The "view original" sandbox (A09) is an explicit, non-default path with all three defense layers (sandbox + CSP + image proxy). The client MUST refuse the original view rather than render raw HTML unsandboxed if any layer is unavailable (A09 §8).
- **A19-REND-3** (hidden-content parity): The client conversion MUST prune hidden content from render AND from the plain-text projection fed to local index/AI (A08-HID, A05-LOC-2), so hidden text is never searched or AI-extracted. This is the client-side hidden detection (A08 §1.1b), distinct from the frontier trust signal.
- **A19-REND-4** (remote content): Remote images blocked by default; on opt-in, loaded via the image proxy (A08-IMG-2, A09-IMG). The SDK MUST NOT let a naive `<img>` load bypass the proxy.

------

# 7. Local Search & AI (client)

- **A19-SRCH-1**: The SDK implements local FTS over decrypted content (A05-LOC), the index sharing the catalogue's encryption boundary (A03-STO-4) — never a plaintext index file. On-device AI keyword extraction (A05-AI) runs locally; message plaintext MUST NOT leave the device for extraction.
- **A19-SRCH-2** (webmail Blind-Index): In the webmail build, a search query is tokenized **in the browser** (HMAC with the in-session `k_bi_kw_user`) and only the token is sent (A05-BI-7); the plaintext query MUST NOT be sent to the server. This is a shared-core function so the token derivation matches the server's stored tokens (A05-BI-4 normalization parity).
- **A19-SRCH-3**: Blind-Index tokens are produced/uploaded ONLY when webmail is enabled (A05-BI-1); a native client without webmail never derives or uploads them. The SDK MUST gate this on the webmail-enabled flag.

------

# 8. Key & Function Parity with Server (Normative)

- **A19-PAR-1**: The drift-sensitive shared functions MUST be byte-identical to the server:
  - `diamy_addr_canon()` (A24) — same canonical address, or Blind-Index/routing/threading break.
  - `normalize_kw()` (A05-BI-4) — same keyword tokenization, or webmail search misses.
  - HKDF labels + nonce discipline (A02-CRY) — same key derivation, or decryption interop breaks.
  - Conflict resolution (A03-SYNC) — same convergence, or devices diverge.
- **A19-PAR-2**: Parity is guaranteed by sharing the actual code (Rust core via WASM/native, A19-SDK-2) OR, where separate implementations exist, by passing the identical normative test vectors (A24 13 vectors, `normalize_kw` vectors, envelope KATs) as a CI gate on every platform (A19-TEST-1). Sharing code is strongly preferred; separate implementations are a drift risk that MUST be continuously conformance-tested.

------

# 9. Best-Effort Zeroization & Plaintext Hygiene (client)

- **A19-ZERO-1**: On managed runtimes, the client MUST minimize plaintext lifetime: decrypt on open, drop references on view close, no long-lived decrypted-body caches (A03-READ-3). Where a platform offers zeroizable buffers (e.g. Rust core holding key material, or `SecureBytes`-style APIs), use them for keys; acknowledge that GC'd strings cannot be guaranteed wiped.
- **A19-ZERO-2** (no leaks): No plaintext to system clipboard beyond user-initiated copy, no plaintext in app logs, crash reports scrubbed, screen-privacy flag on mobile app-switcher (A03-SEC-2). Tokens memory-only, never persisted (A03-SEC-3).
- **A19-ZERO-3**: The SDK MUST document, per platform, exactly what zeroization guarantee it provides, so the weaker-than-server posture (A19-RT-1) is explicit rather than implied.

------

# 10. Testing & Conformance (Normative)

- **A19-TEST-1** (vector parity): Every platform build MUST pass the shared normative vectors as a CI gate: A24 canonicalization (13 vectors, byte-exact, punycode cases), `normalize_kw`, envelope decrypt KATs, conflict-resolution convergence. A platform that diverges on any vector does not ship.
- **A19-TEST-2**: Each A03/A04/A05/A08 "Test Scenarios (Normative)" section MUST have client integration tests: offline full-function, per-field conflict + tag union, purge-wins, new-device bootstrap awaiting-rewrap, idempotent no-double-send, hidden-content exclusion from render+index, webmail token-not-plaintext.
- **A19-TEST-3** (property tests): conflict-resolution convergence regardless of event order; canonicalization idempotence; "cache eviction never loses metadata".
- **A19-TEST-4** (negative tests): assert rejections — damaged blob not rendered (A03-READ-2), unverified manifest not rendered, raw HTML never rendered as fallback (A08-TXT-2), keys never in browser storage (A19-STORE-2).

------

# 11. Forbidden Patterns (client, review-blocking)

1. ❌ Duplicating protocol logic per platform instead of a shared core, risking drift (A19-SDK-3).
2. ❌ Re-implementing `diamy_addr_canon` / `normalize_kw` / HKDF differently from the server, breaking interop/search silently (A19-PAR-1).
3. ❌ Persisting keys or tokens in browser `localStorage`/`sessionStorage`/IndexedDB (A19-STORE-2, A05-BI-9).
4. ❌ Storing `k_cat` derived from password alone without a secure-store-bound factor (A03-KEY-2).
5. ❌ Building the local FTS index as an unencrypted separate file (A19-SRCH-1, A03-STO-4).
6. ❌ Sending plaintext content off-device for AI extraction, or the plaintext query to the server in webmail (A19-SRCH-1/2).
7. ❌ Rendering raw HTML instead of Tiptap, or as a conversion fallback (A19-REND-1, A08-TXT-2).
8. ❌ Rendering a message whose GCM tag or manifest signature failed to verify (A03-READ-2).
9. ❌ Indexing/AI-extracting hidden content because pruning ran after the text projection (A19-REND-3, A08-HID).
10. ❌ Using local wall-clock instead of server journal seq for ordering (A19-SYNC-4).
11. ❌ Double-send on crash from a missing idempotency key (A19-SYNC-2, A04-IDEM).
12. ❌ Whole-record LWW instead of per-field + tag union (A19-SYNC-3, A03-SYNC).
13. ❌ Deriving/uploading Blind-Index tokens when webmail is disabled (A19-SRCH-3, A05-BI-1).
14. ❌ Loading remote images bypassing the proxy, or rendering "view original" without all three sandbox layers (A19-REND-2/4).
15. ❌ Omitting the Tier 2 AppKey header set on a request, sending a Tier 1-shaped value in it, or persisting the AppKey in browser storage on the webmail build (A19-STORE-4, A04-TR-2).

------

# 12. Deferred Items

- Exact shared-core packaging per platform (WASM bundle size, UniFFI vs hand-written bridges) — an engineering choice; the invariant (share the drift-sensitive functions) is fixed, the packaging is deferred.
- PQC in secure elements once platforms support it (A03-KEY-1) — currently secure-store-blob + in-memory decapsulation.
- Push-notification wakeup envelope (APNs/FCM) carrying signal-only content (A04 deferred) — payload rule already fixed (signals only); the platform push integration is here-deferred.
- Client-side semantic/vector search (A05 deferred) — a local-only enhancement; SDK hook noted.
- `diamy-cald` client (calendar) execution — follows this contract; calendar specifics are A12–A15.

------

*End of document.*
