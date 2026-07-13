# Diamy Mail — ANNEX A18: Server Implementation Guide (Rust)

**Document title:** Diamy Mail — ANNEX A18: Server Implementation Guide (Rust)
**Version:** 1.2
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.3 (A00)
**Sibling dependencies:** A01, A02, A04, A10, A17, A21, A22 (all server-side annexes)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: server-side Rust implementation conventions — service topology, crate selection guidance, cryptographic library discipline, memory-zeroization patterns, error-handling and fail-closed idioms, async runtime and resource bounds, database access patterns, secret handling, structured logging without plaintext, testing requirements (test-vector conformance), build/CI security gates, forbidden patterns. Codifies the corpus's cross-cutting SEC/OPS rules into Rust practice. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: content verified against corpus SEC/OPS rules — no contradictions; confirmed the server-side strong zeroization (A18-ZERO) is consistent with (not contradicted by) the client-side best-effort zeroization of A03-READ-3 (different targets, both scoped correctly). Added §13.1 mapping the per-annex "Common AI Implementation Errors" watch-lists to this annex's forbidden-patterns checklist, making A18 the consolidated review gate. |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Coherence extension for the Tier 2 AppKey model (A17 v1.4 §4.2bis, A04 v1.3): added A18-ERR-5 requiring the AppKey-then-token-then-authorization order be implemented as one shared, type-enforced middleware layer rather than inline per-handler checks — recommends the type-state pattern (§9) so a missing/misordered check is a compile error. Added forbidden-pattern #14. |

------

# Table of contents

[toc]

------

# 1. Scope

This annex codifies **how the Diamy Mail server components are implemented in Rust** so that the normative rules scattered across the corpus (zeroization, fail-closed, HKDF discipline, no-plaintext-logging, resource bounds) become concrete, checkable implementation conventions. It is guidance for the implementer (Chahid via Claude Code) and a checklist for review, not new architecture.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Why Rust

The corpus's security posture (memory-safety-critical plaintext handling, zeroization, no buffer-class vulnerabilities) is well served by Rust, consistent with the existing Diamy stack (messaging, IAM, SIP Monitor all Rust). This annex assumes Rust for all server components: `diamy-mxd`, `diamy-maild`, `diamy-submitd`, `diamy-cald`, and the shared libraries.

## 1.2 Out of scope

Client SDK conventions (A19 — TS/mobile). Physical schema (A21). Specific business logic (each annex). Deployment/orchestration (ops).

------

# 2. Service Topology and Shared Crates

- **A18-TOP-1**: Each daemon (`diamy-mxd`, `diamy-maild`, `diamy-submitd`, `diamy-cald`) is a separate Rust binary/service (A00 §2), sharing common functionality through internal library crates, NOT by copy-paste. Mandatory shared crates:
  - `diamy-mail-crypto` — the envelope/AES-GCM/HKDF operations (A02), the ONE implementation of the cryptographic model; no component re-implements crypto (SEC-CRYPT, A17 "never reimplement").
  - `diamy-mail-model` — the data types mirroring A21 (messages, blobs, envelopes, trust_metadata), serialization, classification enums.
  - `diamy-mail-iam` — the IAM consumption client (A17): token verification, principal resolution, key-directory access.
  - `diamy-addr` — the `diamy_addr_canon()` normalization (A24), shared byte-for-byte with the client build target.
  - `diamy-obs` — structured logging, metrics, the A22 health indicators.
- **A18-TOP-2**: Cryptographic operations MUST live only in `diamy-mail-crypto` and reuse the existing Diamy messaging crypto primitives where they exist (ML-KEM-768, ML-DSA-65, HKDF) rather than introducing parallel implementations (A00 SEC-CRYPT-1, "reuse the audited messaging crypto").

------

# 3. Cryptographic Library Discipline

- **A18-CRY-1**: Use vetted, audited crates for primitives; do NOT hand-roll. RECOMMENDED baseline: `aws-lc-rs` or the RustCrypto suite for AES-256-GCM and HKDF-SHA256/512; the same ML-KEM-768 / ML-DSA-65 implementation already used by the Diamy messaging segment (FIPS 203/204). The exact crate is fixed at the shared-crate level (`diamy-mail-crypto`), pinned and version-audited.
- **A18-CRY-2** (HKDF discipline): Every HKDF call MUST pass an explicit, distinct `info` label (A02-CRY-4, SEC-CRYPT-4). Labels are defined as constants in `diamy-mail-crypto` (e.g. `INFO_ENVELOPE`, binding message_id + device_id per A02-CRY-4). A raw shared secret MUST NEVER be used directly as an AEAD/MAC key — always through HKDF with a label. This is enforced by making the low-level key material non-constructible-as-a-key outside the derivation functions (§9 type-state).
- **A18-CRY-3** (nonce discipline): Every AES-GCM nonce MUST come from a CSPRNG (`getrandom`/`rand_core::OsRng`), 96-bit, independent per encryption (A02-CRY-1b). Counter-derived nonces are FORBIDDEN. The encryption API in `diamy-mail-crypto` MUST generate the nonce internally and return it, so a caller cannot supply a reused nonce.
- **A18-CRY-4** (version dispatch): `alg_version` / `blob_alg_version` MUST be checked on every decrypt; unknown versions are rejected, never guessed (A02-CRY-7). Represent the suite as an enum; a `match` with no catch-all `_ => guess` — unknown variants return an error.

------

# 4. Memory Zeroization (Normative)

- **A18-ZERO-1**: All plaintext message material and key material MUST be wrapped in types that zeroize on drop, using the `zeroize` crate (`Zeroizing<T>` / `#[derive(ZeroizeOnDrop)]`). This covers: `k_msg`, derived `k_wrap`, the transient RFC 5322 plaintext at the frontier (`diamy-mxd`) and at emission (`diamy-submitd`), decrypted summaries built server-side (frontier), and `k_hold`. (A01-DESTROY, A10-EMIT, A00 SEC-FC-2.)
- **A18-ZERO-2**: Zeroization MUST be non-eliding: use `zeroize` (which uses volatile writes + compiler fences) so the optimizer cannot remove the wipe (A01-DESTROY-1 "non-eliding"). A manual `= 0` loop is FORBIDDEN (the compiler may elide it).
- **A18-ZERO-3**: Beware hidden copies: `String`/`Vec` reallocation, `format!`, logging, and serialization can copy plaintext to un-zeroized buffers. Plaintext types MUST NOT implement `Debug`/`Display` that prints content, MUST NOT be `Clone`d casually, and MUST NOT flow into `format!`/`log`. Prefer fixed-size buffers for keys (`[u8; 32]` in a `Zeroizing`) over heap types where feasible.
- **A18-ZERO-4** (no core dumps): Production builds MUST run with core dumps disabled (`RLIMIT_CORE = 0` set at startup) so a crash cannot spill plaintext (A01-DESTROY-2, A10-EMIT-1). The service MUST set this itself at boot, not rely solely on the OS config.
- **A18-ZERO-5**: On managed-swap systems, consider `mlock` for the pages holding key material where the platform permits, to reduce plaintext-to-swap risk. This is a SHOULD (best-effort, platform-dependent), documented per deployment.

------

# 5. Error Handling & Fail-Closed Idioms

- **A18-ERR-1**: Use `Result<T, E>` with typed errors (`thiserror`); the crypto/security paths MUST NOT `unwrap()`/`expect()`/panic on attacker-influenced input (a panic on malformed input is a DoS, A01-STAB). Panics are reserved for true invariant violations (bugs), and even those SHOULD be caught at the task boundary so one request cannot crash the process.
- **A18-ERR-2** (fail-closed): On any security-relevant error — decryption failure, signature-verification failure, auth failure, zeroization failure, missing key — the code MUST fail closed: reject/tempfail, never proceed with unverified data (A00 SEC-FC-1/3). The idiom is `?`-propagation to a boundary that returns a safe rejection, NOT a `.unwrap_or(default_that_proceeds)`.
- **A18-ERR-3**: GCM tag / signature verification MUST be checked before using decrypted bytes; the API MUST make it impossible to obtain the plaintext without the tag having verified (return `Result`, never expose an "unverified plaintext" accessor) (A02 failure model, A03-READ-2).
- **A18-ERR-4** (constant-time): Comparisons of secrets, MAC tags, and tokens MUST use constant-time comparison (`subtle::ConstantTimeEq`), never `==` on byte slices, to avoid timing oracles.
- **A18-ERR-5** (request-validation ordering is a middleware type, not ad-hoc checks): `diamy-maild`/`diamy-submitd` request handling MUST implement the AppKey-then-token-then-authorization order (A17-APPKEY-5, A04-TR-2) as a single, shared middleware/extractor layer — never as inline per-handler checks that could be reordered or skipped by a new endpoint. RECOMMENDED: model this with the type-state pattern (§9) — a handler function's signature accepts only a `ValidatedAppKey<ValidatedToken<Request>>`-shaped type that can only be constructed by passing through both checks in order, making "I forgot the AppKey check" or "I checked the token first" a compile error, not a runtime bug to catch in review.

------

# 6. Async Runtime & Resource Bounds

- **A18-ASYNC-1**: Use `tokio` as the async runtime (consistent with the Diamy stack). All network I/O (SMTP, WSS, HTTPS, DB) is async; blocking work (crypto on large blobs, AV invocation) MUST use `spawn_blocking` or a bounded worker pool so it does not stall the async executor.
- **A18-BOUND-1** (resource bounds — normative): Every externally-influenced input MUST be bounded (A01-STAB, A08-STAB analogue server-side): max message size, max MIME parts, max nesting depth, max attachment count/size, max header count/size, decompression-bomb guards on archives (A07-ARC-2), bounded parser allocation. Exceeding a bound is a clean rejection, never OOM/hang. Bounds are configured constants, not magic numbers scattered in code.
- **A18-BOUND-2**: Connection-level limits (max concurrent SMTP sessions, WSS connections per node, request body size) MUST be enforced at the edge, feeding the A22 saturation indicators. Backpressure (reject/slow) is preferred over unbounded queue growth.
- **A18-BOUND-3**: Per-request timeouts MUST bound every stage (parse, analysis, DB, emit) so a stuck dependency cannot pin resources indefinitely (A22 latency indicators). A timeout is a fail-closed tempfail, not a silent drop.

------

# 7. Database Access (PostgreSQL, per A21)

- **A18-DB-1**: Use `sqlx` (compile-time-checked queries) or an equivalent that validates SQL against the A21 schema at build time, catching drift between code and DDL early. Parameterized queries only — string-concatenated SQL is FORBIDDEN (injection).
- **A18-DB-2** (plane roles): Connect with the least-privilege DB role for the plane (A21-X-1): the data-plane services (`diamy-maild`) use a role without write access to `send`/`onboard`; control-plane admin paths use a separate role. Do NOT run everything as a superuser role.
- **A18-DB-3** (transactions): The inbound write path (blobs → catalogue + envelopes + journal) MUST be one transaction with blob writes preceding it and orphan-blob GC on failure (A02 §5.1 / A02-FAIL-2). Use explicit transactions; do not rely on autocommit for multi-row invariants.
- **A18-DB-4**: Respect the schema-level constraints as the last line of defense (A21-ONB-1 fail-closed gate, CHECK constraints); the application enforces them too, but MUST NOT assume it is the only enforcement. Handle constraint-violation errors as typed failures, not panics.
- **A18-DB-5** (ciphertext columns): `CIPHERTEXT`/`BLIND_INDEX` columns are `Vec<u8>`/`[u8;N]` in the model, NEVER deserialized as if the server could read them. No code path attempts to parse `summary_ct` server-side (it can't; no key). Blind-Index columns are compared by equality only (A21-IDX-2).

------

# 8. Secret Handling

- **A18-SEC-1**: Long-lived secrets (DKIM signing keys A10-AUTH-1, `k_hold`, service-to-service credentials A17-S2S-1) MUST come from the secret store (the `diamy-secretd`-derived pattern), loaded at use, held in `Zeroizing` buffers, never in config files, environment variables logged at startup, or source. 
- **A18-SEC-2**: The server holds NO ML-KEM private keys and NO `k_msg` at rest (A02) — it only handles `k_msg` transiently at the frontier/emission (in `Zeroizing`, zeroized after). Any code that would persist `k_msg` or a message-decryption key server-side is a model violation and MUST be rejected in review.
- **A18-SEC-3**: Tokens (mail-plane, service) live in memory for the request lifetime, verified per A17, never logged, never persisted (A17-TOK-3). Constant-time verification (A18-ERR-4).

------

# 9. Type-State for Security Invariants (recommended)

- **A18-TYPE-1**: Encode security invariants in the type system where practical, so violations are compile errors rather than runtime bugs. Examples:
  - A `VerifiedPlaintext` type obtainable ONLY from a successful GCM-verified decrypt, so no code can render/index un-verified bytes (A18-ERR-3).
  - A `DerivedKey` newtype obtainable ONLY from HKDF-with-label, so a raw shared secret cannot be passed where a key is expected (A18-CRY-2).
  - A `CanonicalAddress` newtype produced ONLY by `diamy_addr_canon()`, so no code compares/keys on a non-canonical address (A24, CDM-ADDR-3).
  - A `SendEnabled` capability token minted only when the onboarding gate is green (A11-GATE-1), required to call the emit path.
- **A18-TYPE-2**: This is a SHOULD (strong recommendation): type-state prevents whole classes of the corpus's "AI implementation errors" at compile time. Where a full type-state model is impractical, a documented invariant + test (§10) is the fallback.

------

# 10. Testing Requirements (Normative)

- **A18-TEST-1** (test-vector conformance): The shared crates MUST pass the corpus's normative test vectors: `diamy-addr` against the A24 13-vector suite (byte-exact, including the punycode cases); `diamy-mail-crypto` against known-answer tests for the envelope round-trip; `normalize_kw` (A05-BI-4) against its pinned vectors. These are CI gates, not optional.
- **A18-TEST-2**: Each annex's "Test Scenarios (Normative)" section MUST have corresponding integration tests. Security-invariant scenarios (fail-closed on bad tag, zeroization, no-double-emit idempotency, hidden-content exclusion at the frontier) are REQUIRED, not nice-to-have.
- **A18-TEST-3** (adversarial/fuzz): The parsers (SMTP, MIME, HTML-at-frontier for trust extraction) MUST be fuzzed (`cargo-fuzz`); they process hostile input (A01-STAB, A18-BOUND-1). A parser that hangs/panics/OOMs on a fuzz case is a release blocker.
- **A18-TEST-4**: Property tests (`proptest`) for invariants like "canonicalization is idempotent" (A24), "envelope decrypt only succeeds with the right device key", "per-field LWW converges regardless of event order" (A03-SYNC).
- **A18-TEST-5**: Negative tests are as important as positive: assert that malformed/adversarial inputs are REJECTED (not merely that valid inputs pass). Many corpus rules are "MUST NOT" — test the NOT.

------

# 11. Logging & Observability

- **A18-LOG-1** (no plaintext): Structured logging (`tracing`) MUST NEVER emit message content, subjects, body text, addresses beyond routing necessity, keys, or tokens (A01-DESTROY, A07-OBS-1, A22 discipline). Plaintext types (§4) do not implement content-printing `Debug`. Log IDs (message_id, principal_id) and metadata, never content.
- **A18-LOG-2**: Emit the A22 health indicators via `diamy-obs` (Prometheus). Security-invariant events (zeroization failure, plaintext-leak detection) MUST log at a level that pages (A22-ALERT-2) and MUST be counted.
- **A18-LOG-3**: Audit events (OBS-3: hard purges, key-directory publications, T1/T2/T3 attachment actions, allocation changes, send-enablement) go to a distinct audit sink with actor + before/after + timestamp, tamper-evident where feasible.
- **A18-LOG-4**: Scrub before any external error reporting; a panic/crash report MUST NOT carry plaintext (A18-ZERO-3, A18-ZERO-4).

------

# 12. Build & CI Security Gates

- **A18-CI-1**: `cargo audit` (advisory DB) and `cargo deny` (license + banned crates + duplicate versions) MUST run in CI; a known-vulnerable dependency blocks release.
- **A18-CI-2**: `#![forbid(unsafe_code)]` at the crate level wherever feasible; any `unsafe` block MUST be justified, minimal, reviewed, and documented (crypto FFI may require it — isolate it).
- **A18-CI-3**: `clippy` at deny-warnings; the test-vector, fuzz-smoke, and negative-test suites are required gates. `RLIMIT_CORE=0` and secret-store wiring are verified in the deployment smoke test.
- **A18-CI-4**: Reproducible, pinned dependencies (`Cargo.lock` committed); no wildcard versions on security-relevant crates.

------

# 13. Forbidden Patterns (review-blocking)

1. ❌ Re-implementing crypto outside `diamy-mail-crypto` / not reusing the audited messaging primitives (A18-TOP-2, SEC-CRYPT-1).
2. ❌ Using a raw shared secret as an AEAD/MAC key without HKDF+label (A18-CRY-2).
3. ❌ Counter-derived or caller-supplied reusable GCM nonces (A18-CRY-3).
4. ❌ Manual `= 0` wipes or plaintext/key types without `zeroize`; `Debug`/`Clone` on plaintext that prints/copies content (A18-ZERO-1/2/3).
5. ❌ `unwrap()`/`expect()`/panic on attacker-influenced input in the request path (A18-ERR-1).
6. ❌ Proceeding after a failed GCM tag / signature / auth check instead of failing closed (A18-ERR-2/3).
7. ❌ `==` on secrets/tokens/tags instead of constant-time comparison (A18-ERR-4).
8. ❌ Unbounded parsing/allocation on external input (no size/depth/count/timeout bounds) (A18-BOUND-1).
9. ❌ String-concatenated SQL or a superuser DB role for all planes (A18-DB-1/2).
10. ❌ Persisting `k_msg` / a message-decryption key server-side (A18-SEC-2) — model violation.
11. ❌ Logging content/subjects/addresses/keys/tokens; unscrubbed crash reports (A18-LOG-1/4).
12. ❌ Missing core-dump disable (`RLIMIT_CORE=0`) in production (A18-ZERO-4).
13. ❌ Skipping test-vector conformance / fuzz / negative tests as "later" (A18-TEST-1/3/5) — they are release gates.
14. ❌ Inline, per-handler AppKey/token checks that can be reordered, skipped, or partially applied on a new endpoint instead of one shared, type-enforced validation middleware (A18-ERR-5, A17-APPKEY-5).

## 13.1 Relationship to the per-annex watch-lists

- **A18-FORBID-1**: Each annex's "Common AI Implementation Errors" section lists domain-specific mistakes; this §13 is the **consolidated, cross-cutting** forbidden-patterns list at the Rust level. In review, the two are complementary: the annex list catches "did you get *this feature's* logic right?", A18 §13 catches "did you follow the *security/implementation discipline* everywhere?". A change is review-ready only when it clears both its annex watch-list and this list. This makes A18 the single implementation-review gate that Chahid (and Claude Code) checks against, regardless of which annex a change touches.

------

# 14. Deferred Items

- Specific crate version pins and the audited crypto crate selection — fixed in `diamy-mail-crypto`'s Cargo manifest; this annex sets the discipline, the manifest sets the versions.
- FIPS-validated build variant (aws-lc-rs FIPS mode) for tenants requiring FIPS 140-3 — a build-configuration option; deferred with the compliance track.
- Performance-tuning specifics (connection pool sizes, worker counts) — calibrated on load (A22), not fixed here.
- `diamy-cald` (calendar) specifics — its server conventions follow this annex; calendar-specific concerns are A12–A15.

------

*End of document.*
