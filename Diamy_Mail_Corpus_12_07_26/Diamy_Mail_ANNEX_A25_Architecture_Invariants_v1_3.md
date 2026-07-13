# Diamy Mail — ANNEX A25: Architecture Invariants & Implementation Constitution

**Document title:** Diamy Mail — ANNEX A25: Architecture Invariants & Implementation Constitution
**Version:** 1.3
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.5 (A00)
**Applies to:** every Diamy Mail annex (A00–A24) and every implementation of them

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: the root invariants and implementation constitution — the small set of rules that hold across the entire corpus, each with its owning annex, plus reading/precedence rules and the anti-pattern list. Consolidates cross-cutting invariants previously distributed across A00 and repeated in annexes, so they are stated once and referenced, not restated. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: fixed an internal contradiction between INV-1 and INV-3 — INV-1's absolute "server never holds a decryption key at rest" collided with the declared hold-queue `k_hold` exception that INV-3 itself lists. Reworded INV-1 to "the server cannot decrypt *synced mailbox* content at rest; the one declared exception is the gateway hold queue (k_hold), per INV-3" so the two invariants agree. (An invariants document contradicting itself is the exact failure this document exists to prevent.) Registered A25 in A00's corpus plan and reading order (A00 v1.6). |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Added §2.7 and INV-24 closing the pending A25 dependency flagged by A27 v1.1 §9: **scope is crypto-enforced, role is policy-enforced, and this boundary must always be stated, not implied** — consolidates the honest disclosure pattern first established for A27's shared-mailbox roles (A27-SEC-1/2/3) as a corpus-wide invariant every future annex introducing a role/tier must address explicitly. Added matching anti-pattern #21 (renumbering the meta-error to #22); verified no other section references anti-pattern list positions by number, so no stale cross-references were introduced. |
| 1.3     | Jul 4th 2026 | Cédric BORNECQUE | Coherence extension for the Tier 2 AppKey model discovered on review of the Diamy IAM – Integration Specification v1.6: added §2.8/INV-25 (every client request carries two independent credentials — AppKey for the application, mail-plane token for the user — validated in a fixed order by one shared middleware). Appended rather than inserted mid-sequence, preserving existing INV-1..24 cross-references (e.g. A27 §8 cites INV-24 by number). Softened INV-11's "epoch bump" language, which is no longer asserted as confirmed fact pending A17-TOK-2's flagged mechanism discrepancy; added a new HIGH deferred item consolidating this open question across the four annexes (A04/A17/A20/A25) where the assumption was previously stated. Added anti-pattern #22 (Tier 1/Tier 2 conflation), renumbering the meta-error to #23. |

------

# Table of contents

[toc]

------

# 1. Purpose and Status

This is the **root document** of the Diamy Mail corpus. It is meant to be read **first**, before any feature annex, and consulted whenever an implementation decision is ambiguous. It states two things:

1. the **architecture invariants** — the small set of properties that MUST hold everywhere, distilled from rules distributed across A00 and the annexes; and
2. the **implementation constitution** — the short, ordered rules an implementer (human or AI) follows when the specification does not spell out a case.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

- **A25-STATUS-1** (precedence): This document does not override the normative rules of the annexes; it **summarizes and points to** them. Where this document and a feature annex both speak, the **feature annex's specific rule governs the detail** and this document governs the **invariant** it must not violate. Where any two documents genuinely conflict, **A00 wins** (A25-READ-3). This document exists to prevent conflicts, not to create a new authority above A00.
- **A25-STATUS-2** (no duplication): Each invariant below has exactly **one owning annex** where its detail lives. This document restates the invariant in one line and cites the owner. An implementer needing the detail goes to the owner; an implementer needing to know *the rule exists* reads it here. Business rules and normative detail MUST NOT be duplicated across annexes (A25-CONST-1); this document is the index of invariants, not a second copy of them.

------

# 2. The Architecture Invariants (Normative)

Each invariant holds across the **entire** corpus. Violating one is a corpus-level defect, not a local one. The owner column is where the full rule and its edge cases live.

## 2.1 Confidentiality & zero-access

| # | Invariant | Owner |
| - | --------- | ----- |
| INV-1 | **The server cannot decrypt synced mailbox content at rest.** It holds no `k_msg`/`k_event` and no ML-KEM private key for stored mail; it stores ciphertext + per-device wrapped envelopes it cannot open. The **one declared exception** is the gateway hold queue (`k_hold`, INV-3) for zero-active-device recipients — a bounded, disclosed, transient store, deleted on first device enrollment. | A02, A01-HOLD, A17 |
| INV-2 | **Content is CIPHERTEXT; only declared routing/scheduling fields are metadata.** Every stored field is classified `PLAINTEXT_METADATA` / `BLIND_INDEX` / `CIPHERTEXT`; reclassification needs a migration entry. | A21 (§CDM-ENC), A02 |
| INV-3 | **Plaintext exists only inside declared, bounded exceptions**, each disclosed to tenants and never silently widened: the inbound frontier (A01), the gateway hold queue (A01-HOLD), T3 attachment sandbox (A07, client-initiated), the outbound emission window (A10), webmail key material (A05), external-invitee iMIP (A14), the free/busy projection (A15, consented metadata), and the local Bridge (A20, loopback). Nothing outside this list exposes plaintext. | A00 §3.2, each listed annex |
| INV-4 | **Private keys never leave the OS secure store** (native) / never leave in-session memory (webmail, disclosed weaker posture); all key material is zeroized after use (best-effort on managed runtimes). | A03, A19, A18 |

## 2.2 Cryptographic discipline

| # | Invariant | Owner |
| - | --------- | ----- |
| INV-5 | **Crypto is never re-implemented.** All cryptographic operations reuse the audited Diamy messaging/IAM primitives (ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF) via the one shared crypto crate; no parallel KEM, no hand-rolled primitive. | A18 (`diamy-mail-crypto`), A02, A17 |
| INV-6 | **Every derived key comes from HKDF with an explicit, distinct `info` label**; a raw shared secret is never used directly as an AEAD/MAC key. | A02 (§CDM/§CRY), A18 |
| INV-7 | **Every AEAD nonce is CSPRNG-generated and independent per encryption**; counter-derived or reused nonces are forbidden. Every decrypt checks `alg_version` and rejects unknown versions. | A02, A18 |
| INV-8 | **Nothing is served/rendered/indexed from unverified plaintext**: GCM tag and (for Diamy↔Diamy) manifest signature MUST verify before the bytes are used. | A02, A03, A18 |

## 2.3 Identity & authorization

| # | Invariant | Owner |
| - | --------- | ----- |
| INV-9 | **Authentication and identity are never re-implemented; Diamy IAM is the single authority.** Mail resolves users via IAM by normalized address; it keeps no parallel user registry that could diverge. | A17, A24 |
| INV-10 | **Addresses are canonicalized by the one shared function** (`diamy_addr_canon`, byte-identical server and client) before any lookup, hashing, Blind-Index, or comparison. | A24 |
| INV-11 | **Every device (including the Bridge) is an enrolled IAM device** with its own keys, subject to key-directory publication, re-wrap, and independent revocation. Session revocation stops sessions within a bound target (mechanism confirmation pending, A17-TOK-2). | A17, A20 |

## 2.4 Data plane behavior

| # | Invariant | Owner |
| - | --------- | ----- |
| INV-12 | **The server never pushes content; notifications are signals only.** The client pulls what it decides to fetch (journal-cursor model, not IMAP). | A04 |
| INV-13 | **Every mutating operation is idempotent** (client-supplied idempotency key); a retry never double-applies or double-emits. | A04, A10 |
| INV-14 | **Ordering authority is the server journal sequence, never a local clock.** Conflict resolution is per-field LWW by that sequence, tag-set union, purge-wins. | A03, A04 |
| INV-15 | **Every list/scan is bounded and cursor-paginated**; unbounded scans and OFFSET pagination are forbidden. Every externally-influenced input is size/depth/count/time bounded. | A04, A18 |

## 2.5 Safety posture

| # | Invariant | Owner |
| - | --------- | ----- |
| INV-16 | **Fail closed on any security-relevant error** (decrypt/verify/auth/key/allocation failure): reject, tempfail, or queue — never proceed with unverified data, never emit via an unassigned resource, never render raw on conversion failure. | A00 (SEC-FC), A01, A10, A23 |
| INV-17 | **Rendering is Tiptap closed-schema by default; raw HTML only in the isolated sandbox** (A09), never blended, never as a fallback. Hidden source content never reaches render, index, or the AI extractor. | A08, A09, A05 |
| INV-18 | **Trust and classification are visible aids, never silent gates**, and are orthogonal ("marketing" ≠ "safe"); a class never suppresses a trust warning, a trust pass never skips scrutiny. | A06, A07, A16 |
| INV-19 | **Whitelist-first for attachments and closed-schema for content**: unknown = untrusted; a novel type or an unrepresentable element is excluded/tiered, not passed through. | A07, A08 |

## 2.6 Operability & governance

| # | Invariant | Owner |
| - | --------- | ----- |
| INV-20 | **Every privileged/irreversible action is audit-logged** (actor, before/after, timestamp): hard purges, key-directory publications, attachment-access bypasses, allocation changes, send-enablement, Bridge/webmail/free-busy/external-calendar enablement. | A00 §11 (OBS-3), each annex |
| INV-21 | **Telemetry never contains content**: no message/event bodies, subjects, addresses beyond routing, keys, tokens, URLs, filenames, busy intervals, or the correspondent graph. Counts, IDs, and metadata only. | A00 §11, each observability §|
| INV-22 | **Control plane and data plane are separated**: control-plane admin APIs are SED-gated Super-Admin (A17-SED); the data plane uses mail-plane tokens; DB roles enforce the split. | A17, A21, A23 |
| INV-23 | **Every declared exception is disclosed and tenant-governable**: the tenant can restrict or disable each plaintext-widening capability (webmail, external calendar, Bridge) org-wide. | A05, A14, A20 |

## 2.7 Shared & multi-principal access

| # | Invariant | Owner |
| - | --------- | ----- |
| INV-24 | **Scope is crypto-enforced; role is policy-enforced — and this boundary is always stated, never implied.** Whether a principal can decrypt a resource at all (scope: which key-wrapping set a device is enrolled in — e.g. a calendar delegate never enrolled into mail envelopes) is a structural, crypto-level guarantee. Whether an already-decrypting principal may also write/send/administer (role: viewer vs contributor vs admin) is enforced by the server refusing the authorized-write API call, NOT by withholding key material — since reading and writing typically require the same decryption capability. Every annex introducing a role or tier MUST say explicitly which of the two enforcement mechanisms applies to each boundary it defines. | A27 (§8), A17 |

## 2.8 Client & application authentication

| # | Invariant | Owner |
| - | --------- | ----- |
| INV-25 | **Every client request carries two independent credentials that authenticate two different things, and neither substitutes for the other.** The Tier 2 Diamy Mail AppKey (local lookup, no IAM call) authenticates *which client application* is calling; the mail-plane token (IAM-issued) authenticates *which user*. They are validated in a fixed order (AppKey before token, before authorization) by one shared middleware, never inline per-endpoint checks. This is architecturally distinct from — and MUST NOT be conflated with — the separate Tier 1 IAM AppKey that Diamy Mail's own backend uses when *it* calls *into* IAM; a client never sees or sends a Tier 1 credential. | A17 (§4.2bis), A04, A18 |

------

# 3. Implementation Constitution (Normative, ordered)

These are the rules an implementer — human or AI — follows, especially when the specification does not spell out a specific case. They are ordered: earlier rules win.

1. **When two documents conflict, A00 wins.** Then: the feature annex owns its detail; A25 owns the invariant it must not break (A25-READ-3).
2. **Never implement behavior that is not specified.** If a case is not covered, do NOT invent it: stop and flag it as a specification gap (a Deferred-Items or Open-Decision candidate), rather than guessing. An invented behavior is how an unspecified case becomes a bug. (This is the single most important rule for AI implementation.)
3. **Never duplicate a business rule.** Each rule has one owning annex (A25-STATUS-2); reference it, do not re-encode it. Two copies drift.
4. **Never violate an INV-* invariant to satisfy a feature request.** If a feature seems to require breaking an invariant (e.g. server-side decryption for convenience), the feature design is wrong — escalate, do not break the invariant.
5. **Never re-implement crypto, identity, or address normalization** (INV-5, INV-9, INV-10). Reuse the shared crate/IAM/`diamy_addr_canon`. A second implementation is a drift and a vulnerability.
6. **Fail closed** (INV-16). When unsure whether to proceed on a security-relevant error, do not proceed.
7. **Make plaintext lifetime minimal and never persist it** outside a declared exception (INV-3); zeroize keys and plaintext after use.
8. **Every write is audited; no telemetry carries content** (INV-20, INV-21).
9. **Encode invariants in the type system where practical** (A18-TYPE): a `VerifiedPlaintext`, a `DerivedKey`, a `CanonicalAddress`, a `SendEnabled` capability turn an invariant into a compile error rather than a runtime bug.
10. **Clear the annex watch-list AND the A18/A19 forbidden-patterns list** before a change is review-ready (A18-FORBID-1). The annex list checks "is this feature's logic right?"; the forbidden-patterns list checks "was the discipline followed everywhere?".

------

# 4. Reading & Precedence Rules

- **A25-READ-1** (reading order for an implementer): read **A25 (this) → A00 (master) → the feature annex(es) for the task → A18/A19 (implementation discipline) → A21/A22 (schema/health) as needed**. A25 and A00 set the frame; the feature annex sets the task; A18/A19 set how to build it; A21/A22 set the physical/operational reality.
- **A25-READ-2** (one owner per invariant): the owner column in §2 is authoritative for detail. If a reader finds an invariant's detail in a non-owner annex, that is a duplication defect to fix (fold it into the owner, reference from elsewhere).
- **A25-READ-3** (conflict precedence): **A00 > feature annex > A25 as authority; A25 > silence.** That is: A00 wins genuine conflicts; a feature annex owns its specifics; A25 is the invariant floor no annex may drop below; and where the corpus is silent, the Constitution §3 rule 2 applies (do not invent — flag the gap).
- **A25-READ-4** (this document stays thin): A25 MUST remain a short index + constitution. It MUST NOT accumulate feature detail (that belongs in owners) or grow into a second master. If it starts restating annex bodies, that is a regression to fix.

------

# 5. Anti-Patterns (the corpus-wide "never" list)

Consolidated from the per-annex "Common AI Implementation Errors" watch-lists — the mistakes that recur across domains. Each maps to an invariant.

1. ❌ Giving the server the ability to decrypt synced mailbox content (INV-1) — the model-ending error. (The hold queue's `k_hold` is the one declared, bounded exception, INV-3; anything beyond it is the error.)
2. ❌ Storing content as server-readable metadata instead of CIPHERTEXT (INV-2).
3. ❌ Widening a plaintext exception beyond its declared bound, or adding an undisclosed one (INV-3, INV-23).
4. ❌ Re-implementing crypto / a parallel KEM / hand-rolled primitives (INV-5).
5. ❌ Raw secret as a key, or reused/counter nonces (INV-6, INV-7).
6. ❌ Serving/rendering/indexing unverified plaintext (INV-8).
7. ❌ A parallel user registry or bypassing IAM for auth (INV-9).
8. ❌ Comparing/hashing/indexing a non-canonicalized address (INV-10).
9. ❌ A device (incl. Bridge) that is not an enrolled, revocable IAM device (INV-11).
10. ❌ Pushing content in notifications instead of signals-only pull (INV-12).
11. ❌ Non-idempotent mutations / double-emit on retry (INV-13).
12. ❌ Local-clock ordering / whole-record LWW instead of journal-sequence per-field (INV-14).
13. ❌ Unbounded scans, OFFSET pagination, unbounded input parsing (INV-15).
14. ❌ Proceeding on a security error instead of failing closed (INV-16).
15. ❌ Raw HTML render / blended views / hidden content reaching render-index-AI (INV-17).
16. ❌ Class suppressing a trust warning, or a trust pass skipping scrutiny (INV-18).
17. ❌ Blocklist instead of whitelist / passing through an unrepresentable element (INV-19).
18. ❌ A privileged action without an audit record (INV-20).
19. ❌ Content in telemetry/logs (INV-21).
20. ❌ Control-plane reachable on the data plane, or a shared over-privileged DB role (INV-22).
21. ❌ Inferring write/send/admin authorization from the mere possession of decrypt keys, or conversely encoding a role restriction in key material where scope is what's actually at stake (INV-24) — conflates crypto-enforcement with policy-enforcement, and an annex that doesn't say which applies to a given boundary has left a gap Constitution rule 2 says to flag, not guess.
22. ❌ Conflating the Tier 2 Diamy Mail AppKey with the Tier 1 IAM AppKey, skipping the AppKey check, or checking it after the mail-plane token instead of before (INV-25).
23. ❌ **Implementing an unspecified case by invention instead of flagging the gap** (Constitution rule 2) — the meta-error that produces the others.

------

# 6. Deferred Items

- Diagrams: a companion set of architecture and sequence diagrams (per the external review) would help a **human** auditor navigate the corpus; lower priority while the primary reader is an AI implementing from text, but valued for onboarding and for IP/prior-art documentation. Deferred as a documentation task, not a normative one.
- Automated cross-annex consistency tooling: a linter that verifies no annex contradicts an INV-* invariant, that every cross-reference resolves, and that no business rule is duplicated. A25 §2 is the machine-checkable invariant list such a tool would enforce; building it is an engineering task deferred to the implementation phase.
- A generated API/contract/schema surface derived from the annexes (single-source-of-truth codegen) — the corpus is written to make this feasible (typed models A21, contracts A04/A17, forbidden-patterns A18/A19); the generator is deferred.
- **[HIGH, open]** Revocation-mechanism confirmation: INV-11's "session revocation stops sessions within a bound target" no longer asserts an epoch-counter mechanism as confirmed fact, per A17-TOK-2's flagged discrepancy against the reviewed Diamy IAM – Integration Specification v1.6. Every annex that previously stated "epoch bump" as settled fact (A04, A17, A20) has been softened to reference this open item rather than restate the assumption. Resolving it (against *Auth and Session Model* / *Security Hardening & Runtime Model*) is release-blocking for any claim of sub-15-second revocation propagation.

------

*End of document.*
