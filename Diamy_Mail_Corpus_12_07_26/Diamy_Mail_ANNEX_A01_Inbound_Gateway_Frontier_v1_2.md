# Diamy Mail — ANNEX A01: Inbound Gateway & Frontier Encryption

**Document title:** Diamy Mail — ANNEX A01: Inbound Gateway & Frontier Encryption
**Version:** 1.2
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)
**Sibling dependencies:** A02 (Storage & Envelope Model v1.1), A17 (IAM Integration Contract v1.1), A24 (Identity & Address Normalization v1.1), A27 (Shared Resources v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: `diamy-mxd` SMTP reception pipeline, TLS posture, pipeline ordering (reception → parse → auth checks → AV/CDR → trust hooks → frontier encryption → envelope → plaintext destruction), SMTPUTF8/EAI receive handling, SPF/DKIM/DMARC/ARC evaluation, antivirus/CDR hook contract, frontier crypto binding to A02, gateway hold queue for zero-device recipients (closes A17-DIR-5), plaintext-destruction guarantees, malformed-input stability, failure model, observability, test scenarios, common AI errors |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: resolved CDR/trust ordering ambiguity — A07 MUST score the ORIGINAL attachment risk, not the disarmed artifact (a file that needed CDR is itself a signal), added A01-AV-6; added intra-tenant-domain DMARC-fail as a high-severity signal even when not hard-rejected (A01-AUTH-5 — exact-domain spoofing of one's own execs is the dangerous case); clarified A01-HOLD-5 wording (frontier zone, key-only transit); added AI error #13 |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Coherence extension for A27 (Shared Resources): added pipeline step 0 (§4bis, GROUP EXPAND) — the gateway resolves a group RCPT-TO recipient to its member list via the IAM directory, then processes each member fully independently through steps 6–10 (own canonicalization, own device resolution, own encryption, own envelopes — no shared encryption state, A01-GRP-2). AUTH/AV/TRUST (steps 3–5) run once on the shared pre-encryption plaintext, not per expanded member (A01-PIPE-4). Added a bounded depth/cycle guard for nested groups (A01-GRP-4), group-expansion observability counters, three test scenarios, and five common-error entries. This closes the A01 dependency flagged pending by A27 v1.1 §9. |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies `diamy-mxd`, the inbound mail gateway: how Internet mail is received over SMTP, security-checked, trust-analyzed, encrypted at the frontier (A00 §3.1 zone 2), wrapped per device (A02), and how the transient plaintext is destroyed. It also specifies the **gateway hold queue** that resolves the zero-active-device recipient case fixed as a requirement in A17-DIR-5.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

Inherited invariants (owned elsewhere, restated for locality): the frontier zone is a declared bounded exception (A00 §3.2); frontier encryption uses the A02 cryptographic model; recipient resolution uses A17-RES + A24; trust verdicts are metadata (CMP-BND-1/2). Trust scoring algorithms themselves are A06 (origin) and A07 (links/attachments); this annex defines only where they hook into the pipeline.

## 1.1 Out of scope

Trust scoring logic (A06/A07). HTML→Tiptap conversion (A08, client-side). Outbound submission (A10). Domain onboarding / DNS provisioning (A11). Storage internals (A02).

------

# 2. Component Model

- **A01-CMP-1**: `diamy-mxd` is a standalone OS service (A00 §4.1), the only component that terminates inbound Internet SMTP. It MUST run with the minimum privileges required to bind its listener and MUST NOT share process memory with `diamy-maild`, `diamy-submitd`, or `diamy-cald`.
- **A01-CMP-2**: `diamy-mxd` holds NO ML-KEM private keys and NO user private keys. It reads the mail device-key directory (A17-DIR-2) to obtain recipient **public** bundles for envelope production. Service-to-service reads use the IAM internal service-auth mechanism (A17-S2S-1).
- **A01-CMP-3**: The transient plaintext of an inbound message MUST live only in `diamy-mxd` process memory, for the duration of one message's pipeline, and MUST be zeroized before the pipeline returns (A01-DESTROY, §8).

------

# 3. SMTP Reception

## 3.1 Transport

- **A01-SMTP-1**: `diamy-mxd` MUST accept SMTP over TLS. STARTTLS MUST be offered; implicit TLS MAY be offered. The minimum accepted TLS version is 1.2; 1.3 is RECOMMENDED. The TLS version and cipher of each session MUST be recorded in delivery metadata for the trust engine (A06 transport-security signal).
- **A01-SMTP-2**: `diamy-mxd` MUST advertise and accept **SMTPUTF8** (RFC 6531) and 8BITMIME. Non-ASCII addresses in MAIL FROM / RCPT TO / headers MUST be accepted without rejection or mojibake, `raw` bytes preserved (A24-EAI-1). This is the receive-side of the EAI posture (CDM-I18N-4).
- **A01-SMTP-3**: Standard envelope limits MUST be enforced and returned with correct SMTP codes: max message size (A02-QOS-2) → `552`; too many recipients → `452`; unknown/unentitled recipient → `550` (A17-ENT-1); temporary inability to resolve/encrypt → `4xx` tempfail (never `5xx`, never silent accept).

## 3.2 Anti-abuse at connection time

- **A01-SMTP-4**: Connection-level controls MUST be applied before DATA: IP reputation / rate limiting per source, greylisting MAY be applied. These are anti-abuse (OPS-RL-1), distinct from trust scoring (which runs post-DATA on content). Greylisting, if enabled, MUST use a stable tuple and MUST NOT interact with the hold queue (§7).
- **A01-SMTP-5**: `diamy-mxd` MUST NOT use the connecting IP as an authentication factor, but MUST record it as a trust/audit attribute (consistent with the IAM auth baseline principle).

------

# 4. Pipeline Ordering (Normative)

The pipeline MUST execute in this exact order for each accepted message. Reordering changes security properties.

```
0  GROUP EXPAND   for each envelope-to recipient: if it resolves to a
                  distribution group (A27-GRP-1) in the IAM directory,
                  replace it with its current member list (§4bis);
                  a non-group recipient passes through unchanged
1  RECEIVE        SMTP DATA fully received into RAM (bounded size)
2  PARSE          MIME/RFC 5322 parse; charset recovery (CDM-I18N-2);
                  header decode (RFC 2047/2231). Malformed → §9 stability
3  AUTH CHECKS    SPF, DKIM, DMARC(+alignment), ARC evaluation (§5)
                  → results become PLAINTEXT_METADATA verdicts
4  AV / CDR       antivirus scan + optional CDR on attachments (§6)
                  on the transient plaintext, before any encryption
5  TRUST HOOKS    A06 origin scoring (headers/IP/ASN — metadata)
                  A07 link/attachment analysis (needs body — runs HERE,
                  in the transient-plaintext window, CMP-BND-2)
6  RESOLVE        per recipient (post-expansion): A24 canonicalize → A17
                  resolve principal → entitlement check → active device
                  bundles (A17-DIR-2)
7  ENCRYPT        generate k_msg; encrypt body/attachment/summary blobs
                  (A02-CRY-1..3)
8  ENVELOPE       one envelope per active device (A02-CRY-4)
                  zero active devices → HOLD QUEUE (§7)
9  PERSIST        blobs → object store; catalogue+envelopes+journal in
                  one transaction (A02 §5.1)
10 DESTROY        zeroize k_msg and all plaintext buffers (§8)
11 ACK            SMTP 250 only after 9 commits (and 10 for that message)
```

- **A01-PIPE-1**: SMTP `250` (accept) MUST NOT be returned until step 9 has durably committed (or the message is durably in the hold queue, §7). Acknowledging earlier risks acknowledged-but-lost mail. If steps 2–9 fail, the message is tempfailed (`4xx`) unless the failure is a permanent per-recipient condition (`550`).
- **A01-PIPE-2**: AV/CDR (step 4) and A07 content trust analysis (step 5) MUST run **before** frontier encryption (step 7), because they require plaintext and MUST NOT trigger any later server-side decryption. Their verdicts are stored as metadata; the content they inspected is destroyed at step 10 (CMP-BND-2).
- **A01-PIPE-3**: Per-recipient failures MUST be isolated: one unresolvable/over-quota recipient among several MUST NOT fail the message for the valid recipients (A24 §3.4 per-address rule). The failed recipient receives the appropriate SMTP response or DSN; valid recipients are delivered.
- **A01-PIPE-4**: Group expansion (step 0) runs once per message, **before** AUTH/AV/TRUST (steps 3–5), which then run identically regardless of how many recipients resulted from expansion — a group message is not treated as more or less trustworthy than a directly-addressed one. Content inspected once at steps 4–5 is reused for every expanded recipient's per-recipient encryption at steps 6–8 (the plaintext is one shared transient buffer until step 10 destroys it — expansion does not mean re-receiving or re-scanning the message N times).

------

# 4bis. Distribution Group Expansion (implements A27-GRP-3)

- **A01-GRP-1** (directory resolution): For each envelope-to (RCPT TO) address, the gateway MUST check, via the IAM directory (A24-canonicalized lookup), whether it resolves to a **distribution group** (A27-GRP-1) rather than a mailbox principal. This resolution is deterministic — the directory holds exactly one entry per canonical address, typed as either a mailbox principal or a group, never both — so there is no ambiguity to arbitrate. A group has no mailbox of its own (A27-GRP-1) — it never reaches steps 6–8 as itself; it is replaced by its member list before RESOLVE.
- **A01-GRP-2** (per-member independence): Each expanded member is processed through steps 6–10 **independently**, exactly as if the external sender had addressed that member directly: their own A24 canonicalization, their own A17 entitlement/device resolution, their own `k_msg`/envelope generation, their own hold-queue fallback if they have zero active devices (§7). There is **no shared encryption state** across expanded members (A27-GRP-1) — expansion produces N independent single-recipient deliveries sharing only the already-inspected plaintext (A01-PIPE-4), not any cryptographic material.
- **A01-GRP-3** (visible addressing): The stored/delivered message's To: header MAY retain the original group address (so each member's client shows "To: dev-team@...", matching normal distribution-list expectance) while the actual per-member envelope routing uses the resolved member address internally — the same visible-header-vs-actual-routing separation already used for recipient-set minimization (A02-DM-4).
- **A01-GRP-4** (nested/failure cases): A group resolving to zero current members is not an error (A27 failure model) — the message is accepted and simply reaches no one; this MUST be distinguishable in gateway metrics (§11) from a delivery failure. Nested groups (a group containing another group) MAY be supported by recursive expansion with a bounded depth (fail-closed cycle/depth guard, consistent with A01-STAB's bounded-processing discipline) — a cycle or excessive depth MUST reject cleanly rather than loop or exhaust resources.
- **A01-GRP-5** (no trust bypass): Expansion MUST NOT skip or weaken AUTH/AV/TRUST checks (A01-PIPE-4) — a message to a group is authenticated and scanned exactly as any other inbound mail before it is ever expanded into per-member deliveries.

------

# 5. Authentication Checks (SPF / DKIM / DMARC / ARC)

- **A01-AUTH-1**: `diamy-mxd` MUST evaluate SPF (RFC 7208), DKIM (RFC 6376), DMARC (RFC 7489) including **identifier alignment**, and MUST process ARC (RFC 8617) chains when present. Each result (`pass`/`fail`/`neutral`/`none`/`temperror`/`permerror`) plus DMARC policy and alignment mode MUST be stored as `PLAINTEXT_METADATA` on the message (consumed by A06).
- **A01-AUTH-2**: Domain comparisons for alignment MUST use the A24 canonical domain (A-label, lowercased). Divergent domain normalization between SPF/DKIM/DMARC checks and the stored sender canonical would produce inconsistent alignment verdicts (A24 rationale).
- **A01-AUTH-3**: `diamy-mxd` MUST NOT reject a message solely on a DMARC `fail` at the gateway by default; the verdict feeds the trust score (A06) and tenant-configurable policy (A07/A16 quarantine decisions) rather than a hard SMTP reject, UNLESS the tenant explicitly opts into reject-on-DMARC-fail. Rationale: hard-reject at the gateway removes the user's ability to ever see a legitimately-misconfigured-but-wanted message; the trust model prefers visible warnings over silent loss. (Exception: outbound onboarding fail-closed, SEC-OUT-2, is a different path in A11.)
- **A01-AUTH-4**: ARC evaluation matters for forwarded/mailing-list mail where SPF/DKIM legitimately break; a valid ARC chain from a trusted forwarder SHOULD mitigate the trust penalty of a broken SPF (A06 defines the weighting). This annex only guarantees ARC is parsed and its verdict recorded.
- **A01-AUTH-5** (self-domain spoofing): A DMARC `fail` where the claimed From domain **is one of the recipient tenant's own domains** (an inbound message purporting to come from `someone@mytenant.fr` but failing DMARC) is categorically more dangerous than a generic external DMARC fail — it is the exact-domain executive-impersonation vector. Even under the default no-hard-reject posture (A01-AUTH-3), `diamy-mxd` MUST flag this case distinctly in trust metadata (`dmarc_fail_self_domain: true`) so A06 can treat it as a high-severity signal and A16/client can surface a prominent warning. Tenants SHOULD be offered a stricter default (quarantine or reject) specifically for self-domain DMARC failures, separate from the general DMARC policy.

------

# 6. Antivirus / CDR Hook Contract

- **A01-AV-1**: Every inbound message with attachments MUST be scanned by an antivirus engine (e.g. ClamAV) on the transient plaintext at step 4, before encryption. The verdict (`clean`/`infected:<signature>`/`unscannable`) per attachment MUST be stored as metadata.
- **A01-AV-2**: An `infected` verdict MUST quarantine the attachment per tenant policy (A07): the attachment blob MAY be withheld (not delivered), replaced by a stub referencing the verdict, or delivered blocked-by-default — never delivered as a clean attachment. The message body MAY still be delivered. All quarantine actions are audit-logged (OBS-3).
- **A01-AV-3**: `unscannable` attachments (e.g. password-protected archives that cannot be opened, A00 SEC-ATT-2) MUST be treated as maximum-risk, NOT as clean. The verdict is recorded and the A07 access policy governs downstream handling.
- **A01-AV-4**: CDR (Content Disarm & Reconstruction) is an OPTIONAL per-tenant hook at step 4. When enabled for a file type, the reconstructed (disarmed) artifact replaces the original as the stored attachment blob, and the original's disposition (dropped / retained-encrypted for A07 detonation path) follows tenant policy. CDR runs on plaintext at the frontier; it MUST NOT introduce a later server-side decryption requirement.
- **A01-AV-5**: The AV/CDR engines run in the frontier trust boundary. Their process isolation and update cadence are deployment concerns (A18/ops), but the contract is fixed here: verdict-in-metadata, content-destroyed-with-plaintext, no post-encryption re-scan capability assumed.
- **A01-AV-6** (CDR/trust ordering): When CDR disarms a file at step 4, the trust engine at step 5 (A07) MUST score the **original** attachment's risk, not the disarmed artifact. A file that required disarming is itself a trust signal — the fact that active content was stripped MUST be recorded and MUST contribute to the message trust score, even though the delivered blob is the safe reconstruction. Passing only the disarmed artifact to A07 would erase the signal that the message carried a weaponizable attachment. The metadata MUST therefore record both: `cdr_applied: true`, the original file type/verdict, and the disarm outcome.

------

# 7. Gateway Hold Queue (closes A17-DIR-5)

A principal MAY be entitled and resolvable yet have zero active device bundles (mailbox provisioned, first device not yet enrolled). The frontier cannot produce any envelope. This section specifies the required behavior; it is the resolution of the HIGH open item in A17 §12 for the V1 path.

## 7.1 Behavior

- **A01-HOLD-1**: When step 8 finds zero active device bundles for an otherwise valid, entitled recipient, `diamy-mxd` MUST NOT bounce (`5xx`) and MUST NOT tempfail-until-upstream-expiry. It MUST accept the message (after completing steps 2–7 including AV and trust analysis), encrypt the body/attachment/summary blobs under `k_msg` as normal (A02-CRY-1..3), then wrap `k_msg` under a **gateway hold-queue key** `k_hold` instead of per-device envelopes.
- **A01-HOLD-2**: `k_hold` MUST be a server-side key derived by `diamy-secretd` (Level A pattern per A17-ENC-1), scoped per (tenant, principal), never persisted in `diamy-mxd`, derived on demand and zeroized after use. The held message is thus at-rest-encrypted (protected against a storage dump) but IS server-recoverable — this is the **declared, bounded exception** to zero-access, with the same transparency duty as the frontier zone (A00 §3.2). It MUST be disclosed to tenants.
- **A01-HOLD-3**: The hold queue MUST be bounded: per-message max hold duration is tenant-configurable, RECOMMENDED default 30 days; on expiry, the held message is purged and the original sender receives a DSN (delivery failure). The queue MUST also be size-bounded per principal; overflow tempfails new inbound for that principal (`4xx mailbox not yet provisioned`) rather than unbounded growth.

## 7.2 Release

- **A01-HOLD-4**: Upon publication of the recipient's first device bundle (A17-DIR-3 completes), a release job MUST: for each held message, re-derive `k_hold`, unwrap `k_msg` in the frontier trust boundary, produce normal per-device envelopes (A02-CRY-4), persist them, and destroy the hold-queue copy and `k_hold`. Release MUST be idempotent and resumable (same discipline as A02-RW-2).
- **A01-HOLD-5**: During release, only the message key `k_msg` transits plaintext (unwrapped from `k_hold`, then re-wrapped into per-device envelopes). Message **body** plaintext is NOT reconstructed — the body/attachment/summary blobs remain encrypted under the unchanged `k_msg` throughout; release only changes how `k_msg` is wrapped. This mirrors the key-only discipline of delegated re-wrap (A02-RW-1): the frontier handles a key, never re-decrypts content.
- **A01-HOLD-6**: Every hold/release/expiry event is audit-logged (OBS-3). Held-message count and oldest-held age are health signals (§10).

## 7.3 Relationship to the stricter alternative

- **A01-HOLD-7**: A11 MAY implement onboarding sequencing that mandates first-device enrollment before per-user MX activation, which would make the hold queue a rare safety net rather than a routine onboarding mechanism. If A11 guarantees this for all tenant onboarding paths, the hold-queue default duration MAY be reduced. This annex specifies the hold queue as the V1 baseline because it is robust to onboarding paths A11 cannot enforce (e.g. bulk migration, MX cutover before user login). The final narrowing decision is A11's to close (A17 §12 HIGH item).

------

# 8. Plaintext Destruction (Normative)

- **A01-DESTROY-1**: After step 9 commits (or the message is durably held, §7), `diamy-mxd` MUST zeroize: the raw received message buffer, all parsed plaintext structures, extracted attachment plaintext, the summary plaintext, `k_msg`, and any KEM shared secrets / wrap keys (A02-CRY-5). Zeroization MUST use a method the compiler cannot elide (e.g. `zeroize` crate in Rust).
- **A01-DESTROY-2**: Plaintext MUST NOT be written to disk at any point: no plaintext spooling, no plaintext temp files for AV/CDR (engines MUST be fed via memory or an ephemeral tmpfs explicitly excluded from backups and swap), no plaintext in logs, no plaintext in crash dumps. Core dumps of `diamy-mxd` MUST be disabled in production (fail-closed ops posture).
- **A01-DESTROY-3**: If the process is killed mid-pipeline before step 9, the message is NOT acknowledged (no SMTP 250 was sent), so the sending MTA retries — no plaintext survives the crash because nothing was persisted. This is the safety property that makes at-most-once acknowledgment (A01-PIPE-1) also at-least-once delivery via upstream retry.

------

# 9. Malformed Input & Stability

Precedent: the SIP Monitor parser stability requirement (no single malformed packet crashes the daemon). Inbound mail is at least as hostile.

- **A01-STAB-1**: No single malformed, truncated, oversized, deeply-nested, or adversarial MIME message SHALL crash `diamy-mxd` or exhaust its resources. MIME nesting depth, part count, and header count/size MUST be bounded; exceeding a bound yields a controlled reject (`552`/`554`) or a best-effort partial parse with a `malformed` metadata flag — never an unbounded recursion or allocation.
- **A01-STAB-2**: Charset problems MUST follow CDM-I18N-2: never reject for charset alone; best-effort decode with `charset_recovered` flag. A message with an undecodable part is stored with that part flagged, not dropped.
- **A01-STAB-3**: "MIME bombs" (decompression bombs, billion-laughs-style entity expansion, pathological nesting) MUST be resource-bounded at parse time. Attachment decompression for AV (A01-AV) MUST enforce a decompressed-size ceiling and abort to `unscannable:bomb` (max-risk) rather than exhausting memory.
- **A01-STAB-4**: Duplicate deliveries (same upstream message retried after a tempfail whose commit actually succeeded) MUST be de-duplicated best-effort via the external Message-ID hash + envelope tuple; a duplicate MUST NOT create a second stored copy. Absent a usable Message-ID, at-least-once delivery is acceptable (a rare duplicate is preferable to a drop).

------

# 10. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| IAM unreachable (resolve/entitle) | Tempfail `4xx` for affected RCPT; never accept-for-unknown (backscatter) nor fail-open (A17 §8) |
| Object store / DB unavailable at persist | Tempfail `4xx`; nothing partial; plaintext destroyed; upstream retries |
| Device directory read fails | Treat as "cannot determine devices" → tempfail `4xx`, not zero-device hold (distinguish "no devices" from "couldn't check") |
| Zero active devices (checked successfully) | Hold queue (§7) — accept, hold-encrypt, release on first bundle |
| AV engine unavailable | Tenant policy: fail-closed (tempfail `4xx` until AV restored) is the RECOMMENDED default for security; fail-open (deliver with `av_unscanned` flag) is an explicit opt-in |
| Frontier encryption fails (step 7) | No plaintext stored; tempfail `4xx`; retain nothing readable (A00 SEC-FC-2) |
| Malformed message | §9 controlled handling; never crash |
| Process killed mid-pipeline | No 250 sent → upstream retry; no plaintext persisted (A01-DESTROY-3) |

- **A01-FAIL-1**: The distinction between "successfully determined zero devices" (→ hold) and "failed to determine devices" (→ tempfail) is security-critical and MUST be explicit in code. Conflating them either holds mail that should tempfail, or tempfails mail that should be held through onboarding.

------

# 11. Observability Contract

Per A00 §11:

- counters: `mxd_messages_received_total{result}`, `mxd_auth_results_total{check,result}` (check ∈ spf/dkim/dmarc/arc), `mxd_av_verdicts_total{verdict}`, `mxd_frontier_encrypt_failures_total`, `mxd_hold_enqueued_total`, `mxd_hold_released_total`, `mxd_hold_expired_dsn_total`, `mxd_tempfail_total{reason}`, `mxd_malformed_total{class}`, `mxd_group_expansions_total{result}` (result ∈ ok/zero-members/depth-exceeded/cycle-rejected), `mxd_group_expanded_recipients_total`
- gauges: hold-queue depth per tenant, oldest-held-message age, in-flight pipeline count
- latency: `mxd_pipeline_duration` (p99 target < 500 ms for a 1 MB message incl. AV), `mxd_frontier_encrypt_duration`, `mxd_iam_resolve_duration`
- health indicators (distinct from business metrics, OBS-1): AV engine reachability, IAM reachability, object-store write latency, oldest-held age crossing threshold → WARNING/CRITICAL (A22 thresholds)
- audit (OBS-3): every quarantine, every hold/release/expiry, every DMARC-reject (if tenant opted in), frontier encryption failures

------

# 12. Test Scenarios (Normative)

1. **Happy path**: inbound to a 2-device principal → SPF/DKIM/DMARC pass recorded, AV clean, 1 body blob + envelopes for 2 devices, plaintext zeroized, SMTP 250 after commit.
2. **Pipeline ordering**: instrument that AV (step 4) and A07 content analysis (step 5) both observe plaintext and both complete before step 7; assert no plaintext buffer survives step 10.
3. **Zero-device hold**: provision mailbox, enroll no device, send 3 messages → all held under `k_hold`, no bounce, no plaintext at rest; enroll first device → release job produces per-device envelopes, hold copies destroyed, messages readable; assert idempotent re-run produces no duplicates.
4. **Hold expiry**: hold a message, advance clock past max duration → message purged, sender DSN emitted, audit logged.
5. **Determine-zero vs cannot-check**: kill the device directory → inbound tempfails `4xx` (NOT held); restore → delivery proceeds. Distinct from the genuine zero-device hold path.
6. **DMARC fail default**: send a DMARC-failing message to a tenant without reject-opt-in → delivered with trust metadata `dmarc:fail`, not rejected; same tenant with reject-opt-in → SMTP reject.
7. **Malformed/bomb**: feed a decompression bomb attachment → bounded abort `unscannable:bomb` (max-risk), daemon stable; feed a 10 000-part MIME → bounded reject, no crash.
8. **Crash safety**: kill `diamy-mxd` between step 7 and 9 → no 250 was sent, upstream retries, no plaintext or partial ciphertext persisted.
9. **EAI receive**: inbound from `café@société.fr` with SMTPUTF8 → accepted, `raw` preserved, canonical sender computed (A24), sender Blind Index consistent.
10. **External-to-group expansion**: external sender emails a Diamy distribution group with 3 members → AUTH/AV/TRUST run once on the shared plaintext; 3 independent per-member deliveries follow steps 6–10 independently, each with its own envelope set; assert no shared encryption state between the 3 (A01-GRP-2).
11. **Zero-member group**: external sender emails an empty group → accepted (SMTP 250), zero deliveries produced, `mxd_group_expansions_total{result="zero-members"}` incremented — distinguishable from a delivery failure (A01-GRP-4).
12. **Group expansion doesn't bypass trust**: a DMARC-failing message to a group is still expanded per member, each member's copy carrying the same `dmarc:fail` trust metadata as a direct send would (A01-GRP-5).

------

# 13. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Sending SMTP `250` before the persist transaction commits — acknowledged-but-lost mail on crash (A01-PIPE-1).
2. ❌ Running AV/CDR or A07 content analysis AFTER frontier encryption, forcing a later server-side decryption (A01-PIPE-2, CMP-BND-2).
3. ❌ Writing plaintext to a temp file for the AV engine, or leaving it in a core dump / swap / log (A01-DESTROY-2).
4. ❌ Treating a password-protected archive as `clean` because AV couldn't open it, instead of `unscannable` max-risk (A01-AV-3, SEC-ATT-2).
5. ❌ Hard-rejecting DMARC-fail at the gateway by default, silently losing legitimately-misconfigured wanted mail, instead of feeding the trust score (A01-AUTH-3).
6. ❌ Conflating "zero devices" with "couldn't reach the directory" — one holds, the other tempfails (A01-FAIL-1).
7. ❌ Storing held messages as plaintext, or under a per-device envelope that doesn't exist yet, instead of under the server-side `k_hold` (A01-HOLD-1/2).
8. ❌ Reconstructing message-body plaintext during hold release instead of re-wrapping `k_msg` only (A01-HOLD-5).
9. ❌ Making hold release non-idempotent, so a retried release duplicates envelopes or messages (A01-HOLD-4).
10. ❌ Unbounded MIME recursion/allocation on a crafted message — no depth/size/part-count guard (A01-STAB-1/3).
11. ❌ Using non-eliding memset for zeroization that the compiler optimizes away (A01-DESTROY-1).
12. ❌ Re-running AUTH/AV/TRUST checks once per expanded group member instead of once on the shared plaintext before expansion — wasteful and risks inconsistent verdicts across members of the same message (A01-PIPE-4).
13. ❌ Introducing shared encryption state (e.g. one envelope set reused across expanded members) instead of fully independent per-member encryption — a zero-access violation the moment two members' keys touch the same envelope (A01-GRP-2).
14. ❌ Treating a zero-member group as a delivery error/bounce instead of an accepted, zero-recipient outcome (A01-GRP-4).
15. ❌ Unbounded recursive group expansion (a group containing a cycle of groups) without a depth/cycle guard (A01-GRP-4, A01-STAB discipline).
12. ❌ Comparing SPF/DKIM/DMARC domains with a normalization different from A24, producing inconsistent alignment verdicts (A01-AUTH-2).
13. ❌ Feeding only the CDR-disarmed artifact to the trust engine, erasing the signal that the message carried a weaponizable attachment — A07 scores the original's risk; the disarm is recorded, not hidden (A01-AV-6).

------

# 14. Deferred Items

- Cross-tenant Diamy↔Diamy inbound optimization (bypassing the frontier when the sender is on-platform and already client-encrypted) — the platform-internal delivery path shares the open trust-model item in A02/A17 deferred lists.
- Greylisting tuning and IP-reputation feed integration — operational; the hook is fixed (A01-SMTP-4), the feeds are A06 threat-intelligence territory.
- Milter/relay compatibility (accepting mail relayed from an existing MTA rather than terminating SMTP directly) — deployment topology, revisit with A18.
- Fine-grained hold-queue narrowing once A11 onboarding sequencing is specified (A01-HOLD-7).

------

*End of document.*
