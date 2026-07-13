# Diamy Mail — ANNEX A10: Outbound Submission & Deliverability

**Document title:** Diamy Mail — ANNEX A10: Outbound Submission & Deliverability
**Version:** 1.0
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)
**Sibling dependencies:** A02 (Storage v1.1), A04 (Native Sync API v1.1), A11 (Domain Onboarding), A23 (Outbound Resource Allocation), A17 (IAM Integration v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: `diamy-submitd` outbound pipeline, client-encrypted Sent copy, DKIM signing, SPF/DMARC-aligned emission, per-sender/per-tenant/unique-recipient rate limiting with adaptive baseline + circuit breaker, sending-pool resolution (A23), reputation monitoring (Postmaster/SNDS feedback loops, blocklist), bulk-sender compliance (Google/Yahoo/Microsoft 2024+), retries and DSN, emission-plaintext destruction, failure model, test scenarios, common AI errors |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: specified that `diamy-submitd` finalizes/normalizes server-authoritative headers (Message-ID, Date) before DKIM signing so the signature covers a stable canonical form (A10-AUTH-1b); referenced secure secret storage for the DKIM signing key (diamy-secretd pattern, A10-AUTH-1); nuanced the "one shared engine" claim — the anomaly-detection LOGIC is shared, but the outbound behavioral baseline is server-side (submitd has the data) while the inbound correspondent history is on-device; they are not the same data or location (A10-RL-3); added AI error #13 |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies `diamy-submitd`: how a composed message is submitted, signed, rate-limited, routed to a sending resource, emitted to the Internet, and monitored for deliverability. It also fixes the compliance posture for the Google/Yahoo/Microsoft bulk-sender requirements. It is the outbound counterpart of the inbound gateway (A01).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Boundaries with sibling annexes

- Sending **resource allocation** (which pool/server a tenant uses) is A23; this annex **consumes** the allocation (OPS-SEND-5).
- **Domain onboarding** (publishing SPF/DKIM/DMARC, DNS verification) is A11; this annex assumes onboarding completed and enforces its fail-closed gate (SEC-OUT-2).
- The **submission API** (`/submit`) wire contract is A04 (A04-EP-6); this annex owns what `diamy-submitd` does with a submission.
- Storage of the **Sent copy** is A02 (§5.2); this annex owns the emission side.

## 1.2 Out of scope

Inbound (A01). Trust scoring (A06/A07) — though the same adaptive-baseline reputation engine is shared (§5, cross-ref). Calendar emission (A12–A15).

------

# 2. Outbound Pipeline (Normative order)

```
1  RECEIVE SUBMIT   /submit (A04-EP-6): client-encrypted Sent copy + envelopes
                    + summary_ct + recipient set + emission RFC5322 form
2  AUTHZ            verify mail-plane token, sender owns the From identity
                    (A17), tenant is send-enabled (SEC-OUT-2 / A11 gate)
3  RATE / ABUSE     per-sender + per-tenant + unique-recipient limits,
                    adaptive baseline, circuit breaker (§4)
4  STORE SENT       persist client-encrypted Sent copy (A02 §5.2) — the
                    stored copy is ciphertext; emission form is transient
5  ALLOCATE         resolve tenant → sending pool → healthy sending server
                    (A23 / OPS-SEND-5); fail-closed queue if none (OPS-SEND-6)
6  SIGN             DKIM-sign the emission message with the tenant's key;
                    ensure SPF/DMARC alignment (§3)
7  EMIT             SMTP to the Internet from the chosen sending server/IP
8  DESTROY          zeroize emission plaintext (A04-EP-6, mirrors A01-DESTROY)
9  TRACK            record delivery result; handle 4xx retries / 5xx DSN (§6)
```

- **A10-PIPE-1**: Step 4 (store Sent) MUST commit before step 7 (emit) so a crash after emission still has the Sent copy; combined with idempotency (A04-IDEM), a retry never double-emits (A04-EP-6). The Sent copy stored is the **client-encrypted** one; the emission plaintext is transient (step 8).
- **A10-PIPE-2**: Step 6 signing operates on the **emission plaintext** (DKIM signs the actual bytes sent to the Internet). This is inside the outbound transient-plaintext window (A02 §5.2 exception); the plaintext is zeroized at step 8.
- **A10-PIPE-3**: If step 2 (authz) or step 3 (rate/abuse) fails, the message is NOT emitted; the client is told (typed error, A04-ERR) and — for a rate/circuit-breaker trip — the sender and tenant admin are notified (§4).

------

# 3. Authentication of Outbound Mail

- **A10-AUTH-1**: Every emitted message MUST be **DKIM-signed** with the tenant's domain key. Diamy generates and holds the DKIM signing key (the tenant publishes the public selector via A11), enabling key rotation without tenant action (the conversation's DKIM model). The private signing key MUST be held in the secure secret store (the `diamy-secretd`-derived pattern used across the corpus for signing secrets), never in application config or logs, and loaded only for signing.
- **A10-AUTH-1b** (header finalization before signing): The client-provided emission form (A04-EP-6) MAY omit or carry provisional server-authoritative headers. `diamy-submitd` MUST finalize/normalize these before signing so the DKIM signature covers a stable canonical form: it sets/normalizes `Message-ID` (platform-authoritative, consistent with the internal message_id), `Date`, and any `Received`/return-path handling, THEN computes and adds the `DKIM-Signature` header over the finalized message. The signature MUST cover the headers a receiver will DMARC-align on (`From` in particular). The client MUST NOT be trusted to pre-sign; signing is a `diamy-submitd` responsibility with the tenant key.
- **A10-AUTH-2**: Emission MUST be **SPF-aligned**: the sending server's IP MUST be within the tenant's published SPF (A11), which MUST be consistent with the tenant's assigned sending pool (OPS-SEND-9). A pool reassignment that changes egress IPs MUST NOT emit until SPF re-verification (A11/A23).
- **A10-AUTH-3**: Emission MUST be **DMARC-aligned** (From domain aligns with the DKIM `d=` and/or SPF domain), so recipients' DMARC checks pass. This is the whole point of the onboarding gate: a tenant that cannot align is not send-enabled (SEC-OUT-2).
- **A10-AUTH-4**: `diamy-submitd` MUST verify the sender is authorized to use the `From` identity (A17 principal owns the address / is delegated). A user MUST NOT emit as an arbitrary address; From-spoofing from inside the platform is forbidden (it would make Diamy a spoofing source).

------

# 4. Rate Limiting & Abuse Protection (Normative)

The outbound rate limit protects **Diamy's own sending reputation** against a compromised account (the conversation's core point: a phished employee becomes a spam cannon on your IPs).

- **A10-RL-1**: Limits MUST be enforced at three granularities simultaneously (A00 SEC-OUT-1):
  - **per-sender**: hourly/daily cap with an **adaptive baseline** (a sender normally sending 20/day who jumps to 500 is anomalous even under a global cap);
  - **per-tenant**: aggregate cap, admin-configurable;
  - **per-unique-recipient**: a message to 300 distinct recipients is more suspicious than 300 messages to one — both counters required.
- **A10-RL-2**: A **circuit breaker** MUST trip on strong anomaly (baseline deviation beyond a threshold, sudden unique-recipient fan-out, sudden content-uniformity suggesting bulk): outbound for the account is SUSPENDED (not silently throttled) and the sender + tenant admin are alerted (A00 SEC-OUT-1). Suspension is a protective action of record (audit-logged, OBS-3), reversible by admin after review.
- **A10-RL-3**: The adaptive baseline uses the **same anomaly-detection logic/approach** as the inbound trust engine's behavioral analysis (the conversation's "même moteur d'analyse de réputation, appliqué dans les deux sens") and SHOULD be implemented as one shared component rather than two parallel systems. Precision on data and location: the **outbound** behavioral baseline (per-sender volume/fan-out patterns) is computed **server-side** in `diamy-submitd`, which legitimately sees all of a tenant's outbound submissions; this is distinct from the **inbound** correspondent-history behavioral signals (A06 §7), which are per-user and computed **on-device** to protect the correspondent graph. Same detection logic, different data on different sides of the privacy boundary — an implementer MUST NOT try to compute outbound sender baselines on-device (submitd has the data and the duty), nor push the on-device inbound history server-side (A06-HIST-2).
- **A10-RL-4**: Rate limits are enforced **in addition to** sending-pool capacity limits (A23 / OPS-SEND-7); allocation MUST NOT bypass anti-abuse limits and vice versa — independent controls, both apply.
- **A10-RL-5**: Legitimate bulk (a newsletter from an authorized tenant) MUST be distinguishable from abuse: a tenant MAY be granted a higher baseline for a designated bulk-sending identity, with the corresponding bulk-sender compliance obligations (§7) enforced. The distinction is configured, not guessed.

------

# 5. Reputation Monitoring (product component, not afterthought)

- **A10-REP-1**: Sending-reputation monitoring MUST be a first-class product component (A00 OPS-DELIV-1), integrated with the observability stack (Grafana/Prometheus per corpus culture). It MUST ingest: **feedback loops** (Google Postmaster Tools, Microsoft SNDS/JMRP), **blocklist status** (Spamhaus and equivalents), bounce/complaint rates, and per-pool/per-IP delivery outcomes.
- **A10-REP-2**: Complaint rate MUST be tracked against the bulk-sender threshold (§7, < 0.3% hard, < 0.1% target). Crossing a warning threshold MUST raise an operational alert and MAY auto-tighten the offending sender/tenant's limits (§4) before reputation damage spreads.
- **A10-REP-3**: Blocklist appearance of a sending IP/pool MUST trigger an alert and a documented delisting runbook (A18/ops), and SHOULD trigger automatic tenant re-routing away from the affected pool where an alternative is healthy (A23 fallback).
- **A10-REP-4**: Reputation is monitored **per pool/IP** (A23), so a problem is isolated to its pool and a dedicated-pool tenant's issue never contaminates others' reputation (the segmentation rationale, OPS-DELIV-2).

------

# 6. Retries, Bounces, DSN

- **A10-RETRY-1**: A `4xx` from a recipient MTA MUST be retried with backoff over a bounded window (RECOMMENDED up to ~3–5 days, tenant-configurable), interpreting non-standard 4xx/5xx behavior defensively (the conversation's greylisting/non-standard-code point — some servers send permanent 4xx or temporary 5xx; the retry logic MUST be robust to real-world MTA quirks, logging anomalies).
- **A10-RETRY-2**: A `5xx` (permanent) or retry-window exhaustion MUST generate a **DSN** (delivery status notification) to the sender, and update the message state (A04 sync) so the sender's client shows the failure. A DSN MUST NOT leak the recipient's internal details beyond standard DSN content.
- **A10-RETRY-3**: The outbound queue MUST NOT be head-of-line-blocked by one stuck recipient (A04-IDEM-3): per-recipient delivery is independent; a permanently-failing recipient is DSN'd and does not hold up others in the same or subsequent messages.
- **A10-RETRY-4**: Delivery outcomes feed reputation monitoring (§5) and the observability contract (§9).

------

# 7. Bulk-Sender Compliance (Google / Yahoo / Microsoft)

For tenants sending at volume (the 5000/day-to-Gmail threshold and equivalents), the platform MUST satisfy the 2024+ bulk-sender requirements — and applies the technical baseline to all senders since it is now the deliverability norm (the conversation's summary).

- **A10-BULK-1**: SPF **and** DKIM **and** DMARC (min `p=none`) MUST all be in place with alignment (enforced by the A11 onboarding gate). This is the entry ticket, not an option (SEC-OUT-2).
- **A10-BULK-2**: Reverse DNS (PTR) for sending IPs MUST be valid and consistent (forward-confirmed); this is a pool/IP provisioning obligation (A23/ops) that this annex depends on.
- **A10-BULK-3**: Marketing/bulk messages MUST support **one-click unsubscribe** (RFC 8058: `List-Unsubscribe` + `List-Unsubscribe-Post`), and the platform MUST process unsubscribe requests within the required window (≤ 2 days). This applies to designated bulk-sending identities (A10-RL-5); ordinary 1:1 business mail is not marketing and is not required to carry it (but MUST NOT be mislabeled to evade it).
- **A10-BULK-4**: Complaint rate MUST stay below the enforced threshold (< 0.3%, target < 0.1%, §5). The platform MUST give tenants visibility into their complaint rate (Postmaster-derived) and MUST act (§4/§5) when a tenant approaches the limit, since one tenant's complaints on a shared pool harm others.
- **A10-BULK-5**: The platform MUST NOT allow a tenant to spoof Gmail/Yahoo/Microsoft From domains or otherwise violate the receiving-provider rules; A10-AUTH-4 (From authorization) already forbids arbitrary From.

------

# 8. Emission Plaintext Handling

- **A10-EMIT-1**: The emission RFC 5322 plaintext exists transiently in `diamy-submitd` RAM for signing (§3) and emission (step 7) only. It MUST NOT be persisted, MUST NOT be logged (no full-message logging; envelope/metadata logging only), MUST NOT appear in crash dumps (core dumps disabled in production, mirror A01-DESTROY-2), and MUST be **zeroized immediately after emission** (A04-EP-6, non-eliding). The stored Sent copy is the client-encrypted one (A02 §5.2).
- **A10-EMIT-2**: This is the declared outbound mirror of the frontier exception (A00 §3.2); it MUST be disclosed to tenants with the same transparency as the inbound frontier. The platform necessarily sees emission plaintext because it emits RFC 5322 to the Internet — this is unavoidable for any sending mail server and is bounded to the emission window.

------

# 9. Observability Contract

Per A00 §11:

- counters: `submit_received_total{result}`, `emitted_total{pool,result}`, `dkim_signed_total`, `rate_limit_trips_total{granularity}`, `circuit_breaker_trips_total`, `dsn_generated_total{reason}`, `retries_total{outcome}`, `complaints_total`, `unsubscribe_requests_total`, `blocklist_events_total`
- gauges: per-pool/IP reputation indicators (Postmaster/SNDS-derived), complaint rate per tenant, outbound queue depth, oldest-queued age
- latency: `submit_to_emit_duration`, `dkim_sign_duration`
- audit (OBS-3): circuit-breaker suspensions, admin re-enablement, From-authorization denials, blocklist events + delisting actions
- health (OBS-1, distinct from business metrics): sending-pool health, feedback-loop ingestion freshness, per-pool complaint/bounce thresholds crossing WARNING/CRITICAL (A22)
- **A10-OBS-1**: Telemetry MUST NOT include message content or recipient lists; counts, rates, pools, and outcomes only (A07-OBS-1 discipline).

------

# 10. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Tenant not send-enabled (onboarding incomplete) | Reject submission, clear error, point to onboarding (SEC-OUT-2, A11) |
| No healthy sending server in pool + no fallback | Queue (fail-closed, OPS-SEND-6), alert; do NOT emit via an arbitrary IP |
| Rate limit / circuit breaker trip | Suspend account outbound, alert sender + admin; not silent (A10-RL-2) |
| DKIM key unavailable | Fail-closed: do NOT emit unsigned (unsigned = deliverability + spoofing risk); alert ops |
| SPF/pool IP mismatch | Do NOT emit until re-verified (A10-AUTH-2, A11); the pool egress must match published SPF |
| Recipient 4xx | Retry with backoff, bounded window (A10-RETRY-1) |
| Recipient 5xx / window exhausted | DSN to sender, update state (A10-RETRY-2) |
| Emission succeeds, ack to client lost | Idempotency dedup on retry — no double-emit (A04-IDEM, A10-PIPE-1) |
| Feedback-loop/blocklist feed down | Monitor degraded, alert; emission continues but with reduced reputation visibility |

------

# 11. Test Scenarios (Normative)

1. **Aligned emission**: send from an onboarded tenant → DKIM-signed, SPF-aligned (pool IP in SPF), DMARC-aligned; a receiving check passes all three.
2. **From authorization**: attempt to emit as an address the sender doesn't own → rejected (A10-AUTH-4); no spoofed mail leaves.
3. **Per-sender anomaly**: a sender at 20/day baseline suddenly submits 500 with 500 unique recipients → circuit breaker trips, outbound suspended, sender + admin alerted, audit-logged (A10-RL-1/2).
4. **Unique-recipient counter**: one message to 300 distinct recipients flagged distinctly from 300 messages to one recipient (A10-RL-1).
5. **Pool fail-closed**: mark all pool servers unhealthy, no fallback → message queued, alert; assert NOT emitted via an unassigned IP (OPS-SEND-6).
6. **DKIM unavailable**: remove signing key → emission refused (not sent unsigned), ops alerted (§10).
7. **4xx retry / 5xx DSN**: recipient MTA returns 4xx → retried with backoff; returns 5xx → DSN to sender, message state updated in client (A10-RETRY).
8. **Idempotent re-emit**: crash after emit before ack → client retries same idempotency key → no second emission (A10-PIPE-1, A04-IDEM).
9. **Bulk compliance**: designated bulk identity emits marketing → List-Unsubscribe one-click present, unsubscribe processed ≤ 2 days, complaint rate tracked vs threshold (§7).
10. **Emission plaintext destroyed**: assert emission plaintext is zeroized post-emit, absent from logs and (disabled) core dumps (A10-EMIT-1).
11. **Reputation isolation**: a dedicated-pool tenant's complaint spike affects only its pool's reputation, not a shared pool (A10-REP-4).

------

# 12. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Emitting before the Sent copy is durably stored, or non-idempotently, causing loss or double-emit (A10-PIPE-1, A04-IDEM).
2. ❌ Emitting unsigned when the DKIM key is unavailable instead of failing closed (§10) — unsigned mail is a deliverability and spoofing risk.
3. ❌ Allowing a user to emit as an arbitrary From address (A10-AUTH-4) — makes Diamy a spoofing source.
4. ❌ Silently throttling instead of tripping the circuit breaker + alerting on strong anomaly (A10-RL-2) — a compromised account should stop, loudly.
5. ❌ Building the outbound anomaly engine separately from the inbound reputation/trust engine instead of one shared component (A10-RL-3).
6. ❌ Letting sending-pool allocation bypass anti-abuse rate limits, or vice versa (A10-RL-4, OPS-SEND-7).
7. ❌ Emitting via an arbitrary/unassigned IP when the pool is unhealthy instead of fail-closed queueing (§10, OPS-SEND-6).
8. ❌ Emitting from a pool whose egress IPs are not in the tenant's published SPF (A10-AUTH-2) — breaks SPF alignment at the recipient.
9. ❌ Persisting or logging the emission plaintext, or not zeroizing it after emit (A10-EMIT-1).
10. ❌ Treating all 4xx as permanent or all 5xx as retryable instead of robust real-world MTA behavior handling (A10-RETRY-1).
11. ❌ Head-of-line-blocking the queue on one stuck recipient (A10-RETRY-3, A04-IDEM-3).
12. ❌ Shipping marketing without one-click unsubscribe, or mislabeling marketing as 1:1 to evade it (A10-BULK-3).
13. ❌ Trusting a client-provided DKIM signature or signing before finalizing server-authoritative headers (Message-ID/Date), so the signature covers an unstable form or the client could forge alignment (A10-AUTH-1b); or computing the outbound sender baseline on-device instead of server-side in submitd (A10-RL-3).

------

# 13. Deferred Items

- BIMI (brand indicators) support — a deliverability/brand enhancement building on DMARC enforcement; deferred.
- TLS-RPT / MTA-STS for outbound transport security reporting — deferred, complements the inbound TLS posture.
- Automated IP-warming scheduling for new pools/IPs (gradual volume ramp) — operational automation (A23/ops); the need is noted (the conversation's IP-warming point), the scheduler is deferred.
- ARC-sealing on forwarded mail (if Diamy ever forwards) — not in V1 scope.
- Feedback-loop provider specifics and delisting runbooks — operational (A18).

------

*End of document.*
