# Diamy Mail — ANNEX A22: Health Indicators & Thresholds

**Document title:** Diamy Mail — ANNEX A22: Health Indicators & Thresholds
**Version:** 1.7
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.3 (A00)
**Sibling dependencies:** A01 (Inbound Gateway v1.1), A04 (Native Sync API v1.1), A10 (Outbound Deliverability v1.1), A23 (Outbound Allocation v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: consolidated pipeline health indicators and default WARNING/CRITICAL thresholds for inbound, storage, sync, outbound, deliverability/reputation, key-directory, and webmail planes; health-vs-business-metric separation; alert routing tiers; threshold tuning discipline; SLO targets; deliverability-specific thresholds tied to bulk-sender limits; failure model; common AI errors. Consumed by every annex's observability contract. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: reconciled a cross-annex numeric inconsistency — A21/A04 called 100 ms the catalogue list-page latency TARGET, but v1.0 used 100 ms as the WARNING line (making 100 ms simultaneously good and bad). Aligned: catalogue list-page SLO < 100 ms (matching A21-IDX-1 / A04), WARNING > 150 ms, CRITICAL > 500 ms. Verified complaint-rate (0.1%/0.3%) and epoch-sever (10 s) thresholds match A10/A17 exactly. |
| 1.4     | Jul 4th 2026 | Cédric BORNECQUE | Added the multi-account isolation security indicator (A22-MULTI-1): cross_account_operation_blocks_total (A26-OBS-2) — any occurrence means isolation refused a cross-account operation; should be zero, non-zero is a WARNING warranting investigation, reported as aggregate count only (linkage privacy A26-OBS-1). |
| 1.5     | Jul 4th 2026 | Cédric BORNECQUE | Added §8bis closing the pending A27 (Shared Resources) health-indicator dependency: a calendar-delegate device found in a mail device-key directory is a security-invariant always-page indicator (A22-RESRC-1, added to A22-ALERT-2) — the entire safety property of calendar delegation depends on this never happening. Added informational (non-alerting) tracking for orphaned-admin rejections and send-as denials (A22-RESRC-2 — these are the system correctly enforcing policy, not defects), and an anomaly-detection framing for membership/delegation/group-admin change-rate spikes (A22-RESRC-3 — routed to the operational queue, not paged, unless correlated with other security signals). |
| 1.7     | Jul 4th 2026 | Cédric BORNECQUE | Final sweep: fixed one more unqualified epoch mention (AI error #2, "epoch-sever") missed in v1.6's pass. |
| 1.6     | Jul 4th 2026 | Cédric BORNECQUE | Follow-up sweep: softened three "epoch"-as-fact mentions missed in earlier passes (A22-KEY-1, A22-ALERT-2, AI error #7) to reference A17-TOK-2's flagged, unconfirmed revocation mechanism, completing the corpus-wide correction alongside A03/A04/A17/A20/A25/A26. No threshold values changed — only the certainty with which the underlying mechanism is described. |
| 1.3     | Jul 4th 2026 | Cédric BORNECQUE | Added the Bridge (A20) non-loopback bind/connection refusal as a security-invariant always-page indicator (A22-ALERT-2) — any occurrence signals an attempted plaintext-mailbox exposure or tampering; closes the A20-OBS-1 coherence reference. |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Added §9bis Calendar health indicators, closing the pending tzdata-skew dependency flagged by A13: the **tzdata/CLDR version-skew** indicator (A22-CAL-1, A13-OBS-2/A13-TZ-3) — skew silently corrupts cross-device UTC-instant agreement, so any skew is WARNING and >1 release is CRITICAL, alertable despite not being a crash; plus event-sync, iMIP, free/busy, and orphaned-override indicators, and the registry-candidate flag rate (A22-CAL-2, A14-OBS-1) that keeps the third-party-behavior registry "living". Fixed a section-heading numbering slip introduced by the insert (restored §10 Alert Routing Tiers). |

------

# Table of contents

[toc]

------

# 1. Scope

This annex consolidates the **health indicators** each Diamy Mail plane exposes and their **default WARNING / CRITICAL thresholds**. Every annex's observability contract (A01, A04, A05, A10, A23, …) references "A22 thresholds"; this document is where those numbers live, so they are set and tuned in one place rather than scattered. It is a defaults document: thresholds are starting points to be calibrated on real volume (the corpus's iterative-calibration discipline), not immutable constants.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Health vs business metrics (separation)

- **A22-SEP-1**: **Health indicators** (this annex) answer "is the system operating correctly?" and drive alerting/paging. **Business metrics** (message counts, trust-band distributions, classification rates) answer "what is happening?" and drive product analytics. They MUST be separable (A00 OBS-1 vs OBS-2): a business metric moving is not necessarily a health problem, and health alerting MUST NOT fire on normal business variation. This annex governs health only.

## 1.2 Out of scope

The metrics *definitions* (each annex's observability §). The dashboards/alerting tooling (Prometheus/Grafana/Alertmanager — operational, A18). Client-side telemetry thresholds (A03-OBS; privacy-preserving, mostly product analytics not paging).

------

# 2. Threshold Model

- **A22-MODEL-1**: Each indicator has a **direction** (higher-is-worse or lower-is-worse), a **WARNING** level (investigate, no immediate user impact), and a **CRITICAL** level (active or imminent user impact; page). Some indicators also have an **SLO target** (the level the system is designed to hold in normal operation).
- **A22-MODEL-2**: Thresholds are evaluated over a **window** (not instantaneous), to avoid flapping on transient spikes. Default window: 5-minute rolling for latency/error-rate, longer (hours/days) for reputation/complaint indicators that are inherently slow. Each indicator states its window.
- **A22-MODEL-3**: Thresholds are **defaults, tunable per deployment and per tenant tier** (a dedicated-pool enterprise tenant may warrant tighter deliverability thresholds). A threshold change MUST be recorded (config as versioned artifact) so a regression in alerting is traceable.
- **A22-MODEL-4** (fail-closed observability): If an indicator cannot be computed (metric pipeline gap, feed outage), that absence is itself a WARNING (blind is not healthy) — the system MUST NOT interpret "no data" as "healthy" (A06/A07/A10 feed-outage discipline).

------

# 3. Inbound Gateway (`diamy-mxd`, A01)

| Indicator | Dir | Window | WARNING | CRITICAL | SLO |
| --------- | --- | ------ | ------- | -------- | --- |
| Reception error rate (5xx to senders) | ↑worse | 5 min | > 1% | > 5% | < 0.5% |
| Pipeline processing latency (receive→ACK), p99 | ↑worse | 5 min | > 2 s | > 5 s | < 1 s |
| Trust-analysis duration, p99 | ↑worse | 5 min | > 800 ms | > 2 s | < 500 ms |
| AV/CDR backlog (queued for scan) | ↑worse | 5 min | > 500 | > 5000 | ~0 |
| AV engine availability | ↓worse | 1 min | degraded | unavailable | available |
| Envelope-write failures (post-analysis) | ↑worse | 5 min | > 0.1% | > 1% | 0 |
| Hold-queue depth (zero-device recipients) | ↑worse | 15 min | > tenant-baseline×3 | > tenant-baseline×10 | baseline |
| Plaintext-zeroization failures | ↑worse | 1 min | ANY | ANY | 0 |

- **A22-IN-1**: Plaintext-zeroization failure is WARNING **and** CRITICAL on ANY occurrence — it is a security invariant (A01-DESTROY), not a rate. One failure pages. Same for any detected plaintext-to-disk/log leak.
- **A22-IN-2**: AV-engine unavailable is CRITICAL because the tenant's fail-closed policy (A01-AV) will tempfail inbound while it is down; a fail-open tenant delivers `av_unscanned` mail, which is a security WARNING at minimum. The threshold depends on the tenant's policy but the unavailability itself is always alertable.

------

# 4. Storage Plane (A02 / A21)

| Indicator | Dir | Window | WARNING | CRITICAL | SLO |
| --------- | --- | ------ | ------- | -------- | --- |
| Blob-store write error rate | ↑worse | 5 min | > 0.1% | > 1% | 0 |
| Orphan-blob GC backlog | ↑worse | 1 h | > 1000 | > 10000 | ~0 |
| Catalogue query latency (list page), p99 | ↑worse | 5 min | > 150 ms | > 500 ms | < 100 ms |
| Envelope-directory write latency, p99 | ↑worse | 5 min | > 100 ms | > 500 ms | < 50 ms |
| Transaction rollback rate (write path) | ↑worse | 5 min | > 0.5% | > 2% | < 0.1% |
| Storage capacity utilization | ↑worse | 1 h | > 75% | > 90% | < 70% |
| Re-wrap job backlog (new-device history) | ↑worse | 15 min | > baseline×3 | > baseline×10 | baseline |

- **A22-STO-1**: Catalogue list-page latency is the user-visible hot path (A21-IDX-1); its CRITICAL (> 500 ms p99) means list views feel broken. This is the single most important storage UX indicator.

------

# 5. Sync Plane (`diamy-maild`, A04)

| Indicator | Dir | Window | WARNING | CRITICAL | SLO |
| --------- | --- | ------ | ------- | -------- | --- |
| Sync-events endpoint error rate | ↑worse | 5 min | > 0.5% | > 2% | < 0.1% |
| Per-principal journal lag (events behind head), p99 | ↑worse | 5 min | > 100 | > 1000 | < 10 |
| Blob-fetch error rate | ↑worse | 5 min | > 0.5% | > 2% | < 0.1% |
| Blob-fetch latency by size bucket, p99 | ↑worse | 5 min | > 2× baseline | > 5× baseline | baseline |
| Active WSS connection saturation | ↑worse | 5 min | > 75% cap | > 90% cap | < 70% |
| Cursor-expired resync rate | ↑worse | 1 h | > 2× baseline | > 10× baseline | baseline |
| Idempotency-store availability | ↓worse | 1 min | degraded | unavailable | available |

- **A22-SYNC-1**: A cursor-expired resync spike (many devices forced to full-resync) signals a journal-compaction or retention misconfiguration (A02 §4.4); it is expensive (snapshot delivery) and warrants investigation before it saturates the sync plane.
- **A22-SYNC-2**: Idempotency-store unavailability is CRITICAL because without dedup, submit retries risk double-emit (A04-IDEM) — outbound MUST degrade safely (queue) rather than emit non-idempotently.

------

# 6. Outbound Plane (`diamy-submitd`, A10)

| Indicator | Dir | Window | WARNING | CRITICAL | SLO |
| --------- | --- | ------ | ------- | -------- | --- |
| Submit→emit latency, p99 | ↑worse | 5 min | > 5 s | > 30 s | < 2 s |
| Emission failure rate (per pool) | ↑worse | 5 min | > 2% | > 10% | < 1% |
| Fail-closed queue depth (no healthy server) | ↑worse | 5 min | > 0 | > 100 | 0 |
| Circuit-breaker trip rate | ↑worse | 1 h | > baseline×2 | > baseline×5 | baseline |
| DKIM-signing failure rate | ↑worse | 5 min | > 0.1% | > 1% | 0 |
| Outbound queue oldest-age | ↑worse | 5 min | > 5 min | > 30 min | < 1 min |
| Emission-plaintext zeroization failures | ↑worse | 1 min | ANY | ANY | 0 |

- **A22-OUT-1**: Fail-closed queue depth > 0 is already WARNING: it means at least one message could not be emitted through an assigned resource (A23-SEL-2) and is waiting. Sustained/growing depth (CRITICAL) means a pool-health or allocation problem is blocking a tenant's outbound.
- **A22-OUT-2**: DKIM-signing failure is near-zero-tolerance: an unsigned emission is refused (A10 fail-closed), so signing failures translate directly to undeliverable mail. Any sustained rate is CRITICAL.
- **A22-OUT-3**: Emission-plaintext zeroization failure pages on ANY occurrence (mirror of A22-IN-1; the outbound frontier exception, A10-EMIT-1).

------

# 7. Deliverability & Reputation (A10 §5, A23)

These are inherently slower indicators (reputation moves over hours/days) and are tied to the bulk-sender compliance limits (A10 §7).

| Indicator | Dir | Window | WARNING | CRITICAL | SLO |
| --------- | --- | ------ | ------- | -------- | --- |
| Complaint rate (per tenant / per pool) | ↑worse | 24 h | > 0.1% | > 0.3% | < 0.1% |
| Bounce rate (per pool) | ↑worse | 24 h | > 3% | > 8% | < 2% |
| Pool on a major blocklist | ↓worse | 15 min | listed (any) | listed (major/multiple) | not listed |
| Postmaster/SNDS reputation indicator | ↓worse | 24 h | "medium"/declining | "low"/"bad" | "high" |
| Feedback-loop ingestion freshness | ↑worse | 1 h | > 2 h stale | > 6 h stale | < 1 h |
| Pool capacity utilization | ↑worse | 15 min | > 75% | > 90% | < 70% |

- **A22-DEL-1**: The complaint-rate thresholds are **anchored to the enforced bulk-sender limits** (Google/Yahoo: 0.3% enforced, 0.1% target — A10-BULK-4). WARNING at 0.1% gives runway to act (tighten limits, A10-RL, before reputation damage) BEFORE crossing the enforced 0.3% CRITICAL. These numbers are not arbitrary; they mirror the receiving providers' published limits.
- **A22-DEL-2**: A pool appearing on a **major blocklist** (Spamhaus SBL/XBL, etc.) is CRITICAL — active deliverability damage; triggers the delisting runbook (A10-REP-3) and SHOULD trigger SPF-consistent re-routing (A23-REP-2). Reputation isolation (A23-REP-4) confines the blast radius to that pool.
- **A22-DEL-3**: Feedback-loop staleness matters because reputation decisions made on stale data are wrong; a >6 h gap (CRITICAL) means the platform is flying blind on complaints (A22-MODEL-4).

------

# 8. Key-Directory & Onboarding

| Indicator | Dir | Window | WARNING | CRITICAL | SLO |
| --------- | --- | ------ | ------- | -------- | --- |
| Key-bundle signature-verification failure rate | ↑worse | 5 min | > 0.1% | > 1% | 0 |
| Epoch-revocation propagation latency (session sever) | ↑worse | 1 min | > 10 s | > 30 s | < 10 s |
| Onboarding DNS-verification error rate | ↑worse | 15 min | > 5% | > 20% | < 2% |
| Domains stuck in pending > 7 days | ↑worse | 1 d | > baseline | > baseline×3 | ~0 |
| DMARC aggregate-report ingestion freshness | ↑worse | 6 h | > 12 h stale | > 48 h stale | < 6 h |

- **A22-KEY-1**: Revocation propagation latency > 10 s violates the A17-TOK-5 target (sessions severed within 10 s of a revocation signal, mechanism per A17-TOK-2 — confirmation pending); it is a security-relevant latency, not just performance. > 30 s (CRITICAL) means a revoked/stolen device may still have live access.
- **A22-KEY-2**: Key-bundle signature-verification failures could indicate an attempted forged-bundle publication (A17-KEY-3) or an implementation bug; either is alertable.

------

# 8bis. Shared Resources — Membership, Delegation & Groups (A27)

| Indicator | Dir | Window | WARNING | CRITICAL | SLO |
| --------- | --- | ------ | ------- | -------- | --- |
| Orphaned-admin rejection rate (attempts blocked) | — | 1 d | informational only | informational only | n/a |
| **Calendar-delegate device found in a mail device-key directory** | ↓worse | any | ANY occurrence | ANY occurrence | 0, always |
| Resource-membership change rate | ↑worse | 1 h | > baseline×5 | > baseline×15 | baseline |
| Delegation grant/revocation rate | ↑worse | 1 h | > baseline×5 | > baseline×15 | baseline |
| Group-admin change rate | ↑worse | 1 h | > baseline×5 | > baseline×15 | baseline |
| Send-as authorization denial rate (viewer attempting send) | — | 1 h | informational only | informational only | n/a |

- **A22-RESRC-1** (security invariant — always page): a calendar-delegate device ever appearing in a **mail** device-key directory is a direct violation of A17-DIR-6 / A27-DEL-3's crypto-scope guarantee — the entire safety property of calendar delegation depends on this never happening. This MUST be added to the security-invariant always-page list (A22-ALERT-2) alongside plaintext-zeroization failures and the Bridge non-loopback indicator: ANY occurrence pages regardless of rate.
- **A22-RESRC-2**: The orphaned-admin rejection and send-as-denial rates are **informational**, not alertable — a rejection is the system correctly enforcing A27-ROLE-4/A27-SEC-2; a rising rate reflects usage patterns (e.g., a viewer-heavy shared mailbox), not a defect. They are tracked for product/UX insight, not paged.
- **A22-RESRC-3**: Membership/delegation/group-admin change rates spiking well above baseline (WARNING/CRITICAL) may indicate a compromised admin account performing bulk unauthorized changes (e.g., an attacker adding themselves to many shared mailboxes) — this is an audit-adjacent anomaly signal, not a correctness bug, and routes to the security operational queue rather than paging outright (A22-ALERT-1's WARNING routing), unless correlated with other security-invariant signals.

------

# 9. Webmail (A05, when enabled)

| Indicator | Dir | Window | WARNING | CRITICAL | SLO |
| --------- | --- | ------ | ------- | -------- | --- |
| Blind-Index query latency, p99 | ↑worse | 5 min | > 300 ms | > 1 s | < 150 ms |
| Blind-Index backfill job backlog | ↑worse | 15 min | > baseline×3 | > baseline×10 | baseline |
| Webmail-disable purge completion latency | ↑worse | 1 h | > 12 h | > 24 h | < 6 h |
| Image-proxy error rate | ↑worse | 5 min | > 1% | > 5% | < 0.5% |

- **A22-WEB-1**: Webmail-disable purge exceeding 24 h (CRITICAL) means a user's data-minimization request (A05-BI-6) is unsatisfied past the committed window — a privacy-commitment breach, alertable as such, not merely a performance issue.

------

# 9bis. Calendar (`diamy-cald`, A12–A15)

| Indicator | Dir | Window | WARNING | CRITICAL | SLO |
| --------- | --- | ------ | ------- | -------- | --- |
| **tzdata / CLDR version skew across components** | ↓worse | 15 min | any skew detected | skew > 1 release | consistent |
| Event sync error rate | ↑worse | 5 min | > 0.5% | > 2% | < 0.1% |
| iMIP send/receive error rate | ↑worse | 5 min | > 2% | > 10% | < 1% |
| Registry-candidate flag rate (unhandled third-party deviations) | ↑worse | 1 d | > baseline×2 | > baseline×5 | baseline |
| Free/busy query error rate | ↑worse | 5 min | > 1% | > 5% | < 0.5% |
| Orphaned-override rate | ↑worse | 1 h | > baseline×2 | > baseline×5 | ~0 |

- **A22-CAL-1** (tzdata/CLDR skew — the important one): A tzdata or CLDR-windowsZones **version skew across server and clients** (A13-OBS-2, A13-TZ-3) MUST be a health indicator, because skew silently produces cross-device disagreement on UTC instants near a rule change (a meeting shows at different times on different devices). Any detected skew is a WARNING; skew of more than one tzdata release is CRITICAL (the probability of a materially-different rule rises). This is the calendar analogue of a security-invariant: it fails *silently* and corrupts correctness, so it is alertable even though it is not a crash.
- **A22-CAL-2**: The registry-candidate flag rate (A14-OBS-1) is the signal that the "living" third-party-behavior registry needs attention — a rising rate means clients are deviating in unhandled ways. It is a slow (daily-window) operational indicator, not a page, but it MUST be watched or the registry stops being living.
- **A22-MULTI-1** (multi-account isolation — security): For a multi-account client (A26), `cross_account_operation_blocks_total` (A26-OBS-2) is a **security** indicator: any occurrence means the client attempted a cross-account operation that isolation correctly refused — it should be zero. A non-zero rate is a WARNING (an isolation bug is being exercised) and warrants investigation; it is reported as an aggregate count only, never revealing which accounts (A26-OBS-1 linkage privacy).

------

# 10. Alert Routing Tiers

- **A22-ALERT-1**: WARNING indicators route to an operational queue (investigate within business hours) unless they concern a security invariant (§10.2). CRITICAL indicators page on-call. Security-invariant indicators page regardless of WARNING/CRITICAL labeling.
- **A22-ALERT-2** (security invariants — always page): plaintext-zeroization failure (in or out), detected plaintext-to-disk/log/coredump leak, revocation-propagation failure (mechanism per A17-TOK-2), forged-key-bundle signature failures, a Bridge non-loopback bind attempt or non-loopback connection refusal (A20-NET, A20-OBS-1 — any occurrence signals an attempted plaintext-mailbox exposure or tampering), a calendar-delegate device appearing in a mail device-key directory (A22-RESRC-1, A17-DIR-6 — any occurrence signals a broken delegation-scope guarantee), and any detected zero-access-model violation. These are not rate-tuned; ANY occurrence pages (A22-IN-1, A22-OUT-3, A22-KEY-1, A20-NET, A22-RESRC-1).
- **A22-ALERT-3**: Alert fatigue is itself a risk (the same principle as the trust false-positive discipline, A06-PRIN-3): thresholds MUST be tuned so CRITICAL means "act now" reliably. A perpetually-firing CRITICAL that everyone ignores is a failure of this annex, to be re-tuned (A22-MODEL-3).

------

# 11. SLO Summary (design targets)

The SLO columns above express the levels the system is designed to hold. Consolidated headline SLOs:

- Inbound pipeline p99 < 1 s; reception error rate < 0.5%.
- Catalogue list-page p99 < 100 ms (the felt-speed metric; matches A21-IDX-1 / A04).
- Sync journal lag p99 < 10 events.
- Outbound submit→emit p99 < 2 s; emission failure < 1%.
- Complaint rate < 0.1% (well under the 0.3% enforced limit).
- Epoch-revocation session sever < 10 s (security SLO, A17-TOK-5).
- Zero-access invariants: 0 tolerance (any breach pages).

- **A22-SLO-1**: SLOs are targets, not guarantees to tenants unless a tenant SLA says so; this annex sets engineering targets. Tenant-facing SLAs (if offered) are a commercial matter that MAY adopt a subset of these.

------

# 12. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Indicator cannot be computed (metric gap) | Treat as WARNING (blind ≠ healthy); alert on the gap (A22-MODEL-4) |
| Threshold flapping | Widen window / add hysteresis; do not silence (A22-MODEL-2) |
| Feed outage (reputation/FBL) | Deliverability indicators go stale → WARNING/CRITICAL on staleness (A22-DEL-3); emission continues but blind |
| Alert fatigue (CRITICAL ignored) | Re-tune thresholds; a chronically-firing CRITICAL is a defect (A22-ALERT-3) |
| Security-invariant indicator fires | Page immediately regardless of rate (A22-ALERT-2) |

------

# 13. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Interpreting "no data / metric gap" as healthy instead of a WARNING (A22-MODEL-4) — blind is not healthy.
2. ❌ Rate-tuning security-invariant indicators (zeroization failure, plaintext leak, revocation-sever) instead of paging on ANY occurrence (A22-ALERT-2, A22-IN-1, A22-OUT-3).
3. ❌ Setting complaint-rate thresholds arbitrarily instead of anchoring them to the enforced bulk-sender limits (0.1% warn / 0.3% critical) (A22-DEL-1).
4. ❌ Conflating business metrics with health indicators, paging on normal business variation (A22-SEP-1).
5. ❌ Instantaneous thresholds that flap on transient spikes instead of windowed evaluation (A22-MODEL-2).
6. ❌ Hard-coding thresholds as immutable constants instead of tunable, versioned config (A22-MODEL-3).
7. ❌ Treating revocation-propagation latency as mere performance rather than a security SLO (A22-KEY-1, A17-TOK-5).
8. ❌ Not alerting on webmail-disable purge overrun, silently breaching the data-minimization window (A22-WEB-1).
9. ❌ Ignoring fail-closed queue depth > 0 as "just queued" instead of a WARNING that outbound is blocked (A22-OUT-1).
10. ❌ Leaving a chronically-firing CRITICAL un-tuned, causing alert fatigue that hides real incidents (A22-ALERT-3).

------

# 14. Deferred Items

- Anomaly-detection-based dynamic thresholds (learned baselines replacing static defaults) — an enhancement over the static defaults here; the baseline×N indicators already gesture at it.
- Per-tenant-tier threshold profiles (stricter for enterprise/dedicated) — the mechanism is stated (A22-MODEL-3); the concrete profiles are a commercial/ops artifact.
- Composite health scores (roll-up per plane) for a single-pane status view — dashboard concern (A18/ops).
- Synthetic probes (active end-to-end send/receive canaries) — an ops addition complementing these passive indicators.

------

*End of document.*
