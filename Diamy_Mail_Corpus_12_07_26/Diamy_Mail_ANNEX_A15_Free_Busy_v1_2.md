# Diamy Mail — ANNEX A15: Calendar Free/Busy

**Document title:** Diamy Mail — ANNEX A15: Calendar Free/Busy
**Version:** 1.2
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 5th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.3 (A00)
**Sibling dependencies:** A12 (Calendar Core v1.3), A13 (Timezone Engine v1.2), A14 (iTIP/iMIP Interop v1.2), A17 (IAM v1.5), A28 (Presence v1.0)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: free/busy model — the privacy tension between scheduling utility and zero-access, consented busy-time projection (client-derived, minimized), transparency/CLASS-driven detail levels, RFC 5545 VFREEBUSY + iTIP free/busy query interop, internal (Diamy↔Diamy) vs external free/busy, recurring-event busy projection, default-deny posture, failure model, test scenarios, common AI errors |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: made explicit that the uploaded busy projection is stored as **consented server-visible metadata, NOT ciphertext** — this is the deliberate, disclosed exception that lets the server answer queries from other users (encrypting it would make free/busy impossible); it is the single calendar datum a user consents to expose, and only when free/busy is enabled (A15-PROJ-6). An implementer MUST NOT encrypt the projection like event detail. |
| 1.2     | Jul 5th 2026 | Cédric BORNECQUE | Coherence bump (corpus batch with A28/A29): the deferred item "real-time availability (presence-style)" is now specified by **A28 (Presence v1.0)** — deferred line replaced by a cross-reference; A28-CONSENT-3 makes presence and free/busy separate, independently-revocable consents, and A28-INT-2 forbids deriving one from the other's server-side projection. Sibling references updated to current versions. |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies **free/busy**: how a user's availability (busy/free time blocks, without event detail) is computed, exposed, and queried for scheduling, while respecting the zero-access model. Free/busy is the feature that most tests the privacy boundary, because it inherently exposes *when* a user is busy — so it is a **consented, minimized** capability, not an on-by-default one.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 The core tension

Free/busy is useful (find a meeting slot without seeing everyone's event details) but it exposes availability metadata (when you have events). The zero-access model (A12-ZA-1) keeps event *detail* encrypted; free/busy asks to expose *timing*. This annex resolves the tension by: making free/busy **opt-in / consented**, exposing only **busy/free blocks** (never detail), deriving the projection **on the client** (which has the decrypted events), and uploading only a **minimized busy-time projection** — never the raw events or times of individual events beyond the busy intervals the user agreed to share.

## 1.2 Out of scope

Event storage (A12). Timezone math (A13, used to compute busy intervals correctly across DST). The scheduling message protocol (A14, which carries free/busy queries via iTIP where used).

------

# 2. Free/Busy Model

- **A15-FB-1**: Free/busy is a set of **busy time intervals** over a queried window, each with a **busy type** (RFC 5545 FBTYPE: `BUSY`, `BUSY-TENTATIVE`, `BUSY-UNAVAILABLE`, or `FREE`). It contains NO event detail — no title, no location, no attendees, no description. It answers "is this person busy at time T?" and nothing more.
- **A15-FB-2** (transparency drives inclusion): Only events marked `TRANSP:OPAQUE` (A12 `transparency`) contribute to busy time; `TRANSP:TRANSPARENT` events (e.g. an all-day informational marker the user set as non-blocking) do NOT. This is the RFC 5545 semantics and gives the user control over what counts as "busy".
- **A15-FB-3** (CLASS-aware detail): Even within busy exposure, the event `CLASS` (A12, public/private/confidential) MAY modulate what a querier sees: a `CONFIDENTIAL` event contributes a plain `BUSY` block with no distinguishing type; a `PUBLIC` event MAY (per tenant/user policy) expose slightly more (e.g. tentative vs confirmed). The default is minimal: everything contributes an opaque `BUSY` block, detail withheld.

------

# 3. Consent & Default Posture (Normative)

- **A15-CONSENT-1** (default-deny): Free/busy exposure is **OFF by default**. A user's availability is NOT server-visible or queryable until the user/tenant enables free/busy sharing. This is the zero-access-consistent default (A12-META-2: maximum privacy out of the box). Enabling free/busy is a consented, disclosed action (like webmail, A05-BI-9).
- **A15-CONSENT-2** (scoping): Consent MUST be scopable: a user MAY share free/busy with their tenant/organization (internal colleagues) but not externally, or with specific principals, or publicly. The default when enabled SHOULD be **internal-only** (tenant colleagues), the least-exposing useful setting. External free/busy is a further, separate opt-in.
- **A15-CONSENT-3**: Tenants MAY set an org-wide policy (e.g. internal free/busy on by default for all employees — a common enterprise expectation — while external stays off). A tenant enabling internal free/busy by default MUST be a deliberate admin choice, disclosed to users, not a Diamy default.

------

# 4. Client-Derived, Minimized Projection (Normative)

This is how free/busy coexists with zero-access.

- **A15-PROJ-1**: The busy-time projection MUST be **derived on the client** (which holds the decrypted events, A12-REC-7) — the server cannot compute it from encrypted events. The client expands recurrence (A12/A13), applies transparency (A15-FB-2), and produces a set of busy intervals over a rolling window (e.g. the next N months).
- **A15-PROJ-2** (minimization): The client uploads ONLY the busy intervals (start/end/type), NOT the underlying events, titles, or per-event times beyond the busy-block boundaries. The projection is the minimal data needed to answer availability. Adjacent/overlapping busy blocks SHOULD be **merged** (so the projection reveals "busy 09:00–12:00", not three back-to-back meetings — merging reduces information leakage about meeting density).
- **A15-PROJ-3** (recurring events): Because the RRULE is CIPHERTEXT and the server cannot expand it (A12-META-4), a recurring event's busy contribution MUST be included in the client-derived projection — the client expands the series (A13-DST-1, correct per-instance times) and contributes the resulting busy intervals within the window. The server never sees the RRULE; it sees only the resulting busy blocks the client uploaded. This is precisely why the projection is client-derived (A12-META-4).
- **A15-PROJ-4** (refresh): The projection is refreshed by the client as events change or the rolling window advances. A stale projection is a correctness issue (shows availability that no longer holds); the client MUST re-derive and re-upload on relevant changes, bounded to avoid excessive churn.
- **A15-PROJ-5** (what the server learns): With free/busy enabled, the server (and authorized queriers) learn the user's busy intervals within the shared scope — a disclosed exposure (A15-CONSENT-1). The server still does NOT learn event detail. This exposure is strictly the busy blocks the user consented to share, nothing more (A15-PROJ-2).
- **A15-PROJ-6** (projection is consented metadata, NOT ciphertext — normative): The uploaded busy projection MUST be stored as **server-visible metadata**, NOT as CIPHERTEXT. This is the deliberate, consented exception to the calendar's otherwise-encrypted storage (A12-ZA-1): the whole point of free/busy is that the server answers availability queries from *other* users, which it can only do if it can read the busy blocks. Encrypting the projection like event detail would make free/busy impossible. So enabling free/busy is precisely a consent to expose this one derived, minimized datum (the merged busy intervals) as server-readable metadata — and nothing else about the calendar. An implementer MUST NOT encrypt the projection (that breaks queries), and MUST NOT expand it beyond the minimized busy blocks (that leaks more than consented, A15-PROJ-2). The projection is the single calendar field that crosses from ciphertext to consented metadata, and only when the user opts in.

------

# 5. Querying Free/Busy

## 5.1 Internal (Diamy ↔ Diamy)

- **A15-QRY-1**: An internal query ("when is colleague X free between dates?") is answered from X's uploaded projection, subject to X's consent scope (A15-CONSENT-2) and the querier's authorization (same tenant / permitted principal, via IAM A17). The querier receives busy/free blocks only. If X has not enabled internal free/busy, the query returns "not available" (not an error, not a leak) — X's non-participation is itself minimally disclosed.
- **A15-QRY-2** (scheduling assist): The internal free/busy powers "find a time" across attendees when scheduling a Diamy↔Diamy meeting (A14): the organizer's client queries participants' projections and suggests free slots. This runs within the consent scopes; a participant who hasn't shared internal free/busy is shown as "availability unknown", not blocking scheduling but not revealing their calendar.

## 5.2 External (iTIP free/busy)

- **A15-QRY-3**: RFC 5546 defines an iTIP free/busy query (`METHOD:REQUEST` with `VFREEBUSY`) and reply (`METHOD:REPLY` with `VFREEBUSY`). For external interop, Diamy MAY answer an external free/busy request ONLY if the user has enabled external free/busy sharing (A15-CONSENT-2) for that context, returning a `VFREEBUSY` with busy blocks only. Absent consent, Diamy declines/does not respond (default-deny). Outbound external free/busy queries (asking an external system) are best-effort, subject to the same third-party quirks as A14 (registry).
- **A15-QRY-4** (external exposure = disclosed): Answering an external free/busy query exposes the user's busy times to an external party — a boundary relaxation analogous to A14-ZA (external invitee), disclosed and consented, defaulting off.

------

# 6. Recurring & Timezone Correctness

- **A15-TZ-1**: Busy intervals MUST be computed with correct timezone/DST handling (A13): a weekly 09:00–10:00 Paris meeting contributes a busy block at the correct UTC instant each week, shifting across DST (A13-DST-1). A projection computed with naive UTC arithmetic would show busy at the wrong hour after a DST transition. Because the projection is client-derived, it uses the client's A13 engine (A19 parity).
- **A15-TZ-2**: The projection's intervals SHOULD be expressed in UTC (unambiguous for cross-zone querying) with the understanding that a querier in another zone displays them in their local time. All-day opaque events (rare as busy) and floating events (A13-VAL) are handled per their semantics — a floating "busy" is ambiguous across zones and SHOULD be treated conservatively (documented).

------

# 7. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Free/busy not enabled | Query returns "not available"; no leak, no error (A15-QRY-1) |
| Projection stale | Client re-derives on change; a query on stale data is a correctness bug to bound (A15-PROJ-4) |
| Server asked to compute free/busy from encrypted events | Impossible by design; only the client-derived projection is available (A15-PROJ-1/3) |
| Recurring event in projection | Client expands (A13-DST-1), contributes correct busy blocks; server never sees RRULE (A15-PROJ-3) |
| External free/busy request without consent | Default-deny; decline/no-response (A15-QRY-3) |
| Participant hasn't shared for scheduling | "Availability unknown"; does not block, does not reveal (A15-QRY-2) |
| DST-crossing busy block | Correct per-instance UTC (A15-TZ-1) — not naive UTC arithmetic |

------

# 8. Observability Contract

Per A00 §11:

- counters: `freebusy_projections_uploaded_total`, `freebusy_queries_total{scope,result}` (scope = internal/external), `freebusy_consent_changes_total{from,to}`, `external_freebusy_declined_total` (default-deny hits)
- gauges: users with free/busy enabled (by scope), average projection window
- audit (OBS-3): free/busy consent changes, external free/busy exposures (the disclosed relaxation, A15-QRY-4)
- **A15-OBS-1**: Telemetry MUST NOT include busy intervals, event times, or anything reconstructing a user's schedule (A12-OBS-1 discipline) — only counts, scopes, and consent-state transitions.

------

# 9. Test Scenarios (Normative)

1. **Default-deny**: new user, free/busy not enabled → an internal query returns "not available"; nothing about their calendar is exposed (A15-CONSENT-1, A15-QRY-1).
2. **Internal sharing**: user enables internal free/busy → a colleague's "find a time" sees busy/free blocks, NO titles/detail (A15-FB-1, A15-QRY-2).
3. **Minimized projection**: three back-to-back meetings 09:00–12:00 → projection uploads a single merged 09:00–12:00 busy block, not three (A15-PROJ-2).
4. **Recurring in projection**: weekly meeting → client expands (correct per-instance UTC across DST), contributes weekly busy blocks; server never sees the RRULE (A15-PROJ-3, A15-TZ-1).
5. **Transparency respected**: a `TRANSP:TRANSPARENT` all-day marker does NOT contribute busy time (A15-FB-2).
6. **Confidential class**: a CONFIDENTIAL event contributes a plain BUSY block with no distinguishing detail (A15-FB-3).
7. **External default-deny**: external iTIP free/busy request with no external consent → declined/no-response (A15-QRY-3).
8. **External consented**: user enabled external free/busy → external VFREEBUSY reply with busy blocks only; audit-logged (A15-QRY-3/4).
9. **Unknown participant in scheduling**: a participant hasn't shared internal free/busy → shown "availability unknown", scheduling proceeds, calendar not revealed (A15-QRY-2).
10. **Server cannot compute**: verify no server path expands encrypted events for free/busy; only the client projection is used (A15-PROJ-1).

------

# 10. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Enabling free/busy by default instead of default-deny consented sharing (A15-CONSENT-1).
2. ❌ Exposing event detail (titles, locations, attendees) in free/busy instead of busy/free blocks only (A15-FB-1).
3. ❌ Computing free/busy server-side from events the server cannot read — impossible; MUST be client-derived (A15-PROJ-1).
4. ❌ Uploading the raw events or per-event times instead of the minimized, merged busy projection (A15-PROJ-2).
5. ❌ Not merging adjacent busy blocks, leaking meeting density (A15-PROJ-2).
6. ❌ Trying to expand a recurring event server-side for free/busy (no RRULE server-side) instead of the client contributing the expanded busy blocks (A15-PROJ-3, A12-META-4).
7. ❌ Ignoring transparency (counting TRANSPARENT events as busy) (A15-FB-2).
8. ❌ Answering external free/busy without consent, leaking availability (A15-QRY-3) — default-deny.
9. ❌ Naive UTC arithmetic for recurring busy blocks, wrong after DST (A15-TZ-1, A13-DST-1).
10. ❌ Returning an error (leaking existence/state) instead of "not available" when free/busy is not shared (A15-QRY-1).
11. ❌ Logging busy intervals / reconstructing a schedule in telemetry (A15-OBS-1).
12. ❌ Encrypting the uploaded busy projection like event detail — the server must read it to answer queries; it is consented metadata, not ciphertext (A15-PROJ-6). Encrypting it makes free/busy non-functional.

------

# 11. Deferred Items

- Server-side minimized busy projection with additional privacy tech (e.g. bucketed/coarsened times, differential-privacy-style noise for aggregate availability) — an enhancement over plain busy blocks; deferred.
- Delegated free/busy (an assistant seeing a principal's availability) — depends on the IAM entitlement extension deferred in A17.
- Room/resource free/busy (booking rooms) — ties to the resource-attendee model deferred in A14.
- Cross-org (federated) free/busy with other Diamy tenants or external systems — a larger interop scope; deferred with A20/federation considerations.
- ~~Real-time availability (presence-style) beyond calendar busy~~ — now in scope, specified by **A28 (Presence v1.0)**. Presence and free/busy remain separate, independently-consented exposures (A28-CONSENT-3); neither is derived from the other's server-side projection (A28-INT-2).

------

*End of document.*
