# Diamy Mail — ANNEX A28: Presence & Calendar-Driven Status

**Document title:** Diamy Mail — ANNEX A28: Presence & Calendar-Driven Status
**Version:** 1.0
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 5th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification (A00)
**Sibling dependencies:** A04 (Native Sync API v1.3), A12 (Calendar Core v1.2), A14 (iTIP/iMIP Interop v1.2), A15 (Free/Busy v1.1), A17 (IAM v1.5), A19 (Client SDK v1.2)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 5th 2026 | Cédric BORNECQUE | Initial document: presence model (Teams-style states), consent posture mirroring A15 (default-deny, scoped, separate consent from free/busy), calendar-driven automatic presence computed strictly on-device (the client publishes the state, never the reason — A15-PROJ-1 discipline reapplied), source-precedence model (manual > DND > calendar > activity), multi-device aggregation, TTL/heartbeat aging, no-history retention rule, watcher authorization via A17, distribution over the A04 plane, failure model, test scenarios, common AI errors. Brings the "presence-style real-time availability" item deferred in A15 §11 into scope (A15's deferred line to be updated at its next version bump). |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies **presence**: a real-time, coarse user status (available / busy / in-meeting / do-not-disturb / away / offline) visible to authorized colleagues, in the manner popularized by Microsoft Teams — including the **calendar-driven automatic transitions**: when a confirmed calendar appointment begins, the user's presence automatically reflects it, and reverts when it ends.

Presence is distinct from free/busy (A15): free/busy answers "will X be available at future time T?" for scheduling; presence answers "what is X's status right now?" for communication. They share the same privacy discipline but are separate capabilities with **separate consents** (§3).

This annex brings into scope the item previously deferred in A15 §11 ("Real-time availability (presence-style) beyond calendar busy"). A15's deferred list SHOULD be updated to reference this annex at its next version bump.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 The core tension (same shape as A15)

Presence is inherently an exposure: it reveals, in real time, whether a user is at their desk, in a meeting, or absent. The zero-access model keeps calendar detail encrypted (A12-ZA-1); presence asks to expose a *derived instantaneous state*. The resolution mirrors A15 exactly: presence is **opt-in / consented**, exposes only a **coarse state** (never the reason, never event detail), is **derived on the client** (which holds the decrypted calendar), and is distributed as **consented server-visible metadata** — the presence analogue of the busy projection (A15-PROJ-6).

## 1.2 Out of scope

The calendar data model (A12) and scheduling protocol (A14) — consumed, not redefined. Free/busy (A15). Notification suppression details during DND (a client/A19 behavior; the DND *state* is normative here, its effect on notification rendering is a client concern, hook noted in §10). Federated/external presence (deferred, §12). Presence-driven message routing or auto-replies (deferred, §12).

------

# 2. Presence Model

## 2.1 States

- **A28-ST-1**: The presence state set is closed (V1): `AVAILABLE`, `BUSY`, `IN_MEETING`, `DO_NOT_DISTURB`, `AWAY`, `OFFLINE`. A client MUST NOT invent additional states; extensions require a version bump of this annex (closed-set discipline, same rationale as the Tiptap closed schema A08).
- **A28-ST-2**: An OPTIONAL free-text **status message** ("back at 3pm") MAY accompany the state. It is user content: if the tenant enables status messages, they are distributed within the consent scope like the state itself, and the user MUST understand they are server-visible within that scope (disclosed, like every consented exposure). Status messages MUST NOT be auto-populated from event detail (no leaking "In meeting: Project X standup" — the title is CIPHERTEXT and stays that way, A28-CAL-3).
- **A28-ST-3**: Each published state carries the state value, an OPTIONAL status message, a source class (§4), and a timestamp (CDM-TS). Nothing else — no event UID, no location, no device identity beyond what aggregation needs server-side (§5).

## 2.2 What presence is not

- **A28-ST-4**: Presence is a **coarse, instantaneous, best-effort** signal — not an audit trail, not an attendance record, not a productivity metric. This shapes two hard rules: no server-side presence **history** is retained beyond the current state and the minimal aging data (§8, A28-RET-1), and telemetry never includes per-user states (§11).

------

# 3. Consent & Default Posture (Normative)

Mirrors A15 §3 deliberately — an implementer familiar with one MUST recognize the other.

- **A28-CONSENT-1** (default-deny): Presence is **OFF by default**. A user's state is not published, stored, or queryable until presence is enabled. Absent consent, queries return "not available" — not an error, not `OFFLINE` (which would be a false statement about a user who simply hasn't opted in).
- **A28-CONSENT-2** (scoping): Consent MUST be scopable: tenant-internal (RECOMMENDED default when enabled), specific principals, or (deferred) external. Watcher authorization is enforced via IAM (A17): only principals within the consented scope can read the state.
- **A28-CONSENT-3** (separate consents): Enabling presence MUST NOT silently enable free/busy, and vice versa. They are adjacent exposures with different shapes (instantaneous vs scheduled) and MUST be consented independently. A tenant MAY offer a combined onboarding flow, but the two toggles remain distinct and independently revocable.
- **A28-CONSENT-4** (tenant policy): A tenant MAY enable internal presence org-wide by policy (the common enterprise expectation), as a deliberate, disclosed admin choice — never a Diamy default (A15-CONSENT-3 analogue).
- **A28-CONSENT-5** (revocation): Disabling presence MUST take effect promptly: the server drops the stored state and subsequent queries return "not available". No residual state remains queryable.

------

# 4. Presence Sources & Precedence (Normative)

Presence is computed from up to four source classes. Precedence resolves conflicts deterministically:

```
1  MANUAL     user-set state (including DND and manual status message)
2  CALENDAR   client-derived from confirmed events (§6)
3  ACTIVITY   device activity heuristic (input activity → AVAILABLE,
              idle beyond threshold → AWAY)
4  BASELINE   connectivity (no live device session → OFFLINE via TTL, §8)
```

- **A28-SRC-1**: A **higher class always wins**: a manual state suppresses calendar and activity transitions for its duration; a calendar-driven `IN_MEETING` suppresses activity-derived AWAY/AVAILABLE flapping during the meeting. Baseline applies only when nothing above it holds.
- **A28-SRC-2** (manual stickiness): A manual state persists until the user clears it or its optional expiry passes ("DND for 1 hour"). It MUST NOT be silently overridden by a calendar transition — a user who set DND stays DND when their meeting starts; the calendar transition is simply masked. When the manual state clears, the then-current highest-precedence source applies immediately (if the meeting is still running, IN_MEETING appears).
- **A28-SRC-3** (source class is visible to the user, not to watchers): The user's own client MAY show *why* their state is what it is ("in a meeting until 15:00"); watchers see only the state (and optional status message). The source class travels in the published record (§2.1) solely for aggregation/precedence correctness, and MUST NOT be surfaced to watchers as meeting-detail inference material beyond what the state itself already says.

------

# 5. Multi-Device Aggregation (Normative)

- **A28-AGG-1**: Presence is a **per-principal** state, aggregated from that principal's active devices (A17 device identity). Each device session publishes its local contribution; the server-side aggregation applies the precedence model (§4) across devices: any device's MANUAL state wins (most recent manual across devices); else any device's CALENDAR state (devices share the synced calendar, A12-STO-3, so calendar contributions agree — divergence is transient sync lag, resolved by most-recent-DTSTAMP); else the **most-available** ACTIVITY state across devices (a user active on their phone is AVAILABLE even if their desktop is idle); else OFFLINE per TTL (§8).
- **A28-AGG-2**: Aggregation is the ONE presence computation that runs server-side — and it operates exclusively on the already-published coarse states, never on calendar or activity raw data (which the server does not have). This is the same boundary as A15: the server serves and combines consented projections; it never derives them.
- **A28-AGG-3**: Aggregation MUST be deterministic and idempotent: the same set of device contributions yields the same principal state (A06-SCORE-4 discipline applied to presence).

------

# 6. Calendar-Driven Presence (Normative — the A15-PROJ-1 discipline reapplied)

This is the feature motivating this annex: appointments automatically drive presence.

- **A28-CAL-1** (client-derived, mandatorily): The calendar→presence derivation MUST run **on the client**, which holds the decrypted events (A12-REC-7). The client evaluates its expanded local calendar and publishes only the resulting coarse state transition (`IN_MEETING` at DTSTART, revert at DTEND). The server MUST NOT derive presence from calendar data — not even from the `dtstart`/`dtend` scheduling metadata it may see (A12-META-1). Two reasons make this normative rather than stylistic: (a) a tenant MAY keep event times CIPHERTEXT (A12-META-2 maximum-privacy posture), in which case no server-side derivation is possible at all — the client-side design is the only one that works universally; (b) server-side derivation would couple presence correctness to the metadata-exposure tradeoff, silently pressuring tenants toward more exposure. Same architectural shape as A15-PROJ-1 and A12-ALARM-1 (client-side alarm engine): the client computes from plaintext it legitimately holds; the server receives a minimal derived result.
- **A28-CAL-2** (which events drive presence): Only events that represent a **commitment** drive automatic transitions: the user's own events and invitations with own `PARTSTAT=ACCEPTED`. `NEEDS-ACTION` and `DECLINED` MUST NOT drive presence (A14-REP-3 — an unanswered invitation is not a commitment); `TENTATIVE` SHOULD NOT by default (per-user preference MAY opt tentative in). `TRANSP:TRANSPARENT` events MUST NOT drive presence regardless of PARTSTAT (the user marked them non-blocking, A15-FB-2 semantics) — an all-day informational marker does not put the user "in a meeting" for eight hours.
- **A28-CAL-3** (state only, never the reason): The calendar-driven transition publishes `IN_MEETING` (or `BUSY` for a solo appointment, per user preference) and NOTHING derived from event content: no title, no location, no attendees, no UID, no auto-generated status message from event detail (A28-ST-2). Watchers learn the user is in a meeting; they learn nothing about which one. The event detail remains CIPHERTEXT end to end.
- **A28-CAL-4** (transitions & edge cases): Transitions occur at the event's resolved local instants (A13 timezone engine — a DST-crossing recurring meeting flips presence at the correct wall-clock time, A13-DST-1). Overlapping commitments: presence is IN_MEETING from the first DTSTART to the last DTEND of the overlapping set (no flapping at internal boundaries). Cancellation received mid-meeting (A14-CAN) reverts presence at application time. Back-dated events or clock skew MUST NOT produce retroactive publications — presence is only ever published for "now".
- **A28-CAL-5** (offline device): If no device is online to publish the transition, the presence simply ages to OFFLINE per §8 — the server does NOT simulate calendar transitions for absent clients (it structurally cannot, A28-CAL-1, and OFFLINE is the honest state for a user with no live session).

------

# 7. Distribution & Transport

- **A28-DIST-1**: Presence publication and watching reuse the **native sync/notification plane** (A04): a device publishes a state contribution as a small metadata object; watchers within the consent scope receive change notifications via the existing signal mechanism (the A12-ALARM-1 push-wakeup precedent — signal-only, minimal payload). No new transport protocol.
- **A28-DIST-2**: Watcher reads are authorization-checked per query/subscription against the publisher's consent scope (A28-CONSENT-2, A17 entitlements). Scope narrowing takes effect on the next read/notification; there is no grandfathering of removed watchers.
- **A28-DIST-3** (client UI hook): The client surfaces colleagues' presence wherever a principal is displayed (compose recipients, calendar attendee pickers, the future messaging surface). Presentation is a client concern; the datum is fixed here.

------

# 8. Freshness, TTL & Retention (Normative)

- **A28-TTL-1**: A device contribution carries an implicit freshness lease maintained by the device's live session (heartbeat or connection liveness per A04 mechanics). When all of a principal's contributions have expired, the aggregated state becomes `OFFLINE`. RECOMMENDED lease values are a deployment concern (A18/A22 health-threshold discipline); the normative point is that staleness degrades to OFFLINE, never to a frozen last-known state presented as current.
- **A28-RET-1** (no history — normative): The server stores the **current** aggregated state and per-device contributions needed for aggregation and aging — and nothing else. Presence history (state timelines, transition logs per user) MUST NOT be retained server-side. Presence is an instantaneous signal, not a surveillance record; retaining timelines would convert a consented coarse exposure into an attendance-tracking capability the user never consented to. (Aggregate, non-attributable operational counters are the only record, §11.)
- **A28-RET-2**: On consent revocation (A28-CONSENT-5) or account/device removal (A17), the stored state and contributions are dropped promptly.

------

# 9. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Presence not enabled | Query returns "not available"; not an error, not OFFLINE (A28-CONSENT-1) |
| All devices offline / lease expired | Aggregated state ages to OFFLINE (A28-TTL-1); never a stale state presented as fresh |
| Client cannot evaluate calendar (locked vault, cold start) | Calendar source absent; activity/baseline sources apply; no server-side substitution (A28-CAL-5) |
| Conflicting device contributions | Deterministic aggregation per precedence + most-recent-manual + most-available-activity (A28-AGG-1/3) |
| Clock skew / back-dated event | No retroactive publication; presence only describes "now" (A28-CAL-4) |
| Watcher outside consent scope | Read denied as "not available"; no existence/state leak (A28-DIST-2, A15-QRY-1 discipline) |
| Consent revoked | State dropped promptly; subsequent queries "not available" (A28-CONSENT-5, A28-RET-2) |
| Sync lag between devices' calendar copies | Transiently divergent CALENDAR contributions resolve by most-recent-DTSTAMP; convergence follows A04 (A28-AGG-1) |

------

# 10. Interaction Contracts

- **A28-INT-1** (A14): PARTSTAT gating per A28-CAL-2 is the normative consumer of A14-REP-3's provisional-materialization states — NEEDS-ACTION never drives presence; the accept action (A14-REP-4) is what makes an invitation presence-eligible.
- **A28-INT-2** (A15): Presence and free/busy are computed from the same decrypted local calendar by the same client, but publish different projections under different consents (A28-CONSENT-3). An implementer MUST NOT derive one from the other's server-side projection (e.g. computing IN_MEETING server-side from the busy projection — that couples the two consents and breaks when free/busy is off).
- **A28-INT-3** (DND hook): The `DO_NOT_DISTURB` state is the normative anchor for client-side notification suppression (A19 behavior). This annex fixes the state; the suppression behavior (which notifications, breakthrough rules) is a client/A19 concern, deferred there.
- **A28-INT-4** (A17): Watcher authorization, device identity for contributions, and consent-scope entitlements bind to the IAM contract (A17). Presence introduces no new authentication mechanism.

------

# 11. Observability Contract

Per A00 §11:

- counters: `presence_publications_total{source_class}`, `presence_queries_total{result}` (served/not-available/denied), `presence_consent_changes_total{from,to}`, `presence_aggregations_total`
- gauges: principals with presence enabled (by scope), active watcher subscriptions
- audit (OBS-3): consent enablement/revocation, tenant policy changes (A28-CONSENT-4)
- **A28-OBS-1**: Telemetry MUST NOT include per-user states, state timelines, or anything attributing a presence value to a principal (A28-RET-1 discipline extended to metrics) — only aggregate counts by source class and consent-state transitions. A metric like `users_currently_in_meeting` is FORBIDDEN if derivable per-user; coarse tenant-level aggregates MAY be considered only with the same scrutiny as any new exposure.

------

# 12. Test Scenarios (Normative)

1. **Default-deny**: presence never enabled → watcher query returns "not available", not OFFLINE; nothing stored (A28-CONSENT-1).
2. **Calendar transition round-trip**: user with presence enabled has an accepted 14:00–15:00 meeting → at 14:00 (correct local instant per A13) the client publishes IN_MEETING; watchers see the state and no event detail; at 15:00 it reverts (A28-CAL-1/3/4).
3. **NEEDS-ACTION does not flip**: an unanswered invitation covering "now" → presence unchanged; after accept (A14-REP-4), the next occurrence drives IN_MEETING (A28-CAL-2, A28-INT-1).
4. **Transparent event ignored**: an accepted `TRANSP:TRANSPARENT` all-day marker → presence unaffected all day (A28-CAL-2).
5. **Manual precedence**: user sets DND, meeting starts → state stays DND; DND cleared mid-meeting → IN_MEETING appears immediately (A28-SRC-1/2).
6. **Multi-device most-available**: desktop idle (AWAY contribution), phone active (AVAILABLE) → aggregated AVAILABLE; both idle → AWAY (A28-AGG-1).
7. **Offline aging**: all devices disconnect mid-meeting → state ages to OFFLINE at lease expiry; no server-simulated IN_MEETING (A28-CAL-5, A28-TTL-1).
8. **Overlapping meetings**: 14:00–15:00 and 14:30–15:30 accepted → IN_MEETING continuously 14:00–15:30, no flap at 15:00 (A28-CAL-4).
9. **Separate consents**: free/busy enabled, presence disabled → busy projection queryable, presence "not available"; and inversely (A28-CONSENT-3, A28-INT-2).
10. **Revocation**: user disables presence → stored state dropped, watchers get "not available" on next read; removed-scope watcher likewise (A28-CONSENT-5, A28-DIST-2).
11. **No history**: verify the server holds only current state + live contributions; no queryable timeline exists (A28-RET-1).
12. **No reason leakage**: intercept the published record during an IN_MEETING transition → state, optional manual status message, source class, timestamp; no UID/title/location/attendees (A28-ST-3, A28-CAL-3).
13. **Determinism**: same set of device contributions aggregated twice → identical principal state (A28-AGG-3).

------

# 13. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Computing calendar-driven presence **server-side** from `dtstart`/`dtend` metadata — tempting because times are metadata by default, but it breaks under the A12-META-2 ciphertext-times posture, couples presence to the metadata tradeoff, and violates the client-derived discipline (A28-CAL-1, A15-PROJ-1 analogue).
2. ❌ Auto-populating the status message from event detail ("In meeting: Project X") — leaks CIPHERTEXT content through a side door (A28-ST-2, A28-CAL-3).
3. ❌ Letting a NEEDS-ACTION or TRANSPARENT event flip presence (A28-CAL-2, A14-REP-3) — an unanswered invite or a non-blocking marker is not a commitment.
4. ❌ Overriding a manual DND when a meeting starts (A28-SRC-2) — manual always wins for its duration.
5. ❌ Presenting a stale last-known state as current instead of aging to OFFLINE (A28-TTL-1).
6. ❌ Retaining presence history/timelines server-side, or exposing per-user states in telemetry — converts a consented instantaneous signal into attendance surveillance (A28-RET-1, A28-OBS-1).
7. ❌ Coupling presence to free/busy: enabling one when the user consented to the other, or deriving IN_MEETING from the server-side busy projection (A28-CONSENT-3, A28-INT-2).
8. ❌ Returning OFFLINE (a false state assertion) instead of "not available" for a user who hasn't enabled presence, leaking non-participation semantics (A28-CONSENT-1).
9. ❌ Server "helpfully" simulating calendar transitions for a user whose devices are offline — structurally impossible without event access, and OFFLINE is the honest answer (A28-CAL-5).
10. ❌ Inventing additional presence states outside the closed set (A28-ST-1).
11. ❌ Non-deterministic or order-dependent multi-device aggregation, so the same contributions yield different principal states (A28-AGG-3).
12. ❌ Publishing presence transitions retroactively after clock correction or back-dated event edits (A28-CAL-4) — presence describes only "now".

------

# 14. Deferred Items

- **External/federated presence** (showing presence to non-Diamy parties or across tenants) — a larger exposure and interop scope; requires the A20/federation considerations; default remains internal-only.
- **Presence-driven behaviors** (auto-replies while DND, message deferral, "notify me when X becomes available") — build on the state fixed here; each is a separate feature with its own consent analysis.
- **DND breakthrough rules** (urgent-sender exceptions) — with the A19 notification model.
- **Rich activity sources** (in-call detection from a future voice/telephony integration — natural for W3TEL — driving a distinct `IN_A_CALL` state) — requires reopening the closed state set (A28-ST-1) with a version bump.
- **Room/resource presence** — with the resource-attendee model deferred in A14.

------

*End of document.*
