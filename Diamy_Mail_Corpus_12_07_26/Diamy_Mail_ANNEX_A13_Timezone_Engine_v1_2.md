# Diamy Mail — ANNEX A13: Calendar Timezone Engine

**Document title:** Diamy Mail — ANNEX A13: Calendar Timezone Engine
**Version:** 1.2
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.3 (A00)
**Sibling dependencies:** A12 (Calendar Core Model v1.1), A14 (iTIP/iMIP Interop), A15 (Free/Busy)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: calendar timezone engine — IANA tz database as canonical authority, VTIMEZONE handling, Windows↔IANA mapping (CLDR), floating/UTC/zoned time semantics, DST transition correctness, recurrence×DST interaction, all-day event semantics, tz database update discipline, cross-client consistency rules, failure model, test scenarios, common AI errors |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Coherence close: the A22 tzdata/CLDR version-skew health indicator flagged in v1.1 was DELIVERED in A22 v1.2 (§9bis, A22-CAL-1) — this forward-dependency is now closed; §13 updated to reflect delivery. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: CORRECTED a factual error in the worked DST example (test scenario 2) — 09:00 Europe/Paris is 08:00Z in winter (CET, UTC+1) and 07:00Z in summer (CEST, UTC+2); v1.0 wrongly wrote "07:00Z winter". Verified against a real tz computation. (A wrong worked number in a codegen spec is dangerous — corrected.) Flagged that A22 needs a tzdata/CLDR version-skew health indicator (A13-OBS-2, pending A22 addition). |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies the **timezone and DST engine** for Diamy calendar: how event times are anchored to timezones, how VTIMEZONE (RFC 5545) is handled, how Windows timezone names map to IANA, and how recurrence interacts with DST transitions. Timezone errors are the second-hardest calendar correctness problem after recurrence (A12), and the two interact (a weekly 9 AM meeting must stay 9 AM local across a DST change).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Why this is hard

A meeting is not "at UTC instant X"; it is "at 9 AM in Europe/Paris", which maps to different UTC instants before and after a DST transition. Storing only a UTC instant loses the local intent and breaks when the DST rules or the user's expectation shift. Different clients (Outlook with Windows tz names, Google with IANA, Apple with its own VTIMEZONE quirks) represent this differently, and mismatches cause the notorious "meeting moved by an hour" bug. This annex fixes a single internal model and the mappings to/from each foreign representation.

## 1.2 Out of scope

The event model itself (A12). The invitation protocol and per-client ICS quirks (A14 registry). Free/busy time math (A15, which uses this engine).

------

# 2. Canonical Timezone Authority

- **A13-TZ-1**: The **IANA time zone database** (tzdata / Olson) is the canonical timezone authority for Diamy. All internal timezone identifiers are IANA names (`Europe/Paris`, `America/New_York`). Windows names, VTIMEZONE definitions, and ad-hoc offsets are converted **to** IANA on ingest and converted **from** IANA on emit (§5, §6).
- **A13-TZ-2**: The engine MUST use a maintained tz implementation (not hand-rolled offset tables): the platform's ICU/tz where reliable, or a vendored tzdata with the same version on server and client. Timezone math (local↔UTC, DST transitions) MUST come from this library, never from hard-coded offsets (offsets change; Morocco, Egypt, and others alter DST rules with little notice).
- **A13-TZ-3** (version parity): The tzdata **version** used MUST be tracked and kept consistent across server and all clients (A19 parity discipline). A client on an older tzdata can compute a different UTC instant for the same local time near a rule change, producing cross-device disagreement. tzdata version is a synchronized artifact; updates roll out to all components (§8).

------

# 3. Time Value Semantics (Normative)

RFC 5545 defines three date-time forms; the engine MUST handle all three distinctly.

- **A13-VAL-1** (zoned / `TZID`): A date-time with a `TZID` (e.g. `DTSTART;TZID=Europe/Paris:20260315T090000`) means "9 AM local in that zone". This is the common case. It is stored with its IANA `TZID` preserved (the local intent), and resolved to a UTC instant only for display/comparison in another zone. The `TZID` MUST be retained — collapsing to UTC on storage loses the local intent (A13-VAL-4).
- **A13-VAL-2** (UTC): A date-time with a trailing `Z` (`20260315T080000Z`) is an absolute instant. Stored as UTC; displayed in the viewer's zone.
- **A13-VAL-3** (floating): A date-time with NO `TZID` and no `Z` is **floating** — it means the same wall-clock time in whatever zone the viewer is in (e.g. a "reminder at 9 AM wherever I am"). Floating time MUST NOT be silently converted to a zoned or UTC time; that changes its meaning. Floating is rare but must be preserved as floating.
- **A13-VAL-4** (preserve intent): The engine MUST store the **authored form** (zoned with TZID, UTC, or floating) and MUST NOT normalize everything to UTC instants. A zoned event stored as a bare UTC instant will drift if the zone's DST rules change or if "9 AM Paris" was the intent. Retaining `TZID` is what makes "9 AM local" survive DST and rule changes.

## 3.1 All-day events

- **A13-VAL-5** (all-day / DATE): An all-day event uses a DATE value (no time), e.g. `DTSTART;VALUE=DATE:20260315`. It is **date-only**, timezone-independent, and MUST NOT be given a time or timezone (a common bug is treating all-day as midnight-in-some-zone, which makes it span the wrong day for viewers in other zones). All-day events are the same date for everyone; they are not "midnight UTC to midnight UTC".

------

# 4. VTIMEZONE Handling

- **A13-VTZ-1**: Inbound ICS may carry a `VTIMEZONE` component defining a zone's offsets/DST rules inline (RFC 5545). The engine MUST map an inbound `VTIMEZONE` to the correct **IANA zone** where possible (by `TZID` name match, then by rule-signature match for non-standard names), rather than trusting the inline rules blindly. Many clients emit a `TZID` that is a Windows name or a custom string with inline rules; the engine resolves it to IANA (§5).
- **A13-VTZ-2**: Where an inbound `VTIMEZONE` cannot be matched to a known IANA zone (truly custom/unknown), the engine MUST fall back to the inline `VTIMEZONE` rules to interpret that event's times (they are self-contained), while flagging the unknown zone (A14 registry candidate). It MUST NOT drop the event or guess an offset.
- **A13-VTZ-3** (emit): On emitting ICS to an external client (A14), the engine MUST include a correct `VTIMEZONE` for any `TZID` used, generated from the IANA data, because some clients (older Outlook) require the inline `VTIMEZONE` and do not resolve bare IANA `TZID`s. This is an interop obligation, not optional.

------

# 5. Windows ↔ IANA Mapping

- **A13-WIN-1**: Outlook/Exchange historically use **Windows timezone names** (`"Romance Standard Time"` = `Europe/Paris`, `"Pacific Standard Time"` = `America/Los_Angeles`). The engine MUST map Windows↔IANA using the **CLDR windowsZones mapping** (the authoritative Unicode mapping), not a hand-maintained table. Windows→IANA is many-to-one-ish (a Windows zone maps to a representative IANA zone + a territory); IANA→Windows uses the CLDR reverse mapping.
- **A13-WIN-2**: The CLDR mapping MUST be versioned and updated with tzdata (§8); a stale mapping mis-resolves newer zones. Unmapped Windows names (rare, very old, or bogus) are handled per A13-VTZ-2 (fall back to inline VTIMEZONE, flag).
- **A13-WIN-3**: On emit to an Outlook/Exchange recipient (A14), the engine SHOULD emit a `TZID` the recipient will accept — either an IANA `TZID` with an accompanying `VTIMEZONE` (A13-VTZ-3), or, where a client is known to require Windows names (A14 registry), the mapped Windows name. The choice is driven by the A14 known-behavior registry per recipient client.

------

# 6. Recurrence × DST Interaction (Normative)

This is where timezone and recurrence (A12) collide, and where the "meeting moved an hour" bug lives.

- **A13-DST-1**: A recurring event authored in a zoned time (e.g. weekly `TZID=Europe/Paris` 09:00) means **09:00 local every week**, which is different UTC instants across a DST transition. The engine MUST expand the recurrence in the event's **local zone** and resolve each instance to UTC individually, so every instance is 09:00 Paris regardless of whether Paris is on CET or CEST that week. Expanding in UTC (adding 7×24 h) is WRONG — it drifts by an hour after the DST change.
- **A13-DST-2** (skipped local times — spring forward): When a DST transition **skips** a local time (e.g. 02:30 does not exist on spring-forward day), an instance landing on the skipped time MUST be resolved by a defined rule (RECOMMENDED: shift forward to the next valid instant, matching common client behavior), consistently, and the choice documented. It MUST NOT silently drop the instance or produce an invalid time.
- **A13-DST-3** (ambiguous local times — fall back): When a transition **repeats** a local time (e.g. 02:30 occurs twice on fall-back day), an instance landing there MUST be resolved by a defined rule (RECOMMENDED: the first/earlier occurrence), consistently and documented. It MUST NOT be ambiguous or non-deterministic.
- **A13-DST-4**: The skipped/ambiguous resolution rules MUST match, as closely as the RFC and reality allow, the behavior of the major clients (Outlook/Google) so a Diamy-expanded series and a foreign-expanded copy agree. Divergences are A14 registry entries. Cross-client instance agreement is the goal; where clients themselves disagree, the discrepancy is recorded, not silently resolved in a way that surprises the user.

------

# 7. Cross-Client Consistency Rules

- **A13-CC-1**: The single most important consistency invariant: **a zoned event's local time is preserved; its UTC instant is derived.** Two clients agreeing on "9 AM Paris" but on different tzdata versions can still disagree on the UTC instant near a rule change — hence version parity (A13-TZ-3) and preserving `TZID` (A13-VAL-4) together.
- **A13-CC-2**: When Diamy is the organizer and expands a series for display, and an external client expands the same series, they MUST agree instance-by-instance for the common case (no rule-change edge). The engine's expansion (local-zone, per-instance UTC resolution, A13-DST-1) is what makes this hold.
- **A13-CC-3**: The RECURRENCE-ID of an override (A12-REC-3) is interpreted in the **series' timezone**: the original instance's local time in that zone. Timezone mishandling of RECURRENCE-ID is a way overrides detach — the RECURRENCE-ID's zone MUST be the series zone, resolved with this engine.

------

# 8. tzdata / CLDR Update Discipline

- **A13-UPD-1**: tzdata and the CLDR windowsZones mapping MUST be updatable without a full application release (governments change DST rules with weeks of notice; a stale tzdata computes wrong future instants). The update mechanism MUST propagate a consistent version to server and all clients (A13-TZ-3).
- **A13-UPD-2**: A tzdata update MUST NOT retroactively corrupt stored events: because events store their authored form (TZID + local time, A13-VAL-4), a rule change correctly re-resolves future instances to the new UTC instants — which is the *desired* behavior (the meeting stays 9 AM local under the new rule). Events stored as bare UTC would instead be silently wrong after a rule change. This is the core reason for A13-VAL-4.
- **A13-UPD-3**: The tzdata version in force MUST be observable (health/metadata) so a version skew between components is detectable (A22 — a new indicator: tzdata version consistency).

------

# 9. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Unknown/custom VTIMEZONE | Fall back to inline VTIMEZONE rules; flag unknown zone (A13-VTZ-2, A14 registry) |
| Unmapped Windows tz name | Fall back to inline VTIMEZONE; flag (A13-WIN-2) |
| Recurrence instance on skipped local time (spring-forward) | Defined shift-forward rule, consistent (A13-DST-2) |
| Recurrence instance on ambiguous local time (fall-back) | Defined earlier-occurrence rule, consistent (A13-DST-3) |
| tzdata version skew between components | Detect + alert (A13-UPD-3); resolve to consistent version |
| Floating time about to be normalized | Preserve as floating; never auto-zone it (A13-VAL-3) |
| All-day event given a timezone | Bug — all-day is date-only, tz-independent (A13-VAL-5) |
| Bare UTC storage of a zoned event | Bug — store the TZID + local form (A13-VAL-4) |

------

# 10. Observability Contract

Per A00 §11:

- counters: `tz_resolutions_total{result}`, `windows_tz_mappings_total{result}`, `unknown_vtimezone_total`, `dst_edge_instances_total{kind}` (skipped/ambiguous)
- gauges: tzdata version in force (per component), CLDR mapping version
- **A13-OBS-1**: Timezone telemetry is metadata-level (zone names, versions, counts) — it MUST NOT include event content. Zone names alone are low-sensitivity but MUST NOT be joined to identifiable event details in logs.
- **A13-OBS-2**: tzdata/CLDR version skew across components is a WARNING health indicator (A22 addition, A13-UPD-3) — skew silently produces cross-device disagreement.

------

# 11. Test Scenarios (Normative)

1. **Zoned preserved**: store `TZID=Europe/Paris` 09:00 → TZID retained; UTC derived for a New York viewer shows correct local; the stored form is not bare UTC (A13-VAL-1/4).
2. **DST-crossing weekly series**: weekly 09:00 Paris spanning the spring transition → every instance is 09:00 Paris local, resolving to **08:00Z in winter (CET, UTC+1)** and **07:00Z in summer (CEST, UTC+2)** — i.e. the correct per-instance UTC, NOT a fixed UTC that would make the local time drift by an hour after the transition (A13-DST-1).
3. **Spring-forward skipped instance**: a daily 02:30 series across spring-forward → the skipped-day instance resolves by the shift-forward rule, consistently (A13-DST-2).
4. **Fall-back ambiguous instance**: a daily 02:30 series across fall-back → resolves to the defined (earlier) occurrence, deterministically (A13-DST-3).
5. **Windows mapping**: inbound `TZID="Romance Standard Time"` → mapped to `Europe/Paris` via CLDR (A13-WIN-1).
6. **Unknown VTIMEZONE**: custom inline VTIMEZONE with no IANA match → interpreted from inline rules, flagged (A13-VTZ-2).
7. **All-day**: all-day event on 2026-03-15 → same date for Paris and Auckland viewers; not shifted by zone (A13-VAL-5).
8. **Floating**: floating 09:00 reminder → shows 09:00 in whatever zone the viewer is in; not auto-zoned (A13-VAL-3).
9. **tzdata update**: a future DST rule change lands via tzdata update → a stored zoned future event re-resolves to the new correct UTC instant automatically; a bare-UTC-stored event would be wrong (A13-UPD-2).
10. **Emit VTIMEZONE**: emit to an Outlook recipient → ICS includes a correct generated VTIMEZONE for the TZID (A13-VTZ-3).

------

# 12. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Storing zoned events as bare UTC instants, losing local intent and drifting after DST/rule changes (A13-VAL-4) — the root cause of most timezone bugs.
2. ❌ Expanding a zoned recurring series in UTC (adding 24 h) instead of in local zone with per-instance UTC resolution, drifting an hour after DST (A13-DST-1) — the "meeting moved an hour" bug.
3. ❌ Hand-coded offset tables instead of a maintained tzdata library (A13-TZ-2) — offsets change.
4. ❌ Treating all-day events as midnight-in-a-zone, making them span the wrong day for other-zone viewers (A13-VAL-5).
5. ❌ Silently converting floating time to zoned/UTC, changing its meaning (A13-VAL-3).
6. ❌ A hand-maintained Windows↔IANA table instead of CLDR windowsZones (A13-WIN-1).
7. ❌ Dropping or guessing on an unknown VTIMEZONE instead of using inline rules + flagging (A13-VTZ-2).
8. ❌ Non-deterministic or undocumented resolution of skipped/ambiguous DST-edge instances (A13-DST-2/3).
9. ❌ tzdata version skew between server and clients, causing cross-device instant disagreement (A13-TZ-3, A13-UPD-3).
10. ❌ Interpreting RECURRENCE-ID in the wrong timezone, detaching overrides (A13-CC-3, A12-REC-3).
11. ❌ Emitting bare IANA TZID to a client that requires an inline VTIMEZONE (older Outlook) (A13-VTZ-3).

------

# 13. Deferred Items

- **A22 tzdata-skew indicator (DELIVERED in A22 v1.2)**: The tzdata/CLDR version-skew health indicator (A13-OBS-2, A13-TZ-3) was added to A22 in v1.2 (§9bis, A22-CAL-1) — any skew is WARNING, >1 release is CRITICAL, because skew silently corrupts cross-device UTC-instant agreement. This dependency is closed.
- Per-recipient-client timezone-representation selection (IANA+VTIMEZONE vs Windows name) — driven by the A14 known-behavior registry; the mechanism is stated (A13-WIN-3), the per-client policy is A14.
- Leap-second handling — out of scope for calendar granularity (minute-level events); noted for completeness.
- User-facing timezone-conflict warnings ("this attendee is in a different zone; the time shown is your local") — a UX enhancement.
- Historical-date timezone accuracy (events far in the past, pre-tzdata-rule) — tzdata handles historical rules; edge accuracy for very old dates is best-effort.

------

*End of document.*
