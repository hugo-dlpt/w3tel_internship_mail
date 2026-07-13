# Diamy Mail — ANNEX A12: Calendar Core Model & Storage

**Document title:** Diamy Mail — ANNEX A12: Calendar Core Model & Storage
**Version:** 1.3
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 5th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.3 (A00)
**Sibling dependencies:** A02 (Storage v1.1), A03 (Vault Client v1.2), A04 (Native Sync API v1.3), A13 (Timezone Engine v1.2), A14 (iTIP/iMIP Interop v1.2), A21 (Storage Schema DDL v1.4), A28 (Presence v1.0)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: calendar core data model (RFC 5545 VEVENT subset), encrypted-at-rest calendar storage reusing the mail envelope model, recurrence model (RRULE/RDATE/EXDATE + RECURRENCE-ID override instances), participant/organizer model, attachment handling, calendar collections, sync integration, zero-access boundary for calendar data, timezone/iTIP boundary references, failure model, test scenarios, common AI errors |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Coherence close: the A21 `cal` schema extension flagged in v1.1 was DELIVERED in A21 v1.2 (§6bis) — this forward-dependency is now closed; §13 updated to reflect delivery. |
| 1.3     | Jul 5th 2026 | Cédric BORNECQUE | Coherence bump (corpus batch with A28/A29): A12-PART-2 now cross-references the PARTSTAT→presence gate (A28-CAL-2 — only own/ACCEPTED events drive automatic presence; NEEDS-ACTION/DECLINED never do, per A14-REP-3 provisional materialization); sibling references updated to current versions. No data-model change. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: clarified the recurring-event privacy detail — because the RRULE is CIPHERTEXT (A12-META-3) and only the master `dtstart` is metadata, the server sees the master start time but NOT the expanded instance times of a recurring series, unless a consented busy-projection is uploaded (A12-META-4); flagged the forward-dependency that A21 must be extended with a `cal` schema for the calendar tables (this DDL extension is a pending A21 update, tracked in §13) — A12 is the logical model, A21 remains the physical source of truth. |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies the **calendar core**: the event data model (an RFC 5545 subset), how calendar objects are stored **encrypted at rest** reusing the mail storage/envelope model (A02), the recurrence model, and the participant model. It is the foundation the timezone engine (A13), invitation interop (A14), and free/busy (A15) build on. `diamy-cald` is the calendar service (A00 §2).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Design stance

Calendar is the highest interop-risk subsystem (A00 §12 corpus plan): its value depends on interoperating with Outlook, Google, and Apple, which deviate from RFC 5545/5546 in documented and undocumented ways. This annex fixes the **internal, RFC-conformant core**; the messy third-party reality is quarantined into A14's "Known Third-Party Behaviors" registry, so the core stays clean and the deviations are handled at the boundary. The core is specifiable; the boundary is observational (A14).

## 1.2 Zero-access for calendar

- **A12-ZA-1**: Calendar event content (title, description, location, attendee list, attachments) is **user content** and MUST be encrypted at rest under the same zero-access model as mail (A00 §3, A02): the server stores ciphertext, holds no decryption key, and cannot read event details. Only the minimal routing/scheduling metadata that must be server-visible (for sync and — with consent — free/busy) is metadata (§7, A15). This is the calendar analogue of the mail storage model, and Open Decision #5 (external-invitee zero-access, A14) is the one place this is deliberately relaxed under disclosure.

## 1.3 Out of scope

Timezone/DST resolution (A13). Invitation/reply protocol iTIP/iMIP and third-party quirks (A14). Free/busy (A15). This annex is the data model + storage; the dynamic protocols are A13–A15.

------

# 2. Event Data Model (RFC 5545 subset)

- **A12-EVT-1**: The core object is a **VEVENT**-equivalent, stored as a structured record (not raw ICS) so it can be rendered, edited, and re-serialized to ICS for interop (A14). V1 supports the VEVENT component; VTODO and VJOURNAL are deferred (§13). The canonical internal representation is a typed model; ICS is an interchange format at the boundary (A14), not the storage form.

## 2.1 Core fields

| Field | RFC 5545 | Class | Notes |
| ----- | -------- | ----- | ----- |
| `event_uid` | UID | PLAINTEXT_METADATA | Stable global UID (RFC 5545); MUST be preserved across edits and round-trips (A14 threading) |
| `sequence` | SEQUENCE | PLAINTEXT_METADATA | Monotonic revision counter (iTIP update ordering, A14) |
| `dtstart` / `dtend` (or `duration`) | DTSTART/DTEND/DURATION | see §7 | Start/end; timezone-bearing (A13) |
| `summary_ct` (title) | SUMMARY | CIPHERTEXT | Event title — user content, encrypted |
| `description_ct` | DESCRIPTION | CIPHERTEXT | Body — user content, encrypted |
| `location_ct` | LOCATION | CIPHERTEXT | User content, encrypted |
| `organizer` | ORGANIZER | see §5 | Scheduling metadata (§7) |
| `attendees_ct` | ATTENDEE | CIPHERTEXT (default) | Participant list — user content; minimized metadata exposure like mail recipients (A02-DM-4 analogue) |
| `status` | STATUS | PLAINTEXT_METADATA | tentative/confirmed/cancelled (scheduling-relevant) |
| `transparency` | TRANSP | PLAINTEXT_METADATA | opaque/transparent — drives free/busy (A15) |
| `recurrence` | RRULE/RDATE/EXDATE | see §3 | Recurrence definition |
| `recurrence_id` | RECURRENCE-ID | PLAINTEXT_METADATA | Identifies an overridden instance (§3) |
| `created` / `last_modified` / `dtstamp` | | PLAINTEXT_METADATA | CDM-TS timestamps |
| `alarms_ct` | VALARM | CIPHERTEXT | Reminders — user content |
| `classification` | CLASS | PLAINTEXT_METADATA | public/private/confidential (RFC 5545 CLASS; informs free/busy detail, A15) |

- **A12-EVT-2**: `summary_ct`, `description_ct`, `location_ct`, `attendees_ct`, `alarms_ct` are CIPHERTEXT (A21 discipline): the server cannot read them. `dtstart`/`dtend`, `status`, `transparency`, and `class` are the minimal scheduling metadata needed for sync and (consented) free/busy — the calendar analogue of mail's routing metadata (§7).
- **A12-EVT-3**: `event_uid` MUST be preserved verbatim across every edit, sync, and ICS round-trip — it is the identity anchor for updates/replies/cancellations (A14) and for matching an override to its series (§3). Regenerating a UID on edit is a data-integrity bug (breaks the whole invitation chain).

------

# 3. Recurrence Model (Normative)

Recurrence is the single hardest part of calendar correctness (the corpus's flagged risk). This annex fixes the model; A13 fixes timezone/DST interaction.

- **A12-REC-1**: A recurring event is defined by a master VEVENT carrying `RRULE` (and/or `RDATE` additions, `EXDATE` exclusions). The recurrence set is **computed**, not stored per-instance — storing every instance is wrong (infinite/large series) and diverges on edit. The engine expands the RRULE on demand within a queried window (bounded, §3.4).
- **A12-REC-2** (override instances): A single instance of a series MAY be modified (moved, retitled, cancelled) via an **override VEVENT** sharing the series `event_uid` and carrying a `RECURRENCE-ID` identifying which instance it replaces. The override is a separate stored object linked to the master by `(event_uid, recurrence_id)`. This is the RFC 5545 model and MUST be followed exactly — Outlook and Google both rely on it (A14).
- **A12-REC-3** (RECURRENCE-ID semantics): The `RECURRENCE-ID` value is the **original** start time of the instance being overridden (in the series' timezone), NOT the new time. Getting this wrong (using the new time) is a classic bug that detaches the override from its instance. A13 governs how the timezone applies to this value.
- **A12-REC-4** (cancellation of one instance): Cancelling a single occurrence is expressed as an `EXDATE` on the master (removing that occurrence) OR an override with `STATUS:CANCELLED` — the engine MUST handle both forms (different clients emit different forms; A14 registry).
- **A12-REC-5** (this-and-future edits): "Change this and all following" is modeled per RFC 5545 by splitting the series: the master's `RRULE` is bounded with an `UNTIL`, and a new series starts from the edit point with a new `event_uid`. The client MUST implement the split correctly so interop clients see a coherent result (A14).
- **A12-REC-6** (bounded expansion): RRULE expansion MUST be bounded by the query window and a hard instance cap (guard against `RRULE` with no `UNTIL`/`COUNT` producing unbounded sets). An unbounded expansion request is clamped to the window, never expanded infinitely (A18-BOUND analogue, client-side A19-bound).

## 3.4 Expansion discipline

- **A12-REC-7**: Instance expansion happens **client-side** on decrypted event data (the RRULE lives inside the event; recurrence detail is user content). The server does NOT expand recurrence (it cannot read most of the event) — it stores master + overrides as opaque objects with only the scheduling metadata visible. Free/busy expansion that must happen server-side (A15) uses only the consented time metadata, never the encrypted detail.

------

# 4. Storage Model (reuses A02)

- **A12-STO-1**: Calendar objects are stored using the **same envelope model as mail** (A02): each event (master or override) is encrypted once under a fresh `k_event` (AES-256-GCM), wrapped per authorized device via ML-KEM-768 + HKDF (A02-CRY-4 discipline, distinct `info` label for calendar, e.g. `INFO_CALENDAR_ENVELOPE`). The server stores ciphertext + per-device envelopes + minimal scheduling metadata. No new crypto — the mail envelope mechanism is reused wholesale (A00 SEC-CRYPT reuse).
- **A12-STO-2**: A **calendar collection** (a calendar the user owns or is shared into) groups events, analogous to a mail folder. Collection names are CIPHERTEXT (client-encrypted, like folder names A02-DM-1); the server sees collection UUIDs.
- **A12-STO-3**: Calendar objects sync through the **same native sync API** as mail (A04): journal events (`event_added`, `event_updated`, `event_deleted`, `override_added`), cursor-based pull, blobs-by-reference for large event data (rare; most events are small and fit in the catalogue-equivalent row). No separate sync protocol — calendar is another object type on the existing sync plane.
- **A12-STO-4**: The physical schema for calendar tables (events, overrides, collections, participant metadata) is defined in A21 (extended) as the source of truth; this annex is the logical model. The tables follow the same classification discipline (CIPHERTEXT for content, metadata only for scheduling fields).

------

# 5. Organizer & Attendee Model

- **A12-PART-1**: The **organizer** is the scheduling authority for an event (RFC 5545/5546). For a Diamy-organized event, the organizer is a Diamy principal (A17); the organizer address is scheduling metadata (needed to route replies, A14) — canonicalized via A24. For an event Diamy received as an invitation, the organizer is external.
- **A12-PART-2**: **Attendees** carry a role (req/opt/chair), a participation status (`PARTSTAT`: needs-action/accepted/declined/tentative), and an RSVP flag. The full attendee list is user content (CIPHERTEXT `attendees_ct` by default); however, the **scheduling subset** needed to send/receive iTIP (A14) is handled at the boundary where plaintext is transiently required to emit an invitation (the outbound calendar analogue of the mail frontier exception, A14). `PARTSTAT` additionally gates calendar-driven presence: only own/ACCEPTED events drive automatic presence transitions; NEEDS-ACTION and DECLINED never do (A28-CAL-2, A14-REP-3).
- **A12-PART-3** (attendee-list minimization): As with mail recipients (A02-DM-4), an attendee's stored view of an event SHOULD NOT gratuitously expose the entire attendee list as server-visible metadata; the list lives in `attendees_ct`. Where a tenant enables server-side scheduling features (free/busy across attendees), the exposure is explicit and consented (A15), not default.

------

# 6. Attachments & Alarms

- **A12-ATT-1**: Event attachments (RFC 5545 ATTACH) are handled like mail attachments where they are binary: stored as encrypted blobs (A02), referenced by the event, and — if received from outside — subject to the same attachment trust model (A07) since a calendar invite can carry a malicious attachment. Inline `ATTACH` URIs follow the link-safety rules (A07/A08).
- **A12-ALARM-1**: `VALARM` reminders are user content (`alarms_ct`, CIPHERTEXT). Alarm triggering is **client-side** (the client has the decrypted event and computes the trigger); the server does NOT fire alarms (it cannot read them). Push-wakeup for alarms uses the signal-only mechanism (A04 deferred / A19), carrying no content.

------

# 7. Metadata vs Ciphertext Boundary (calendar)

- **A12-META-1**: The server-visible calendar metadata is deliberately minimal: `event_uid`, `sequence`, `dtstart`/`dtend` (time only — see A12-META-2), `status`, `transparency`, `class`, `recurrence_id`, timestamps, collection UUID, and the scheduling addresses (organizer, and attendee addresses only where a consented server-side feature needs them). Everything else — title, description, location, attendee names beyond scheduling need, alarms — is CIPHERTEXT.
- **A12-META-2** (time exposure tradeoff): `dtstart`/`dtend` are metadata because sync ordering and (consented) free/busy need them. This means the server learns **when** a user has events, though not what they are. This is an inherent, disclosed tradeoff of offering server-assisted scheduling/free-busy: for maximum privacy a tenant MAY keep times in CIPHERTEXT too (disabling server-side free/busy, making all scheduling client-side) — the analogue of the webmail tradeoff (A05-BI-9). The default posture and its exposure MUST be disclosed (like every other declared exception).
- **A12-META-3**: The `RRULE` itself: is it metadata or ciphertext? It is **CIPHERTEXT** (part of the event detail, expanded client-side, A12-REC-7). The server does not need the RRULE for basic sync (it syncs the opaque event object). Only if server-side free/busy over recurring events is enabled does the recurrence need server-side expansion — and A15 handles that as a consented feature, potentially via a derived, minimized busy-time projection rather than exposing the raw RRULE.
- **A12-META-4** (recurring-event time privacy — clarification): A consequence of A12-META-3 is that for a **recurring** event, the server sees only the master `dtstart`/`dtend` (metadata) but NOT the expanded instance times, because the RRULE that generates them is CIPHERTEXT. So even with the time-exposure tradeoff (A12-META-2) accepted, the server learns "a series starts at time T" — not the full set of occurrence times. Server-side free/busy over a recurring series therefore CANNOT be computed from metadata alone; it requires the consented, minimized busy-time projection (A15), which the client derives and uploads deliberately. This makes recurring events **more** privacy-preserving by default than single events (the server sees one time, not all instances), and it means an implementer MUST NOT attempt to expand recurrence server-side to build free/busy (it lacks the RRULE) — only the client-supplied projection is available (A12-REC-7).

------

# 8. Sync Integration (reuses A04)

- **A12-SYNC-1**: Calendar changes produce journal events on the same per-principal journal (A04), so a single sync cursor covers mail and calendar (or a parallel calendar cursor — A21 fixes whether it's one journal or a calendar-scoped one; the model is the same). Conflict resolution reuses A03-SYNC (per-field LWW by sequence) for event field edits; a concurrent edit to different fields of an event merges, same as mail flags.
- **A12-SYNC-2** (override vs master conflict): Editing the master series while another device edits an override instance are non-conflicting (different objects linked by `(event_uid, recurrence_id)`); both apply. Deleting the master while editing an override resolves as: master deletion cascades to its overrides (the series is gone), analogous to purge-wins (A03-SYNC-3) — with a client notice so a surprising cascade is visible.

------

# 9. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| RRULE with no UNTIL/COUNT (unbounded) | Clamp expansion to query window + instance cap; never expand infinitely (A12-REC-6) |
| Override with RECURRENCE-ID not matching any instance | Store but flag as orphaned; surface to user; do not silently drop (A14 registry candidate) |
| Regenerated event_uid on edit | Data-integrity bug — MUST be prevented; UID is immutable across edits (A12-EVT-3) |
| Master deleted, overrides remain | Cascade delete overrides; client notice (A12-SYNC-2) |
| Time metadata needed but tenant keeps times encrypted | Server-side free/busy unavailable; scheduling is client-side only (A12-META-2) |
| Malicious attachment on received invite | Apply A07 attachment trust model (A12-ATT-1) |
| Corrupt/undecryptable event | Mark damaged, safe representation, never render unverified (A02/A03 discipline) |

------

# 10. Observability Contract

Per A00 §11 (privacy-preserving):

- counters: `calendar_events_total{op}` (op = added/updated/deleted/override), `recurrence_expansions_total`, `orphaned_override_total`, `series_split_total` (this-and-future edits)
- latency: `event_sync_duration`, `recurrence_expansion_duration` (client-side; if telemetered, aggregate only)
- **A12-OBS-1**: Telemetry MUST NOT include event titles, descriptions, locations, attendee identities, or any CIPHERTEXT-derived content — only counts and operation types (mail telemetry discipline, A07-OBS-1). Event times (metadata) MUST NOT be logged in a way that reconstructs a user's schedule.

------

# 11. Test Scenarios (Normative)

1. **Encrypted at rest**: create an event → server stores CIPHERTEXT title/description/location/attendees + minimal metadata; assert the server cannot read the title (no plaintext column).
2. **Recurrence expansion**: weekly RRULE → correct instances within a queried window; unbounded RRULE clamped to window + cap (A12-REC-1/6).
3. **Override instance**: move one occurrence → override VEVENT with correct RECURRENCE-ID = original start time (not new time); series otherwise intact (A12-REC-2/3).
4. **Single-instance cancel**: cancel one occurrence via EXDATE and (separately) via override STATUS:CANCELLED → both handled (A12-REC-4).
5. **This-and-future**: edit this-and-following → master UNTIL-bounded + new series with new UID; interop-coherent (A12-REC-5).
6. **UID immutability**: edit an event's title → same event_uid preserved (A12-EVT-3).
7. **Master delete cascade**: delete a series with overrides → overrides removed, client notified (A12-SYNC-2).
8. **Concurrent field edit**: device A changes time, device B changes location → both apply (per-field LWW, A12-SYNC-1).
9. **Time-encrypted tenant**: tenant keeps times in CIPHERTEXT → server-side free/busy off; scheduling client-side; no time metadata leaked (A12-META-2).
10. **Malicious invite attachment**: received invite with a risky attachment → A07 tiering applies (A12-ATT-1).

------

# 12. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Storing event content (title/description/location/attendees) as server-readable metadata instead of CIPHERTEXT (A12-ZA-1, A12-EVT-2).
2. ❌ Storing every recurrence instance instead of computing the set from RRULE on demand (A12-REC-1).
3. ❌ Using the NEW start time as RECURRENCE-ID instead of the ORIGINAL instance time, detaching the override (A12-REC-3) — a classic, high-impact bug.
4. ❌ Regenerating `event_uid` on edit, breaking the invitation/update chain (A12-EVT-3).
5. ❌ Expanding an unbounded RRULE infinitely instead of clamping to window + cap (A12-REC-6).
6. ❌ Implementing this-and-future as anything other than the RFC series-split (UNTIL + new series), producing interop-incoherent results (A12-REC-5).
7. ❌ Silently dropping an override whose RECURRENCE-ID matches no instance instead of flagging it (A12 failure model, A14 registry).
8. ❌ Expanding recurrence server-side on data the server cannot read, or exposing the RRULE as metadata unnecessarily (A12-REC-7, A12-META-3).
9. ❌ Reinventing calendar crypto instead of reusing the mail envelope model with a calendar HKDF label (A12-STO-1).
10. ❌ Firing alarms server-side (the server cannot read VALARM) instead of client-side (A12-ALARM-1).
11. ❌ Skipping attachment trust analysis on received invites because "it's a calendar event" (A12-ATT-1).
12. ❌ Logging event times/titles in a way that reconstructs a user's schedule (A12-OBS-1).

------

# 13. Deferred Items

- **A21 calendar-schema extension (DELIVERED in A21 v1.2)**: The `cal` schema (collections, events with event detail incl. RRULE as the single CIPHERTEXT `event_ct`, event envelopes, free/busy projection) was added to A21 in v1.2, closing this dependency. A12 is the logical model; A21 §6bis is the physical source of truth (A12-STO-4). The schema enforces the all-day/timezone integrity and master/override model at the DB-constraint level (A21-CAL-2/3), and it was re-validated against the real PostgreSQL grammar.
- VTODO (tasks) and VJOURNAL — V1 is VEVENT only; extend later.
- Server-side recurrence expansion for cross-attendee free/busy over recurring events — coordinated with A15 as a consented, minimized projection (A12-META-3).
- Attachment lazy-envelopes for large event attachments (shares the A02 deferred item).
- Shared/delegated calendars (multi-principal write, scheduling on behalf of) — depends on the IAM entitlement extension deferred in A17; the storage model (collections) is ready, the authorization is not yet.
- External-invitee zero-access relaxation — Open Decision #5, resolved in A14 (the boundary where non-Diamy invitees must receive plaintext ICS).

------

*End of document.*
