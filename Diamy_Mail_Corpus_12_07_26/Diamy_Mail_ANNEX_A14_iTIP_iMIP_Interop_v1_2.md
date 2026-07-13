# Diamy Mail — ANNEX A14: Calendar iTIP/iMIP Interop & Third-Party Behaviors

**Document title:** Diamy Mail — ANNEX A14: Calendar iTIP/iMIP Interop & Third-Party Behaviors
**Version:** 1.2
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 5th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.3 (A00)
**Sibling dependencies:** A01 (Inbound Gateway v1.1), A10 (Outbound Deliverability v1.1), A12 (Calendar Core v1.1), A13 (Timezone Engine v1.1), A15 (Free/Busy v1.1), A28 (Presence v1.0)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: iTIP (RFC 5546) / iMIP (RFC 6047) scheduling protocol — invitation/reply/update/cancellation/counter flows, ICS-over-email transport, organizer/attendee state machine, sequence/UID matching, the "Known Third-Party Behaviors" registry (living structure for Outlook/Google/Apple deviations), external-invitee zero-access boundary (closes Open Decision #5), robustness principle, failure model, test scenarios, common AI errors. The interop-risk boundary annex. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: content verified coherent (iTIP flows, UID/SEQUENCE matching, living registry, robustness principle strict-emit/liberal-accept, phishing-aware invitations); seed registry entries correctly hedged as re-verify-against-current-versions. Confirmed closure of A00 Open Decision #5 (external-invitee zero-access boundary); A00 updated to v1.4 to reflect this (only #1 Bridge/A20 now remains open). |
| 1.2     | Jul 5th 2026 | Cédric BORNECQUE | Closed three under-specified acceptance corners found by cross-review: (a) attendee-side provisional materialization of an inbound REQUEST (A14-REP-3 — event materialized as PARTSTAT=NEEDS-ACTION, contributes BUSY-TENTATIVE to a consented A15 projection, MUST NOT drive presence per A28); (b) atomic accept/decline sequence on the attendee side (A14-REP-4 — persist-local-first, then emit, pending-reply retry, never emit-without-persist); (c) organizer-side REPLY application idempotency across multiple devices through the zero-access boundary (A14-REP-5 — client-side application keyed on (UID, RECURRENCE-ID, attendee, SEQUENCE, DTSTAMP), convergent under A04 sync). Added test scenarios 12–14, AI errors 13–15; sibling deps now reference A28 (Presence). |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies **calendar scheduling interoperability**: how Diamy sends and receives meeting invitations, replies, updates, and cancellations via iTIP (RFC 5546) carried over email as iMIP (RFC 6047), and — critically — how it copes with the fact that the dominant real-world clients (Outlook/Exchange, Google Calendar, Apple) deviate from the standards in known and unknown ways. It also fixes the **external-invitee zero-access boundary** (Open Decision #5).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 The interop-risk stance (the limit of spec-first)

This is the annex where the corpus's specification-first method meets its natural limit: **third-party behavior cannot be pre-specified, only observed and accommodated.** No document can enumerate in advance every way Outlook or Google will surprise us. Therefore this annex does two things: (a) specifies a **strictly RFC-conformant core** for what Diamy emits and how it interprets conformant input; and (b) establishes a **living registry** (§7) of observed third-party deviations, designed to be appended to during implementation and operation. The spec is the skeleton; the registry is where reality is recorded as it is discovered. An implementer MUST expect the registry to grow and MUST build the accommodation layer as data-driven (registry entries), not as hard-coded special cases scattered through the code.

## 1.2 Out of scope

The event data model (A12). Timezone resolution (A13, used heavily here). Free/busy (A15). Mail transport mechanics (A01/A10) — reused for iMIP carriage.

------

# 2. iTIP / iMIP Overview

- **A14-OV-1**: **iTIP** (RFC 5546) defines the scheduling messages (METHOD:REQUEST, REPLY, CANCEL, ADD, COUNTER, DECLINECOUNTER, REFRESH, PUBLISH) as ICS payloads. **iMIP** (RFC 6047) defines carrying those ICS payloads over email (a `text/calendar` MIME part with a `method` parameter, plus conventionally a human-readable alternative part). Diamy uses iMIP for external scheduling (invitations to/from non-Diamy addresses) and MAY use a native path for Diamy↔Diamy scheduling (§3.3).
- **A14-OV-2**: An invitation email is an ordinary email (A01/A10 transport) whose body carries a `text/calendar; method=REQUEST` part. Inbound iMIP is detected at the gateway/client and routed to the calendar subsystem; outbound iMIP is composed by the calendar subsystem and emitted via `diamy-submitd` (A10).

------

# 3. Scheduling Flows (Normative core)

## 3.1 Organizer → Attendee (REQUEST)

- **A14-REQ-1**: To invite, the organizer's client builds a VEVENT (A12) with the attendee list and emits an iMIP `METHOD:REQUEST`. `UID` is the event's stable UID (A12-EVT-3); `SEQUENCE` starts at 0 and increments on each subsequent update (A14-UPD). `DTSTAMP` is set. Timezone data follows A13 (correct VTIMEZONE emitted, A13-VTZ-3).
- **A14-REQ-2**: An **update** to an existing meeting is a new `REQUEST` with the same `UID` and an incremented `SEQUENCE`. Attendees' clients match on `UID` and apply the higher `SEQUENCE`, replacing the prior version (A14-MATCH). A lower/equal sequence is a stale/duplicate and MUST NOT downgrade a newer version.

## 3.2 Attendee → Organizer (REPLY)

- **A14-REP-1**: An attendee accepting/declining/tentatively-accepting emits an iMIP `METHOD:REPLY` with their `PARTSTAT` and the matching `UID`/`RECURRENCE-ID`/`SEQUENCE`. The organizer's client matches it and updates that attendee's status. A REPLY carries only the replying attendee's status, not the whole attendee list (privacy + RFC).
- **A14-REP-2**: A reply to a **single instance** of a recurring meeting carries the `RECURRENCE-ID` (A12-REC-3, A13-CC-3) so the organizer updates only that instance's status.
- **A14-REP-3** (provisional materialization — normative): On receiving a valid inbound `REQUEST`, the attendee's client MUST materialize the event in the attendee's calendar **before any response**, with the attendee's own `PARTSTAT=NEEDS-ACTION`, visually distinguishable from confirmed events (client UI concern; the state is normative, the rendering is not). This matches dominant-client expectations (Outlook/Google auto-add) and gives the invitation a stable local anchor for subsequent updates/cancels (A14-MATCH). Consequences are fixed here to prevent invented behavior: a NEEDS-ACTION or TENTATIVE event contributes `BUSY-TENTATIVE` to a consented free/busy projection (A15-FB-1 FBTYPE semantics; nothing is exposed if free/busy is not enabled, A15-CONSENT-1); a NEEDS-ACTION event MUST NOT drive automatic presence transitions (A28-CAL-2 — an unanswered invitation is not a commitment). On `DECLINED`, the materialized event is hidden or removed per user preference (RECOMMENDED default: hidden, recoverable) and its busy contribution removed; on `ACCEPTED` it becomes a confirmed event (contributes `BUSY`, eligible to drive presence per A28).
- **A14-REP-4** (atomic accept/decline sequence — normative): The attendee's accept/tentative/decline action is one logical operation in this order: (1) update own `PARTSTAT` in the local encrypted copy and persist (re-encrypt + sync per A02/A04); (2) emit the `REPLY` (iMIP via `diamy-submitd`, or native path per A14-NAT-1). If (2) fails, the local state is kept with a **pending-reply** marker and emission is retried (bounded, surfaced to the user if persistently failing) — the user's decision is never silently lost. An implementer MUST NOT emit the REPLY without persisting local state, and MUST NOT persist a state change while silently skipping the REPLY (the organizer would never learn the decision). Persist-first ordering is deliberate: a crash between (1) and (2) leaves a recoverable pending-reply, whereas emit-first would leave the organizer informed of a state the attendee's own devices do not hold.
- **A14-REP-5** (organizer-side application idempotency — normative): Because `attendees_ct` is CIPHERTEXT (A12-EVT-2), an inbound REPLY cannot be applied server-side; it is applied by **an organizer client** after decryption, then re-encrypted and synced (A04). With multiple organizer devices, the same REPLY may be processed more than once; application MUST be **idempotent**, keyed on `(UID, RECURRENCE-ID, attendee, SEQUENCE, DTSTAMP)`: applying the same key twice yields the same state, and a REPLY with an older DTSTAMP than the attendee's currently-stored status is stale and MUST NOT downgrade it (same collision discipline as A14-MATCH-1). Two devices applying the same REPLY concurrently MUST converge through A04 conflict resolution to a single identical attendee status — the idempotency key makes the merge trivially commutative.

## 3.3 Diamy ↔ Diamy (native path)

- **A14-NAT-1**: For scheduling between Diamy principals, Diamy MAY use a **native, encrypted** scheduling path (reusing the mail envelope + native sync, A02/A04) instead of iMIP-over-email, keeping event detail zero-access end-to-end (no plaintext ICS leaves the trust zone). The iMIP path is used when at least one participant is external. The organizer's client determines per-attendee which path applies (internal vs external), and a mixed meeting uses native for internal attendees and iMIP for external ones.

## 3.4 Cancellation (CANCEL)

- **A14-CAN-1**: Cancelling a meeting emits `METHOD:CANCEL` with the `UID` (and `RECURRENCE-ID` for a single instance). Attendees' clients remove/mark-cancelled the matching event. A CANCEL for an unknown UID is handled gracefully (nothing to cancel — not an error).

## 3.5 Counter-proposal (COUNTER / DECLINECOUNTER)

- **A14-CTR-1**: An attendee MAY propose a different time via `METHOD:COUNTER`; the organizer accepts (issuing a new REQUEST) or rejects (`DECLINECOUNTER`). Support is RECOMMENDED but secondary; many clients handle COUNTER inconsistently (a prime registry area, §7).

------

# 4. UID / SEQUENCE Matching (Normative)

- **A14-MATCH-1**: Scheduling messages are matched to events by **`UID`** (and `RECURRENCE-ID` for instance-level). `SEQUENCE` (with `DTSTAMP` as tiebreaker) orders revisions. The engine MUST: apply a higher SEQUENCE as an update; treat an equal SEQUENCE with newer DTSTAMP as a modification; ignore a lower SEQUENCE as stale. This is the RFC 5546 collision model and MUST be implemented precisely — it is how "the meeting time changed" propagates correctly.
- **A14-MATCH-2**: The engine MUST NOT match on anything other than UID (not subject, not time) — subject/time change across updates, UID does not (A12-EVT-3). Matching on subject is a bug that fragments a meeting into duplicates.
- **A14-MATCH-3** (foreign UID preservation): A UID received from an external client MUST be stored and echoed back verbatim in replies/updates, even if it is malformed by RFC standards (some clients emit non-conformant UIDs). Rewriting a foreign UID detaches Diamy's replies from the organizer's meeting (a registry-class issue, §7).

------

# 5. iMIP Transport Details

- **A14-IMIP-1**: An outbound iMIP message MUST be a well-formed multipart email: a human-readable part (so non-calendar clients show something useful) and the `text/calendar; method=X` part with the ICS. It MUST be DKIM-signed and deliverability-compliant (A10) — invitations are real email and are subject to spam filtering; a poorly-formed invite lands in spam and the meeting never happens.
- **A14-IMIP-2** (inbound detection): Inbound mail carrying a `text/calendar` part MUST be recognized and surfaced as a scheduling action (accept/decline UI) in addition to (or instead of) plain rendering. The ICS part is parsed by the calendar subsystem; the surrounding email follows normal mail trust analysis (A06/A07) — an invitation can be a phishing vector (a fake "meeting" with a malicious link/attachment), so trust scoring still applies (A12-ATT-1).
- **A14-IMIP-3**: The `text/calendar` part MUST be parsed defensively (bounded, robust to malformed ICS, A18-BOUND/A13-VTZ-2) — hostile or broken ICS MUST NOT crash the client or the gateway.

------

# 6. External-Invitee Zero-Access Boundary (closes Open Decision #5)

- **A14-ZA-1** (the decision): When a Diamy user schedules with **external, non-Diamy invitees** (Outlook/Google/etc.), those invitees MUST receive a standard iMIP email containing **plaintext ICS** — there is no other way for a non-Diamy client to read the invitation. This is a **necessary, disclosed relaxation** of zero-access at the external boundary: the event detail (title, time, location, organizer, the invitee's own presence) leaves the trust zone in plaintext *to reach that external invitee*, exactly as any email to an external recipient does (A01/A10 — mail to the outside is inherently plaintext at the destination). This closes Open Decision #5.
- **A14-ZA-2** (what is and isn't relaxed): The relaxation is **only** the outbound plaintext ICS necessary to reach an external invitee — the same category as sending any plaintext email outside. It does NOT relax:
  - Diamy↔Diamy scheduling, which stays end-to-end encrypted via the native path (A14-NAT-1);
  - at-rest storage, which stays zero-access (A12-ZA-1) — the organizer's own copy is encrypted even though the outbound iMIP was plaintext;
  - the internal attendees of a mixed meeting, who get the native encrypted path.
  So a meeting with 3 Diamy users and 1 Gmail user: the 3 Diamy users are E2E-encrypted; only the single outbound iMIP to the Gmail user is plaintext (as any email to Gmail is).
- **A14-ZA-3** (disclosure): This boundary MUST be disclosed with the same transparency as every other declared exception (the frontier, hold queue, T3, webmail, calendar time-metadata): a user inviting an external party is, in effect, sending them a plaintext email, and the UI SHOULD make the internal-vs-external distinction visible (e.g. indicating which invitees are encrypted-native and which receive standard email). Tenants requiring absolute zero-access MAY restrict external calendar invitations (analogous to native-only webmail enforcement).

------

# 7. Known Third-Party Behaviors Registry (Normative structure)

This is the heart of the annex: a **living, data-driven registry** of observed deviations, because they cannot be pre-enumerated (§1.1).

## 7.1 Registry principle

- **A14-REG-1**: The accommodation layer MUST be **data-driven from a registry**, not hard-coded special cases. Each registry entry describes: the client/version exhibiting the behavior, the trigger (what input/situation), the deviation (how it differs from RFC), the accommodation (what Diamy does), and the evidence/date observed. New deviations are added as entries; the code reads the registry. This keeps the accommodation auditable, testable, and maintainable as clients change — and it means discovering a new Outlook quirk is a registry addition, not a code-scattered patch.
- **A14-REG-2** (robustness principle): Diamy MUST be **strict in what it emits** (RFC-conformant ICS, correct VTIMEZONE, proper SEQUENCE/UID) and **liberal in what it accepts** (tolerate common deviations rather than reject). Postel's principle, applied deliberately: emit clean, accept messy. Rejection of a slightly-non-conformant real invitation means the meeting fails, which users blame on Diamy, not on the non-conformant sender.

## 7.2 Registry entry schema

Each entry (stored as structured data, versioned):

| Field | Meaning |
| ----- | ------- |
| `id` | stable registry entry ID |
| `client` | e.g. `outlook_desktop`, `exchange`, `google_calendar`, `apple_ical`, `outlook_mobile` |
| `version_range` | affected versions where known |
| `trigger` | the input/situation that exhibits it |
| `deviation` | how it differs from RFC 5545/5546 |
| `accommodation` | what Diamy does to interoperate |
| `direction` | inbound-parse / outbound-emit / both |
| `severity` | meeting-breaking / cosmetic / edge |
| `observed` | date + evidence reference |
| `status` | active / superseded (client fixed it) / candidate |

## 7.3 Seed entries (known at authoring; illustrative, NOT exhaustive)

These are starting entries; the registry is expected to grow substantially during implementation. They are recorded as the known landscape, with the explicit caveat that specifics MUST be re-verified against current client versions at implementation time.

- **A14-REG-SEED-1** (Outlook Windows timezone names): Outlook/Exchange historically emit Windows timezone names rather than IANA `TZID`s, sometimes without a resolvable inline VTIMEZONE. *Accommodation*: map via CLDR (A13-WIN-1); on emit, include a generated VTIMEZONE (A13-VTZ-3) and, per this registry, possibly emit the Windows name to Outlook recipients.
- **A14-REG-SEED-2** (Outlook RECURRENCE-ID / exception handling): Outlook's representation of recurring-meeting exceptions has historically differed from strict RFC in edge cases (e.g. handling of the master's changes vs exceptions). *Accommodation*: preserve foreign UID/RECURRENCE-ID verbatim (A14-MATCH-3), apply A12/A13 recurrence rules, flag mismatches.
- **A14-REG-SEED-3** (Google COUNTER handling): Google Calendar's support for COUNTER/counter-proposals has been inconsistent. *Accommodation*: treat COUNTER as best-effort; do not depend on a DECLINECOUNTER being understood; surface the proposal to the organizer regardless.
- **A14-REG-SEED-4** (Apple all-day / floating quirks): Apple clients have had specific behaviors around all-day and floating times. *Accommodation*: strict A13-VAL-5 (all-day date-only) / A13-VAL-3 (floating preserved) on our side; tolerate their representation on parse.
- **A14-REG-SEED-5** (non-conformant UIDs): Some clients emit UIDs that are non-conformant or unusually long. *Accommodation*: store/echo verbatim (A14-MATCH-3), never rewrite.
- **A14-REG-SEED-6** (sequence/dtstamp inconsistencies): Some clients do not increment SEQUENCE on every meaningful change, relying on DTSTAMP. *Accommodation*: use DTSTAMP as tiebreaker (A14-MATCH-1), do not assume SEQUENCE strictly increases.

- **A14-REG-3**: These seeds MUST be validated against current client versions during implementation — client behavior changes over time (a deviation may be fixed, or a new one introduced). The registry entry `status` field tracks this. An entry marked `superseded` means a client fixed the behavior; Diamy keeps the accommodation only as long as affected versions are in the field.

------

# 8. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Malformed inbound ICS | Parse defensively, bounded; if unparseable, surface as a non-actionable message with a notice, never crash (A14-IMIP-3) |
| Unknown/foreign UID | Store/echo verbatim; match on it; never rewrite (A14-MATCH-3) |
| Lower/equal SEQUENCE received | Treat as stale (DTSTAMP tiebreak); do not downgrade a newer version (A14-MATCH-1) |
| CANCEL for unknown UID | Graceful no-op (A14-CAN-1) |
| External invitee (non-Diamy) | Send plaintext iMIP (disclosed A14-ZA); internal attendees stay native-encrypted (A14-ZA-2) |
| Client deviation not in registry | Robustness principle: accept if interpretable, flag as a registry candidate; escalate for a new entry (A14-REG-2) |
| Invitation is a phishing vector | Normal mail trust analysis applies (A06/A07); a "meeting" with a malicious link/attachment is scored (A14-IMIP-2) |
| Timezone quirk | Handled per A13 + registry (A14-REG-SEED-1) |

------

# 9. Observability Contract

Per A00 §11:

- counters: `imip_sent_total{method}`, `imip_received_total{method,result}`, `scheduling_matches_total{result}` (uid-matched/stale/orphan), `registry_accommodations_applied_total{entry_id}`, `registry_candidates_flagged_total`, `external_invitations_total`
- gauges: registry size (active entries), candidates awaiting triage
- audit (OBS-3): external invitations sent (the disclosed zero-access relaxation, A14-ZA), registry entry additions/status changes
- **A14-OBS-1**: `registry_candidates_flagged_total` is a key operational signal — a rising rate means clients are deviating in unhandled ways and the registry needs attention. This is the metric that makes the "living registry" actually live (someone watches it and triages).
- **A14-OBS-2**: Telemetry MUST NOT include event content or attendee identities; method types, match results, registry entry IDs, and counts only (A12-OBS-1 discipline).

------

# 10. Test Scenarios (Normative)

1. **REQUEST round-trip**: organizer invites → attendee receives iMIP REQUEST, accepts → REPLY → organizer sees accepted status; UID matched, SEQUENCE 0 (A14-REQ/REP).
2. **Update propagation**: organizer changes time → new REQUEST, SEQUENCE 1 → attendees apply the higher sequence, old version replaced; a re-sent SEQUENCE 0 is ignored as stale (A14-MATCH-1).
3. **Single-instance reply**: attendee declines one occurrence of a series → REPLY with RECURRENCE-ID → only that instance's status changes (A14-REP-2).
4. **Cancel**: organizer cancels → CANCEL → attendees mark cancelled; CANCEL for unknown UID is a no-op (A14-CAN-1).
5. **Foreign UID preserved**: inbound invite with a non-conformant UID → stored/echoed verbatim; reply matches the organizer's meeting (A14-MATCH-3, A14-REG-SEED-5).
6. **Mixed internal/external meeting**: 3 Diamy + 1 Gmail → Diamy attendees via native encrypted path, Gmail via plaintext iMIP; at-rest copy encrypted (A14-ZA-2).
7. **External disclosure**: inviting an external party surfaces the encrypted-vs-plaintext distinction in the UI; audit-logged (A14-ZA-3).
8. **Malformed ICS**: hostile/broken ICS part → parsed defensively, no crash, surfaced with notice (A14-IMIP-3).
9. **Windows tz invite**: inbound Outlook invite with "Romance Standard Time" → resolved to Europe/Paris via registry/CLDR; times correct (A14-REG-SEED-1, A13-WIN).
10. **Phishing invite**: "meeting" email with a malicious link → mail trust analysis flags it; the calendar action does not bypass trust (A14-IMIP-2).
11. **Registry candidate**: an unhandled deviation → accepted if interpretable, flagged as a candidate, counter incremented (A14-REG-2, A14-OBS-1).
12. **Provisional materialization**: inbound REQUEST → event appears in the attendee's calendar as NEEDS-ACTION, distinguishable; with free/busy enabled it contributes BUSY-TENTATIVE; presence (A28) is NOT affected; decline hides it and removes the busy contribution (A14-REP-3).
13. **Accept with emission failure**: attendee accepts, local PARTSTAT persisted, REPLY emission fails → pending-reply marker, bounded retry, user surfaced on persistent failure; local decision never lost; REPLY never emitted without prior local persist (A14-REP-4).
14. **Duplicate REPLY across organizer devices**: the same REPLY reaches two organizer devices → both apply idempotently, A04 sync converges to one identical attendee status; a re-delivered copy of an already-applied REPLY is a no-op; an older-DTSTAMP REPLY does not downgrade a newer status (A14-REP-5).

------

# 11. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Hard-coding client special-cases scattered through the code instead of a data-driven registry (A14-REG-1) — unmaintainable as clients change.
2. ❌ Matching scheduling messages on subject/time instead of UID, fragmenting a meeting into duplicates (A14-MATCH-2).
3. ❌ Rewriting a foreign (non-conformant) UID, detaching replies from the organizer's meeting (A14-MATCH-3).
4. ❌ Applying a lower/equal SEQUENCE as an update, downgrading a newer version (A14-MATCH-1).
5. ❌ Being strict on input (rejecting slightly-non-conformant real invites) instead of liberal-accept / strict-emit (A14-REG-2) — rejection makes the meeting fail and users blame Diamy.
6. ❌ Sending a malformed/undeliverable iMIP that lands in spam (not DKIM-signed / not deliverability-compliant), so the meeting never arrives (A14-IMIP-1).
7. ❌ Treating an invitation email as trusted and skipping mail trust analysis, missing invitation-borne phishing (A14-IMIP-2).
8. ❌ Crashing on malformed inbound ICS instead of defensive bounded parsing (A14-IMIP-3).
9. ❌ Relaxing zero-access more than the necessary external-invitee plaintext — e.g. sending Diamy↔Diamy scheduling as plaintext iMIP, or storing the organizer's copy in plaintext (A14-ZA-2).
10. ❌ Not disclosing the external-invitee plaintext boundary, so a user thinks an external invite is encrypted (A14-ZA-3).
11. ❌ Ignoring the registry-candidate signal, letting unhandled deviations accumulate silently (A14-OBS-1).
12. ❌ Depending on COUNTER/DECLINECOUNTER being universally understood (A14-CTR-1, A14-REG-SEED-3).
13. ❌ Adding the event to the attendee's calendar only on accept (no provisional materialization), so updates/cancels arriving before the response have no local anchor and the user has no visibility of pending invitations (A14-REP-3) — or the symmetric error: letting a NEEDS-ACTION invitation flip the user's presence or contribute plain BUSY as if committed.
14. ❌ Emitting the REPLY without persisting the local PARTSTAT (state lost on crash), or persisting locally without ever emitting (organizer never learns), instead of the persist-first + pending-reply-retry sequence (A14-REP-4).
15. ❌ Applying inbound REPLYs non-idempotently on the organizer side, so multi-device processing produces divergent attendee statuses or an older REPLY downgrades a newer one (A14-REP-5) — or attempting to apply a REPLY server-side, which is structurally impossible against `attendees_ct` CIPHERTEXT.

------

# 12. Deferred Items

- The full registry contents beyond the seed entries — by design, populated during implementation and operation (§7); this annex fixes the structure and discipline, not the exhaustive list (which cannot be pre-written).
- Resource/room scheduling (booking rooms as resource attendees) — an extension of the attendee model; deferred.
- Delegation (scheduling on behalf of another principal) — depends on the IAM entitlement extension deferred in A17.
- Rich COUNTER negotiation UX — secondary (A14-CTR-1).
- Cross-checking a received invite's organizer against sender authentication (does the iMIP organizer match the authenticated From?) as an anti-spoofing calendar signal — a promising trust extension (ties A06 to calendar); deferred for design with A06.

------

*End of document.*
