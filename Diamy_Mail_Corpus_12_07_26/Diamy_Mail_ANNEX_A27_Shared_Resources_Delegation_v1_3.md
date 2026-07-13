# Diamy Mail — ANNEX A27: Shared Resources — Shared Mailboxes, Calendar Delegation & Distribution Groups

**Document title:** Diamy Mail — ANNEX A27: Shared Resources — Shared Mailboxes, Calendar Delegation & Distribution Groups
**Version:** 1.3
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.7 (A00)
**Sibling dependencies:** A02 (Storage v1.1), A03 (Vault Client v1.1), A10 (Outbound Deliverability v1.1), A12 (Calendar Core v1.2), A17 (IAM v1.2), A24 (Address Normalization v1.1), A25 (Architecture Invariants v1.1), A26 (Multi-Account Client v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: three organizational-mail capabilities — shared mailboxes with role-based membership (viewer/contributor/admin) as a resource-principal extension of the multi-device envelope model; self-service calendar delegation between two personal principals with crypto-scoped (calendar-only) key wrapping and full delegate write access; distribution-list groups resolved by client-side or gateway expansion with no shared encryption state. Unifies shared mailboxes and delegation under one entitlement model; groups are a separate, simpler directory-expansion concept. |
| 1.3     | Jul 4th 2026 | Cédric BORNECQUE | Final sweep: fixed one more unqualified epoch mention (A27-ROLE-3) missed in v1.2's pass, referencing A17-TOK-2. |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Coherence close: all five pending dependencies flagged in v1.1 §9 are now DELIVERED — A01 v1.2 (gateway group expansion), A17 v1.3 (resource-principal type + group directory + delegation device scoping), A21 v1.3 (entitlement/delegation/group DDL), A22 v1.5 (delegation-scope security indicator), A25 v1.2 (INV-24 crypto-vs-policy invariant). §9 updated to reflect delivery; no other normative change. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: caught that A27-GRP-3 normatively requires a new `diamy-mxd` gateway capability (directory-driven group expansion for external-to-group inbound mail) that A01 v1.1 does not yet have — added A01 to the §9 pending coherence list (was missing alongside A17/A21/A22/A25), consistent with the corpus's honest forward-dependency discipline. No other issues found; the crypto-scoped delegation claim (A27-DEL-3) was verified against A21's existing `cal.event_envelopes`/`mail.envelopes` table separation and holds structurally. |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies three related but distinct organizational capabilities, all requested against the O365 baseline users expect:

1. **Shared mailboxes** (e.g. `support@teqtel.fr`) — a mailbox (and its calendar) accessed by several human principals, each with a differentiated role: viewer, contributor, or admin.
2. **Calendar delegation** — a self-service grant from one personal principal to another, giving the delegate full read/write access to the grantor's calendar (create and modify events on the grantor's behalf), without granting any mail access.
3. **Distribution groups** — an address (e.g. `dev-team@teqtel.fr`) that resolves to a list of member addresses; mail sent to the group is delivered as an individually-encrypted copy into each member's own mailbox. No shared mailbox, no shared store.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Design stance: reuse, don't reinvent

Per the corpus's implementation constitution (A25 §3, rule 5), this annex introduces **no new cryptographic primitive**. Shared mailboxes and calendar delegation are both realized as extensions of the existing multi-device envelope model (A02): a resource's content is encrypted once under a fresh content key, wrapped per authorized device exactly as today — the only change is that the set of "authorized devices" for a mailbox or calendar can now include devices belonging to **more than one human principal**. Distribution groups need no crypto extension at all — they are directory-level address expansion, reusing the recipient-minimization discipline already in A02-DM-4.

## 1.2 Out of scope

External (cross-tenant, cross-provider) shared mailboxes or groups. Mail delegation (as opposed to calendar delegation) — noted as a natural future extension of the same model (§8, Deferred). Room/resource booking (treating a meeting room as a bookable resource principal) — a related but separate extension, deferred. Federation of groups with external directories (e.g., syncing from an external IdP) — deferred.

------

# 2. Resource Principals (the shared foundation for shared mailboxes)

- **A27-RES-1**: A **resource principal** is a new IAM principal type (alongside the existing personal principal, A17): it has its own canonical address (A24), its own mail keys, its own key-directory entry — but unlike a personal principal, it is **not** bound to a single human's authentication. Instead, **membership** (§3) determines which human principals' devices are authorized to access it.
- **A27-RES-2**: A resource principal's mailbox and calendar are stored exactly as a personal principal's are (A02, A12) — encrypted content, per-device wrapped envelopes. The mechanism does not change; what changes is that the device set spans multiple humans.
- **A27-RES-3** (admin-provisioned): A resource principal is created by a tenant admin (control-plane, SED-gated per A17-SED, mirroring A23's admin operations), not self-service — this matches the O365 expectation that shared mailboxes are provisioned by IT, not spun up ad hoc by end users. Self-service creation MAY be enabled by tenant policy (deferred configuration knob), but the default is admin-provisioned.

------

# 3. Shared Mailbox Membership & Roles

- **A27-ROLE-1**: Each member of a shared mailbox holds exactly one role: **viewer**, **contributor**, or **admin**. Roles are additive in capability (admin ⊇ contributor ⊇ viewer):

| Capability | Viewer | Contributor | Admin |
| ---------- | :----: | :----------: | :---: |
| Read mail & calendar | ✅ | ✅ | ✅ |
| Local search / trust history on the shared mailbox | ✅ | ✅ | ✅ |
| Compose & send **as** the mailbox (§4) | ❌ | ✅ | ✅ |
| Organize: move/flag/delete mail, create/edit/delete calendar events | ❌ | ✅ | ✅ |
| Manage membership (add/remove members, change roles) | ❌ | ❌ | ✅ |
| Manage mailbox settings (retention, webmail/Bridge policy for this resource) | ❌ | ❌ | ✅ |

- **A27-ROLE-2** (membership grants device access): Adding a member at any role enrolls that member's device(s) into the resource principal's key-wrapping set (A27-RES-2) — a viewer's device receives wrapped content keys exactly as a contributor's or admin's does, because **reading requires the same decryption capability regardless of role**. The roles differ in what the client/server **permit**, not in what can be decrypted (A27-SEC-1 below states this precisely).
- **A27-ROLE-3** (removal): Removing a member revokes their device(s) from future key-wrapping (new content encrypted after removal is not wrapped to them) and MUST invalidate their session/token for that resource (mirrors A17-TOK-5's revocation requirement, mechanism per A17-TOK-2, applied per-resource). As with personal-device revocation elsewhere in the corpus, this does not retroactively un-decrypt content the member already synced locally before removal — a policy MAY additionally trigger local wipe guidance (A03-SEC-5 pattern) but cannot force it on a device outside Diamy's control.
- **A27-ROLE-4** (multiple admins): A shared mailbox MAY have more than one admin (as requested); any admin can add/remove members and promote/demote roles, including other admins. The last remaining admin MUST NOT be removable/demotable without first designating a replacement (fail-closed against an orphaned, admin-less resource).

------

# 4. Send-As Behavior (Outbound)

- **A27-SEND-1**: A contributor or admin composing from a shared mailbox sends with **From: the shared mailbox's address** ("Send As" semantics — the message is indistinguishable from one sent by the mailbox itself, matching the common shared-support-inbox expectation). The corpus does NOT implement "Send on Behalf Of" (which would show "Member X on behalf of support@...") in this version — noted as a deferred refinement (§8) for organizations that want sender attribution visible externally.
- **A27-SEND-2** (authorization, reusing A10): The outbound path (A04→A10) MUST verify the sending session's role for that resource is contributor-or-admin before accepting the send (server-side authorization check — this is the policy enforcement point, A27-SEC-1). DKIM signing, SPF/DMARC alignment, and rate limiting (A10) apply to the shared mailbox's own sending identity/pool exactly as they would for a personal mailbox — a shared mailbox is, for A10's purposes, just another mail identity.
- **A27-SEND-3** (attribution for audit): While the From header shows only the shared address, the outbound record MUST retain (as audit metadata, INV-20) which member's session actually sent the message — visible to admins, not exposed externally. This is the same discipline as A14-MATCH-3-adjacent audit practice: the outward-facing behavior is clean, the accountability trail is preserved internally.

------

# 5. Shared Mailbox Calendar

- **A27-CAL-1**: A resource principal's calendar (A12) follows the identical role matrix (§3): viewers see events (full detail, per A27-ROLE-1 — decrypt capability is shared), contributors and admins can create/edit/delete events and manage scheduling (A14) as the shared identity, admins additionally manage the calendar's sharing/free-busy policy (A15) for the resource.
- **A27-CAL-2**: Free/busy for a shared mailbox (A15) follows the same consented-metadata model; enabling it is an admin action (mirrors A15-CONSENT-3's tenant-admin-default pattern) since it affects all members collectively, not one individual's personal choice.

------

# 6. Calendar Delegation (personal, self-service)

This is distinct from a shared mailbox: no new resource principal is created — a **personal principal grants another personal principal scoped access to their own calendar.**

- **A27-DEL-1** (self-service grant): Any user MAY grant another Diamy principal **delegate** access to their calendar via a self-service action (no admin involvement) — mirroring how O365 users self-delegate calendar access to an assistant. The grantor chooses the delegate; the grant is scoped to **calendar only** in this version (mail delegation is a natural future extension of the identical mechanism, §8).
- **A27-DEL-2** (full read/write, per the confirmed requirement): A calendar delegate has full read/write capability on the grantor's calendar: viewing all events, creating, editing, and deleting events, and — for scheduling — accepting/declining invitations and sending updates (A14) **as the grantor's calendar**, analogous to an executive assistant managing a manager's diary. There is no viewer-only calendar-delegate tier in this version (contrast with the multi-tier shared-mailbox roles, §3) since the confirmed use case is the full-delegate pattern; a lighter-weight delegate tier MAY be added later if requested (§8).
- **A27-DEL-3** (crypto-scoped: calendar keys only — normative, security-critical): The delegate's device is enrolled **only** into the grantor's **calendar** key-wrapping set (A12-STO-1's `k_event` envelopes) — it MUST NOT be enrolled into the grantor's **mail** key-wrapping set. This is enforced the same way multi-device wrapping is always enforced (A02-CRY-4 distinct HKDF labels, separate envelope tables A21 `cal.event_envelopes` vs `mail.envelopes`) — the delegate's device simply has no wrapped mail envelopes to decrypt, a structural (crypto-level) guarantee, not a policy one. This is the calendar-delegation analogue of A19-CRY separation and directly extends A25 INV-11 (every device is independently enrolled/revocable) to a per-**scope** granularity.
- **A27-DEL-4** (attribution): An event created or modified by a delegate MUST carry delegate-attribution metadata (who acted), visible to the grantor, mirroring A27-SEND-3's accountability discipline and satisfying INV-20.
- **A27-DEL-5** (client presentation): Per the A26 multi-account model, a delegated calendar appears in the delegate's client as another entry the delegate can view/switch to — visually similar to how a shared mailbox appears (§7), but it is understood as "Alice's calendar, delegated to me," not a standalone resource. It follows A26-ISO's isolation discipline: the delegate's own personal account and any delegated calendars are separate, non-merged stores in the delegate's client (a unified calendar view, if enabled, is a presentation merge only — mirrors A26-UNI-1).
- **A27-DEL-6** (revocation): The grantor can revoke delegation at any time; this stops the delegate's device from receiving future calendar envelopes (its enrollment is removed) and invalidates its calendar-scoped session. As with A27-ROLE-3, past locally-synced data is not retroactively erased by the protocol.

------

# 7. Distribution Groups

- **A27-GRP-1** (a directory construct, not a mailbox): A distribution group is an IAM directory entry: an address (A24-canonicalized) mapped to a **member list** and one or more **group admins**. A group has **no mailbox, no keys, no stored content of its own** — sending to a group is exactly equivalent to sending individually to each current member, per the confirmed priority ("un mail envoyé au groupe arrive dans les boîtes de chaque membre").
- **A27-GRP-2** (Diamy-to-group expansion — client-side): When a Diamy sender addresses a message to a group, the sender's client resolves the group's current membership via an IAM directory lookup and encrypts an individually-wrapped copy for each member — architecturally identical to addressing every member directly (A02), with the group address retained in the visible To: header (recipient-set minimization, A02-DM-4, still applies to the underlying per-member envelope set). No server-side decryption or group-aware storage is introduced.
- **A27-GRP-3** (external-to-group expansion — gateway-side): When an **external** (non-Diamy) sender addresses mail to a Diamy group, the group cannot be resolved by the external sender's system, so **`diamy-mxd` (A01) MUST expand it**: the frontier resolves the group's membership via the IAM directory and produces one normal inbound delivery per member, each following the standard A01 inbound pipeline (trust analysis, hold-queue-if-no-device, envelope creation) independently, exactly as if the external sender had sent to each member's address directly. This is a new, explicit gateway responsibility (extends A01's inbound pipeline with a directory-resolution step before per-recipient processing) and does not touch the zero-access model — each member's copy is encrypted to that member's own devices exactly as any inbound mail is (A01/A02).
- **A27-GRP-4** (governance): Group admins (one or more) add/remove members and manage other admins, via a control-plane, SED-gated API (mirrors A27-ROLE-4's no-orphaned-admin rule: the last admin cannot be removed without a replacement). Group creation MAY be self-service or admin-provisioned per tenant policy (tenant configuration, mirrors A27-RES-3's default-admin-provisioned stance, but groups being lower-risk (no shared key material) MAY reasonably default to self-service in many tenants — a tenant policy choice, not fixed here).
- **A27-GRP-5** (no storage duplication concerns beyond normal mail): Because each member receives their own fully independent encrypted copy (no content dedup, per A02's existing no-dedup rule against equality-oracle risk), a group message consumes storage proportional to membership size — identical to today's behavior for any message with N recipients. No new storage model is needed.

------

# 8. Security Model — What Is Crypto-Enforced vs Policy-Enforced (Normative disclosure)

Per the corpus's transparency discipline (mirrors A15-PROJ-6, A07's T3 disclosure), this boundary MUST be stated precisely, not left implicit.

- **A27-SEC-1** (crypto-enforced): **Scope** boundaries are crypto-enforced: a calendar delegate's device holds no mail envelopes and therefore cannot decrypt mail, structurally, regardless of any policy bug (A27-DEL-3). Likewise, a principal with no membership/delegation grant at all holds no wrapped envelope and cannot decrypt anything for that resource — this is the baseline zero-access guarantee (A25 INV-1/INV-2), unchanged.
- **A27-SEC-2** (policy-enforced, honestly disclosed): **Role** boundaries **within** a granted scope are **not** crypto-enforced. A shared-mailbox viewer's device holds the same decryption capability as a contributor's (A27-ROLE-2) — the difference between "can read" and "can also send/organize/manage" is enforced by the **server refusing the write/send/admin API call** for a viewer-role token (A27-SEND-2), not by withholding key material. A determined viewer with legitimate decrypt access could, in principle, construct a message or event locally; they cannot submit it as the shared identity because the authenticated write path checks role server-side. This is the same class of model as ordinary ACL-based systems and is not a weakness specific to Diamy — but the corpus's own standard (state the boundary precisely) requires saying so plainly rather than implying cryptography alone enforces role tiers.
- **A27-SEC-3**: This distinction MUST be reflected in the client/server implementation as a type-level or at least a clearly-named separation (A18-TYPE spirit): "enrollment" (crypto: do I have wrapped keys for this resource/scope) is a different concept from "role" (policy: what am I authorized to submit), and code MUST NOT conflate them — e.g., MUST NOT infer send-authorization from the mere presence of a decryptable envelope.

------

# 9. IAM & Schema Impact (coherence — pending, tracked)

Following the corpus's practice of flagging forward-dependencies honestly rather than pretending they're already closed (as A12 did for A21/A22):

- **A17 extension (DELIVERED in A17 v1.3)**: §3bis adds the resource-principal type (A17-RESRC-1..5) and distribution-group directory model (A17-GRP-1..3), plus A17-DIR-6 for calendar-delegation device scoping — closing this dependency.
- **A01 extension (DELIVERED in A01 v1.2)**: §4bis/pipeline step 0 adds directory-driven group expansion (A01-GRP-1..5) for external-to-group inbound delivery — closing this dependency.
- **A21 extension (DELIVERED in A21 v1.3)**: §6ter adds `keydir.resource_membership`, `cal.delegation_grants`, and `iam.groups`/`iam.group_members` — closing this dependency. Full DDL re-validated against the real PostgreSQL grammar (52 statements, no forward-reference bugs).
- **A25 addition (DELIVERED in A25 v1.2)**: §2.7/INV-24 states the scope-is-crypto-enforced/role-is-policy-enforced boundary as a named, corpus-wide invariant — closing this dependency.
- **A22 addition (DELIVERED in A22 v1.5)**: §8bis adds the calendar-delegate-in-mail-directory security-invariant indicator (A22-RESRC-1, always-page) plus informational admin-operation tracking and anomaly-detection framing — closing this dependency.

------

# 10. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Last admin of a shared mailbox/group being removed | Fail closed: reject the removal until a replacement admin is designated (A27-ROLE-4, A27-GRP-4) |
| Viewer attempts to send/organize/manage | Server rejects at the authorized-write path (A27-SEC-2); no key material is withheld, but the API call fails |
| Removed member's already-synced local data | Not retroactively erased by protocol; future sync stops (A27-ROLE-3, A27-DEL-6) — consistent with existing device-revocation semantics elsewhere in the corpus |
| Delegate device somehow attempts mail decrypt | Structurally impossible — no wrapped mail envelope exists for that device (A27-DEL-3) |
| External sender addresses an unknown/removed group | Gateway treats as unknown recipient per normal A01 handling (no special group-shaped failure mode) |
| Group with zero remaining members | Group persists (an empty distribution list is valid, not an error); sends to it simply reach no one — surfaced to the sender as zero-recipient, not silently dropped |
| Conflicting simultaneous role changes (two admins) | Last-write-wins by server sequence, consistent with A03-SYNC discipline, applied to entitlement records |

------

# 11. Observability Contract

Per A00 §11 and A25 INV-21 (no sensitive content in telemetry):

- counters: `resource_principals_total`, `resource_membership_changes_total{role}`, `send_as_total{result}`, `delegation_grants_total`, `delegation_revocations_total`, `group_expansions_total{origin}` (origin = client/gateway), `group_membership_changes_total`
- audit (INV-20): every membership/role change, every delegation grant/revocation, every group admin action — actor, before/after, timestamp
- **A27-OBS-1**: Telemetry MUST NOT reveal mailbox/calendar content, nor the specific member identities beyond what's needed for the count (aggregate counts by default; audit logs carry identities but are access-restricted to admins, not general telemetry).

------

# 12. Test Scenarios (Normative)

1. **Viewer cannot send**: a viewer's authenticated attempt to send-as the shared mailbox is rejected server-side, despite holding decrypt keys (A27-SEC-1/2).
2. **Contributor can send-as**: a contributor sends as `support@...`; DKIM/SPF/DMARC align to the shared identity; audit records the actual sending member (A27-SEND-1/2/3).
3. **Admin membership management**: an admin adds a new viewer; the new member's device receives wrapped keys and can read but not send (A27-ROLE-1/2).
4. **Orphaned-admin prevention**: removing the last admin of a shared mailbox is rejected until a replacement is set (A27-ROLE-4).
5. **Calendar delegate full access**: a delegate creates and edits events on the grantor's calendar; changes sync to the grantor with delegate attribution (A27-DEL-2/4).
6. **Delegate cannot read mail**: a calendar delegate's device has no wrapped mail envelope; attempting to decrypt any mail message fails structurally (A27-DEL-3).
7. **Delegation revocation**: grantor revokes delegate access; delegate's session for that calendar is invalidated; future events are not wrapped to the removed device (A27-DEL-6).
8. **Diamy-to-group send**: sender addresses a group; client resolves membership and sends individually-wrapped copies to each current member; To: shows the group address (A27-GRP-2).
9. **External-to-group inbound**: an external sender emails a Diamy group; the gateway expands it into independent per-member deliveries, each through normal A01 processing (A27-GRP-3).
10. **Group governance**: a group admin removes a member; subsequent group sends no longer reach that member (A27-GRP-4).
11. **Empty group**: sending to a group with zero members surfaces as zero-recipient to the sender, not a silent failure (failure model).

------

# 13. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Inferring send/write authorization from the mere presence of a decryptable envelope instead of checking role server-side (A27-SEC-2/3) — conflates crypto-enforcement with policy-enforcement.
2. ❌ Enrolling a calendar delegate's device into the mail key-wrapping set "for convenience" (A27-DEL-3) — breaks the crypto-scoped guarantee that is the whole point of delegation being safe.
3. ❌ Allowing removal of the last admin of a shared mailbox or group, orphaning it (A27-ROLE-4, A27-GRP-4).
4. ❌ Implementing shared-mailbox content as a single re-encrypted copy the server can access to "simplify" multi-member sharing, instead of reusing the per-device envelope model (A27-RES-2) — a zero-access violation (INV-1).
5. ❌ Building group expansion as a server-side stored mailing-list mailbox (introducing shared storage) instead of pure per-member individual delivery (A27-GRP-1/5) — unnecessary complexity and a privacy regression.
6. ❌ Deduplicating a group message's storage across members (content dedup) — forbidden by the existing equality-oracle rule (A02), applies unchanged here.
7. ❌ Not attributing delegate/member-sent actions internally for audit while correctly hiding attribution externally (A27-SEND-3, A27-DEL-4) — loses accountability.
8. ❌ Merging a shared mailbox's or delegated calendar's data into the accessing user's own personal store instead of treating it as an isolated account per A26 (A27-DEL-5).
9. ❌ Failing to revoke a removed member's/delegate's session (only removing future key-wrapping without invalidating the live session) (A27-ROLE-3, A27-DEL-6).
10. ❌ Having the gateway silently drop mail to an external-to-group send instead of expanding it per-member (A27-GRP-3).

------

# 14. Deferred Items

- **Mail delegation** (as opposed to calendar-only): the identical mechanism (A27-DEL-3's scoped key-wrapping) extends naturally to a `mail` scope; deferred because the confirmed priority was calendar-only full delegation. A lighter-weight "viewer" calendar-delegate tier is a related deferred refinement.
- **Send on Behalf Of** (as opposed to Send As): showing delegate/member attribution in the visible From/Sender headers for shared mailboxes — a refinement of A27-SEND-1, deferred.
- **Room/resource booking** (treating meeting rooms as bookable resource principals): a natural extension of the resource-principal model (§2) with an availability/booking-acceptance workflow layered on A14/A15; deferred, ties to A14's already-deferred resource-attendee model.
- **Self-service resource-principal creation** and **tenant-configurable group self-service** policy knobs: noted as tenant policy choices (A27-RES-3, A27-GRP-4) but the specific admin UI/policy surface is deferred.
- **Cross-tenant / federated groups and shared mailboxes**: out of scope entirely for this version (§1.2).
- **A17/A01/A21/A25/A22 coherence extensions** listed in §9 — tracked as pending, to be applied as follow-up updates to those documents.

------

*End of document.*
