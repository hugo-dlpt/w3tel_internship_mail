# Diamy Mail — ANNEX A11: Domain Onboarding Wizard

**Document title:** Diamy Mail — ANNEX A11: Domain Onboarding Wizard
**Version:** 1.1
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)
**Sibling dependencies:** A01 (Inbound Gateway v1.1), A10 (Outbound Deliverability v1.1), A17 (IAM Integration v1.1), A23 (Outbound Resource Allocation), A24 (Identity & Address Normalization v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: guided domain onboarding, DNS record generation (SPF/DKIM/DMARC + MX + PTR guidance), real-time verification, fail-closed activation gate, SPF-merge handling for existing senders, DMARC progressive rollout (p=none→quarantine→reject), pending-DNS mailbox state, MX cutover sequencing, first-device enrollment sequencing decision (closes A17 §12 HIGH item), failure model, test scenarios, common AI errors |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: added MX-cutover impact warning — pointing MX to Diamy diverts mail from the tenant's existing mail system, which MUST be disclosed before cutover (A11-MX-2); confirmed the A17 §12 HIGH closure is coherent (hold queue stays mandatory, sequencing is an optimization) and noted A17 updated to v1.2 to reflect closure; added AI error #13 |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies the **domain onboarding wizard**: the guided flow that takes a tenant from "I own `example.fr`" to "my domain sends and receives through Diamy, fully authenticated," by generating the required DNS records, verifying them in real time, and enabling mail only when verification is green (fail-closed). It fixes the SPF/DKIM/DMARC provisioning that A01/A10 depend on, and it **closes the HIGH open decision** from A17 §12 (onboarding sequencing vs the gateway hold queue).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Design stance

Onboarding is a **guided 15-minute wizard**, not a documentary prerequisite (the conversation's Microsoft-model reference). The tenant enters a domain; Diamy generates every record; the wizard verifies publication in real time; mail activates only when green. The requirement (SPF/DKIM/DMARC mandatory) becomes a walkthrough, not friction — and it is fail-closed, matching the platform's discipline (SEC-FC, SEC-OUT-2).

## 1.2 Out of scope

The emission mechanics that consume this (A10). Sending-resource allocation / pool egress IPs (A23) — referenced where SPF must match the pool. IAM tenant/principal creation (A17); this annex assumes the tenant exists in IAM and onboards its mail domain.

------

# 2. Onboarding Flow (Normative order)

```
1  DOMAIN CLAIM      tenant enters domain; verify tenant is authorized to
                     onboard it (domain-control proof, §3)
2  GENERATE RECORDS  Diamy generates: MX, SPF (include/merge, §4), DKIM
                     selector CNAME/TXT (§5), DMARC (§6), PTR guidance (§7)
3  PUBLISH (tenant)  tenant publishes records at their DNS provider
                     (copy-paste values Diamy supplies)
4  VERIFY (real-time) Diamy polls DNS, shows per-record green/red live (§8)
5  ACTIVATE          only when required records verify → mail enabled
                     (fail-closed gate, §9). Receiving and sending may
                     activate on different gates (§9.2)
6  MONITOR           ongoing DNS drift detection; DMARC rollout assist (§6)
```

- **A11-FLOW-1**: The wizard MUST show clear per-record status and never claim "done" while any required record is unverified. Partial completion leaves the domain in a **pending** state (§10), not an ambiguous half-active one.

------

# 3. Domain-Control Proof

- **A11-CTRL-1**: Before generating sending credentials or accepting MX for a domain, the tenant MUST prove control of the domain (publish a Diamy-provided verification TXT, or an equivalent challenge). This prevents a tenant from onboarding a domain they do not own (which would let them receive another org's mail or spoof it). Domain-control proof MUST be re-checkable and MUST be recorded/audited.
- **A11-CTRL-2**: Domain names MUST be normalized with the A24 domain rules (IDNA2008 A-label, lowercase) so the onboarded domain, the SPF/DKIM/DMARC checks (A01-AUTH-2), and the principal addresses (A24) all agree. A domain onboarded in one form and checked in another would silently misalign.

------

# 4. SPF Generation and Merge (Normative)

- **A11-SPF-1**: Diamy MUST generate the SPF mechanism authorizing its sending infrastructure (e.g. `include:spf.diamy.app`), scoped to match the tenant's assigned sending pool egress IPs (A23 / OPS-SEND-9). The include target MUST resolve to the tenant's actual egress IPs, so SPF alignment holds at recipients (A10-AUTH-2).
- **A11-SPF-2** (merge, not replace — critical): If the tenant already has an SPF record (they send via a CRM, marketing platform, ERP, etc.), the wizard MUST **detect the existing record and offer a merge**, NOT a replacement. Replacing would break the tenant's existing senders (their Salesforce/Brevo mail would start failing SPF the day of migration — the conversation's exact warning). The wizard MUST parse the existing SPF, add Diamy's include, preserve existing mechanisms, and present the merged record for publication.
- **A11-SPF-3** (10-lookup limit): SPF has a hard 10-DNS-lookup limit (RFC 7208); adding an include can exceed it if the tenant already has many. The wizard MUST count the resulting lookups and, if the merge would exceed 10, warn and propose remedies (flattening, removing stale includes, using a dedicated subdomain) rather than silently producing an SPF that `permerror`s. A `permerror` SPF is worse than none.
- **A11-SPF-4**: The wizard MUST re-verify SPF whenever the tenant's sending pool changes (A23 reassignment changes egress IPs → OPS-SEND-9); a pool change without SPF re-verification MUST NOT be allowed to emit from the new pool (A10-AUTH-2).

------

# 5. DKIM Provisioning

- **A11-DKIM-1**: Diamy generates the DKIM key pair and holds the private key (A10-AUTH-1); the tenant publishes only the public selector as a CNAME (pointing to a Diamy-hosted record) or TXT. A CNAME to a Diamy-managed target is RECOMMENDED because it lets Diamy rotate keys without tenant DNS changes (the conversation's rotation-without-tenant-action point).
- **A11-DKIM-2**: The wizard MUST support (and default to) a rotatable selector scheme so key rotation is a Diamy-side operation. At least one valid selector MUST verify before sending is enabled (A11-DKIM covers the sending gate; §9).
- **A11-DKIM-3**: DKIM alignment (the `d=` domain matching the From domain) MUST be verified as part of activation, since DMARC alignment (A10-AUTH-3) depends on it.

------

# 6. DMARC Progressive Rollout

- **A11-DMARC-1**: Diamy generates a DMARC record, starting at **`p=none`** (monitoring only, zero risk to existing flows — the conversation's staged approach). `p=none` with a `rua` reporting address (Diamy-hosted aggregate report ingestion) lets the tenant see what would be affected before enforcing.
- **A11-DMARC-2**: The wizard MUST assist a **progressive rollout**: `p=none` → observe aggregate reports until the tenant's legitimate sources are all aligned → `p=quarantine` → `p=reject`. Each step is presented with the evidence (are all your senders aligned?) so the tenant advances safely, not blindly. Advancing to `quarantine`/`reject` MUST be a deliberate, informed tenant action, never auto-forced (auto-forcing could quarantine a tenant's own legitimate-but-unaligned source).
- **A11-DMARC-3**: Diamy MUST ingest DMARC aggregate (`rua`) reports and present them intelligibly (which sources pass/fail alignment), so the rollout is data-driven. This is the tooling that makes progressive DMARC feasible for a non-expert tenant.
- **A11-DMARC-4**: The **inbound** self-domain DMARC-fail protection (A01-AUTH-5) benefits from the tenant reaching `p=quarantine`/`reject`, but Diamy's inbound flagging of self-domain spoofing does NOT depend on the tenant's own DMARC policy level — Diamy flags it regardless (defense in depth).

------

# 7. MX and PTR

- **A11-MX-1**: The wizard generates the MX record pointing to `diamy-mxd` (A01), and manages the **cutover** (§9.2): receiving activates when the MX is verified and the tenant is ready, with attention to the sequencing decision (§11).
- **A11-MX-2** (cutover impact warning): Pointing the domain's MX to Diamy **diverts inbound mail away from the tenant's existing mail system**. The wizard MUST warn the tenant before MX cutover that their current mail server will stop receiving new mail for this domain once MX propagates, and SHOULD guide a safe transition (e.g. keep receiving on both during a migration window if the tenant runs a dual-delivery setup, or schedule cutover deliberately). A silent MX change that unexpectedly cuts off the tenant's existing inbox is an operational failure the wizard MUST prevent by disclosure.
- **A11-PTR-1**: Reverse DNS (PTR) for Diamy's sending IPs is a Diamy/pool provisioning obligation (A10-BULK-2, A23), NOT a tenant DNS action — the tenant does not control Diamy's sending IPs' PTR. The wizard informs the tenant this is handled platform-side, so they are not confused into thinking they must set it.

------

# 8. Real-Time Verification

- **A11-VER-1**: The wizard MUST poll DNS and show **live per-record status** (green when the published record matches the expected value, red/amber otherwise), so the tenant sees progress as they publish (the Microsoft-model UX). It MUST handle DNS propagation delay gracefully (retry/poll, "waiting for propagation" state), not fail permanently on a not-yet-propagated record.
- **A11-VER-2**: Verification MUST check not just presence but **correctness**: SPF includes the right target and stays within 10 lookups (§4); DKIM selector resolves and the key matches; DMARC is syntactically valid and at the expected policy; MX points to Diamy. A record that is present-but-wrong MUST show as an error with the specific problem, not a false green.
- **A11-VER-3**: Verification results and the DNS values observed MUST be recorded/audited at activation, so a later deliverability issue can be traced to the DNS state at onboarding.

------

# 9. Fail-Closed Activation Gate (Normative)

- **A11-GATE-1**: Mail activation is **fail-closed** (SEC-FC, SEC-OUT-2): the domain does NOT send until SPF, DKIM, and DMARC are verified aligned. This mirrors Microsoft's functional block (the conversation's reference: not a warning, a real gate). A tenant cannot bypass the gate; unverified = not-send-enabled.
- **A11-GATE-2** (Microsoft-style block): Following the conversation's note that Microsoft now *blocks* domain addition until DNS verification passes, Diamy MUST likewise block send-enablement (not merely warn) until the required records are green. Warnings-only would let a misconfigured tenant degrade shared-infrastructure reputation (A10-REP-4).

## 9.2 Split activation (receive vs send)

- **A11-GATE-3**: Receiving and sending activate on **different gates**, because their prerequisites differ:
  - **Receiving** activates when the MX is verified (and domain-control proven, §3). A tenant can receive before its sending auth is fully rolled out.
  - **Sending** activates only when SPF + DKIM + DMARC verify aligned (A11-GATE-1). Sending is the reputation-bearing direction, so its gate is stricter.
  This split lets a tenant start receiving quickly while completing the sending-auth rollout, without either compromising the fail-closed sending gate or blocking inbound unnecessarily.

------

# 10. Pending States

- **A11-PEND-1**: A domain mid-onboarding is in a **pending** state with explicit sub-states: `awaiting_domain_control`, `awaiting_dns_publish`, `awaiting_propagation`, `receive_active_send_pending`, `fully_active`. The UI and API MUST expose the precise sub-state so the tenant knows exactly what remains.
- **A11-PEND-2** (unresponsive DNS provider): For the common case of a tenant whose DNS is managed by a slow third-party provider (the conversation's edge case), the domain MAY sit in `awaiting_dns_publish`/`awaiting_propagation` indefinitely without error — the wizard keeps polling and the tenant completes when their provider acts. Receiving MAY be pre-staged (MX pending) but MUST NOT deliver until MX verifies.
- **A11-PEND-3**: A mailbox provisioned under a domain that is `receive_active_send_pending` can receive but its user's outbound is blocked with a clear reason (domain sending not yet enabled), consistent with A10 §10.

------

# 11. First-Device Enrollment Sequencing — closes A17 §12 HIGH item

The HIGH open decision (A17 §12): should onboarding mandate first-device enrollment before per-user MX activation, which would narrow the gateway hold queue (A01-HOLD / A17-DIR-5) from a routine mechanism to a rare safety net?

- **A11-SEQ-1** (decision): Onboarding **SHOULD** sequence, per user, so that a mailbox becomes an active MX destination only after (or concurrently with) that user's first device enrollment, **where the onboarding path allows it** — specifically for interactive, user-by-user onboarding. For these paths, the hold queue is then a rare safety net, not the routine landing zone.
- **A11-SEQ-2** (why not mandatory): Sequencing CANNOT be mandated for all paths. Two real paths defeat it: **bulk migration** (a tenant migrates 500 mailboxes and points MX to Diamy before any user logs in) and **MX cutover before user login** (the domain's MX flips atomically; mail arrives for users who have not yet enrolled). For these, mail WILL arrive for zero-device recipients, and the hold queue (A01-HOLD) is REQUIRED. Therefore the hold queue remains the mandated baseline (A01 keeps it), and sequencing is an **optimization** that narrows its routine use, not a replacement.
- **A11-SEQ-3** (resolution): The decision is: **keep the hold queue as the mandatory baseline (A01-HOLD unchanged); add per-user sequencing as an onboarding optimization for interactive paths (this annex); the hold-queue default duration MAY be shorter for tenants whose onboarding is fully sequenced.** This closes A17 §12: the hold queue is not removed, and sequencing does not become a false guarantee. Both mechanisms coexist, each covering what the other cannot.
- **A11-SEQ-4**: A tenant onboarding profile MUST record whether it is `sequenced` (interactive, per-user enrollment before MX-active) or `bulk` (MX-active before enrollment). The hold-queue policy (duration, size) MAY be tuned per profile (A01-HOLD-3), with `bulk` getting the fuller default and `sequenced` a shorter safety-net window.

------

# 12. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Domain-control proof fails | No credentials generated, no MX accepted; clear error; not onboarded (A11-CTRL-1) |
| Existing SPF present | Merge, never replace; warn on 10-lookup overflow (A11-SPF-2/3) |
| SPF would exceed 10 lookups | Warn + propose remedies; do NOT publish a permerror SPF (A11-SPF-3) |
| DNS not yet propagated | Keep polling, `awaiting_propagation` state; do NOT fail permanently (A11-VER-1) |
| Record present but wrong | Show specific error, not false green (A11-VER-2) |
| Partial verification (e.g. SPF green, DKIM red) | Domain stays pending; sending NOT enabled; receiving MAY enable if MX green (A11-GATE-3) |
| Pool reassigned (egress IPs change) | SPF re-verification required before emitting from new pool (A11-SPF-4, A10-AUTH-2) |
| Tenant tries to advance DMARC to reject with unaligned sources | Warn with report evidence; require deliberate confirmation; never auto-force (A11-DMARC-2) |

------

# 13. Observability Contract

Per A00 §11:

- counters: `onboarding_started_total`, `onboarding_completed_total`, `domain_control_verifications_total{result}`, `dns_verifications_total{record,result}`, `spf_merge_performed_total`, `spf_lookup_overflow_warnings_total`, `dmarc_rollout_advances_total{from,to}`, `send_enablement_total{result}`
- gauges: domains by onboarding sub-state, domains at each DMARC policy level, domains send-enabled vs receive-only
- audit (OBS-3): domain-control proofs, send-enablement (the fail-closed gate crossing), DMARC policy advances, SPF merges, pool-reassignment re-verifications
- **A11-OBS-1**: The DMARC aggregate reports ingested (A11-DMARC-3) contain third-party sending metadata; their storage and display MUST respect tenant data boundaries and MUST NOT leak one tenant's report data to another.

------

# 14. Test Scenarios (Normative)

1. **Clean onboard**: new domain, no existing SPF → generate SPF/DKIM/DMARC(p=none)/MX → publish → live verification greens each → receiving activates on MX, sending activates on SPF+DKIM+DMARC aligned.
2. **SPF merge**: domain with existing `include:_spf.salesforce.com` → wizard merges Diamy include, preserves Salesforce, presents merged record; Salesforce mail keeps passing SPF post-onboard (A11-SPF-2).
3. **SPF overflow**: existing SPF already at 9 lookups → adding Diamy would hit 11 → wizard warns, proposes flattening/subdomain, does not publish a permerror record (A11-SPF-3).
4. **Fail-closed send gate**: SPF+DKIM green, DMARC not yet published → sending NOT enabled; attempt to send → blocked with reason; receiving works (A11-GATE-1/3).
5. **DMARC rollout**: p=none → ingest rua reports → show unaligned source → tenant fixes → advance to quarantine (deliberate) → later reject; never auto-forced (A11-DMARC-2).
6. **Slow DNS provider**: records not propagated for hours → stays `awaiting_propagation`, keeps polling, no permanent failure; completes when provider publishes (A11-PEND-2).
7. **Present-but-wrong**: DKIM selector published with a typo → shows specific DKIM error, not green (A11-VER-2).
8. **Pool reassignment**: tenant moved to a pool with different egress IPs → SPF re-verification triggered; emitting from new pool blocked until SPF green (A11-SPF-4).
9. **Sequenced vs bulk**: interactive onboard enrolls a device before MX-active → hold queue rarely used; bulk migration flips MX before enrollment → hold queue catches mail for un-enrolled users (A11-SEQ, A01-HOLD).
10. **Domain-control**: attempt to onboard a domain without publishing the control TXT → refused, no MX/credentials (A11-CTRL-1).

------

# 15. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Replacing an existing SPF record instead of merging, breaking the tenant's other senders on migration day (A11-SPF-2) — the single most damaging onboarding bug.
2. ❌ Publishing an SPF that exceeds 10 lookups (permerror), which is worse than no SPF (A11-SPF-3).
3. ❌ Enabling sending on a warning instead of a fail-closed green gate (A11-GATE-1/2) — a misconfigured tenant degrades shared reputation.
4. ❌ Auto-forcing DMARC to quarantine/reject, quarantining the tenant's own unaligned-but-legitimate sources (A11-DMARC-2).
5. ❌ Skipping domain-control proof, letting a tenant onboard a domain they don't own (A11-CTRL-1).
6. ❌ Showing a false green on a present-but-wrong record (A11-VER-2).
7. ❌ Failing permanently on un-propagated DNS instead of polling (A11-VER-1, A11-PEND-2).
8. ❌ Using one activation gate for both receive and send, either blocking inbound needlessly or enabling send too early (A11-GATE-3).
9. ❌ Not re-verifying SPF on pool reassignment, emitting from IPs outside the published SPF (A11-SPF-4, A10-AUTH-2).
10. ❌ Treating per-user sequencing as a replacement for the hold queue, so bulk-migration mail for un-enrolled users is lost (A11-SEQ-2/3, A01-HOLD).
11. ❌ Normalizing the onboarded domain differently from the auth checks / principal addresses (A11-CTRL-2, A24).
12. ❌ Instructing the tenant to set PTR for Diamy's sending IPs (they can't; it's platform-side) (A11-PTR-1).
13. ❌ Cutting over the MX to Diamy without warning the tenant that their existing mail system stops receiving, silently black-holing their current inbox during migration (A11-MX-2).

------

# 16. Deferred Items

- Registrar/DNS-provider API integrations (auto-publish records via the provider's API where the tenant authorizes) — a major UX improvement over copy-paste; deferred, the manual-publish + live-verify flow is V1.
- Hosted-DNS option (Diamy operating the tenant's DNS) — removes the publish step entirely for tenants who delegate; deferred, has support/liability considerations.
- BIMI record generation (builds on DMARC reject) — deferred with A10 BIMI.
- Automated SPF flattening service — the overflow remedy (A11-SPF-3) is currently advisory; automating it is deferred.

------

*End of document.*
