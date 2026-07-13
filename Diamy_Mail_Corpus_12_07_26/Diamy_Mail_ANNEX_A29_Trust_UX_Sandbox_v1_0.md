# Diamy Mail — ANNEX A29: Trust UX, Protective Actions & Sandbox Workspace

**Document title:** Diamy Mail — ANNEX A29: Trust UX, Protective Actions & Sandbox Workspace
**Version:** 1.0
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 5th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification (A00)
**Sibling dependencies:** A06 (Trust — Origin v1.2), A07 (Trust — Links & Attachments v1.2), A08 (HTML→Tiptap v1.1), A09 (Rendering Sandbox v1.1), A16 (Message Classification v1.1), A19 (Client SDK v1.2)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 5th 2026 | Cédric BORNECQUE | Initial document: the client-side behavioral contract for trust — contextual-warning discipline (signal-triggered, explained, never categorical; the anti-"external banner" principle), the normative action×band matrix (open/save/click/reply/forward per A06 band, consuming A07 tiers; save blocked at high band), the sandbox workspace (suspicious mail routed to a visible constrained folder where the message can be worked with safely; sandbox is a message STATE, not a folder — release is explicit, explained, audited), progressive-disclosure pedagogy and teachable moments, green-state parity, responsible bypass, the alarm-budget metric making anti-fatigue measurable, failure model, test scenarios, common AI errors. Motivated by a real sample (a legitimate in-thread business reply carrying a categorical "external sender" banner — the alarm-fatigue anti-model). |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies the **client-side behavioral contract for trust**: how the scores, bands, reason codes, and access tiers produced by A06/A07 translate into what the user sees and what the client allows — warnings, degraded actions, and the **sandbox workspace** where suspicious messages can be examined safely. A06/A07 fix the *data*; this annex fixes the *behavior*; the visual rendering (colors, layout, wording of localized strings) remains a client design concern.

Implementation lives in the client per the A19 execution contract. Server-side routing of sandboxed messages reuses the A16 folder-routing machinery. In-sandbox isolation reuses the A08 (safe default rendering) and A09 (view-original isolation) mechanisms — this annex introduces **no new isolation technology**, only a policy composition of existing ones.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 The gap this annex closes

Industry email security is largely binary: a message is either blocked/quarantined (invisible to the user) or delivered as implicitly clean. Everything delivered inherits full capability — open, save, click, reply — regardless of residual suspicion. The characteristic failure is the message that "slips through the net": scored suspicious-but-not-blockable, delivered with full powers. The second characteristic failure is the categorical warning (e.g. an unconditional "this message comes from outside the company" banner on every external mail) that triggers on ~100% of legitimate correspondence and trains users to ignore warnings entirely. This annex defines the missing third class: **delivered, visible, explained, and capability-degraded proportionally to its band** — the practical realization of A06-PRIN-1 (transparent), A06-PRIN-3 (false-positive-averse), and A06-PRIN-5 (aid, not gate).

## 1.2 Out of scope

Score computation (A06/A07). Tier governance and the T1–T4 mechanisms (A07 §6 — consumed here, not redefined; the A07-POL-1 floor is inviolable from this annex). Rendering isolation mechanics (A08/A09). Spam/bulk classification and its folders (A16 — the sandbox is NOT the spam folder, §5.1).

------

# 2. Contextual Warning Discipline (Normative — the anti-banner principle)

- **A29-WARN-1** (signal-triggered only): Every user-visible trust warning MUST be triggered by the message's own trust signals (its A06/A07 band and factors). A warning MUST NOT be triggered by a categorical property alone — external vs internal origin, presence of an attachment, presence of links, first-ever sender as a standalone criterion. Categorical banners mark everything and therefore mark nothing; they are the documented alarm-fatigue anti-model (A06-PRIN-3, "once users stop believing the alerts, the tool becomes useless").
- **A29-WARN-2** (explained, always): A warning MUST state *why*, using the localized rendering of the stable reason codes (A06-EXP-1, A07-UX-3): "authentification valide mais infrastructure de soumission incohérente avec le domaine" — never a generic "be careful with this message". A warning that cannot cite at least one concrete factor MUST NOT be shown.
- **A29-WARN-3** (band-proportionate): `low` band → no warning (a clean message looks clean, A29-GRN-1). `moderate` → a discreet indicator, no interruption. `elevated` → a visible contextual warning on the message. `high` → prominent warning + sandbox routing per policy (§5). Severity presentation follows bands, never raw scores (A06-PRIN-2).
- **A29-WARN-4** (the alarm budget — normative and measured): The proportion of delivered messages carrying a visible warning (elevated+high) is a first-class calibration metric (§9). A rising warning rate on legitimate traffic is a calibration regression (A06-FP-3) to detect and revert — the anti-fatigue discipline as a measurable contract, not an aspiration. Tenants MUST be able to see their warning rate.
- **A29-WARN-5** (no warning duplication): One message, one coherent assessment surface (A06-COMB-2): origin, link, and attachment factors merge into a single explained indicator — never a stack of separate banners competing for attention.

------

# 3. Action × Band Matrix (Normative defaults)

The matrix defines the default behavior of each user action per combined band (A06 §9). Tenants MAY tighten any cell; they MUST NOT loosen below the A07-POL-1 floor (known-malicious = T4 always) nor below the `high`-band save block (A29-ACT-3). Attachment cells compose with the A07 tier already assigned to the specific attachment — the stricter of (band default, attachment tier) applies.

| Action | low | moderate | elevated | high |
| ------ | --- | -------- | -------- | ---- |
| **Open attachment** | direct | direct + indicator | T1 informed confirmation | secure viewer (T3) only, per attachment tier |
| **Save / download attachment** | direct | direct | T1 + audited | **BLOCKED** (A29-ACT-3) |
| **Click link** | direct | real destination shown pre-click (A07-UX-1) | interstitial with explanation + real destination | blocked with explanation; copy-URL requires T1-style confirm |
| **Reply** | direct | direct | contextual warning before send | strong warning; RECOMMENDED tenant option: require confirmation |
| **Forward** | direct | direct | contextual warning (propagation) | warning + forwarded copy carries the trust metadata (A29-ACT-5) |
| **Load remote content** | per user default | per user default | blocked, explicit opt-in via proxy (A09-IMG) | forced-blocked (sandbox restriction set, §5.3) |

- **A29-ACT-1**: The matrix governs *defaults*; the explained bypass path (§7) exists for every degraded cell except the inviolable floors (T4; the high-band save block is bypassable only by an admin release through the sandbox ceremony §5.5, not by the end user in place).
- **A29-ACT-2**: Degradation MUST be visible and explained at the point of action ("Enregistrement bloqué : score de confiance élevé-risque — ouvrir dans la visionneuse sécurisée à la place"), never a silently missing button. A capability that vanishes without explanation teaches the user nothing and reads as a bug (A29-PED).
- **A29-ACT-3** (the save block — normative): At `high` band, saving/downloading an attachment to the device filesystem is **blocked**. Rationale: saving is the moment the platform loses custody — once the file is on disk, no tier, viewer, or later intelligence update can protect the user. Reading via the T3 secure viewer remains available (work is not blocked; custody transfer is). The block is lifted only by release from the sandbox (§5.5) or by the A07 T2 admin-approval path where the tenant enables it.
- **A29-ACT-4** (reply as attack surface): Reply warnings exist because reply IS the payload of BEC/impersonation fraud — the victim's damage is done by responding, not by clicking. An `elevated`/`high` message with `compromised_account_pattern` or `self_domain_dmarc_fail` factors (A06) MUST surface those factors in the reply-time warning specifically.
- **A29-ACT-5** (forward propagation): Forwarding an `elevated`/`high` message within the same tenant MUST propagate the trust metadata so the recipient's client shows the same assessment — forwarding MUST NOT launder a suspicious message into a trusted-colleague delivery. Forwarding externally carries the standard outbound path (A10); the warning notes the user is propagating suspect content.

------

# 4. Pedagogy & Progressive Disclosure

- **A29-PED-1** (three depths): Trust information is presented in three progressive layers: (1) the at-a-glance band indicator; (2) one tap/click → the explained factor list in plain language (localized reason codes); (3) an explicit "technical details" drill-down → auth results, infrastructure summary, and (per A06-EXP-2) optionally raw headers. Layer 1 is ambient; layer 2 is the product's core promise (replace header-reading with an explanation); layer 3 exists for the expert and the evidence case (A09-LEGAL).
- **A29-PED-2** (teachable moments): The FIRST time a user encounters a given high-severity pattern (`compromised_account_pattern`, display-vs-href mismatch, `self_domain_dmarc_fail`, password-protected archive), the client SHOULD show a one-time short plain-language explanation of what the pattern *means* and why it matters — then never re-show it unprompted (a persistent "learn more" link suffices thereafter). Teaching once builds competence; repeating forever builds blindness.
- **A29-PED-3**: Warning language addresses the situation, never the user's competence, and states what the user CAN do safely (read, secure-view) alongside what is degraded — protective, not punitive.
- **A29-GRN-1** (green-state parity — normative): Low-band messages MUST look affirmatively clean (A07-UX-2 elevated to a general rule): the visible absence/positive-state of the indicator on ordinary mail is what makes its presence on suspect mail credible. An implementer MUST NOT show trust chrome only on bad messages — contrast is the mechanism.

------

# 5. Sandbox Workspace (Normative)

The user-facing containment: suspicious messages are routed to a visible **sandbox folder** where they can be read and worked with safely under a forced restriction set, until explicitly released or deleted.

## 5.1 What it is — and is not

- **A29-SBX-1** (state, not folder — normative): Sandbox containment is a **message state** (`sandbox_state: active | released | none`), not a folder location. The folder named e.g. "Zone sécurisée" is the UI **projection** of that state. Consequences an implementer MUST honor: moving the message to another folder does NOT clear the state (restrictions follow the message); the state is cleared ONLY by the explicit release ceremony (§5.5); search results, thread views, and any other surface showing a sandboxed message apply the same restriction set. Implementing the sandbox as a mere folder whose exit lifts restrictions is the primary anticipated implementation error (§11 #1).
- **A29-SBX-2** (not the spam folder, not server quarantine): The sandbox is a *workspace*, distinct from: the A16 junk/bulk folders (classification, not containment); server-side withholding (A07 T2/T4 — those attachments never reach the client in openable form regardless of sandbox state). A message can be in the sandbox with a T4-blocked attachment: the sandbox governs the message-level interaction; the tier governs that attachment.
- **A29-SBX-3** (server-visible state, deliberately): `sandbox_state` and its entry reason are `PLAINTEXT_METADATA` — they derive from `trust_metadata` (already plaintext, A06-OUT-1) and the server needs them for frontier routing (§5.2) and multi-device consistency (A04 sync). No content exposure is added.

## 5.2 Entry

- **A29-SBX-4** (automatic entry): Band→sandbox routing is tenant policy applied at the frontier via the A16 folder-routing hook. RECOMMENDED defaults: `high` → auto-sandbox; `elevated` → deliver to inbox with the §3 degradations, plus a one-tap "examiner en zone sécurisée" affordance; `moderate`/`low` → never auto-sandboxed. Auto-sandboxing MUST be visible (the message appears in the sandbox folder with its explanation) — never silent disappearance (A01-AUTH-3 discipline: visible over silent).
- **A29-SBX-5** (manual entry): The user MUST be able to send ANY message to the sandbox regardless of band ("this looks off to me") — the user's suspicion is a legitimate signal the platform respects. Manual entry is recorded as such (entry reason `user_initiated`).
- **A29-SBX-6** (retroactive entry): If post-delivery intelligence upgrades a message's assessment (e.g. a hash-reputation hit arriving after delivery, A07 §12 feeds), the platform MAY retroactively sandbox the affected message. Retroactive entry MUST notify the user with the new factor ("cette pièce jointe correspond désormais à une signature malveillante connue") — retroactive silent capability loss without explanation is forbidden.

## 5.3 The restriction set (what "in the sandbox" means)

Inside `sandbox_state: active`, the client MUST enforce, regardless of band:

| Capability | In-sandbox behavior |
| ---------- | ------------------- |
| Read body | ALLOWED — Tiptap safe rendering only (A08); this is the point: the user can work |
| View original | ALLOWED via the full A09 path (it is already maximal isolation); remote content forced-blocked, no opt-in override while sandboxed |
| Copy text | ALLOWED — the Tiptap-rendered text is sanitized content (A08); reading and quoting is "working safely" |
| Open attachment | T3 secure viewer ONLY (A07-POL-4 flow), regardless of the attachment's own tier being lower |
| Save attachment | BLOCKED (A29-ACT-3, unconditional in sandbox) |
| Click link | BLOCKED; real destination + explanation shown; copy-URL behind explicit confirm |
| Reply / Forward | BLOCKED by default; tenant MAY allow reply with a strong warning (some workflows must answer, e.g. abuse desks) |
| Remote content | forced-blocked, no opt-in |
| Print / export | export via the A09-LEGAL evidence path (explicit, warned, audited); ordinary print MAY be allowed |

- **A29-SBX-7**: The restriction set composes with, and never weakens, the per-attachment tiers and the A07-POL-1 floor. Sandbox is a ceiling clamp on capability, never a source of additional capability.
- **A29-SBX-8** (working safely is the goal): The sandbox MUST remain a place where reading, inspection, and evidence handling are fluid — a sandbox so locked that users fight to release messages defeats itself (the same fatigue economics as warnings, A29-WARN-4). Read + secure-view + copy-text + evidence-export is the deliberate "safe work" envelope.

## 5.4 Multi-device & sync

- **A29-SBX-9**: `sandbox_state` syncs through A04 like any message state; all devices enforce the same restriction set. State transitions (entry, release) are journal events; conflicting concurrent transitions resolve by the A04 conflict rules with the SAFER state winning a tie (active beats released on identical timestamps — fail-closed, SEC-FC discipline).

## 5.5 Release (the exit ceremony)

- **A29-SBX-10** (explicit, explained, audited): Release is a deliberate action that MUST: (1) display the message's full explained assessment (the §4 layer-2 view) at the moment of decision; (2) require explicit confirmation in plain language ("Je comprends les risques signalés et je libère ce message"); (3) be audit-logged (who, when, which message, which factors — OBS-3, the A07-POL-2 decision-of-record discipline). Release sets `sandbox_state: released`: the §5.3 clamp lifts and the message reverts to its band's §3 matrix behavior — release does NOT rewrite the band or the trust metadata (the message stays `high` with `released_by_user`; an implementer MUST NOT launder the score on release).
- **A29-SBX-11** (who may release): By default the user releases their own sandboxed messages, EXCEPT: the high-band save block after release still requires the T2 admin path where tenant policy says so, and T4/known-malicious attachments are never releasable below their floor (A07-POL-1). A tenant MAY require admin approval for any release from auto-sandboxed `high` messages (the A07-POL-3 governance reused).
- **A29-SBX-12** (the other exits): Delete and report-and-delete (feeding the report to tenant security / abuse per A16 governance) MUST be first-class sandbox actions, presented with equal prominence to release — the safest exit should be the easiest.

------

# 6. Trust Context Preservation

- **A29-CTX-1**: The assessment (band + factors) MUST remain visible on every surface where the message or its content appears: message view, sandbox, view-original (A09-TRUST-1), thread list entry, search results, and the reply/forward composer when quoting a suspect message. No trust-context-free zone.

------

# 7. Responsible Bypass

- **A29-BYP-1**: Every bypassable degradation (§3, A29-ACT-1) follows the T1 discipline: the risk restated in plain language at the decision point, explicit confirmation, audit log (A07-POL-2). A bypass is a decision of record.
- **A29-BYP-2** (no global fatigue valves): There MUST NOT be a global "ne plus me demander" that disables warnings or confirmations wholesale. Per-correspondent easing MAY exist, ONLY as an on-device preference informed by accumulated positive history (A06 §7 discipline — the correspondent graph never leaves the device), and MUST NOT suppress `high`-band warnings even for a trusted correspondent (a trusted correspondent whose account is compromised is precisely the A06-SCORE-5 case).

------

# 8. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Trust metadata missing/unreadable for a message | Treat as unassessed: `moderate`-equivalent presentation with an honest "could not assess" factor (A06-EXP-3 discipline); MUST NOT default to clean chrome, MUST NOT default to high-band alarm |
| T3 secure viewer unavailable for a sandboxed attachment | Fail safe per A07 §9: attachment stays inaccessible with clear notice; never fall back to raw delivery |
| `sandbox_state` sync conflict | Safer state wins ties (A29-SBX-9); convergence via A04 |
| Client version predating a reason code | Show the factor with a generic-but-honest label + severity (codes are stable, strings are client-side, A06-EXP-1); never drop the factor silently |
| Release audit log unavailable | Release is deferred (fail-closed): the decision of record cannot be off the record; user sees "libération momentanément indisponible" |
| Retroactive sandbox on an already-open message | Restrictions apply from the transition moment; the user is notified with the new factor (A29-SBX-6); no retroactive pretense the past exposure didn't happen |

------

# 9. Observability Contract

Per A00 §11:

- counters: `warnings_shown_total{band}`, `actions_degraded_total{action,band}`, `sandbox_entries_total{reason}` (auto/user/retroactive), `sandbox_releases_total`, `sandbox_deletes_total`, `bypasses_total{action}` , `teachable_moments_shown_total{pattern}`
- gauges: messages currently sandboxed (aggregate), **warning rate** = share of delivered messages at elevated+high (the A29-WARN-4 alarm budget, per tenant)
- audit (OBS-3): every release (A29-SBX-10), every bypass (A29-BYP-1), retroactive sandboxings, tenant policy changes to the matrix
- **A29-OBS-1**: Telemetry MUST NOT include message content, subjects, sender identities, or URLs (A07-OBS-1 discipline) — bands, actions, counts, and reason-code identifiers only.

------

# 10. Test Scenarios (Normative)

1. **The banner anti-test (SFR-inverse)**: a legitimate in-thread reply from a regular external correspondent, all-auth-pass, low band → NO warning of any kind; clean chrome (A29-WARN-1, A29-GRN-1). This scenario failing (any categorical "external" warning appearing) is a release blocker.
2. **Explained warning**: elevated-band message → warning cites concrete localized factors, one coherent surface, no factor-free generic text (A29-WARN-2/5).
3. **Save blocked at high**: high-band message with a whitelisted-clean PDF → open-in-secure-viewer available, save/download blocked with explanation (A29-ACT-2/3).
4. **Matrix composition**: moderate-band message carrying a T2 attachment → attachment follows T2 (stricter wins); body actions follow moderate (A29-ACT intro).
5. **Reply warning targets the factor**: elevated message with `compromised_account_pattern` → the reply-time warning names that pattern (A29-ACT-4).
6. **Forward does not launder**: forwarding a high-band message internally → recipient's client shows the same band/factors (A29-ACT-5).
7. **Sandbox is a state**: auto-sandboxed message dragged to Inbox → restriction set still fully enforced; only release lifts it (A29-SBX-1).
8. **Safe work inside**: sandboxed message → body readable (Tiptap), text copyable, PDF viewable via T3, link click blocked with real destination shown, save blocked (A29-SBX-8, §5.3).
9. **Release ceremony**: release → assessment displayed, explicit confirm, audit entry written; band metadata unchanged, `released_by_user` set; failed audit write defers the release (A29-SBX-10, §8).
10. **Manual + retroactive entry**: user sandboxes a low-band message (accepted, `user_initiated`); a later hash-reputation hit retroactively sandboxes a delivered message with notification (A29-SBX-5/6).
11. **Multi-device convergence**: device A releases while device B is offline-sandboxed-active with an identical-timestamp conflicting transition → safer state wins the tie; devices converge (A29-SBX-9).
12. **Teachable moment fires once**: first `self_domain_dmarc_fail` → one-time explanation; second occurrence → indicator + factors only (A29-PED-2).
13. **No global opt-out**: verify no setting disables warnings wholesale; per-correspondent easing never suppresses high-band (A29-BYP-2).
14. **Unassessed message**: message with missing trust metadata → honest "could not assess" presentation, neither clean nor alarming (§8).

------

# 11. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Implementing the sandbox as a plain folder whose exit (drag, move, search-open) lifts restrictions — it is a message STATE; only the release ceremony clears it (A29-SBX-1).
2. ❌ Adding a categorical warning (external sender, has-attachment, has-links) — the exact alarm-fatigue anti-model this annex exists to forbid (A29-WARN-1).
3. ❌ Showing warnings without concrete factors, or stacking multiple competing banners on one message (A29-WARN-2/5).
4. ❌ Silently removing a degraded capability (a save button that just isn't there) instead of visible-and-explained degradation (A29-ACT-2).
5. ❌ Letting release rewrite or launder the trust metadata instead of setting `released_by_user` over the intact assessment (A29-SBX-10).
6. ❌ Allowing sandbox restrictions to be weaker than the message's own tiers/floors — sandbox is a clamp, never a capability grant (A29-SBX-7).
7. ❌ Making the sandbox so locked (no read, no copy, no secure view) that it becomes a fight-to-release friction generator (A29-SBX-8).
8. ❌ Silent auto-sandboxing (message vanishes from inbox with no visible trace) — visible over silent, always (A29-SBX-4).
9. ❌ Shipping a global "don't ask again", or letting per-correspondent easing suppress high-band warnings (A29-BYP-2) — the trusted-but-compromised correspondent is the A06-SCORE-5 case.
10. ❌ Defaulting missing trust metadata to clean chrome (false reassurance) or to high alarm (false positive) instead of honest "could not assess" (§8).
11. ❌ Skipping the audit write on release/bypass, or proceeding when it fails — decisions of record are fail-closed (A29-SBX-10, §8).
12. ❌ Forgetting trust context on secondary surfaces (search results, thread previews, quote-in-composer), creating trust-context-free zones (A29-CTX-1).
13. ❌ Showing trust chrome only on suspicious messages — green-state parity is the mechanism that keeps warnings credible (A29-GRN-1).
14. ❌ Re-showing teachable-moment explanations forever, converting pedagogy into noise (A29-PED-2).

------

# 12. Deferred Items

- **Sandbox for outbound** (a "hold my own send for review" staging state) — a different flow; recorded for consideration.
- **Collaborative sandbox** (share a sandboxed message with tenant security for analysis without releasing it) — ties to A27 delegation and the A16 report path; deferred.
- **Automatic release on intelligence downgrade** (a feed correction lowers the band — auto-release or notify-and-suggest?) — RECOMMENDED posture is notify-and-suggest, never silent auto-release; full design deferred.
- **Warning-rate anomaly alerting** (operational alert when a tenant's alarm budget spikes, indicating calibration regression) — with A22 health thresholds.
- **Localized reason-code string corpus** (the full FR/EN string set for all A06/A07 codes) — a content deliverable, tracked separately from this behavioral contract.

------

*End of document.*
