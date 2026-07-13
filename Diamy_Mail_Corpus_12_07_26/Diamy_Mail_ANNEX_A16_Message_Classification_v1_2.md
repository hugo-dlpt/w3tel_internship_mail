# Diamy Mail — ANNEX A16: Message Classification

**Document title:** Diamy Mail — ANNEX A16: Message Classification
**Version:** 1.2
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 5th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)
**Sibling dependencies:** A06 (Trust — Origin v1.2), A07 (Trust — Links & Attachments v1.2), A08 (HTML→Tiptap v1.1), A01 (Inbound Gateway v1.2), A29 (Trust UX & Sandbox Workspace v1.0)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: message classification (bulk/marketing vs transactional vs 1:1), signal reuse from Tiptap structure + headers + trust metadata, classification-vs-trust separation, folder/label routing, frontier-vs-client placement decision (closes A00 Open Decision #6), false-classification discipline, tenant policy, failure model, test scenarios, common AI errors. Closes A00 Open Decision #6. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: content verified coherent (classification/trust separation, two-layer placement mirroring A06-COMB-1b, signal reuse). No content issues found. Confirmed closure of A00 Open Decision #6; A00 updated to v1.3 to reflect this and the other annex-closed decisions (#2/#3/#4). |
| 1.2     | Jul 5th 2026 | Cédric BORNECQUE | Coherence bump (corpus batch with A28/A29): sibling references updated to current versions; added A16-ROUTE-4 registering the sandbox-routing consumer — band→sandbox routing (A29-SBX-4) reuses this annex's frontier routing machinery but is TRUST-driven (A06/A07 band + tenant policy), not classification-driven, preserving the A16-SEP classification/trust separation; a sandbox-routed message still receives its normal classification labels. |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies **message classification**: labeling an inbound message by *kind* — marketing/bulk, transactional, mailing-list, or ordinary 1:1 mail — primarily to enable a "Promotions"-style organization and to inform (but never replace) the trust assessment. It reuses signals already produced elsewhere (the Tiptap structure from A08, headers from A01, trust metadata from A06/A07), so classification is largely free once those exist.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Closes Open Decision #6

A00 §14 Open Decision #6 asked where classification runs: server-side signal vs client-side only, given the structure signal is available post-Tiptap which is client-side. **This annex fixes the placement in §6**: a **frontier base classification** on header + origin signals (server-visible metadata, no body needed) plus a **client refinement** using the full Tiptap structure (which is client-side). Both layers, mirroring the trust two-layer model (A06-COMB-1b).

## 1.2 Classification is not trust (critical separation)

- **A16-SEP-1**: Classification (*what kind* of message) and trust (*how dangerous*) are **orthogonal** and MUST NOT be conflated (the conversation's key point: "la détection 'c'est de la pub' et la détection 'c'est dangereux' ne sont pas la même question"). A legitimate newsletter is "marketing + safe". A phishing mail imitating a newsletter is "looks-like-marketing + dangerous". A CEO-impersonation is "1:1-looking + dangerous". Routing a message to "Promotions" MUST NOT lower its trust scrutiny, and a high trust score MUST NOT suppress a phishing warning just because it looks like ordinary mail.

## 1.3 Out of scope

Trust scoring (A06/A07). Spam rejection at the gateway (A01 anti-abuse). The client folder UI. This annex classifies; the client presents (Promotions tab, etc.) and the tenant configures routing.

------

# 2. Classification Taxonomy (V1)

| Class | Meaning | Typical signals |
| ----- | ------- | --------------- |
| `transactional` | Automated 1:1 (receipts, password resets, order confirmations) | automated sender, single recipient, no unsubscribe, coherent org domain |
| `marketing` | Bulk promotional | List-Unsubscribe, bulk domain (`.news`, `mkt.`), high image/text ratio, many recipients over time |
| `mailing_list` | List/newsletter/discussion | `List-Id`, `List-*` headers, ARC from a list forwarder |
| `personal` | Ordinary 1:1 human mail | human sender, low automation markers, conversational structure |
| `bulk_other` | Bulk but not clearly marketing | bulk markers without clear promo intent |

- **A16-TAX-1**: Classes are not mutually exclusive at the signal level but the message gets one **primary class** for routing, plus secondary labels (e.g. primary `marketing`, label `has_unsubscribe`). The primary class drives default folder routing (§5); labels inform display and policy.
- **A16-TAX-2**: The taxonomy is versioned (`classification_version`) like the trust model, so a past classification remains interpretable after the taxonomy evolves.

------

# 3. Signals (reused, not re-derived)

Classification reuses signals already computed, avoiding a separate expensive model (the conversation's "presque gratuit une fois que tu as déjà construit le pipeline Tiptap").

## 3.1 Header signals (frontier, server-visible)

| Signal | Source |
| ------ | ------ |
| `List-Unsubscribe` / `List-Unsubscribe-Post` (RFC 8058) | headers — strong marketing/list marker |
| `List-Id` / `List-*` | headers — mailing-list marker |
| `Precedence: bulk` / `Auto-Submitted` | headers — bulk/automated marker |
| Bulk sending domain (`.news`, `mkt.`, ESP domains) | sender domain (A24) |
| Sender is a known ESP (Mailjet/Brevo/Mailchimp patterns) | infrastructure (A06) |
| Single vs many recipients (over history) | metadata + on-device history |

## 3.2 Structure signals (client, from Tiptap — A08)

| Signal | Source |
| ------ | ------ |
| Image/text ratio (many images, little text) | Tiptap node counts (A08) |
| Tracking-pixel presence | A08-IMG-2 detection |
| Layout-table-heavy structure (flattened count) | A08-TBL |
| Presence of a prominent CTA/unsubscribe in body | Tiptap link nodes |
| Hidden preheader present | A08-HID (benign marketing marker) |

## 3.3 Trust metadata (already computed, A06/A07)

Auth alignment, sending infrastructure, and link/attachment signals are available as trust_metadata and inform classification (e.g. an ESP with aligned DMARC + clean List-Unsubscribe = legitimate marketing; the same structure WITHOUT those = suspicious imitation, §4).

------

# 4. Classification-Trust Interplay (Normative)

- **A16-INT-1**: A "legitimate marketing" verdict requires the marketing structure signals (§3.2) **AND** the compliance/auth signals (aligned DMARC, valid List-Unsubscribe, coherent bulk domain — §3.1/§3.3). Marketing structure **without** the compliance signals is a phishing-imitates-marketing candidate — classified cautiously and NOT given a benign trust pass (the conversation's point: phishing imitates marketing structure precisely to blend in; conversely a message that imitates marketing without the conformity signals becomes a suspicious candidate).
- **A16-INT-2**: Classification MAY refine trust context but MUST NOT override it (A16-SEP-1): routing to "Promotions" MUST NOT suppress a phishing warning, and a message with strong negative trust signals MUST retain its trust warning regardless of its class. The client MUST show both (this is marketing) AND (this is dangerous) when both hold.
- **A16-INT-3**: The same instrumentation serves both directions (the conversation's "elles partagent une bonne partie de la même instrumentation"): the structure and header signals feed classification, the auth/infra/link signals feed trust, and they overlap. This annex MUST reuse the trust pipeline's outputs, not re-run analysis.

------

# 5. Routing and Labels

- **A16-ROUTE-1**: The primary class MAY drive a default folder/tab routing (e.g. `marketing` → Promotions tab), tenant-configurable. Routing is a **default suggestion**, overridable per-user (a user can move a message and train their own preference locally) and per-tenant (an org may disable Promotions grouping entirely).
- **A16-ROUTE-2**: Routing MUST NOT hide or auto-delete: a `marketing` message goes to a Promotions view, not to Trash, unless the user/tenant explicitly configures filtering. Silent loss is forbidden (consistent with the trust model's visible-over-silent principle, A01-AUTH-3).
- **A16-ROUTE-3**: User corrections (moving a misclassified message) MUST be respected and MAY train a **local, on-device** preference (per the privacy boundary: a user's classification corrections are personal data and SHOULD stay on-device like correspondent history, A06-HIST-2). Server-side aggregate learning across users is NOT done in V1 (privacy tension, recorded in deferred).
- **A16-ROUTE-4** (sandbox routing consumer — cross-ref): The sandbox workspace's automatic entry (A29-SBX-4, band→sandbox per tenant policy) reuses this annex's frontier routing machinery as its transport, but its trigger is the **trust band** (A06/A07), never the classification class — the classification/trust separation (A16-SEP-1) holds in both directions. A sandbox-routed message still receives its normal classification (primary class + labels); the sandbox state and the class are orthogonal, and the client MAY show both ("marketing" AND "en zone sécurisée") when both hold, consistent with A16-INT-2. Sandbox routing MUST NOT be implemented as a classification class.

------

# 6. Placement — Frontier Base + Client Refinement (closes Decision #6)

- **A16-PLACE-1** (frontier base): A **base classification** MUST be computable at the frontier from header + origin signals (§3.1, §3.3) that are server-visible metadata and need no body. This gives an immediate class stored in `trust_metadata.classification` (alongside trust, both metadata), so even a webmail or freshly-synced client has a class without local processing. Header markers (List-Unsubscribe, List-Id, Precedence) are strong and header-only — most marketing/list mail is classifiable from headers alone.
- **A16-PLACE-2** (client refinement): The client MAY **refine** the class using the full Tiptap structure signals (§3.2), which are only available client-side after conversion (A08 is client-side). The refinement can upgrade confidence or adjust the class (e.g. header-ambiguous mail that is clearly image-heavy marketing by structure). The refined class is a client-side enhancement; it MAY be cached in the encrypted local catalogue (A03) but the structure-derived refinement is NOT uploaded (same discipline as A06 on-device refinement, A06-COMB-1b).
- **A16-PLACE-3** (resolution of Decision #6): The decision is: **frontier computes a header/origin base class (metadata); the client refines with Tiptap structure (on-device).** This mirrors the trust two-layer model exactly (A06-COMB-1b) and reuses the same frontier-vs-client boundary. An implementer MUST NOT expect Tiptap structure at the frontier (it's client-side), and MUST NOT upload the client structure refinement.

------

# 7. False-Classification Discipline

- **A16-FALSE-1**: Misclassification is low-harm compared to mis-trust, but still matters: routing legitimate transactional mail (a password reset) to Promotions could make a user miss it. The classifier MUST be conservative about routing **transactional** mail away from the primary inbox — when in doubt between transactional and marketing, favor keeping it visible in the inbox (transactional is often time-sensitive).
- **A16-FALSE-2**: The classifier MUST NOT let classification decisions leak into trust (A16-SEP-1): a message being confidently `marketing` MUST NOT reduce link/attachment scrutiny. Marketing mail carries plenty of malicious links historically; "it's just promo" is not a safety pass.
- **A16-FALSE-3**: Classification confidence MUST be represented (not just a hard label), so the client can present low-confidence classifications tentatively and route conservatively.

------

# 8. Tenant Policy

- **A16-POL-1**: Tenants MAY: enable/disable Promotions-style grouping, configure which classes route where, and set whether user corrections train local preferences. Defaults SHOULD be conservative (group marketing into a Promotions view, keep everything else in inbox, never auto-delete).
- **A16-POL-2**: A tenant MAY define allow/deny rules by sender/domain that override classification (a tenant wants all mail from a partner in the inbox regardless of bulk markers). Explicit tenant rules take precedence over automatic classification.

------

# 9. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Ambiguous / low-confidence class | Represent confidence; route conservatively (favor inbox for transactional-ambiguous) (A16-FALSE-1/3) |
| Client structure refinement unavailable (webmail / not-yet-synced) | Use the frontier base class; no functional break (A16-PLACE-1) |
| Classifier disagrees with trust | Both are shown; trust is never suppressed by class (A16-SEP-1, A16-INT-2) |
| User moves a misclassified message | Respect it, optionally train local preference (A16-ROUTE-3) |
| Taxonomy version mismatch | Past class interpretable via its recorded version (A16-TAX-2) |

------

# 10. Observability Contract

Per A00 §11 (privacy-preserving):

- counters: `classifications_total{class,layer}` (layer = frontier/client), `class_refinements_total{from,to}`, `user_reclassifications_total{from,to}` (aggregate counts only), `tenant_rule_overrides_total`
- latency: `frontier_classification_duration` (part of A01 pipeline budget), `client_refinement_duration`
- **A16-OBS-1**: Telemetry MUST NOT include sender addresses, subjects, or content — only class labels and aggregate counts. User reclassification patterns MUST NOT be uploaded in a way that reveals who corresponds with whom (A06-HIST-2 discipline); local-only training keeps corrections on-device.

------

# 11. Test Scenarios (Normative)

1. **Header-only marketing**: message with List-Unsubscribe + Precedence:bulk from `.news` domain → frontier base class `marketing` immediately, before any client processing (A16-PLACE-1).
2. **Structure refinement**: header-ambiguous message that is image-heavy with a tracking pixel and CTA → client refines to `marketing` using Tiptap structure (A16-PLACE-2); refinement not uploaded.
3. **Marketing ≠ safe**: legitimate-looking marketing structure but DMARC fail + no valid List-Unsubscribe → classified cautiously, trust warning retained, NOT given a benign pass (A16-INT-1).
4. **Class doesn't suppress trust**: a `marketing` message containing a phishing link → routed to Promotions BUT the phishing warning is shown; trust not suppressed by class (A16-SEP-1, A16-INT-2).
5. **Transactional stays visible**: a password-reset (transactional, single recipient, no unsubscribe) → NOT routed to Promotions; kept in inbox (A16-FALSE-1).
6. **User correction**: user moves a mis-routed newsletter to inbox → respected; local preference trained on-device; not uploaded (A16-ROUTE-3).
7. **Tenant override**: tenant rule "partner.fr always inbox" → partner's bulk-looking mail stays in inbox regardless of markers (A16-POL-2).
8. **Webmail base class**: webmail (no local Tiptap refinement) → shows the frontier base class; no break (A16-PLACE-1, §9).

------

# 12. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Conflating classification with trust — letting "it's marketing" lower link/attachment scrutiny, or letting "high trust" suppress a phishing warning (A16-SEP-1, A16-INT-2, A16-FALSE-2).
2. ❌ Giving marketing-structured mail a benign trust pass without checking the compliance/auth signals, so phishing-imitating-marketing slips through (A16-INT-1).
3. ❌ Running a separate expensive classification model instead of reusing the Tiptap structure + header + trust signals already computed (A16-INT-3).
4. ❌ Expecting Tiptap structure signals at the frontier (they are client-side) or uploading the client structure refinement (A16-PLACE-2/3).
5. ❌ Auto-deleting or hiding classified mail instead of routing to a visible view (A16-ROUTE-2) — silent loss.
6. ❌ Routing time-sensitive transactional mail (password resets) to Promotions on a weak signal (A16-FALSE-1).
7. ❌ Uploading user reclassification patterns server-side, leaking correspondence patterns (A16-ROUTE-3, A16-OBS-1).
8. ❌ Not recording classification confidence / version, so ambiguous classes are presented as certain and past classes become uninterpretable (A16-FALSE-3, A16-TAX-2).
9. ❌ Ignoring explicit tenant allow/deny rules in favor of automatic classification (A16-POL-2).
10. ❌ Hard-failing when the client refinement layer is unavailable instead of using the frontier base class (A16-PLACE-1, §9).

------

# 13. Deferred Items

- Server-side / cross-user aggregate classification learning — has the correspondent-privacy tension (A06-HIST-2); any such feature MUST solve the privacy boundary first, recorded so it is not added casually. V1 is frontier-base + on-device refinement + local user training.
- Finer taxonomy (separating "social", "forums", "updates" à la Gmail categories) — V1 keeps a coarse taxonomy; extend later.
- ML-based classification model (on-device) beyond the reused-signal heuristics — the reused signals go far; a dedicated on-device model is a later enhancement, privacy-preserving by staying on-device.
- Priority-inbox / importance ranking (distinct from kind classification) — a separate feature; not in V1 scope.

------

*End of document.*
