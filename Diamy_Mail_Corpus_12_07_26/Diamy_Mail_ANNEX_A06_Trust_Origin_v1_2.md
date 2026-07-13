# Diamy Mail — ANNEX A06: Trust Analysis — Message Origin

**Document title:** Diamy Mail — ANNEX A06: Trust Analysis — Message Origin
**Version:** 1.2
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 5th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)
**Sibling dependencies:** A01 (Inbound Gateway v1.1), A02 (Storage v1.1), A07 (Trust — Links & Attachments), A24 (Identity & Address Normalization v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: origin trust model, analyzed signals (auth, sending infrastructure, domain coherence, SMTP path, transport), scoring model (transparent, explainable, additive), correspondent reputation history (per-user, on-device privacy boundary), signal catalogue with weights guidance, false-positive discipline, self-domain-spoof and homograph integration, output metadata contract, calibration, failure model, test scenarios, common AI errors |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: made the frontier-vs-on-device signal split explicit to prevent an implementer from computing history server-side — brand-list confusable (A24-CONF bit 3) is frontier-scoreable, but correspondent-history confusable (A24-CONF bit 2) and all history-anomaly signals are on-device only (A06-INT-1b); clarified the two-layer score flow: frontier computes origin+content+combined base score (metadata), on-device history is the ONLY refinement layer (A06-COMB-1b); added AI error #11 |
| 1.2     | Jul 5th 2026 | Cédric BORNECQUE | Compromised-legitimate-account pattern (motivated by a real sample: fully-authenticated mail from a hijacked university account submitted from a geo-incoherent client IP): added authenticated-submission origin anomaly and anomalous-submission-client signals to §3.4; added A06-SCORE-5 — full SPF/DKIM/DMARC pass MUST NOT cap the negative contribution of path/coherence/history signals (authentication proves the account sent it, not that the account is uncompromised); added reason codes `submission_origin_anomaly`, `legacy_submission_client`, `compromised_account_pattern`; added normative test scenario 10; added AI error #12 |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies the **message-origin** trust analysis: turning SMTP headers, authentication results, sending infrastructure, and correspondent history into a transparent, explainable trust score attached to each inbound message as metadata. It covers the origin of the message (who/where it came from). Link and attachment trust is A07; the two combine into an overall assessment (§9).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Design goal

Transform technical headers most users cannot read into a simple, understandable confidence indicator with an explanation (A00 §1.2 mail scope). The score is a **decision aid for the user**, not an automated verdict that silently hides mail (A01-AUTH-3 — visible warnings over silent loss).

## 1.2 Where it runs

- **A06-LOC-1**: Origin scoring runs at the **frontier** (A01 pipeline step 5) on server-visible metadata and, where needed, on the transient plaintext (for content-derived origin signals). Its output is `trust_metadata` (A02 §4.1), classified `PLAINTEXT_METADATA`, requiring no later decryption (CMP-BND-1). The **correspondent reputation history** comparison that needs the user's private correspondent graph runs **on-device** (§7), never server-side, to preserve the per-user privacy boundary.

## 1.3 Out of scope

Link and attachment scoring (A07). Threat-intelligence feed integration internals (deferred, §12). The trust UI presentation (client; this annex fixes the data and the explanation strings' content, not their visual rendering).

------

# 2. Trust Model Principles

- **A06-PRIN-1** (transparent): The score MUST be accompanied by an explanation enumerating the factors that raised or lowered it. A bare number is insufficient — the user MUST be able to see *why* (A00 §1.2). "94/100, low risk, because: SPF/DKIM/DMARC aligned, known infrastructure, domain seen regularly."
- **A06-PRIN-2** (additive & bounded): The score is computed from weighted signals, bounded to a fixed range (RECOMMENDED 0–100), mapped to coarse bands (e.g. low / moderate / elevated / high risk) for display. Bands, not raw numbers, drive user-facing severity, so small weight changes don't flip user perception.
- **A06-PRIN-3** (false-positive-averse): Legitimate-but-imperfect mail is common (a small business with no DKIM, a valid forwarder breaking SPF). The model MUST be calibrated so that ordinary legitimate mail does NOT land in alarming bands, because alarm fatigue destroys the score's value ("once users stop believing the alerts, the tool becomes useless" — the Sublime observation). Missing-DKIM alone MUST NOT produce a high-risk verdict.
- **A06-PRIN-4** (explainable weighting): The weight of each signal MUST be documented and versioned. The scoring model version MUST be recorded on each scored message (A06-OUT) so a past score remains interpretable after the model evolves.
- **A06-PRIN-5** (aid, not gate): By default the score informs; it does not silently reject (A01-AUTH-3). Hard actions (quarantine/reject) are tenant-configurable policy (A16/A07 governance), applied transparently and auditably, not baked into the score.

------

# 3. Analyzed Signals

## 3.1 Authentication

| Signal | Source | Direction |
| ------ | ------ | --------- |
| SPF result | A01-AUTH-1 | pass ↑ / fail ↓ / softfail ~ |
| DKIM result | A01-AUTH-1 | valid ↑ / absent ~ / fail ↓ |
| DMARC result + policy | A01-AUTH-1 | pass ↑ / fail ↓ |
| DMARC **alignment** | A01-AUTH-1 | aligned ↑ / not aligned ↓ |
| ARC chain | A01-AUTH-1 | valid trusted forwarder mitigates SPF/DKIM breakage (A01-AUTH-4) |
| **Self-domain DMARC fail** | A01-AUTH-5 | HIGH severity ↓↓ (exec-impersonation vector) |

## 3.2 Sending infrastructure

| Signal | Source |
| ------ | ------ |
| Sending IP | SMTP session |
| Reverse DNS (PTR) coherence | DNS |
| HELO/EHLO announced hostname vs rDNS | SMTP |
| ASN + network operator | IP → ASN mapping (A-RDAP-style enrichment, cf. SIP Monitor RDAP annex precedent) |
| IP geo (country) | IP → geo |
| IP reputation | reputation feed (§12 deferred) |
| Infrastructure↔domain coherence | does the sending infra match the claimed domain's usual infra? |

## 3.3 Domain coherence

| Signal | Source |
| ------ | ------ |
| From domain | header |
| Return-Path domain | header |
| Message-ID domain | header |
| Cross-domain coherence | do these agree? |
| Domain age | RDAP/WHOIS (optional; recently-registered = ↓) |
| Homograph/confusable From domain | A24-CONF (mixed-script, confusable-with-known-correspondent) |

## 3.4 SMTP path

| Signal | Source |
| ------ | ------ |
| Received-chain hop count | headers |
| Chronological ordering sanity | headers |
| Unexpected/anomalous relays | headers |
| Path vs claimed origin coherence | headers |
| Authenticated-submission origin anomaly | headers — the first authenticated-client hop (`Authenticated sender` / ESMTPSA `Received` line, when the sending MTA exposes it) whose client IP/geo/network is incoherent with the claimed domain's plausible user base (e.g. a university account submitted from an unrelated residential network in another country) |
| Anomalous/legacy submission client | headers — `X-Mailer`/`User-Agent` identifying an obsolete or spam-kit-associated client (e.g. "Microsoft CDO for Windows 2000" in 2026); soft signal |

These path signals are frontier-scoreable: they read only the received headers, no user-private data (A06-INT-1b split unaffected).

## 3.5 Transport

| Signal | Source |
| ------ | ------ |
| TLS used | A01-SMTP-1 |
| TLS version | A01-SMTP-1 |
| Cipher suite (if available) | A01-SMTP-1 |

------

# 4. Scoring Model

- **A06-SCORE-1**: The score is a bounded aggregate of weighted signals. Positive factors (auth aligned, known infrastructure, coherent domains, regularly-seen correspondent, valid TLS) raise it; negative factors (auth fail, incoherent domains, anomalous relays, unknown/bad-reputation infrastructure, recently-created domain, self-domain spoof, homograph) lower it. Weights are documented and versioned (A06-PRIN-4).
- **A06-SCORE-2**: Signal combination MUST be non-linear where appropriate: certain combinations are worse than the sum of parts (self-domain DMARC fail + confusable domain + urgency-in-content = coordinated spoof, far worse than any alone). The model MUST support such combination rules, documented in the versioned model.
- **A06-SCORE-3**: The output band MUST be conservative on the alarm side (A06-PRIN-3): reserve the highest-risk band for strong, corroborated signals (e.g. self-domain spoof, known-bad IP, active-campaign match), not for a single soft signal like missing DKIM. A single soft negative signal SHOULD produce at most a "moderate" band.
- **A06-SCORE-4**: The score MUST be reproducible: same signals + same model version → same score (determinism, for auditability and cross-message consistency).
- **A06-SCORE-5** (compromised legitimate account — normative): A full authentication pass (SPF + DKIM + DMARC aligned) MUST NOT cap, floor, or otherwise dominate the negative contribution of path-coherence, domain-coherence, or on-device history signals. Authentication proves the sending account transmitted the message; it does NOT prove the account is uncompromised. The characteristic combination — all-auth-pass + authenticated-submission origin anomaly (§3.4) + no prior correspondent history (on-device, §7) + contextual incoherence — is the **compromised-account pattern** (reason code `compromised_account_pattern`) and MUST be able to reach at least the "elevated" band despite valid authentication, via the non-linear combination rules (A06-SCORE-2). Conversely, an authenticated-submission anomaly ALONE (mobile users travel; VPNs exist) is a soft signal and MUST NOT exceed "moderate" (A06-PRIN-3, A06-SCORE-3).

------

# 5. Explanation Contract

- **A06-EXP-1**: Every scored message MUST carry a structured explanation: an ordered list of the contributing factors, each with a direction (positive/negative), a severity, and a stable human-readable reason code (e.g. `dkim_valid`, `dmarc_aligned`, `domain_recently_registered`, `self_domain_dmarc_fail`, `confusable_sender_domain`, `submission_origin_anomaly`, `legacy_submission_client`, `compromised_account_pattern`). Reason codes are stable identifiers; their localized display strings are a client concern.
- **A06-EXP-2**: The explanation MUST be sufficient for the presentation described in A00 §1.2 (Origin / Authentication / Trust index with reasons). It MUST NOT expose raw headers as the primary surface (the whole point is to replace raw-header reading), though a "technical details" drill-down MAY show them.
- **A06-EXP-3**: Explanations MUST be honest about uncertainty: a `temperror`/`permerror` in auth checks yields an "could not verify" factor, not a false "passed" or a false "failed".

------

# 6. False-Positive Discipline

- **A06-FP-1**: The model MUST be calibrated against a corpus of real legitimate mail (newsletters, transactional mail, small-business mail without DKIM, forwarded/mailing-list mail) to ensure ordinary legitimate mail lands in benign bands. This is empirical calibration, not a one-time design (A00 estimation noted trust calibration is iterative on real volume).
- **A06-FP-2**: Common legitimate-but-imperfect patterns MUST have documented handling that avoids false alarm: no-DKIM small business (soft, not high), valid-ARC forwarder with broken SPF (mitigated), bulk sender with proper List-Unsubscribe + aligned DMARC (benign marketing, not phishing — the A16 classification interplay).
- **A06-FP-3**: The model version and its calibration dataset lineage MUST be recorded, so a regression (a model update that starts alarming on legitimate mail) is detectable and revertable — the same discipline as the corpus's versioned-artifact approach.

------

# 7. Correspondent Reputation History (on-device)

- **A06-HIST-1**: Diamy MAY build a per-user knowledge base of past correspondents' typical infrastructure (usual sending domain, ASN, country, sending servers) to detect behavioral changes: same correspondent from new infrastructure, ASN change, country change, new sending server, changed patterns. These are surfaced as **informational** signals ("this contact usually writes from X, this message came from Y").
- **A06-HIST-2** (privacy boundary — normative): The correspondent history is **per-user** and the comparison that requires the user's correspondent graph MUST run **on-device**, NOT server-side. A shared/server-side correspondent graph would reveal who each user communicates with (a severe metadata leak) — FORBIDDEN. This is the same boundary as A24-CONF-1 (confusable-vs-history runs on-device). The server MUST NOT learn a user's correspondent relationships to power this feature.
- **A06-HIST-3**: History-based signals are, by default, **informational and non-alarming** (a contact legitimately changes email providers). A history anomaly COMBINED with hard negative signals (self-domain spoof, confusable domain, auth fail) escalates per the combination rules (A06-SCORE-2); alone it is a gentle notice, not a red alert (A06-PRIN-3).
- **A06-HIST-4**: Because history lives on-device, the frontier score (server-side) MUST be computable **without** it; the on-device layer augments the displayed assessment after decryption. The message therefore carries a server-computed base origin score (metadata) which the client MAY refine with on-device history signals at render time. The client refinement MUST NOT require sending history to the server.

------

# 8. Integration with A24 and A01 Signals

- **A06-INT-1**: Homograph/confusable sender-domain flags (A24-CONF) are consumed as origin signals; `CONFUSABLE_DOMAIN` colliding with correspondent history is high-severity (A24-CONF-1), computed on-device (§7).
- **A06-INT-1b** (frontier vs on-device confusable split — normative): The two confusable checks live on different sides of the encryption boundary and MUST NOT be conflated:
  - `PUNYCODE_LOOKALIKE` / mixed-script (A24-CONF bits 0,1,3) compare against **static platform data** (brand lookalike list, script tables). These are **frontier-scoreable** — they need no user-private data — and contribute to the server-computed base origin score.
  - `CONFUSABLE_DOMAIN` (A24-CONF bit 2) compares against the **user's correspondent history**. This MUST run **on-device** (A06-HIST-2, A24-CONF-1) — it needs the user's correspondent graph, which never leaves the device. It is therefore an **on-device refinement**, NOT part of the frontier base score.
  An implementer MUST NOT move the history-based confusable check to the frontier to "simplify", because that would require shipping the correspondent graph server-side.
- **A06-INT-2**: Self-domain DMARC fail (A01-AUTH-5, `dmarc_fail_self_domain`) is a HIGH-severity origin signal — a message claiming to be from the recipient's own organization but failing DMARC is the executive-impersonation vector and MUST be weighted accordingly.
- **A06-INT-3**: Hidden-content signal (A07/frontier, cf. A08 §1.1b) and link/attachment signals (A07) combine with origin signals into the overall assessment (§9). This annex owns origin; A07 owns content-actionable; the combination is §9.

------

# 9. Combined Assessment (origin + content)

- **A06-COMB-1**: The user-facing message trust assessment is the combination of the **origin** score (this annex) and the **link/attachment** score (A07). The combination MUST be non-linear (A06-SCORE-2): a message with a suspicious origin AND a deceptive link AND a risky attachment is far more dangerous than any single factor, and MUST escalate accordingly.
- **A06-COMB-1b** (two-layer flow — normative): Both origin (A06) and link/attachment (A07) scoring run at the **frontier** on transient plaintext (A01 pipeline step 5), so the **combined base score is fully frontier-computed** and stored in `trust_metadata` (metadata, no later decryption). The **on-device history refinement** (§7, correspondent-history signals including the bit-2 confusable check) is the **only** layer added after decryption, on the client, and it MUST NOT be uploaded (A06-HIST-2, A06-OUT-2). So: frontier = origin + content + combined base (server-visible metadata); client = optional history refinement (never leaves device). An implementer building the score MUST NOT expect any on-device input to be available at the frontier, and MUST NOT push any on-device refinement back to the server.
- **A06-COMB-2**: The combined assessment and its explanation (merged factor list from A06 + A07) are stored in `trust_metadata` and surfaced to the user as one coherent indicator with a unified reason list, not two disconnected scores.

------

# 10. Output Metadata Contract

- **A06-OUT-1**: `trust_metadata.origin` MUST contain: the origin score, the band, the ordered factor list (reason codes + direction + severity), the model version, the auth results (SPF/DKIM/DMARC/alignment/ARC), the sending infrastructure summary (IP, rDNS, ASN, operator, country), the domain-coherence summary, and any flags (`self_domain_dmarc_fail`, confusable flags). All `PLAINTEXT_METADATA` (needs no decryption, A02).
- **A06-OUT-2**: On-device history refinements are NOT stored server-side; they are computed and displayed client-side and MAY be cached in the encrypted local catalogue (A03) but MUST NOT be uploaded (A06-HIST-2).

------

# 11. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Auth check temperror/permerror | Record "could not verify" factor; do not fabricate pass/fail (A06-EXP-3) |
| Reputation/RDAP feed unavailable | Score without that signal; record "reputation unavailable"; MUST NOT block delivery or default to alarming |
| Enrichment (ASN/geo) unavailable | Degrade gracefully; the missing signal is absent, not assumed-bad |
| Model version mismatch (stored score vs current model) | Stored score remains interpretable via its recorded version; re-scoring is optional, not required |
| On-device history unavailable (new device) | Base server score displayed; history refinements appear as history accrues (A06-HIST-4) |

------

# 12. Observability Contract

Per A00 §11:

- counters: `origin_scores_total{band}`, `auth_results_total{check,result}` (shared with A01), `self_domain_spoof_flagged_total`, `confusable_sender_flagged_total`, `history_anomaly_signals_total` (aggregate count only, NEVER correspondent identities)
- latency: `origin_scoring_duration` (frontier, part of the A01 pipeline budget)
- audit (OBS-3): messages landing in the highest-risk band, self-domain-spoof detections, any tenant-configured hard action (quarantine/reject) taken on the basis of the score
- **A06-OBS-1**: Telemetry MUST NOT include correspondent identities, addresses, or the user's correspondent graph (A06-HIST-2). Only aggregate counts and bands.

------

# 13. Test Scenarios (Normative)

1. **Clean legitimate**: SPF/DKIM/DMARC aligned, known ASN, coherent domains, TLS 1.3 → high score, low-risk band, explanation lists positive factors.
2. **No-DKIM small business**: SPF pass, no DKIM, coherent domains → moderate at worst, NOT high-risk (A06-PRIN-3, A06-FP-2); explanation notes missing DKIM as soft.
3. **Self-domain spoof**: From `ceo@mytenant.fr`, DMARC fail, self-domain → HIGH-risk band, `self_domain_dmarc_fail` factor prominent (A06-INT-2).
4. **Confusable sender**: From a domain confusable with a known correspondent's domain → on-device high-severity signal (A06-INT-1, §7); assert the comparison ran on-device, no correspondent graph left the device.
5. **Forwarder with broken SPF but valid ARC**: SPF fail, ARC valid trusted → mitigated, not alarming (A01-AUTH-4).
6. **Coordinated combo**: self-domain fail + confusable + risky link (A07) → combined non-linear escalation to highest band (A06-SCORE-2, A06-COMB-1).
7. **History anomaly alone**: known contact from a new-but-legitimate ASN, all auth passes → gentle informational notice, NOT a red alert (A06-HIST-3).
8. **Feed outage**: reputation feed down → scored without it, "reputation unavailable" factor, delivery not blocked (§11).
9. **Determinism**: same message + model version → identical score twice (A06-SCORE-4).
10. **Compromised legitimate account**: SPF/DKIM/DMARC all pass and aligned (real university account), but the authenticated-submission hop shows a client IP geo-incoherent with the domain, first contact (no on-device history), generic urgent content with attachment → at least "elevated" band despite full auth pass, `compromised_account_pattern` factor prominent (A06-SCORE-5); same message WITHOUT the corroborating signals (anomalous submission alone) → at most "moderate". Shares its auth signals with scenario 1 — only coherence and history signals distinguish them, which is the point.

------

# 14. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Treating missing DKIM as a high-risk signal, producing false alarms on legitimate small-business mail (A06-PRIN-3, A06-FP-2).
2. ❌ Building the correspondent reputation graph server-side, leaking who each user communicates with (A06-HIST-2) — it MUST be on-device.
3. ❌ Showing a bare score with no explanation (A06-PRIN-1, A06-EXP-1).
4. ❌ Making the score a silent hard gate (auto-reject) instead of a visible aid, losing legitimately-misconfigured wanted mail (A06-PRIN-5, A01-AUTH-3).
5. ❌ Linear-only scoring that misses dangerous combinations (self-domain spoof + confusable + risky link scoring merely "moderate") (A06-SCORE-2).
6. ❌ Not recording the model version, so past scores become uninterpretable after a model update (A06-PRIN-4, A06-OUT-1).
7. ❌ Fabricating a pass/fail for an auth check that actually temperror'd (A06-EXP-3).
8. ❌ Blocking or alarming when a reputation/enrichment feed is merely unavailable (A06 §11 — absent signal ≠ bad signal).
9. ❌ Reserving no headroom in the top band, so ordinary mail creeps into "high risk" over time (A06-SCORE-3 calibration).
10. ❌ Uploading on-device history refinements or correspondent identities in telemetry (A06-OBS-1, A06-HIST-2).
11. ❌ Computing the correspondent-history confusable check (A24-CONF bit 2) or any history-anomaly signal at the frontier instead of on-device, which would require the correspondent graph server-side (A06-INT-1b, A06-COMB-1b) — brand-list confusable (bit 3) is frontier-fine; history confusable (bit 2) is on-device only.
12. ❌ Treating a full SPF/DKIM/DMARC pass as a trust ceiling that suppresses or caps path/coherence/history negatives, so compromised-legitimate-account mail scores as clean (A06-SCORE-5) — authentication verifies the channel, not the account holder. The symmetric error: alarming on an authenticated-submission anomaly alone (travelers, VPNs), which A06-SCORE-5 forbids beyond "moderate".

------

# 15. Deferred Items

- Threat-intelligence feed integration (Spamhaus, AbuseIPDB, MISP-style) — the hook is defined (IP/domain reputation signals); the specific feeds, update cadence, and governance are an operational/A18 concern.
- AI-generated pedagogical explanations of anomalies (natural-language "why this looks suspicious") — an enhancement over the reason-code list; on-device generation preferred to preserve privacy.
- Cross-user aggregate threat intelligence (collective phishing-campaign detection) — attractive but has the correspondent-graph privacy tension (A06-HIST-2); any such feature MUST solve the privacy boundary before consideration, recorded here so it is not added casually.
- Automatic quarantine/alert policies by score band — governance lives in A16; this annex provides the score, A16 provides the policy.

------

*End of document.*
