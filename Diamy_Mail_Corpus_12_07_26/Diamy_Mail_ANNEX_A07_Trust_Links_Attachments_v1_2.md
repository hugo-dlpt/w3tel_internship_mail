# Diamy Mail — ANNEX A07: Trust Analysis — Links & Attachments

**Document title:** Diamy Mail — ANNEX A07: Trust Analysis — Links & Attachments
**Version:** 1.2
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 5th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)
**Sibling dependencies:** A01 (Inbound Gateway v1.1), A06 (Trust — Origin v1.2), A08 (HTML→Tiptap v1.1), A24 (Identity & Address Normalization v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: link trust analysis (display-vs-href mismatch, shortener/redirect resolution, typosquat/homograph, domain age/reputation, self-domain coherence, blocklist), attachment trust analysis (whitelist-first, MIME-vs-content, double-extension, archive inspection, password-protected=max-risk, AV/hash), tiered attachment access policies (user-confirm / admin-approve / sandboxed CDR-detonation), pre-click and pre-open UX contract, resolution privacy discipline, output metadata, failure model, test scenarios, common AI errors. Closes the attachment-whitelist and access-policy design from the conversation. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: fixed a security-critical gap in T3 sandboxed viewing — the server CANNOT decrypt the attachment at rest (it holds no envelope), so T3 MUST be client-decrypts-then-submits-to-sandbox, not server-decrypts (A07-POL-4 rewritten with explicit direction and channel); clarified that the frontier does lightweight link/attachment EXTRACTION for scoring, not full Tiptap conversion which is client-side (A07-LOC-1); added AI error #13 |
| 1.2     | Jul 5th 2026 | Cédric BORNECQUE | Closed the embedded-link gap (motivated by a real sample: a clean whitelisted PDF is the most likely carrier when origin auth passes): added embedded-links-in-documents signal to §3 and A07-ATT-4 — frontier SHOULD extract URLs embedded in link-capable document formats (PDF, Office) and score them via the §2 link machinery; extraction failure yields `embedded_links_unextracted` (mild, not clean, not max-risk) per new failure-model row; embedded-link findings added to A07-OUT-2; added test scenario 13 and AI error #14 |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies **content-actionable** trust analysis: links and attachments — the two things a user clicks or opens, and the primary phishing/malware vectors. It produces link and attachment risk signals that combine with origin (A06) into the overall assessment (A06 §9), and it defines the **tiered access policies** governing how a user may reach a risky attachment.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Where it runs

- **A07-LOC-1**: Content analysis that needs the message body/attachment plaintext runs at the **frontier** (A01 pipeline step 5, on transient plaintext, before encryption, CMP-BND-2). Its verdicts are stored as `trust_metadata` (A02, needs no later decryption). Attachment AV/inspection is the frontier hook (A01-AV). At the frontier this is a **lightweight link/attachment extraction for scoring** — parsing out hrefs, display text, and attachment structure — NOT the full HTML→Tiptap conversion (A08), which is client-side for rendering. The frontier extracts what it needs to score; the client separately does the full Tiptap conversion for display. Both use the same underlying link data, computed independently on each side of the encryption boundary (same pattern as the two hidden-content detections, A08 §1.1b).
- **A07-LOC-2**: **URL resolution** (following shorteners/redirect chains) has a privacy constraint (§4): it MUST NOT be performed in a way that leaks to the tracker that the user received/opened the mail. Resolution, when done, happens server-side at the frontier (before the user is involved) or via a privacy-preserving path — NEVER by the client fetching the URL at render time (A08-URL-3).

## 1.2 Out of scope

Origin scoring (A06). The score combination math (A06 §9). Antivirus engine internals and CDR engine internals (A01-AV hook / A18 deployment); this annex fixes the verdict contract and the access-policy governance.

------

# 2. Link Trust Signals

| Signal | Detection | Direction |
| ------ | --------- | --------- |
| Display-text vs href mismatch | A08-URL-2 (visible text says `bank.fr`, href elsewhere) | ↓ (deception) |
| Shortener / redirect | href matches known shortener/redirector; final destination unresolved | ~ (resolve, §4) |
| Redirect-chain length/anomaly | multi-hop resolution | ↓ if excessive/evasive |
| Typosquat / homograph domain | A24 domain normalization + confusable (A24-CONF) on the href domain | ↓↓ (esp. vs known brand/correspondent) |
| Newly-registered domain | RDAP/WHOIS age of href domain | ↓ |
| href domain reputation | blocklist/reputation (Safe Browsing, Spamhaus, PhishTank — §12 deferred feeds) | ↓↓ if listed |
| href vs sender/org coherence | does the link go to a domain unrelated to the sender's org? | ↓ context-dependent |
| Non-TLS (`http:`) link | A08-URL-1 | ~ mild |
| Dangerous scheme attempted | `javascript:`/`data:` (stripped by A08-URL-1) | ↓↓ (attempted, recorded even though stripped) |
| Credential-form target | link leads to a login-like page on a suspicious domain | ↓↓ (phishing) — best-effort |

- **A07-LINK-1**: The display-vs-href mismatch (A08-URL-2) is a primary phishing signal and MUST be surfaced **before the click** (§6). The user MUST be able to see the real destination without clicking.
- **A07-LINK-2**: Homograph/typosquat detection on href domains MUST reuse the A24 normalization + confusable machinery (A24-CONF), consistent with sender-domain checks — and with the same frontier-vs-on-device split (A06-INT-1b): brand-list confusable is frontier-scoreable; confusable-vs-user-correspondent-history is on-device.
- **A07-LINK-3**: A dangerous scheme that A08 stripped (`javascript:`, `data:text/html`) MUST still be **recorded as a signal** — the fact that the message attempted to embed an executable-scheme link is itself evidence, even though the link was neutralized (A08-URL-1, A08-EXH-3). Neutralization removes the threat; the signal remains.

------

# 3. Attachment Trust Signals

| Signal | Detection | Direction |
| ------ | --------- | --------- |
| Extension whitelist status | §5 whitelist | non-whitelisted ↓ |
| MIME type vs actual content (magic bytes) | frontier inspection | mismatch ↓↓ (renamed executable) |
| Double extension (`facture.pdf.exe`) | filename analysis | ↓↓ |
| Dangerous extension | `.exe .scr .js .vbs .hta .lnk .ps1 .bat .msi .iso` + Office macros (`.docm .xlsm .pptm`) | ↓↓ |
| Archive contents | frontier extraction + per-file whitelist (§5.2) | inner executable ↓↓ |
| Password-protected archive | cannot inspect | **max-risk** (A00 SEC-ATT-2) |
| AV verdict | A01-AV | `infected` ↓↓↓, `unscannable` max-risk |
| Hash reputation | known-malicious hash (VirusTotal-style, §12) | ↓↓↓ if listed |
| CDR-required | active content stripped (A01-AV-6) | ↓ (needed disarming = signal) |
| Embedded links in document formats | frontier extraction from link-capable documents (PDF, Office) → scored via §2 link signals | inherits §2 directions (a risky embedded link ↓↓) |

- **A07-ATT-1**: Attachment analysis is **whitelist-first** (A00 SEC-ATT-1): only explicitly approved types are treated as safe by default; everything else is untrusted (§5).
- **A07-ATT-2**: A password-protected archive whose contents cannot be inspected MUST be treated as **maximum risk** (A00 SEC-ATT-2, A01-AV-3), because the platform cannot verify what it contains. A password supplied in the message body is itself a strong negative signal (classic AV-evasion technique) and MUST be detected and recorded.
- **A07-ATT-3**: MIME-vs-content mismatch (a `.pdf` that is actually a PE executable by magic bytes) is a high-severity signal — the declared type lies. Extension, declared MIME, and actual magic-byte content MUST all be checked and disagreements flagged.
- **A07-ATT-4** (embedded links in documents): The frontier inspection SHOULD extract URLs embedded in link-capable document formats (PDF link annotations, Office hyperlinks) and score each through the §2 link machinery (display-vs-href where the format carries display text, confusable/typosquat, domain age, reputation, sender/org coherence). Rationale: when origin authentication passes (e.g. a compromised legitimate account, A06-SCORE-5), a clean whitelisted document carrying a phishing link is the most likely payload — the document *is* the link vector. Extracted embedded links populate `trust_metadata.links[]` (A07-OUT-1) with an `embedded_in_attachment` provenance marker referencing the carrier attachment, so the pre-open UX (A07-UX-2) can warn before the document is opened, not only before an in-body link is clicked. Extraction is bounded (A01-STAB discipline: page/object limits, no rendering, no JS execution); a document whose links cannot be extracted within bounds yields the `embedded_links_unextracted` factor (§9) — a mild signal, neither clean-by-default nor max-risk. This is static extraction only; it does not replace AV (A01-AV) or T3 detonation (§6) for active-content threats.

------

# 4. URL Resolution Privacy (Normative)

- **A07-RES-1**: Resolving a shortener/redirect chain requires fetching the URL, which reveals to the destination that the URL was accessed. This MUST NOT leak that a specific user received or opened the message. Permitted approaches: (a) resolve **server-side at the frontier**, once, before the user is involved (the fetch is attributable to the platform's infrastructure, not to a user opening mail), caching the final destination in metadata; (b) resolve via a shared platform resolver that does not correlate to a user. FORBIDDEN: the client fetching the URL at render/open time (A08-URL-3) — that leaks user engagement to the tracker and reveals the user's IP.
- **A07-RES-2**: Frontier resolution MUST be bounded (max redirect hops, timeout) and MUST NOT execute content (no JS, no headless-browser rendering that could trigger exploits) — it follows HTTP redirects only, safely. A chain that cannot be safely resolved is recorded as `unresolved` (a mild signal), not fetched aggressively.
- **A07-RES-3**: Resolution results (final destination domain, chain length) are stored in `trust_metadata` so the client can show "this link actually goes to X" without any client-side fetch (A07-LINK-1, §6).

------

# 5. Attachment Whitelist Model

## 5.1 Default whitelist

- **A07-WL-1**: The default whitelist (A00 SEC-ATT-1) contains common safe document/media types: documents (`.pdf .docx .xlsx .pptx .odt .ods .odp .txt .rtf .csv`), images (`.jpg .jpeg .png .gif .webp .svg`†), audio/video (`.mp3 .mp4 .wav .mov`). † SVG is whitelisted **only after** the same script/active-content sanitization as HTML (an SVG can carry script) — an un-sanitizable SVG is treated as non-whitelisted.
- **A07-WL-2**: Everything not on the whitelist — archives (`.zip .rar .7z .gz`), executables/scripts (`.exe .js .vbs .hta .lnk .ps1 .bat .msi .iso .scr`), Office macro formats (`.docm .xlsm .pptm`) — is **non-whitelisted by default** and subject to the access policy (§6). Office macro formats are excluded by default even though the base format is common, because the macro is the vector (Emotet-class); a tenant MAY opt them in for a genuine internal-macro use case.
- **A07-WL-3**: A format not explicitly on either list (a novel/unusual type) is treated as **non-whitelisted** by default (allow-list posture: unknown = not-yet-trusted). This is the deliberate advantage over a blocklist — a new malicious format is caught without needing prior knowledge of it.

## 5.2 Archive handling

- **A07-ARC-1**: Whitelisted-but-container types (`.zip` and similar) that CAN be inspected MUST be **extracted at the frontier** and each contained file checked against the whitelist (§5.1) and AV (A01-AV). If all inner files are whitelist-clean, the archive MAY be delivered normally; if any inner file is non-whitelisted or infected, the archive is treated per the access policy (§6) with the offending inner file identified in the signal.
- **A07-ARC-2**: An archive that cannot be inspected (password-protected, corrupt, nested beyond bound, or a decompression bomb per A01-STAB-3) is **maximum risk** (A07-ATT-2) — the platform cannot verify contents.

------

# 6. Tiered Access Policies (Normative)

For a non-whitelisted or risky attachment, the tenant configures how a user may reach it. Four tiers, increasing safety, selectable per tenant and escalatable by risk band.

| Tier | Mechanism | Server decrypt? |
| ---- | --------- | --------------- |
| **T1 — Informed confirmation** | User sees the risk, explicitly confirms "open anyway" | No |
| **T2 — Administrator approval** | Attachment withheld until an admin/security role approves | No |
| **T3 — Sandboxed viewing (CDR / detonation)** | User views a disarmed/rendered version in isolation; original never reaches the device | Yes (declared exception) |
| **T4 — Blocked** | No access; highest-risk / known-malicious | N/A |

- **A07-POL-1**: The tier applied MUST scale with the attachment's risk signals (§3): whitelisted-clean → direct access (no tier); non-whitelisted-no-strong-signal → T1; elevated (dangerous extension, MIME mismatch) → T2 or T3 per tenant; critical (infected hash, password-protected archive, known-malicious) → T4 blocked. The mapping is tenant-configurable within these bounds; a tenant MAY tighten (force T3 for all non-whitelisted) but MUST NOT loosen below the floor (a known-malicious hash is always T4).
- **A07-POL-2** (T1 audit): Informed confirmation MUST be audit-logged (who bypassed, when, which file, which risk) — A00 OBS-3. A bypass is a decision of record, not a silent click.
- **A07-POL-3** (T2 governance): Administrator approval uses an IAM role/entitlement (`attachment_release_authority`, per A17/Role model). Approval/denial is audit-logged. Latency is the tradeoff (A00 conversation note); a stuck approval MUST surface to the user, and the request MUST be trackable.
- **A07-POL-4** (T3 declared exception — normative, corrected direction): Sandboxed viewing requires the risky attachment to be processed in an isolated ephemeral environment. **The server cannot decrypt the attachment at rest** — it holds no envelope and no `k_msg` (the whole storage model, A02). Therefore T3 MUST work as follows: on **explicit user request for that specific file**, the **client decrypts the attachment on-device** (it has the envelope), and submits the **decrypted file to an isolated sandbox service** over an authenticated channel (mail-plane token + TLS). The sandbox — an ephemeral VM/container, destroyed after use, never persisting plaintext — performs CDR reconstruction or detonation and returns either the disarmed inert artifact or a render stream. The original decrypted file exists in the sandbox transiently and is destroyed with the environment. This is a **declared, bounded exception** to zero-access (like the frontier and hold-queue exceptions, A00 §3.2): it is client-initiated per-file, disclosed to tenants, audit-logged, and the sandbox persists nothing. Two variants: **CDR** (return a safe inert artifact the client stores as the usable attachment) and **detonation/RBI** (open in the jettable sandbox, stream only the render to the user, original never returns to the device in active form). The key correction over a naive design: the exposure is **client→sandbox by explicit user action**, NOT server-decrypts-your-mail — the server never had the ability to decrypt it, and gains it only for one file, momentarily, because the user's own client handed it over.
- **A07-POL-5**: Tenants MUST be able to set the default tier per risk band and per file class; the client MUST present the applicable tier's UX (confirm dialog, "awaiting admin approval", "open in secure viewer") clearly, never silently downgrading a tier.

------

# 7. Pre-Click / Pre-Open UX Contract

- **A07-UX-1** (links, pre-click): On hover/long-press, before any click, the client MUST show the resolved real destination and its risk (from `trust_metadata`), e.g. "⚠️ elevated risk — link text says bank.fr but goes to login-verify.ru — domain registered 4 days ago". This is prevention, not post-incident notice (the conversation's core link-safety point). No client-side fetch is needed — the resolution is already in metadata (A07-RES-3).
- **A07-UX-2** (attachments, pre-open): Before opening, the client MUST show the attachment's risk assessment and the applicable access tier, e.g. "🔴 danger — password-protected archive, contents unverifiable — [Open in secure viewer]" or "🟢 no threat detected — type matches extension, scanned". Green states are as important as red (calibration/trust, A06-PRIN-3): a clean file should look clean.
- **A07-UX-3**: The assessment strings use stable reason codes (like A06-EXP-1); localized display is a client concern. The UX MUST NOT require the user to read raw headers or MIME structure.

------

# 8. Output Metadata Contract

- **A07-OUT-1**: `trust_metadata.links[]` MUST contain, per link: display text, raw href, resolved final destination (if resolved, §4), href-domain analysis (age, confusable flags, reputation if available), display-vs-href mismatch flag, scheme, and a link risk sub-score + reason codes.
- **A07-OUT-2**: `trust_metadata.attachments[]` MUST contain, per attachment: filename, declared MIME, detected content type (magic bytes), extension whitelist status, AV verdict, archive inspection result (inner findings), password-protected flag, hash-reputation result (if available), CDR-applied flag (A01-AV-6), embedded-link findings (count + worst embedded-link sub-score + `embedded_links_unextracted` flag when applicable, with the per-link detail living in `trust_metadata.links[]` under the `embedded_in_attachment` provenance, A07-ATT-4), assigned access tier, and an attachment risk sub-score + reason codes.
- **A07-OUT-3**: These combine with A06 origin into the overall assessment (A06 §9 / A06-COMB). All `PLAINTEXT_METADATA` (frontier-computed, no later decryption). On-device refinement (confusable-vs-history on href domains, A07-LINK-2) follows the A06-INT-1b / A06-COMB-1b split (on-device only, never uploaded).

------

# 9. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| URL resolution times out / unsafe | Record `unresolved` (mild signal); do NOT aggressively fetch; never client-fetch (A07-RES-1/2) |
| Reputation/blocklist feed down | Score without it; "reputation unavailable"; do not default to blocking legitimate mail |
| AV engine down | Per A01 tenant policy (fail-closed default = tempfail; fail-open = deliver flagged `av_unscanned`) |
| Archive inspection fails (corrupt/bomb) | Max-risk (A07-ARC-2); do not deliver as clean |
| Embedded-link extraction fails/exceeds bounds (A07-ATT-4) | Record `embedded_links_unextracted` (mild signal); the attachment keeps its other verdicts (whitelist, magic bytes, AV) — do NOT mark clean-by-default, do NOT escalate to max-risk on extraction failure alone |
| CDR/detonation env unavailable (T3) | The T3 action fails safe: attachment stays inaccessible with a clear "secure viewer unavailable, try later"; NEVER fall back to delivering the raw risky file |
| Admin approver unavailable (T2) | Request stays pending, surfaced to user and admin; never auto-approve on timeout |

------

# 10. Observability Contract

Per A00 §11:

- counters: `link_signals_total{type}`, `link_resolutions_total{result}`, `attachment_verdicts_total{tier}`, `attachment_whitelist_blocks_total`, `password_protected_archive_total`, `mime_mismatch_total`, `t1_bypasses_total`, `t2_approvals_total{result}`, `t3_sandbox_sessions_total`
- latency: `link_resolution_duration` (frontier, bounded), `attachment_inspection_duration`, `cdr_detonation_duration` (T3)
- audit (OBS-3): every T1 bypass (A07-POL-2), every T2 approval/denial (A07-POL-3), every T3 sandbox session (declared exception, A07-POL-4), attachments blocked at T4, known-malicious hits
- **A07-OBS-1**: Telemetry MUST NOT include URLs, filenames, or content; only counts, types, tiers, and outcomes. (A filename can be sensitive — `salary_2026.xlsx`.)

------

# 11. Test Scenarios (Normative)

1. **Display-vs-href mismatch**: link text "www.banque.fr", href to `banque-fr.secure-login.ru` → mismatch flagged, real destination shown pre-click (A07-UX-1), no client fetch.
2. **Shortener resolution**: `bit.ly/...` → resolved server-side at frontier to final domain, stored in metadata; client shows real destination without fetching (A07-RES-1/3).
3. **Homograph link**: href `аmazon.com` (Cyrillic а) → confusable flag, high-severity if vs known brand (frontier) / correspondent history (on-device) (A07-LINK-2).
4. **javascript: attempt**: stripped by A08, but recorded as an attempted-dangerous-scheme signal (A07-LINK-3).
5. **Whitelist pass**: `report.pdf`, MIME matches magic bytes, AV clean → green, direct access, no tier.
6. **Renamed executable**: `invoice.pdf` that is a PE by magic bytes → MIME-mismatch high-severity, tiered (A07-ATT-3).
7. **Password-protected .rar with body password**: → max-risk, password-in-body signal, T3/T4 per tenant; never delivered as clean (A07-ATT-2, A07-ARC-2).
8. **Zip inspection**: `.zip` with one inner `.js` → inner executable flagged, archive tiered with the offending file identified (A07-ARC-1).
9. **Tier escalation**: known-malicious hash → T4 blocked regardless of tenant loosening attempt (A07-POL-1 floor).
10. **T1 bypass audit**: user opens a T1 file "anyway" → audit-logged with who/when/file/risk (A07-POL-2).
11. **T3 declared exception**: user requests secure-view of a risky file → client decrypts that file on-device and submits it to the isolated ephemeral sandbox; sandbox processes, returns render/disarmed artifact, destroys env; audit-logged; server never had at-rest decryption ability; original never returns to the device in active form (A07-POL-4).
12. **T3 env down**: secure viewer unavailable → action fails safe, raw file NOT delivered as fallback (§9).
13. **Clean PDF, phishing link inside**: genuine PDF (magic bytes match, AV clean, whitelisted) containing a link annotation to a recently-registered confusable domain → embedded link extracted at frontier, scored via §2, stored in `trust_metadata.links[]` with `embedded_in_attachment` provenance; pre-open UX shows the warning before the document is opened (A07-ATT-4); the same PDF with only benign links → green, no false alarm. Corrupt PDF whose links can't be extracted → `embedded_links_unextracted`, mild, other verdicts unchanged (§9).

------

# 12. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Fetching a link/tracker URL from the client at render/open time to resolve it, leaking user engagement + IP to the tracker (A07-RES-1, A08-URL-3).
2. ❌ Treating a password-protected archive as clean/empty because it couldn't be opened, instead of maximum risk (A07-ATT-2, SEC-ATT-2).
3. ❌ Using a blocklist instead of a whitelist for attachments, so a novel malicious type passes (A07-WL-3, SEC-ATT-1).
4. ❌ Trusting the declared MIME/extension without checking magic-byte content, missing renamed executables (A07-ATT-3).
5. ❌ Not inspecting inside inspectable archives, so an inner `.exe`/`.js` is delivered as part of a "zip" (A07-ARC-1).
6. ❌ Exempting reassuring-label links ("view in browser", "unsubscribe") from analysis (A08-EXH-2 cross-ref).
7. ❌ Showing link/attachment risk only AFTER the click/open instead of before (A07-UX-1/2) — prevention, not post-mortem.
8. ❌ Letting the T3 secure-viewer failure fall back to delivering the raw risky file (§9) — must fail safe.
9. ❌ Allowing a tenant to loosen a known-malicious-hash attachment below T4 (A07-POL-1 floor).
10. ❌ Not auditing T1 bypasses / T2 approvals / T3 sandbox sessions (A07-POL-2/3/4) — these are decisions of record.
11. ❌ Treating T3 sandboxed viewing as unremarkable instead of a declared, disclosed, per-file, audited zero-access exception requiring server decryption of that file (A07-POL-4).
12. ❌ Putting URLs/filenames in telemetry (A07-OBS-1) — a filename can be sensitive.
13. ❌ Designing T3 sandboxed viewing as "server decrypts the attachment at rest" — the server holds no envelope and structurally cannot. T3 is client-decrypts-on-device-then-submits-to-sandbox, per explicit user action for one file (A07-POL-4). An implementer assuming server-side decryption will either build something impossible or, worse, add a server decryption capability that breaks the entire model.
14. ❌ Treating a whitelisted, AV-clean document as fully assessed without extracting its embedded links (A07-ATT-4) — the clean-PDF-with-phishing-link is the primary payload when origin auth passes. The symmetric errors: rendering/executing the document at the frontier to find links (extraction is static and bounded), or escalating to max-risk merely because extraction failed (§9 — `embedded_links_unextracted` is mild).

------

# 13. Deferred Items

- Threat-intelligence feed integration (Safe Browsing, PhishTank, Spamhaus DBL, VirusTotal hash reputation) — hooks defined; specific feeds/governance are operational/A18.
- On-device link-destination resolution via a privacy-preserving proxy (for links that arrive unresolved) — must satisfy A07-RES-1; deferred until the proxy design is fixed.
- Credential-phishing page classification (does the link lead to a fake login) — best-effort, likely ML-assisted; deferred.
- Detonation environment specification (Firecracker/gVisor microVM, lifecycle, resource bounds) — A18/deployment; this annex fixes the contract and the zero-access exception discipline.
- Attachment-level lazy envelopes to support per-attachment access policies without decrypting the whole message (interacts with A02 deferred item) — revisit with A02.

------

*End of document.*
