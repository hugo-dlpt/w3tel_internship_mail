# Diamy Mail — ANNEX A08: HTML Ingestion & Tiptap Conversion

**Document title:** Diamy Mail — ANNEX A08: HTML Ingestion & Tiptap Conversion
**Version:** 1.0
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)
**Sibling dependencies:** A03 (Vault Client v1.1), A05 (Search & Local AI v1.1), A07 (Trust — Links & Attachments), A09 (Rendering Sandbox)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: HTML→Tiptap closed-schema conversion pipeline, closed node/mark schema, layout-table flattening, hidden-content rejection with exhaustiveness rule, CID image resolution, link/image normalization, URL scheme validation, "view in browser" and functional-link preservation, plaintext/rich fallback, conversion determinism, output contract for search/AI/render, failure model, test scenarios, common AI errors |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: resolved a frontier-vs-client timing confusion — hidden-content detection happens in TWO places for TWO purposes: the frontier (A07, on plaintext, before encryption) computes the trust-score signal; the client (A08, after decryption) prunes for render/index exclusion. Clarified A08-HID-2/3 and A08-LOC-1 so the client conversion is not described as feeding the already-computed server trust score. Tightened tracking-pixel handling to keep the signal in the log even when the node is dropped (A08-IMG-2). Added AI error #13 |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies the conversion of inbound message content (HTML and/or plain text, MIME) into a **closed-schema Tiptap/ProseMirror JSON** document, which is the default representation for rendering (A00 SEC-RENDER-1), for local search/AI indexing (A05), and for consistent display. It replaces direct raw-HTML rendering, eliminating by construction the CSS/script/tracking vulnerability classes (A00 §1.2, SEC-RENDER-1..3).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Where it runs

- **A08-LOC-1**: Conversion is a **client-side** operation by default (A00 CMP-BND-3), performed on decrypted content on the device, in the same trust boundary as rendering. The gateway does NOT hold a Tiptap representation. (Exception: webmail MAY convert server-side within the honest-but-curious constraints; when it does, the same rules apply and the conversion runs on content the browser decrypted, not on server-held plaintext — the server never sees the body.)

## 1.1b Two hidden-content detections (do not conflate)

Hidden content is detected in **two different places for two different purposes**, and an implementer MUST NOT conflate them:

1. **Frontier trust signal (A07, server-side, on plaintext, before encryption)** — during the A01 pipeline (step 5), A07 analyzes the message body while plaintext is transiently available and records a hidden-content signal into the `trust_metadata` (which needs no later decryption, A02). This is what feeds the **trust score**.
2. **Client render/index exclusion (A08, client-side, after decryption)** — this annex's conversion prunes hidden content so it is neither rendered nor indexed nor AI-extracted (§5). This does NOT feed the server trust score (already computed at the frontier); it protects the local render and local search surfaces.

Both detections use the same definition of "hidden" (§5) so they agree, but they run at different times, on different sides of the encryption boundary, and serve different consumers. A08's hidden-content log entry is a **client-side transparency artifact** ("what Diamy removed"), not the trust-score input.

## 1.2 Out of scope

The rendering of the resulting Tiptap JSON (client renderer — A03/A09). The "view original" raw-HTML sandbox (A09). Link/attachment trust *scoring* (A07); this annex produces the structured link/attachment nodes A07 scores, and enforces URL-scheme safety, but the risk verdict is A07's.

------

# 2. The Closed-Schema Principle

- **A08-SCH-1**: Conversion targets a **closed schema**: a fixed, whitelisted set of node types and marks. Anything in the source HTML that has no representation in the schema is either mapped to the nearest safe node, converted to text, or dropped-with-logging (§6 exhaustiveness) — it is NEVER passed through as raw HTML. This is allow-list-by-construction, the structural analogue of the attachment whitelist (A00 SEC-ATT-1): a `<script>`, a `<style>` block, an `onload` attribute, a `<link rel=preconnect>` simply have no schema representation and thus cannot survive conversion.
- **A08-SCH-2**: The schema is versioned. `schema_version` MUST be recorded on each converted document so a renderer knows which node/mark set to expect and past conversions stay interpretable.

## 2.1 Node whitelist (V1)

| Node | Notes |
| ---- | ----- |
| `doc` | root |
| `paragraph` | |
| `heading` | levels 1–6, mapped from `<h1>`–`<h6>` |
| `bulletList` / `orderedList` / `listItem` | from `<ul>`/`<ol>`/`<li>` |
| `blockquote` | from `<blockquote>` |
| `codeBlock` | from `<pre>` |
| `image` | src normalized (§8), remote gated (§8) |
| `hardBreak` | from `<br>` |
| `horizontalRule` | from `<hr>` |
| `table` / `tableRow` / `tableCell` / `tableHeader` | ONLY for genuine data tables (§7); layout tables are flattened |

## 2.2 Mark whitelist (V1)

| Mark | Notes |
| ---- | ----- |
| `bold` / `italic` / `underline` / `strike` | inline emphasis |
| `code` | inline code |
| `link` | href scheme-validated (§9); tracking-resolved metadata attached for A07 |
| `textColor` / `highlight` | OPTIONAL, from a **sanitized, bounded** palette only — arbitrary CSS color is NOT carried; no CSS expressions |

- **A08-SCH-3**: Any mark or styling not in this list (font-family, font-size, arbitrary CSS, positioning, background images, animations, MSO/VML/Word namespaces) MUST be dropped. Visual fidelity is intentionally sacrificed for safety and uniformity (A00 §1.2 Tiptap rationale). The dropped styling MUST NOT be reconstructed via inline style attributes on schema nodes.

------

# 3. Conversion Pipeline (Normative order)

```
1  SELECT PART   choose the richest safe MIME part:
                 text/html if present, else text/plain (wrapped to paragraphs)
2  PRE-STRIP     remove <script>, <style>, <head>, MSO/VML/Word namespaces,
                 comments, conditional comments — before DOM building
3  PARSE DOM     build a DOM from the (pre-stripped) HTML with a hardened,
                 resource-bounded parser (§10 stability)
4  HIDDEN PRUNE  remove hidden subtrees (display:none, visibility:hidden,
                 zero-size, off-screen, color==background) — §5
5  TABLE CLASSIFY  classify each <table> as layout vs data; flatten layout
                 tables to block sequences (§7)
6  MAP NODES     walk DOM → emit closed-schema nodes/marks; unknown → §6
7  NORMALIZE     CID image resolution (§8), URL scheme validation (§9),
                 link tracking-resolution metadata (§9), NFC text (CDM-I18N-9)
8  EMIT          Tiptap JSON with schema_version; build the conversion log (§6)
```

- **A08-PIPE-1**: Steps 2 and 4 are both required and distinct: pre-strip (step 2) removes categorically dangerous elements textually before DOM building (so a hardened parser never even instantiates a `<script>`); hidden-prune (step 4) removes *visible-schema-eligible* content that is hidden by CSS. Neither replaces the other.
- **A08-PIPE-2**: Conversion MUST be **deterministic**: the same source bytes + same schema_version MUST yield the same Tiptap JSON, so that (a) local search indexing is stable and (b) two devices converting the same message agree. Non-determinism (e.g. hash-map iteration order affecting node order) is a defect.

------

# 4. Plain-Text and Fallback

- **A08-TXT-1**: A `text/plain` message MUST be converted to paragraphs (splitting on blank lines), with URL auto-detection producing `link` marks (scheme-validated §9). No HTML parsing path is involved.
- **A08-TXT-2**: If HTML parsing fails catastrophically (malformed beyond recovery, §10), the client MUST fall back to the `text/plain` alternative part if present, else to a best-effort text extraction of the HTML, rendered as plain paragraphs — NEVER to raw-HTML rendering. A message is always displayable as safe text; conversion failure degrades to text, never to unsafe rendering (A00 SEC-FC-3).

------

# 5. Hidden-Content Rejection (Normative)

- **A08-HID-1**: Content hidden in the source MUST be pruned before node mapping and MUST NOT appear in the Tiptap output, MUST NOT be indexed (A05-LOC-2), and MUST NOT be fed to the AI keyword extractor (A05-AI-2, SEC-RENDER-3). Hidden means any of: `display:none`, `visibility:hidden`, `hidden` attribute, zero width/height, off-screen positioning (e.g. huge negative text-indent / absolute off-canvas), font-size 0, or text color equal (or near-equal) to its background color.
- **A08-HID-2**: The presence and volume of hidden content MUST be recorded in the client conversion log — hidden text is a known phishing/marketing-cloaking technique (the Palanquée preheader pattern is benign; the same mechanism weaponized is not). Diamy does not silently discard the fact that hiding occurred; it discards the content but keeps the record. (The trust-*score* hidden signal is computed separately at the frontier by A07 on plaintext, §1.1b — this client-side record is a transparency artifact, "what Diamy removed", available even for messages whose frontier processing predates a given detection rule.)
- **A08-HID-3**: The "preheader" pattern (hidden inbox-preview text padded with zero-width characters) is the common benign case. It is still pruned (not shown, not indexed) and recorded in the conversion log. The trust weighting of hidden content is A06/A07's (computed at the frontier); this annex guarantees client-side detection, pruning, and transparency reporting.

------

# 6. Exhaustiveness Rule (no silent omission)

Derived from the "view in browser" link observation: a link that disappears with no trace is a conversion defect hard to detect except by a user who knows the original.

- **A08-EXH-1**: Every interactive or content-bearing element in the source (link, image, form control, embedded object, iframe, button) MUST be either (a) represented in the Tiptap JSON, or (b) recorded in the **conversion log** with the reason it was dropped. Silent omission is FORBIDDEN. The conversion log is attached to the message (client-side metadata) and is inspectable ("what did Diamy remove from this message?").
- **A08-EXH-2**: Functional links with reassuring labels ("view in browser", "unsubscribe", "view online", "afficher dans le navigateur") MUST NOT be treated as a special exempt category. They are converted as ordinary `link` marks and receive the same A07 trust analysis as any link — a reassuring label is precisely a phishing lever, so exemption would be a vulnerability (the "view in browser" observation). If such a link is dropped for any reason, it MUST appear in the conversion log.
- **A08-EXH-3**: Elements with no safe schema representation (form controls, `<iframe>`, `<object>`, `<embed>`, `<button>`) MUST be dropped (not rendered) and logged. Where the element carried a URL (e.g. a form action, an iframe src), that URL MUST be captured in the log for A07 inspection — a phishing form's action URL is a signal even though the form itself is not rendered.

------

# 7. Layout-Table Flattening

- **A08-TBL-1**: `<table>` elements MUST be classified as **layout** vs **data**. Heuristics for layout: single visible column, no `<th>`, cells containing only images/spacers/presentational text, `role=presentation`, nested-table depth > 1, or width-driven positioning. Data tables have header cells, multiple meaningful columns, and tabular semantics.
- **A08-TBL-2**: Layout tables MUST be **flattened** into a linear sequence of block nodes (the cell contents emitted in document order as paragraphs/images/lists), NOT mapped to `table` nodes. Mapping a layout table to a data `table` node produces a semantically absurd grid (the marketing-email pattern) and breaks reading order on narrow viewports.
- **A08-TBL-3**: Genuine data tables MAY be mapped to `table`/`tableRow`/`tableCell` nodes, bounded in size (max rows/cols; oversized tables degrade to a flattened or truncated representation with a log entry). When ambiguous, flattening is the safer default (a data table rendered as blocks is readable; a layout table rendered as a grid is not).

------

# 8. Image Handling

- **A08-IMG-1**: **CID images** (`cid:` references to inline MIME parts) MUST be resolved to the corresponding attachment blob and emitted as `image` nodes referencing the local/blob source, so inline signature/logo images render. An unresolved `cid:` (missing part) becomes a placeholder image node with a log entry, never a broken silent gap.
- **A08-IMG-2**: **Remote images** (`http(s)://` src) MUST be gated: by default remote content is blocked (A00 SEC-RENDER-5). The `image` node carries the remote URL as metadata but the renderer MUST NOT load it until the user opts in ("load remote images"), and when loaded it MUST go through the image proxy (A09) to prevent IP/tracking leakage. A tracking pixel (1×1 remote image) SHOULD be detected; when it is, the image node MAY be dropped from the render, but the tracking-pixel detection MUST be retained in the conversion log regardless (dropping the node MUST NOT drop the signal).
- **A08-IMG-3**: `data:` image URIs (inline base64) MAY be carried for small images within a size bound; oversized `data:` URIs are dropped-with-log (DoS/bloat guard). `data:` URIs of non-image MIME types MUST be dropped (a `data:text/html` is an XSS vector, not an image).

------

# 9. Link and URL Safety

- **A08-URL-1**: Every `link` mark's href MUST have its scheme validated against a whitelist: `https`, `http` (flagged as non-TLS, A07 signal), `mailto`, `tel`. All other schemes — `javascript:`, `data:`, `vbscript:`, `file:`, and unknown schemes — MUST be stripped (the link becomes plain text with a log entry). A `javascript:` href is representable as a Tiptap link mark string, so scheme validation is a REQUIRED explicit step, not implied by the schema (SEC-RENDER type-vs-attribute distinction).
- **A08-URL-2**: The **displayed text vs actual href** mismatch MUST be captured: the link node carries both the visible text and the resolved href so A07 can score deception (text says `bank.fr`, href goes elsewhere). This annex captures the data; A07 scores it.
- **A08-URL-3**: **Tracking/redirect resolution**: where a link points to a known redirector/tracker pattern, the conversion SHOULD record the raw href and leave resolution of the final destination to A07 (which may resolve chains server-side or on-device per its rules). This annex MUST NOT itself fetch the URL to resolve it (fetching at conversion time would leak to the tracker before the user ever clicks) — it records, A07 decides how/whether to resolve safely.
- **A08-URL-4**: Punycode/IDN and confusable domains in link hrefs MUST be normalized (A24 domain rules) and flagged (A24-CONF) so A07 can score homograph deception in links, mirroring the address-level check.

------

# 10. Malformed Input & Stability

- **A08-STAB-1**: The HTML parser MUST be resource-bounded (bounded DOM node count, nesting depth, attribute count/size) and MUST NOT crash, hang, or exhaust memory on adversarial input (deeply nested tags, billions of attributes, unclosed-tag storms). Exceeding a bound yields a truncated/best-effort conversion with a `malformed` log entry, or the text fallback (§4), never a crash (mirrors A01-STAB for the gateway; the client parser is equally exposed).
- **A08-STAB-2**: Conversion MUST be time-bounded per message; a pathological message that would take too long to convert falls back to text (§4) with a log entry, so a single message cannot freeze the client UI.
- **A08-STAB-3**: Encoding follows CDM-I18N-2: charset recovery, never reject/lose content over encoding; the converted text is NFC-normalized (CDM-I18N-9) so search/indexing is consistent.

------

# 11. Output Contract

- **A08-OUT-1**: The conversion produces: (a) the **Tiptap JSON** document (schema_version tagged); (b) a **plain-text projection** (the visible text, for FTS indexing and AI keyword extraction — A05); (c) the **conversion log** (dropped elements + reasons, hidden-content report, link/href pairs, tracking-pixel flags — consumed by A06/A07 and user-inspectable). All three are client-side artifacts derived from decrypted content; none requires server involvement in native mode.
- **A08-OUT-2**: The plain-text projection (b) MUST contain only visible content (hidden pruned, §5), so search and AI never see hidden text (A05-LOC-2). The Tiptap JSON (a) is the render source; the log (c) is the transparency/trust source.

------

# 12. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| HTML unparseable | Fall back to text/plain part or text extraction; render as paragraphs; never raw HTML (A08-TXT-2) |
| Conversion times out / hits resource bound | Text fallback with `malformed` log; UI not frozen (A08-STAB) |
| CID part missing | Placeholder image + log; not a silent gap (A08-IMG-1) |
| Unknown/unsafe URL scheme | Strip to plain text + log (A08-URL-1) |
| Ambiguous table classification | Flatten (safer default) + log (A08-TBL-3) |
| Oversized data: URI / table | Drop-with-log (A08-IMG-3, A08-TBL-3) |
| Schema_version mismatch on render | Renderer handles known versions; unknown → safe text projection fallback |

------

# 13. Test Scenarios (Normative)

1. **Script/style elimination**: HTML with `<script>`, `<style>@import`, `onload=`, `<link rel=preconnect>` → none survive conversion; conversion log records the drops.
2. **Hidden preheader**: the Palanquée-style hidden preheader (`display:none` + zero-width padding) → not in Tiptap output, not in plain-text projection, not indexed; hidden-content signal recorded.
3. **Hidden malicious**: `display:none` text "verify your account at evil.fr" → absent from render, absent from AI keywords (assert search for that text returns nothing), signal recorded.
4. **Layout table flatten**: an 8-nested-table marketing email → linear block sequence, readable top-to-bottom; NOT a Tiptap data table; images in document order.
5. **Data table preserved**: a genuine 3-column pricing table with headers → `table` nodes preserved (bounded).
6. **CID resolution**: inline signature logo via `cid:` → resolved to attachment blob, renders; a missing CID → placeholder + log.
7. **Remote image gating**: remote `<img>` → blocked by default, URL carried as metadata; 1×1 tracking pixel → flagged, optionally dropped; on user opt-in, load via proxy (A09).
8. **javascript: link**: `<a href="javascript:...">click</a>` → link stripped, becomes plain text "click", log entry; no executable href in output.
9. **View-in-browser link**: reassuring "view in browser" link → converted as ordinary link, receives A07 analysis, appears in output (not dropped, not exempted); if dropped for any reason, logged.
10. **Text/plain**: plain-text message with a bare URL → paragraphs + auto-linked (scheme-validated).
11. **Malformed bomb**: deeply nested/unclosed-tag storm → bounded, text fallback, no crash/hang.
12. **Determinism**: convert the same message twice → byte-identical Tiptap JSON (same schema_version).

------

# 14. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Passing any raw HTML through to the renderer as a fallback instead of the text projection (A08-TXT-2, SEC-RENDER-1) — the single most dangerous shortcut.
2. ❌ Reconstructing dropped CSS/styling via inline `style` attributes on schema nodes, re-introducing the vulnerability the closed schema eliminates (A08-SCH-3).
3. ❌ Mapping HTML layout tables to Tiptap `table` nodes instead of flattening them (A08-TBL-2 — also A00 watch-list #12).
4. ❌ Indexing or AI-extracting hidden content because pruning ran after (or instead of) the text-projection step (A08-HID-1, A08-OUT-2, SEC-RENDER-3).
5. ❌ Silently dropping a link/image with no conversion-log entry (A08-EXH-1) — the "view in browser" class of defect.
6. ❌ Exempting "view in browser"/"unsubscribe" links from trust analysis because the label looks safe (A08-EXH-2).
7. ❌ Not scheme-validating link hrefs, letting a `javascript:` or `data:text/html` href survive as a link mark (A08-URL-1) — schema membership does NOT validate attribute content.
8. ❌ Fetching a link/tracker URL at conversion time to "resolve" it, leaking to the tracker before any click (A08-URL-3).
9. ❌ Carrying `data:text/html` as an image node (A08-IMG-3) — an XSS vector disguised as an image.
10. ❌ Loading remote images by default instead of gating behind opt-in + proxy (A08-IMG-2, SEC-RENDER-5).
11. ❌ Non-deterministic conversion (node order depends on hash-map iteration), breaking search stability and cross-device agreement (A08-PIPE-2).
12. ❌ Unbounded HTML parsing that hangs/crashes the client on an adversarial message (A08-STAB-1/2).
13. ❌ Assuming the client-side conversion's hidden-content detection feeds the server trust score — the score's hidden signal is computed at the frontier by A07 on plaintext (§1.1b); the client detection serves render/index exclusion and transparency. Conflating them leads to either a missing frontier signal or a client trying to push a signal server-side after encryption.

------

# 15. Deferred Items

- Richer table handling (responsive reflow of genuine wide data tables) — V1 flattens/truncates; enhance later.
- Preserving a bounded, sanitized subset of layout/spacing for higher fidelity on trusted senders — explicitly deferred; V1 favors uniformity and safety over fidelity.
- Inline calendar/ICS part rendering (meeting invitations embedded in mail) — interacts with A12–A15; the ICS part is handled by the calendar subsystem, not this converter.
- On-device final-destination resolution of tracker chains — coordinated with A07's link-resolution rules.

------

*End of document.*
