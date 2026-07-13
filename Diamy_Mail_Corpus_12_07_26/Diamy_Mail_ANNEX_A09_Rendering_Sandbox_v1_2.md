# Diamy Mail — ANNEX A09: Rendering Sandbox (View Original)

**Document title:** Diamy Mail — ANNEX A09: Rendering Sandbox (View Original)
**Version:** 1.2
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 5th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)
**Sibling dependencies:** A03 (Vault Client v1.2), A07 (Trust — Links & Attachments v1.2), A08 (HTML→Tiptap v1.1), A29 (Trust UX & Sandbox Workspace v1.0)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: "view original" path, defense-in-depth (sandboxed iframe + strict CSP + image proxy), non-default explicit-action gating, isolation from application context, remote-content control, no-script guarantee, image proxy contract, per-platform sandbox mechanisms, legal/evidence use case, failure model, test scenarios, common AI errors |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: made the image proxy's protection boundary precise — it defeats the EXTERNAL tracker learning the user's IP/read-receipt, but the Diamy proxy itself observes that a load occurred (honest-but-curious, consistent with A00 §3.2); added the transparency note so the guarantee is not overstated (A09-IMG-1b); added AI error #11 |
| 1.2     | Jul 5th 2026 | Cédric BORNECQUE | Coherence bump (corpus batch with A28/A29): sibling references updated to current versions (A03 v1.2, A07 v1.2); noted the new consumer — the A29 sandbox workspace forces this view-original path with remote content forced-blocked and no opt-in while a message is in `sandbox_state: active` (A29 §5.3); no change to the isolation mechanics themselves. |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies the **"view original" rendering path**: the explicit, non-default, isolated mechanism by which a user may view a message's raw HTML as the sender intended, when the default Tiptap rendering (A08) is insufficient (rendering seems truncated/incoherent, or a legal/evidence need to see the message exactly as received). It is defense-in-depth around an inherently riskier operation.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Relationship to A08

- **A09-REL-1**: Tiptap (A08) is the **default and safe** rendering. This annex is the **exception path** for viewing the original. The two are never mixed in one view (A00 SEC-RENDER, the "never both in the same view" principle from the conversation): Tiptap by default, raw-on-explicit-request-in-isolation, never the reverse, never blended.
- **A09-REL-2**: The raw HTML source is always retained (encrypted, A02) even though not rendered by default. "View original" renders that retained source. Content the Tiptap pipeline filtered (hidden text, stripped elements) IS visible in this mode — it is the mode that shows everything, unfiltered, which is exactly its purpose (a user demanding the original must be able to see all of it, including what was filtered by default).

## 1.2 Out of scope

Default rendering (A08). Trust analysis (A06/A07) — though the trust assessment MUST remain visible alongside the original view (§6). Attachment sandboxing/detonation (A07 T3) — that is a different isolation mechanism for a different object. The sandbox *workspace* (A29) — a message-level containment state that consumes this annex: for a message in `sandbox_state: active`, view-original runs through this path with remote content forced-blocked and no opt-in override (A29 §5.3).

------

# 2. Threat Model

The original HTML may contain: tracking pixels and remote resources (beacon the user's IP/engagement/read-time), CSS-based exfiltration, script (if not stripped), external font/resource loads, form-based phishing, and layout designed to deceive. Rendering it naively re-introduces exactly the vulnerability classes the Tiptap pipeline eliminated (A00 §1.2). Therefore the original is rendered only inside a hardened, isolated container.

------

# 3. Defense-in-Depth (Normative — all layers required)

The "view original" path MUST apply all of the following simultaneously. No single layer is sufficient.

## 3.1 Layer 1 — Sandboxed container

- **A09-SBX-1**: The original HTML MUST be rendered in a **sandboxed container** isolated from the application context: on web/webmail, an `<iframe sandbox>` with the most restrictive attribute set that still permits display (NO `allow-scripts`, NO `allow-same-origin`, NO `allow-forms`, NO `allow-popups`, NO `allow-top-navigation`); on desktop (Electron/native), an isolated WebView/renderer process with node integration disabled, context isolation on, and navigation blocked; on mobile, an isolated `WKWebView`/`WebView` with JavaScript disabled and navigation delegates blocking loads.
- **A09-SBX-2**: The sandbox MUST NOT share cookies, storage, session, or DOM access with the Diamy application. A script that somehow executed inside MUST be unable to reach app tokens, the catalogue, keys, or other messages (isolation is the containment, not the assumption that no script runs).

## 3.2 Layer 2 — Strict Content Security Policy

- **A09-CSP-1**: A strict CSP MUST be applied to the sandbox document: `default-src 'none'`; `script-src 'none'` (no script executes, belt-and-braces with the sandbox no-allow-scripts); `style-src` limited to inline styles needed for display (or a sanitized style set); `img-src` restricted to the **image proxy origin only** (§4); `frame-src 'none'`; `object-src 'none'`; `form-action 'none'`; `connect-src 'none'`; `base-uri 'none'`. No origin outside the proxy may be contacted.
- **A09-CSP-2**: `script-src 'none'` MUST be enforced regardless of the sandbox attributes — two independent mechanisms both forbidding script, so a gap in one is covered by the other (defense-in-depth, not redundancy to be optimized away).

## 3.3 Layer 3 — Image proxy (no direct remote loads)

- **A09-CSP-3** / defers to §4: every image and resource MUST route through the Diamy image proxy; no direct origin fetch from the sandbox is permitted (CSP `img-src` proxy-only + sandbox blocking). This prevents IP/engagement leakage even in the original view.

------

# 4. Image Proxy Contract

- **A09-IMG-1**: Remote images (and any permitted remote resources) in the original view MUST load through a **Diamy-operated image proxy**, never directly from the sender's/tracker's origin. The proxy fetches the resource server-side (attributable to Diamy infrastructure, not the user), strips/normalizes tracking-relevant headers, and serves it to the sandbox. This severs the IP-leak and read-receipt-beacon (the tracking-pixel concern from the conversation).
- **A09-IMG-1b** (precise protection boundary): The proxy defeats the **external** threat — the sender/tracker cannot learn the user's IP, user-agent, or read-receipt timing, because the fetch comes from Diamy infrastructure uniformly. It does NOT hide from **Diamy** that a load occurred: the honest-but-curious Diamy server observes that a proxy request happened (and can correlate it to load timing). This is consistent with the platform's honest-but-curious model (A00 §3.2) — Diamy already holds the message metadata — and MUST be stated plainly rather than implying the proxy makes the load invisible to everyone. The proxy's purpose is anti-external-tracking, not hiding activity from the platform.
- **A09-IMG-2**: Remote content in the original view MUST be **blocked by default** and load only after the user's explicit "load remote content" action (A00 SEC-RENDER-5, A08-IMG-2) — even inside the original view, remote loading is a second opt-in, because loading a tracking pixel confirms the read to the sender.
- **A09-IMG-3**: The proxy MUST NOT forward user-identifying information (no user IP, no user-agent revealing the user, no cookies, no referer that identifies the user or message). Proxy requests MUST be uniform across users/messages to the extent feasible, so the tracker cannot distinguish which user or message triggered the load. The proxy MAY cache to further decouple fetch from view.
- **A09-IMG-4**: The proxy MUST enforce resource limits (size, type, timeout) and MUST NOT proxy non-image resource types requested as images (a `text/html` served as an `<img>` src is rejected — mirrors A08-IMG-3).

------

# 5. Gating (Explicit, Non-Default)

- **A09-GATE-1**: "View original" MUST be an explicit user action (a deliberate menu item / button), NEVER the default view and NEVER auto-triggered. The default is always Tiptap (A08, A09-REL-1).
- **A09-GATE-2**: Entering the original view SHOULD carry a brief inline notice that this is the raw sender-provided content shown in isolation, and that remote content is blocked (with the option to load it). This sets user expectation (why it may look different) and reinforces the security posture without being obstructive.
- **A09-GATE-3**: The original view MUST be dismissible back to the safe Tiptap view at any time, and MUST NOT become "sticky" (viewing one message's original MUST NOT switch the whole app into original-by-default mode).

------

# 6. Trust Context Preservation

- **A09-TRUST-1**: The message's trust assessment (A06/A07: origin score, link risks, attachment risks, hidden-content report) MUST remain visible **alongside** the original view, not hidden by it. A user viewing the raw original still needs the "this link goes to X", "elevated risk" context — arguably more so, since the original may render a deceptive link exactly as the attacker intended. The original view MUST NOT be a trust-context-free zone.
- **A09-TRUST-2**: Links inside the original view, if made clickable at all, MUST route through the same pre-click safety (A07-UX-1) — showing the real destination and risk before navigation — and navigation MUST be blocked/confirmed (the sandbox blocks top-navigation; any click-through is an explicit, trust-checked action). Rendering the original MUST NOT bypass link trust checks.

------

# 7. Legal / Evidence Use

- **A09-LEGAL-1**: For a legal/evidence need (view the message exactly as received, with headers), the client MUST be able to present the retained raw source (A09-REL-2) and the full technical headers in a read-only, non-executing view. This is a legitimate documented use case (the conversation's litigation/complaint scenario). Even here, script never executes and remote content never auto-loads — "exactly as received" means the bytes are faithful, not that the client becomes a vulnerable renderer.
- **A09-LEGAL-2**: An export of the original (e.g. `.eml`) for evidence MUST warn the user it contains the raw message including any tracking/active content, and MUST be an explicit action (A00 file-download / A03 export discipline; scrub nothing from an evidence export, but make its nature clear).

------

# 8. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Sandbox unavailable / cannot enforce isolation | Do NOT render the original; fall back to Tiptap with a notice "original view unavailable" — NEVER render raw HTML unsandboxed (A00 SEC-FC-3) |
| CSP cannot be applied on a platform | Same: refuse original view rather than render without CSP |
| Image proxy down | Original view renders with remote content blocked (as if user hadn't opted in); no direct-origin fallback (that would leak) |
| Malformed original HTML | Sandbox renders best-effort; a rendering failure is contained (cannot crash the app); fall back to Tiptap/text |
| User clicks a link in original view | Pre-click trust (A07-UX-1) + explicit confirm; sandbox blocks silent navigation |

------

# 9. Observability Contract

Per A00 §11:

- counters: `view_original_opens_total`, `remote_content_loads_total` (in original view, post-opt-in), `image_proxy_requests_total{result}`, `original_view_unavailable_fallbacks_total`, `eml_exports_total`
- latency: `image_proxy_duration`
- audit (OBS-3): eml/original exports (evidence-grade action); MUST NOT log message content or URLs (A07-OBS-1 discipline)
- **A09-OBS-1**: Telemetry MUST NOT record which message was viewed-original, URLs loaded, or content — only aggregate counts.

------

# 10. Test Scenarios (Normative)

1. **Script never executes**: original HTML with `<script>alert(1)</script>` and `onerror=` handlers → nothing executes (sandbox no-allow-scripts AND CSP script-src none); assert no script side-effects.
2. **No app-context reach**: original with a script that (hypothetically) tries to read `document.cookie`/localStorage/parent → isolated, cannot reach app tokens/catalogue/keys (A09-SBX-2).
3. **Remote blocked by default**: original with remote `<img>` + tracking pixel → nothing loads until explicit opt-in; on opt-in, loads via proxy only (A09-IMG-1/2); assert zero direct-origin request, sender cannot see user IP.
4. **Proxy uniformity**: two different users viewing the same tracker image → proxy requests do not reveal which user/message (A09-IMG-3).
5. **Trust context visible**: original view of a phishing message → origin/link/attachment risk still shown alongside; a deceptive link shows its real destination pre-click (A09-TRUST-1/2).
6. **Non-sticky**: view one original → dismiss → app is back to Tiptap default; other messages still default to Tiptap (A09-GATE-3).
7. **Sandbox unavailable**: force sandbox init failure → original view refused, Tiptap fallback with notice, NO unsandboxed raw render (§8).
8. **Evidence export**: export `.eml` → explicit action, warning shown, raw bytes faithful, nothing executes on export (A09-LEGAL).
9. **data:text/html img**: original with `<img src="data:text/html,...">` → rejected by proxy/type check (A09-IMG-4).

------

# 11. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Making "view original" render raw HTML directly (no sandbox, or a sandbox with `allow-scripts`/`allow-same-origin`) — reintroduces every class the Tiptap pipeline eliminated (A09-SBX-1).
2. ❌ Relying on the sandbox attribute OR the CSP but not both — the two are independent required layers (A09-CSP-2).
3. ❌ Loading remote images directly from the sender's origin in the original view, leaking IP/read-receipt, instead of proxy-only + opt-in (A09-IMG-1/2).
4. ❌ Making original view the default or auto-triggering it (A09-GATE-1) — it is always an explicit exception.
5. ❌ Letting original view become sticky / switch the app to raw-by-default (A09-GATE-3).
6. ❌ Hiding the trust assessment during original view, leaving the user to face the attacker's intended rendering with no safety context (A09-TRUST-1).
7. ❌ Allowing silent link navigation from inside the original view, bypassing pre-click trust (A09-TRUST-2).
8. ❌ Falling back to unsandboxed rendering when the sandbox/CSP is unavailable, instead of refusing and using Tiptap (§8, SEC-FC-3).
9. ❌ Proxy forwarding user-identifying headers/IP, defeating the anti-tracking purpose (A09-IMG-3).
10. ❌ Proxying a `data:text/html` or non-image type requested as an image (A09-IMG-4).
11. ❌ Overstating the proxy guarantee — claiming remote-image loads are invisible to everyone when the honest-but-curious Diamy proxy does observe the load; the proxy defeats the EXTERNAL tracker, not internal platform metadata (A09-IMG-1b).

------

# 12. Deferred Items

- Remote-browser-isolation (RBI) rendering of the original (render server-side in isolation, stream pixels) as an even stronger option for high-risk tenants — shares mechanism with A07 T3 detonation; deferred, the iframe+CSP+proxy model is the V1 baseline.
- Per-tenant policy to disable "view original" entirely (maximum-lockdown tenants) — trivial to add; recorded so it is considered.
- Header-analysis pedagogical view (explain the Received chain) — enhancement over raw header display.

------

*End of document.*
