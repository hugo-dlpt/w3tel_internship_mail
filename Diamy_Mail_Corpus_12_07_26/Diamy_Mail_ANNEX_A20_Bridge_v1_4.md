# Diamy Mail — ANNEX A20: Bridge (Local IMAP/SMTP Facade)

**Document title:** Diamy Mail — ANNEX A20: Bridge (Local IMAP/SMTP Facade)
**Version:** 1.4
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.4 (A00)
**Sibling dependencies:** A02 (Storage v1.1), A03 (Vault Client v1.1), A04 (Native Sync API v1.1), A08 (HTML→Tiptap v1.1), A17 (IAM v1.2), A19 (Client SDK v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: local IMAP/SMTP/CalDAV facade (`diamy-bridged`) for third-party clients — strictly-local loopback architecture, threat model and the reintroduced-plaintext boundary made explicit and bounded, credential model (app-specific bridge passwords), decrypt-locally / speak-plaintext-on-loopback discipline, IMAP/SMTP command mapping onto the native SDK, no-remote-listener rule, trust-metadata surfacing within protocol limits, CalDAV bridge for calendar, failure model, test scenarios, common AI errors |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Hardening (external review): made Bridge activation explicitly **opt-in, non-default, and dual-gated** (user opt-in AND tenant policy, neither alone) and added **endpoint-posture gating** — tenants may permit the Bridge only on managed devices / full-disk-encrypted / EDR-present (A20-THREAT-4b); foregrounded the third-party-client local-cache residual risk (Outlook/Apple Mail/Thunderbird keep their own, possibly unencrypted, local stores that may sync to the client vendor's cloud) as the single most important disclosed exposure (A20-DISC-1). |
| 1.4     | Jul 4th 2026 | Cédric BORNECQUE | Final sweep: fixed one more unqualified epoch mention (AI error #11) missed in v1.3's pass, referencing A17-TOK-2. |
| 1.3     | Jul 4th 2026 | Cédric BORNECQUE | Coherence extension for the Tier 2 AppKey model (A17 v1.4 §4.2bis): added A20-CRED-5 — the Bridge is issued its own AppKey (`diamy-mail-bridge`), distinct from the co-located native app's, mirroring A20-CRED-4b's device-independence principle at the application-authentication layer. Softened epoch-specific language in A20-CRED-3 and the failure model pending A17-TOK-2's confirmation of the actual revocation mechanism. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: clarified that the Bridge is its OWN enrolled device with its own keys even when co-located on the same machine as the native app — so revoking the Bridge does not disable the native app, and each has independent envelopes/re-wrap/revocation (A20-CRED-4b); added the Bridge non-loopback-refusal / startup-refusal **security** indicators to A22 (a non-zero rate means an attempted plaintext-exposure or tampering — this coherence action was applied to A22 v1.3). |

------

# Table of contents

[toc]

------

# 1. Scope

This annex specifies the **Diamy Bridge** (`diamy-bridged`): a component that lets a user access their Diamy mailbox and calendar from a **third-party client** (a legacy Outlook profile, Apple Mail, Thunderbird, a mobile stock mail app, a CalDAV client) by exposing standard **IMAP, SMTP, and CalDAV** on the user's own machine. It is the interoperability bridge between the native, zero-access Diamy protocol (A04) and the standard protocols those clients speak.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Why a bridge, and the precedent

Many users cannot or will not switch mail clients; a mailbox that only works in the native Diamy app excludes them. The Bridge follows the well-established **Proton Mail Bridge** model (studied in design): a small local process that presents IMAP/SMTP to the user's existing client while doing the encryption/decryption itself, so the third-party client sees ordinary plaintext mail and never touches Diamy's keys or servers directly.

## 1.2 The honest framing (read this first)

The Bridge is the one component that **deliberately reintroduces plaintext at a boundary the rest of the corpus eliminated**. A third-party IMAP client cannot speak Diamy's encrypted native protocol; it speaks plaintext IMAP. Therefore the Bridge MUST decrypt locally and hand plaintext to that client over a local channel. This annex does not hide that — it **bounds** it: the plaintext exists only on the user's own device, only over loopback, only for a client the user chose to connect, and never on the network or the server. The security argument is not "no plaintext exists" (false for the Bridge) but "the plaintext boundary is the user's own machine, exactly where the native app already decrypts (A03), and nothing is weakened server-side." Getting these bounds exactly right is the whole point of this annex.

## 1.3 Out of scope

The native protocol (A04). Server storage (A02). The native app's own rendering/trust (A03/A06–A09) — the Bridge surfaces what the protocol allows, but a third-party client renders per its own rules, outside Diamy's control (§8).

------

# 2. Architecture

- **A20-ARCH-1**: `diamy-bridged` runs as a **local process on the user's device** (desktop; a mobile equivalent is constrained by OS background limits, §12). It embeds (or links) the Diamy client core SDK (A19) — the same code that the native app uses to authenticate (A17), sync (A04), decrypt (A02 envelopes), and convert content (A08). The Bridge is a client SDK consumer, not a new protocol implementation, and reuses A19's shared core (no re-implemented crypto, A19-SDK-2).
- **A20-ARCH-2** (loopback only — normative): The Bridge's IMAP, SMTP, and CalDAV listeners MUST bind to **loopback only** (`127.0.0.1` / `::1`), NEVER a routable interface. A third-party client connects to `127.0.0.1:<port>`. The Bridge MUST NOT expose these listeners on the network under any configuration — a network-exposed plaintext IMAP of a decrypted mailbox would be a catastrophic breach. This is a hard rule, not a default (§6).
- **A20-ARCH-3**: The Bridge maintains the local vault (A03) as its backing store — it is, in effect, a headless vault client that additionally speaks IMAP/SMTP/CalDAV to a local consumer. It syncs via the native API (A04), stores encrypted at rest (A03), and decrypts on demand to answer IMAP fetches. There is one local encrypted store; the Bridge is another face on it, not a second copy.
- **A20-ARCH-4** (local TLS): Even on loopback, the listeners SHOULD offer STARTTLS/implicit TLS with a locally-generated, machine-scoped certificate the third-party client is configured to trust, so the loopback traffic is encrypted against local same-host snoopers (other user processes). Loopback is not automatically private on a multi-user machine. Where the client cannot do TLS on loopback, the fallback is plaintext-on-loopback with the exposure documented (§9).

------

# 3. Threat Model & Bounded Plaintext (Normative)

- **A20-THREAT-1**: The Bridge's plaintext exposure is bounded to: (a) the user's own device, (b) loopback interface only (A20-ARCH-2), (c) mailbox content the user's chosen third-party client fetches, (d) for the duration of serving that client. It does NOT extend to: the network (loopback-only), the Diamy server (which stays zero-access — the Bridge changes nothing server-side), other devices, or other users.
- **A20-THREAT-2** (equivalence to native app): The Bridge decrypts on the user's device exactly as the native app does (A03 read path). It does not create a *new class* of exposure — the plaintext already exists transiently in the native app when the user reads mail. The Bridge's addition is that the plaintext is handed to a *third-party* client over loopback. That third-party client's handling of the plaintext (its local storage, its own cloud sync, its rendering) is **outside Diamy's control** and MUST be disclosed to the user as the residual risk (§8, A20-DISC).
- **A20-THREAT-3** (what is NOT weakened): Enabling the Bridge MUST NOT weaken: server-side zero-access (A02 — the server never gains decryption ability), the native protocol, other users' or devices' security, or the at-rest encryption of the local vault (A03 — the Bridge's backing store stays encrypted; it decrypts on demand, not at rest). The Bridge is a local read/write face, not a decryption of the stored data.
- **A20-THREAT-4** (tenant control): Because the Bridge extends plaintext to third-party clients, tenants MUST be able to **disable the Bridge organization-wide** (the same enforcement lever as native-only webmail, A05-BI-9, and native-only-no-external-calendar, A14-ZA-3). A tenant with strict data-handling requirements may forbid third-party-client access entirely.
- **A20-THREAT-4b** (opt-in, non-default, policy-gated — normative): The Bridge MUST be **off by default** and requires **both** an explicit user opt-in **and** a tenant policy that permits it — neither alone enables it. It MUST NOT be silently available. Beyond a simple allow/deny, tenants MUST be able to gate the Bridge on **endpoint posture**, e.g. permit it only on managed devices, or only where full-disk encryption is active, or only with an EDR agent present, per the tenant's device-management policy. Rationale: the residual risk of the Bridge is not in Diamy's code but in the third-party client's local handling of plaintext (A20-THREAT-2, A20-DISC) — so the tenant's control MUST extend to *where* the Bridge may run, not just *whether*. A tenant that cannot verify endpoint posture MAY restrict the Bridge to deny-by-default. This posture gate is a control-plane, audited setting (INV-20, INV-22).

------

# 4. Credential Model

- **A20-CRED-1**: A third-party client authenticates to the Bridge with a **Bridge-specific, app-scoped password** (the Proton Bridge model), NOT the user's Diamy account password and NOT their IAM credentials. The user generates a Bridge password in the native app; it authorizes exactly one third-party-client connection to the local Bridge and is revocable independently.
- **A20-CRED-2**: The Bridge holds the user's actual Diamy session/keys (via the SDK, A17/A19) in its own process, protected by the OS secure store (A19-STORE-1) exactly as the native app; the Bridge password gates the *third-party client → Bridge* hop, while the *Bridge → Diamy* hop uses the real authenticated session. Compromise of a Bridge password exposes the local Bridge to a local attacker but does not yield the Diamy account credentials or work off-device (loopback-only, A20-ARCH-2).
- **A20-CRED-3**: Bridge passwords MUST be individually revocable (revoking one disconnects that client without affecting others or the account), enumerable (the user sees which clients are connected), and session-revocation-aware (a session revocation event — mechanism per A17-TOK-2, currently unconfirmed as epoch-based vs JTI-cache-based — MUST stop the Bridge and invalidate its session, requiring re-auth — a revoked device's Bridge stops serving).
- **A20-CRED-4**: The Bridge counts as a **device** in the IAM/device model (A17): it has its own device identity and mail keys (A17-KEY), publishes to the key directory (A17-DIR), and is subject to re-wrap for historical access (A02-RW) and to revocation. It is not a credential-sharing shim; it is an enrolled device that additionally speaks IMAP locally.
- **A20-CRED-4b** (own device even co-located): The Bridge is its OWN enrolled device with its OWN keys, distinct from the native app's device identity — even when both run on the same physical machine. Consequences: revoking the Bridge (A20-CRED-3) does NOT disable the co-located native app, and vice versa; each has independent envelopes and independent re-wrap on enrollment (A02-RW); the key directory shows them as separate devices. This keeps the Bridge cleanly revocable as a unit (kill third-party-client access without touching the user's native app) and avoids coupling two very different trust surfaces (the native app with Tiptap/sandbox protections vs the Bridge handing plaintext to a third-party client) onto one device identity.
- **A20-CRED-5** (own Tier 2 AppKey — implements A17-APPKEY-1): The Bridge is its own client application for the purposes of the Tier 2 Applicative AppKey model (A17 §4.2bis) — it MUST be issued its own AppKey (e.g. `diamy-mail-bridge`), distinct from the co-located native app's AppKey, and MUST send it on every request to `diamy-maild`/`diamy-submitd` alongside its own device's mail-plane token. Revoking the Bridge's AppKey stops it independently of the native app's AppKey, mirroring A20-CRED-4b's device-independence principle at the application-authentication layer.

------

# 5. Protocol Mapping

## 5.1 IMAP (read/organize)

- **A20-IMAP-1**: The Bridge presents the user's folders (A02/A03) as IMAP mailboxes (decrypting folder names locally, A03-KEY-3) and messages as standard RFC 5322 messages. On an IMAP `FETCH`, the Bridge decrypts the message blob (A02 envelope, locally) and returns the plaintext RFC 5322 form to the client. IMAP flags (`\Seen`, `\Answered`, `\Flagged`, `\Deleted`) map to the native state flags (A03/A04), and changes propagate through the native sync (A04) with the same per-field-LWW conflict semantics (A03-SYNC).
- **A20-IMAP-2** (content form): The Bridge returns the **original RFC 5322 / MIME** message (the stored body blob is exactly that, A02-CRY-2), NOT a Tiptap-converted form — a third-party IMAP client expects standard MIME and does its own rendering. This means the third-party client renders raw HTML with its own engine, outside Diamy's Tiptap safety (A08) and sandbox (A09). This is an inherent limitation of bridging to a standard client and MUST be disclosed (§8): the Tiptap/sandbox protections apply in the native app, not in a third-party client reached via the Bridge.
- **A20-IMAP-3** (idempotent, bounded): IMAP operations map onto the native sync's idempotent, bounded operations (A04); the Bridge MUST enforce the same resource bounds (A18/A19) so a misbehaving client cannot exhaust resources. Large `FETCH`es stream from the local blob store.

## 5.2 SMTP (send)

- **A20-SMTP-1**: The Bridge presents a local SMTP submission endpoint. On send, it takes the client's RFC 5322 message, runs it through the native outbound path (A04 `/submit` → A10 emission): building the client-encrypted Sent copy (A02 §5.2), and emitting via `diamy-submitd` with DKIM/SPF/DMARC alignment (A10). The third-party client's message is emitted with the same deliverability and authentication as a native-app send — the Bridge does not bypass A10.
- **A20-SMTP-2**: The Bridge MUST apply the same outbound anti-abuse (A10-RL rate limits, From-authorization A10-AUTH-4) — a third-party client sending via the Bridge is subject to the identical limits; the Bridge is not an escape hatch around emission controls.

## 5.3 CalDAV (calendar)

- **A20-CALDAV-1**: The Bridge presents the user's calendars (A12) as CalDAV collections and events as iCalendar (ICS) to a CalDAV client, decrypting event detail locally (A12) and serializing to ICS with correct timezone handling (A13). Writes from the CalDAV client map onto the native calendar model (A12) and sync (A04). iTIP scheduling initiated from the third-party client flows through A14. This gives calendar interop to Apple Calendar / Thunderbird / etc. on the same bounded-plaintext-local basis.
- **A20-CALDAV-2**: Free/busy requests from a CalDAV client are answered per A15 (consent-scoped); the Bridge does not expand the consent scope — a client reaching free/busy via the Bridge sees exactly what A15 permits.

------

# 6. No-Remote-Listener Rule (Normative, security-critical)

- **A20-NET-1**: The Bridge listeners MUST bind to loopback only (A20-ARCH-2). The Bridge MUST NOT provide any configuration option, flag, or "advanced mode" that binds a listener to a routable address. This is enforced in code (bind address is a fixed loopback constant, not user-configurable) — it MUST NOT be possible to turn the Bridge into a network-reachable plaintext IMAP server for a decrypted mailbox, even by an advanced user who thinks they want it. If a user needs remote access, that is the native app or webmail, not a network-exposed Bridge.
- **A20-NET-2**: The Bridge MUST verify at startup that its listeners are loopback-bound and MUST refuse to start (fail-closed) if it detects a non-loopback bind (misconfiguration, port-forwarding shim, container networking that would expose it). A Bridge that cannot guarantee loopback-only does not run.
- **A20-NET-3** (defense in depth): The Bridge SHOULD additionally reject connections whose peer address is not loopback (belt-and-braces with the bind restriction), so even a misconfigured network path is refused at the connection level.

------

# 7. Trust-Metadata Within Protocol Limits

- **A20-TRUST-1**: IMAP has no native "trust score" concept. The Bridge SHOULD surface Diamy's trust assessment (A06/A07) to the third-party client within IMAP's limits: e.g. prepending a concise trust summary to the message (an added header like `X-Diamy-Trust:` and/or a short note in the body preamble), or using a dedicated folder/flag convention, so a user in a third-party client still gets *some* of the trust signal. The exact mechanism is bounded by what IMAP clients display; this is best-effort, not the rich native presentation.
- **A20-TRUST-2**: The Bridge MUST NOT suppress or downgrade trust warnings when bridging — a high-risk message reached via the Bridge is still high-risk. If the trust signal cannot be conveyed through IMAP in a given client, that limitation MUST be disclosed (§8): the Bridge cannot guarantee the trust UI a third-party client shows.

------

# 8. Disclosure of Residual Risk (Normative)

- **A20-DISC-1**: Enabling the Bridge MUST disclose to the user (and the tenant admin) the residual risks that are inherent to bridging to a third-party client and are outside Diamy's control:
  - **the third-party client stores the decrypted plaintext in its own local cache, per its own rules** — Outlook, Apple Mail, and Thunderbird all maintain local mail stores that may be unencrypted, and may sync to the client vendor's own cloud (e.g. a third-party client's own server-side copy). This is the single most important residual risk: the Bridge respects the Diamy model, but the third-party client can break it locally once it holds the plaintext. It is why endpoint-posture gating (A20-THREAT-4b) matters — a managed device with full-disk encryption bounds this exposure;
  - the third-party client renders content with its own engine, outside Diamy's Tiptap/sandbox protections (A20-IMAP-2) — remote content, tracking pixels, and unsafe HTML are the client's responsibility;
  - the trust presentation is limited to what IMAP allows (A20-TRUST).
- **A20-DISC-2**: This disclosure is the Bridge's analogue of every other declared boundary in the corpus (frontier, hold queue, T3, webmail, external calendar): the exposure is real, bounded, and stated plainly rather than hidden. The user makes an informed choice to trade some of Diamy's protections for third-party-client convenience.

------

# 9. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| Non-loopback bind detected at startup | Fail-closed: refuse to start (A20-NET-2) |
| Connection from non-loopback peer | Reject at connection level (A20-NET-3) |
| Session revoked (mechanism per A17-TOK-2) | Stop serving, invalidate session, require re-auth (A20-CRED-3, A17-TOK-5 target) |
| Bridge's own AppKey revoked | Bridge rejected at `diamy-maild`/`diamy-submitd` independent of the native app's AppKey (A20-CRED-5) |
| Bridge password compromised (local attacker) | Local-only exposure; revoke that password; account creds not exposed; loopback-only limits blast radius (A20-CRED-2) |
| Third-party client requests a message with no local envelope (historical, pre-rewrap) | Await re-wrap (A02-RW); represent as temporarily unavailable, not an error |
| GCM/manifest verify fails on decrypt | Do not serve unverified plaintext; represent as a damaged message (A03-READ-2) |
| Loopback TLS unavailable in client | Plaintext-on-loopback with documented exposure (A20-ARCH-4, §8) |
| Tenant disabled the Bridge | Bridge does not run for that tenant's users (A20-THREAT-4) |
| Outbound via Bridge hits rate limit | Same A10-RL limits apply; surfaced as SMTP error (A20-SMTP-2) |

------

# 10. Observability Contract

Per A00 §11:

- counters: `bridge_sessions_total`, `bridge_imap_ops_total{op}`, `bridge_smtp_sends_total{result}`, `bridge_caldav_ops_total`, `bridge_password_revocations_total`, `bridge_nonloopback_refusals_total` (security-relevant — should be ~0), `bridge_startup_refusals_total{reason}`
- gauges: active bridge devices, connected third-party clients per user
- audit (OBS-3): Bridge enablement (per user/tenant), Bridge password creation/revocation, any non-loopback refusal (a non-zero rate here is a red flag warranting investigation)
- **A20-OBS-1**: `bridge_nonloopback_refusals_total` and `bridge_startup_refusals_total` are security indicators — a non-loopback bind attempt (whether misconfiguration or tampering) MUST be visible (A22 candidate). Telemetry MUST NOT include message content (A07-OBS-1 discipline) — the Bridge handles plaintext locally but MUST NOT log it.

------

# 11. Test Scenarios (Normative)

1. **Loopback-only enforced**: attempt to configure/start the Bridge with a non-loopback bind → refused at startup (A20-NET-2); no config option exposes a routable bind (A20-NET-1).
2. **Non-loopback peer rejected**: a connection routed to appear from a non-loopback peer → rejected at connection level (A20-NET-3).
3. **IMAP fetch decrypts locally**: third-party client FETCHes a message → Bridge decrypts the blob locally, returns standard RFC 5322; server never decrypts (A20-IMAP-1); assert server zero-access unchanged.
4. **SMTP send via native path**: third-party client sends → Bridge routes through A04/A10 → DKIM-signed, SPF/DMARC-aligned, Sent copy client-encrypted, A10-RL limits applied (A20-SMTP-1/2).
5. **Flag sync**: mark \Seen in the third-party client → propagates via native sync to the native app and other devices (per-field LWW) (A20-IMAP-1).
6. **Bridge password scope**: a Bridge password authorizes one client, is revocable independently, does not equal the account password, does not work off-device (A20-CRED-1/2/3).
7. **Device revocation**: revoke the Bridge device via IAM → Bridge stops serving, re-auth required (A20-CRED-3).
8. **Bridge AppKey independence**: revoke the Bridge's Tier 2 AppKey → Bridge requests rejected `ERR_APPKEY_INVALID`; native app's own AppKey and sessions unaffected (A20-CRED-5).
8. **Residual-risk disclosure**: enabling the Bridge surfaces the third-party-rendering / plaintext-handling / limited-trust-UI disclosures (A20-DISC-1).
9. **Tenant disable**: tenant forbids the Bridge → it does not run for that tenant (A20-THREAT-4).
10. **CalDAV**: a CalDAV client reads/writes events → maps to native calendar (A12), correct timezones (A13), free/busy consent-scoped (A15) (A20-CALDAV).
11. **Trust surfacing**: a high-risk message reached via IMAP carries a trust indication within IMAP limits; the warning is not suppressed (A20-TRUST-1/2).
12. **No content in logs**: verify Bridge telemetry/logs contain no message plaintext despite handling it locally (A20-OBS-1).

------

# 12. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Binding the Bridge's IMAP/SMTP/CalDAV listeners to a routable interface, or providing any config that allows it — a network-exposed plaintext IMAP of a decrypted mailbox (A20-NET-1/2) — the single most catastrophic Bridge bug.
2. ❌ Not failing closed when a non-loopback bind is detected at startup (A20-NET-2).
3. ❌ Weakening server-side zero-access to implement the Bridge (e.g. server-side decryption) instead of decrypting locally in the Bridge process (A20-THREAT-3, A20-ARCH-3).
4. ❌ Using the user's Diamy account/IAM password for third-party auth instead of a revocable, app-scoped Bridge password (A20-CRED-1).
5. ❌ Treating the Bridge as a credential shim rather than an enrolled device with its own keys, subject to re-wrap and revocation (A20-CRED-4).
6. ❌ Bypassing A10 emission controls (DKIM/alignment/rate limits) on SMTP-via-Bridge sends (A20-SMTP-1/2).
7. ❌ Suppressing or failing to convey trust warnings when bridging (A20-TRUST-2).
8. ❌ Not disclosing the residual risks (third-party rendering outside Tiptap/sandbox, third-party plaintext handling, limited trust UI) (A20-DISC-1).
9. ❌ Logging the plaintext the Bridge necessarily handles locally (A20-OBS-1).
10. ❌ Serving unverified plaintext when GCM/manifest verification failed (A20 failure model, A03-READ-2).
11. ❌ Ignoring session/device revocation (mechanism per A17-TOK-2) so a revoked Bridge keeps serving (A20-CRED-3).
12. ❌ Not offering tenants an org-wide Bridge disable (A20-THREAT-4).
13. ❌ Sharing the co-located native app's Tier 2 AppKey with the Bridge instead of issuing it a distinct one — breaks the independent-revocation guarantee A20-CRED-4b already establishes at the device layer (A20-CRED-5).

------

# 13. Deferred Items

- Mobile Bridge (iOS/Android background-execution constraints make a persistent local IMAP listener hard) — the native mobile app is the primary mobile path; a mobile Bridge is a platform-constrained future item.
- POP3 support (in addition to IMAP) — POP3's download-and-delete model fits the vault poorly; deferred unless a concrete client need arises.
- Per-message trust-detail surfacing richer than a header/preamble (e.g. a companion local UI the third-party client links to) — an enhancement over A20-TRUST-1.
- JMAP as a modern alternative to IMAP for capable third-party clients — potentially a cleaner bridge target than IMAP; noted for future consideration.
- Bridge auto-configuration profiles (one-click setup for common clients) — a UX convenience; the security rules (loopback-only, app-scoped password) are unchanged by it.

------

*End of document.*
