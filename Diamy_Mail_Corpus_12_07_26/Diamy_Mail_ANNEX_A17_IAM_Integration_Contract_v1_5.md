# Diamy Mail — ANNEX A17: IAM Integration Contract

**Document title:** Diamy Mail — ANNEX A17: IAM Integration Contract
**Version:** 1.5
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.9 (A00)
**External reference (reviewed July 2026):** Diamy IAM – Integration Specification v1.6 (informs §4.2 flag and §4.2bis)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: consumption contract with Diamy IAM (principal resolution via primary_email_hash, mail-plane token, epoch revocation effects), separation identity keys vs mail encryption keys (per Key Management §13bis), mail device key directory, SED scope decision (control-plane only), Level A/B applicability to mail metadata, failure model, test scenarios, common AI errors |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: identified and documented the zero-active-device recipient gap (frontier cannot wrap for a provisioned-but-never-enrolled principal) — added failure-model row, gateway hold-queue requirement A17-DIR-5, and HIGH open item; added service-to-service authentication rule A17-S2S-1 (was absent — only user tokens were covered); tightened webmail-token epoch verification (periodic re-check, not only at resume); added live-connection termination on epoch bump (A17-TOK-5); added AI error #11 |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | §12 HIGH open item CLOSED by A11 §11: the gateway hold queue (A01-HOLD) remains the mandatory baseline; per-user first-device enrollment sequencing is added as an onboarding optimization for interactive paths (A11-SEQ), narrowing but not replacing the hold queue (bulk migration / MX-cutover-before-login paths still require it). No normative change to A17's rules; this is a forward-reference update. |
| 1.3     | Jul 4th 2026 | Cédric BORNECQUE | Coherence extension for A27 (Shared Resources): added §3bis — resource principals (shared mailboxes, A17-RESRC-1..5: membership as a scoped entitlement, device enrollment signed by the enrolling member's own identity, role carried on the mail-plane token rather than in key material) and distribution groups (A17-GRP-1..3: directory-only, no mailbox/keys/token of their own). Added A17-DIR-6: calendar-delegation device enrollment is scope-restricted to the grantor's calendar directory only, structurally excluded from the mail device-key directory — the directory-API enforcement point for A27-SEC-1's crypto-scope guarantee. Extended SED scope (A17-SED-1) to resource-principal/group admin operations. Closes the A17 dependency flagged pending by A27 v1.1 §9. |
| 1.4     | Jul 4th 2026 | Cédric BORNECQUE | Major correction after reviewing the actual Diamy IAM – Integration Specification v1.6: fixed A17-TOK-4, which conflated two independent AppKey tiers (§2.4 of that spec). Added §4.2bis specifying Diamy Mail's own Tier 2 Applicative AppKey — local `app_keys` store, mandatory dual-factor validation order (AppKey before mail-plane token, before authorization), per-client/platform key isolation (incl. the Bridge), IAM-outage independence, SED-gated lifecycle. Also flagged, rather than silently asserted, a real open question in A17-TOK-2: this annex's "epoch bump" revocation language was inherited by analogy from the messaging corpus and has NOT been confirmed against the actual IAM mechanism — the reviewed Integration Specification describes a JTI-revocation-cache model with optional webhook and a ≤300s degraded fallback, materially looser than A17-TOK-5's 10s bound. Marked this a new HIGH open item (§12) pending review of *Auth and Session Model* / *Security Hardening & Runtime Model*, softened the affected test scenario and one common-error entry accordingly, and closed a stale deferred item (shared-mailbox/delegation entitlements — already resolved by §3bis in v1.3 but not marked closed). Added AI errors #16–20 and test scenarios #11–15 for the AppKey model. |
| 1.5     | Jul 4th 2026 | Cédric BORNECQUE | Follow-up sweep: the v1.4 pass only fully qualified A17-TOK-2/TOK-5; six other "epoch" mentions in this same document (A17-P-1, A17-RES-3, A17-ENT-2, A17-RESRC-2, A17-DIR-2, A17-DIR-4, and one audit-events line) still stated epoch semantics as settled fact. Added a consolidating scope note to A17-TOK-2 (all other epoch mentions inherit its caveat) and lightly re-worded each of the six to cross-reference A17-TOK-2 instead of restating or contradicting it. No normative behavior changed — only the certainty with which an unconfirmed mechanism is described. |

------

# Table of contents

[toc]

------

# 1. Scope

This annex defines the **consumption contract** between Diamy Mail and Diamy IAM: which IAM primitives Diamy Mail uses, how, and the strict boundary of what Diamy Mail MUST NOT reimplement (A00 §1.4, API-2).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Direction of authority

For every mechanism defined in the Diamy IAM corpus, **the IAM corpus prevails**. This annex only binds Diamy Mail to those mechanisms; it does not redefine them. Referenced IAM documents:

| IAM document | Authoritative for |
| ------------ | ----------------- |
| *Diamy IAM – Auth and Session Model v1.2* | Authentication phases, X-App-* headers, token issuance, `primary_email_hash` user lookup |
| *Diamy IAM – Key Management Specification v1.2* | Dilithium identity keypair lifecycle, Shamir 2-of-3 custody, §13bis scope boundary |
| *Diamy IAM – Client Execution and SDK Contract v1.1* | SED chain mechanics, recovery, token storage rules |
| *Diamy IAM – Payload Encryption Model v1.1.2* | Level A / Level B definitions, field classification, AAD rules |
| *Diamy IAM – DEK Lifecycle and Rotation v1.4* | Server-side DEK derivation (`diamy-secretd`, KEK seed) |
| *Diamy IAM – Role and Authorization Model v1.1* | Role resolution, tenant context |

If an IAM mechanism needed by Diamy Mail does not exist yet (see §5 device mail keys), this annex specifies the **requirement**, and the change is submitted to the IAM corpus as an extension — Diamy Mail MUST NOT ship a private workaround.

## 1.2 Non-goals

Diamy Mail does NOT implement, store, or process: passwords, authentication challenges, OTP/TOTP/WebAuthn/Passkey flows, refresh tokens issuance, Shamir shares, or DEK derivation. These belong to IAM exclusively.

------

# 2. Integration Principles

- **A17-P-1**: Diamy Mail authenticates every API call with IAM-issued, plane-specific, revocable tokens (mechanism per A17-TOK-2) (A00 API-2). Diamy Mail MUST NOT mint identity or session tokens.
- **A17-P-2**: Diamy Mail MUST NOT maintain a user registry. The user set is exactly the set of IAM principals with a mail-enabled entitlement (§3).
- **A17-P-3**: A Diamy Mail tenant IS a Diamy IAM tenant (A00 §2). Tenant creation, suspension, and deletion are IAM lifecycle events that Diamy Mail consumes; it MUST NOT define a parallel tenant lifecycle.
- **A17-P-4**: Fail-closed boot (A00 SEC-FC-1): every Diamy Mail server component MUST verify at startup that its IAM binding (endpoint, signing-secret references, service credentials) is present and non-default, and MUST refuse to start otherwise.

------

# 3. Principal Resolution and Mail Entitlement

## 3.1 Resolution path

Per *Auth and Session Model §3.4*, IAM resolves users by `primary_email_hash` — a BLAKE2b hash of the primary email with **global uniqueness** (not filtered by partner).

- **A17-RES-1**: `resolve_principal(canonical_address)` (A24-IAM-1) MUST be implemented as: canonicalize via `diamy_addr_canon()` (A24 §3) → compute the IAM-side lookup per the IAM hashing contract → query the IAM directory. The BLAKE2b hashing parameters (key, output length, encoding) are owned by the IAM corpus; Diamy Mail MUST call the IAM-provided lookup API or shared library — it MUST NOT re-derive the hash with locally assumed parameters.
- **A17-RES-2**: The **input** to the IAM lookup is the A24 canonical form. If the IAM directory was populated with addresses normalized differently, resolution breaks silently. Therefore, at tenant onboarding (A11), mailbox provisioning MUST write addresses through the same `diamy_addr_canon()` function before IAM registration. This is a corpus-level invariant: A24 → A17 → A11 share one normalization.
- **A17-RES-3**: Resolution results MAY be cached for at most 60 s (A24-IAM-1) and the cache MUST be keyed on a value that guarantees prompt invalidation on a directory change (`(canonical_address, iam_epoch_watermark)` if IAM does expose an epoch-style watermark — to be confirmed alongside A17-TOK-2; the invariant is "invalidates promptly on change", not the specific watermark mechanism).

## 3.2 Mail entitlement

- **A17-ENT-1**: A principal is mail-enabled if and only if IAM carries a `diamy_mail` entitlement for that principal in the active tenant context (entitlement representation per *Role and Authorization Model*). The inbound gateway MUST verify the recipient's entitlement before accepting RCPT TO for final delivery; a non-entitled but syntactically valid tenant address yields SMTP 550 (mailbox unavailable), never a silent drop.
- **A17-ENT-2**: Entitlement removal MUST stop new mail delivery within 60 s (cache bound of A17-RES-3), MUST NOT delete stored mail (retention is a tenant-policy matter, out of scope here), and MUST immediately revoke mail-plane tokens via the confirmed revocation mechanism (A17-TOK-2).

------

# 3bis. Resource Principals & Distribution Groups (implements A27)

A27 (Shared Resources) introduces two directory concepts beyond the personal principal this annex otherwise assumes. Both are IAM directory entries, resolved by the same `resolve_principal()` path (A17-RES-1) but typed differently.

## 3bis.1 Resource principals (shared mailboxes)

- **A17-RESRC-1**: A **resource principal** (A27-RES-1) is an IAM principal, canonically addressed (A24) exactly like a personal principal, but with no bound human authenticator of its own. It carries the `diamy_mail` entitlement like any mailbox, and it MUST have its own mail device-key directory entries (§5.2) — except the devices enrolled against it belong to its **members**, not to a single authenticating human. This reuses the identical directory infrastructure (§5.2) keyed under the resource principal's own principal ID; it is not a separate directory implementation.
- **A17-RESRC-2** (membership is an entitlement extension): A resource principal's **membership** — the set of (member principal, role) pairs (A27-ROLE-1: viewer/contributor/admin) — is stored as an IAM entitlement record scoped to that resource principal, distinct from the `diamy_mail` entitlement itself. Resolving whether a given human principal may enroll a device against a resource principal, and at which role, is a membership-entitlement lookup, cached and invalidated on the same confirmed-mechanism basis as A17-RES-3/A17-ENT-2 (A17-TOK-2).
- **A17-RESRC-3** (device enrollment follows the member, not the resource): When a human member enrolls a device against a shared mailbox, the enrollment sequence is identical to A17-DIR-3 (IAM identity → ML-KEM-768 keypair → signed bundle → directory verification), except the bundle is published **against the resource principal's mail device-key directory**, signed by the **member's own** Dilithium identity key. The directory verifies the signature against the enrolling member's IAM identity, then checks the membership entitlement (A17-RESRC-2) before accepting the bundle — a device MUST NOT be enrolled against a resource principal without a valid membership record, at any role (viewer is sufficient for enrollment; role only gates what the resulting session may subsequently do, per A27-SEC-2).
- **A17-RESRC-4** (role is carried on the token, not the key): The mail-plane token (§4) minted for a member's session against a resource principal MUST embed that member's **role** for that resource. `diamy-maild`/`diamy-submitd` read this role to authorize write/send/admin operations (A27-SEND-2, A27-ROLE-1) — this is the token-level mechanism implementing the policy-enforcement side of A27-SEC-2/3 (role is not, and cannot be, encoded in the key material itself, since decrypt capability is uniform across roles, A27-ROLE-2).
- **A17-RESRC-5** (admin operations, SED-gated): Creating a resource principal, and adding/removing/re-roling its members, are control-plane operations and MUST go through the SED-protected admin path (§6), mirroring A23's allocation-API pattern. The last-admin-cannot-be-removed rule (A27-ROLE-4) MUST be enforced at this API, server-side — not merely as a client-side UI guard.

## 3bis.2 Distribution groups

- **A17-GRP-1**: A **distribution group** (A27-GRP-1) is an IAM directory entry with a canonical address (A24) that resolves to a **member address list** plus one or more **group admins** — it has no mailbox entitlement, no mail device-key directory, and no mail-plane token of its own, because it is never itself a delivery endpoint (A27-GRP-1). `resolve_principal()` on a group address MUST return a distinguishable "group" result (member list), not a mailbox resolution, so callers (A01's gateway expansion, A27-GRP-2's client-side expansion) can tell the two apart deterministically (mirrors A01-GRP-1's determinism note).
- **A17-GRP-2** (membership lookup for client-side expansion): A Diamy sender's client, composing to a group address, MUST resolve current membership via an IAM directory lookup (the same mechanism the gateway uses per A01-GRP-1) before encrypting — membership MAY be cached briefly (RECOMMENDED ≤ 60 s, mirroring A17-RES-3) so a just-added/removed member is reflected promptly without a directory round-trip on every keystroke.
- **A17-GRP-3** (admin operations, SED-gated): Creating a group and managing its membership/admins are control-plane operations through the SED-protected admin path (§6). The last-admin-cannot-be-removed rule (A27-GRP-4) is enforced server-side at this API.

------

# 4. Token Model — the Mail Plane

Following the plane-token pattern of the messaging corpus (edge token 15 min, SFU token 4 h; *Diamy E2EE Security Overview*), Diamy Mail introduces one new plane:

| Credential | Grants access to | Signing secret | Lifetime | Revocation |
| ---------- | ---------------- | -------------- | -------- | ---------- |
| **Mail-plane token** | `diamy-maild` sync API (WSS/HTTPS), `diamy-submitd` submission | `MAIL_JWT_TOKEN` (HS256, distinct per-plane secret) | 15 min | see A17-TOK-2 (mechanism under verification, §4.2) |
| Webmail token | Webmail session (browser) | `MAIL_WEB_JWT_TOKEN` | 1 h | see A17-TOK-2; re-verified server-side at least every 5 min of activity |
| Admin/control token | A23 allocation API, tenant mail policy | IAM Admin/Super Admin planes (existing) | per IAM spec | per IAM spec |
| **Diamy Mail AppKey (Tier 2)** | authenticates the *client application* (native app, webmail, Bridge) on every request — companion to, not a substitute for, the tokens above | Diamy Mail's own `app_keys` store (§4.2bis) | per-key, admin-set (rotatable, no forced expiry by default) | immediate on `status='revoked'` (local lookup, no IAM round-trip) |

- **A17-TOK-1**: Mail-plane tokens are minted by the IAM backend upon presentation of a valid IAM session, exactly like edge/SFU tokens. `diamy-maild` and `diamy-submitd` verify signature + expiry + revocation state (§4.2) on register and on every reconnection.
- **A17-TOK-2** (revocation mechanism — verify against *Auth and Session Model* before implementation): Every user token MUST be invalidated promptly on logout or admin revocation. The messaging-corpus plane-token pattern this annex was modeled on uses a revocation-epoch counter (instant invalidation on bump). However, the Diamy IAM Integration Specification v1.6 (§7.4, reviewed July 2026) describes generic resource-server session revocation via a **JTI revocation cache** populated on explicit revocation events, with webhook push notification marked **optional ("if implemented")** and a documented degraded fallback of ≤300 s token TTL when no cache/webhook exists — not an epoch-counter push mechanism. **This is a flagged discrepancy, not yet resolved**: it is possible mail-plane tokens use a specialized epoch-based plane (as edge/SFU tokens reportedly do) distinct from the generic resource-server model that v1.6 documents, but this has not been confirmed against *Auth and Session Model* or *Security Hardening & Runtime Model*, neither of which has been reviewed at authoring time. Per A25 Constitution rule 2 (never implement an unspecified/unverified case by invention), the implementer MUST confirm the actual mechanism against those documents before building revocation, and MUST NOT assume the 10 s bound of A17-TOK-5 is achievable until confirmed — if the real mechanism is JTI-cache-with-optional-webhook, A17-TOK-5's requirement needs revision to match (§4.3, deferred pending that verification). **Scope note**: every other reference to "epoch"/"epoch watermark" elsewhere in this document (A17-P-1, A17-ENT-2, A17-RESRC-2, A17-DIR-2, A17-DIR-4, §9 audit events) describes the same assumed fast-invalidation signal and inherits this identical caveat — they are not independently more or less certain than this paragraph, and MUST be revisited together once the mechanism is confirmed.
- **A17-TOK-3**: Clients keep plane tokens in memory only and re-mint from the IAM session (cookie/refresh), per the *Client Execution and SDK Contract* storage rules. Tokens MUST NOT appear in URLs, logs, or persistent storage.
- **A17-TOK-4** (corrected — two independent AppKey tiers, not one): Per the Diamy IAM Integration Specification v1.6 §2.4, the Diamy ecosystem has **two distinct, independent AppKey tiers** that MUST NOT be confused:
  - **Tier 1 (IAM AppKey)**: a server-side secret Diamy Mail's own backend components use when *they* call *into* IAM (minting mail-plane tokens, SED session init, entitlement queries). Never exposed to end-user clients. Governed entirely by the IAM Integration Specification; Diamy Mail does not define its own Tier 1 behavior.
  - **Tier 2 (Diamy Mail's own Applicative AppKey)**: a **separate, Diamy-Mail-owned** AppKey that Diamy Mail's own clients (native app, webmail, Bridge) present on every request to Diamy Mail's own APIs (`diamy-maild` sync, `diamy-submitd` submission) — validated **locally by Diamy Mail**, never by calling IAM. This is new: prior versions of this annex described a single undifferentiated "X-App-*" header set and did not specify Tier 2. §4.2bis is now the normative specification for it, since the IAM Integration Specification v1.6 §11.6 states this pattern is mandatory for "every Diamy ecosystem application... that exposes its own REST API to client applications" — Diamy Mail is such an application.
- **A17-TOK-5**: `diamy-maild` MUST subscribe to IAM epoch-bump signals (or the confirmed equivalent, per A17-TOK-2) and MUST terminate live WSS connections belonging to a principal or device whose session was invalidated, within 10 s of the signal, **once the actual revocation-propagation mechanism is confirmed** (A17-TOK-2). Token expiry alone is not sufficient for stolen-device response; revocation must sever active sessions.

## 4.2bis Diamy Mail Applicative AppKey (Tier 2 — Normative)

This section implements the Tier 2 model mandated by the IAM Integration Specification v1.6 §11.6 for Diamy Mail specifically. It is independent of IAM's own availability (§4.2bis.4) and of the mail-plane token (§4).

### 4.2bis.1 Scope

- **A17-APPKEY-1**: Every client application that calls a Diamy Mail API — the native vault client (A03/A19), the webmail client (A05), and the Bridge (A20, itself an enrolled client per A20-CRED-4b) — MUST be issued its own Diamy-Mail-specific AppKey, distinct per application/platform (e.g. `diamy-mail-desktop`, `diamy-mail-ios`, `diamy-mail-webmail`, `diamy-mail-bridge`). Two different platforms of the same logical client (desktop vs mobile) MUST NOT share an AppKey (mirrors the IAM spec's own R3-equivalent discipline).
- **A17-APPKEY-2**: The AppKey authenticates the **client application**, not the user — it is unrelated to, and does not substitute for, the mail-plane token (§4) which authenticates the user's session. Both MUST be present and independently valid on every request (mirrors the IAM spec's R5).

### 4.2bis.2 Local store and request headers

- **A17-APPKEY-3**: Diamy Mail (`diamy-maild`/`diamy-submitd`) MUST maintain its own `app_keys` store (A21 §7ter), structurally mirroring the IAM Integration Specification v1.6 §11.6.1 schema: a SHA-256 hash of the raw key (never the raw value) keyed to an app name, platform, optional version range, and `active`/`revoked` status.
- **A17-APPKEY-4**: Every client request to `diamy-maild`/`diamy-submitd` MUST include `X-App-Key` (raw Tier 2 AppKey value), `X-App-Name`, `X-App-Platform`, `X-App-Version`, in addition to `Authorization: Bearer <mail-plane token>`. This is the Diamy-Mail-owned header set — it MUST NOT be confused with, or reuse the same values as, the Tier 1 IAM AppKey headers Diamy Mail's backend sends when calling IAM (A17-TOK-4).

### 4.2bis.3 Validation order (Normative)

- **A17-APPKEY-5**: `diamy-maild`/`diamy-submitd` MUST validate every incoming request in this order, mirroring the IAM Integration Specification v1.6 §11.6.3 exactly:
  1. **AppKey validation (local, no IAM call)**: hash the presented `X-App-Key`, look up `app_keys` by hash, verify `status = 'active'`, verify `X-App-Name`/`X-App-Platform` match the record, verify `X-App-Version` within any configured range. Any failure → reject `401` with a generic error that does not reveal which check failed (enumeration resistance, mirrors A17-DIR's signature-failure discipline).
  2. **Mail-plane token validation (§4)**: signature, expiry, revocation state.
  3. **Authorization**: entitlement/role checks (A17-ENT, A27-ROLE where applicable).
  - Step 1 MUST run before step 2 — an invalid AppKey is rejected before any token processing, exactly as the IAM spec requires for its own Tier 2 model.
- **A17-APPKEY-5b** (record-match enforcement): Within step 1, `X-App-Name` and `X-App-Platform` MUST match the `app_keys` record the hash resolved to — a key issued for one platform (e.g. iOS) MUST NOT authenticate a request declaring a different platform (e.g. web). This is a record-integrity check, not merely a hash lookup: a stolen key's raw value alone is insufficient if the platform/name declared doesn't match what it was issued for.

### 4.2bis.4 Availability guarantee

- **A17-APPKEY-6**: Because AppKey validation is fully local, Diamy Mail's backend MUST be able to reject or accept the AppKey check independent of IAM's availability. This does NOT mean mail operations continue during an IAM outage (mail-plane token validation still depends on IAM-issued material, §4) — it means the AppKey layer specifically must never be the thing that fails due to an IAM outage, since local validation has no IAM dependency in its own right (mirrors the IAM spec's R4-equivalent for its own Tier 1).

### 4.2bis.5 Lifecycle

- **A17-APPKEY-7**: AppKey creation, rotation (dual-slot, non-overlapping version ranges — mirrors the IAM spec's §3.5/§11.6.4 pattern), and revocation are Diamy Mail admin operations, SED-gated (A17-SED-1), audited (INV-20). Revocation takes effect on the next request (no propagation delay, since validation is a local lookup).

## 4.1 Service-to-service authentication

- **A17-S2S-1**: Server components (`diamy-mxd` → `diamy-maild` key-directory reads, `diamy-maild`/`diamy-submitd` → IAM internal API) MUST authenticate using the IAM internal service-authentication mechanism (*Diamy IAM – Internal API Specification*), over authenticated channels per A00 OPS-IPC-1. User-plane tokens MUST NOT be used for service-to-service calls, and service credentials MUST NOT grant user-data decryption capabilities (they authenticate the component, nothing more).

------

# 5. Device Identity vs Mail Encryption Keys

This is the most security-sensitive part of the contract.

## 5.1 The §13bis boundary

*Key Management Specification v1.2 §13bis* states that device **Dilithium keypairs are identity keys only** and do not constitute an access mechanism for application data layers. Additionally, Dilithium (ML-DSA) is a signature scheme and cannot encrypt.

Consequently:

- **A17-KEY-1**: Diamy Mail MUST NOT use the IAM Dilithium identity key as (or to derive) a message-decryption capability. Frontier envelopes (A00 STO-1) are wrapped for a **separate per-device mail encryption keypair**.
- **A17-KEY-2**: The mail encryption keypair MUST be **ML-KEM-768** (FIPS 203), aligned with the messaging corpus KEM (A00 SEC-CRYPT-2). It is generated client-side on the device; the private key resides in the OS secure store (A00 STO-5) and never leaves the device.
- **A17-KEY-3**: The mail encryption public key MUST be published to the **mail device-key directory** (§5.2) in a bundle **signed by the device's Dilithium identity key**. The directory MUST verify this signature against the IAM key directory before accepting the bundle. This binds the encryption key to the IAM identity without ever using the identity key for encryption — the same publish-signed-bundles pattern as the messaging prekey directory.

## 5.2 Mail device-key directory

- **A17-DIR-1**: `diamy-maild` hosts the mail device-key directory: for each (principal, device) it stores the current signed ML-KEM-768 public-key bundle, its Dilithium signature, the signing device ID, and a validity state (`active`, `revoked`).
- **A17-DIR-2**: The inbound gateway (`diamy-mxd`) reads this directory at frontier-encryption time to wrap the per-message AES key for every `active` device of every recipient (A00 STO-1/STO-2). Directory reads are the hot path: `diamy-mxd` MAY cache bundles with a TTL ≤ 60 s, keyed on (principal, device, invalidation watermark — mechanism per A17-TOK-2) — same discipline as A17-RES-3.
- **A17-DIR-3**: Device enrollment order is: (1) device enrolls in IAM (Dilithium identity, per IAM Key Management), (2) device generates ML-KEM-768 mail keypair locally, (3) device publishes signed bundle to the mail directory, (4) directory verifies the Dilithium signature via IAM, (5) envelopes start being produced for this device. A device that completed (1) but not (3–5) is mail-invisible: no envelopes are produced for it, and it cannot decrypt mail. The client MUST surface this state ("mail setup incomplete on this device") rather than failing silently.
- **A17-DIR-4**: Device revocation (IAM-side event) MUST propagate to the mail directory within the confirmed invalidation bound (A17-TOK-2): envelope production for the revoked device stops (A00 STO-4), its bundle transitions to `revoked`, and the directory change is audit-logged. Historical envelopes already produced are not retroactively erasable; forward secrecy for future messages is the guarantee, consistent with the messaging model. Key rotation for remaining devices MAY be offered (STO-4).
- **A17-DIR-5** (zero-active-device recipient): A principal MAY be entitled and resolvable yet have **no active device bundle** (mailbox provisioned, user never enrolled a device — a certainty during onboarding, not an edge case). The frontier cannot produce any envelope for such a recipient. `diamy-mxd` MUST NOT bounce (5xx) and MUST NOT tempfail-until-upstream-expiry (typical upstream retry windows are ~5 days; onboarding can exceed that). Required behavior: the gateway accepts the message, completes all frontier security checks, encrypts the payload under a **gateway hold-queue key** (server-side, `diamy-secretd`-derived, Level A pattern), and parks it in a bounded hold queue. Upon publication of the recipient's first device bundle, held messages are decrypted in the frontier zone, envelope-wrapped normally, and destroyed from the hold queue. The hold queue is a **declared, bounded exception** to zero-access (same transparency duty as the frontier zone, A00 §3.2): it MUST be documented to tenants, capped in duration (tenant-configurable, RECOMMENDED default 30 days, then sender receives a DSN), capped in size, and audit-logged. The exact queue mechanics belong to A01; the resolution of whether a stricter alternative (e.g. A11 sequencing that mandates first-device enrollment before MX cutover for the user) can replace the hold queue is OPEN — see §12.
- **A17-DIR-6** (calendar-delegate device is scope-restricted, not a resource principal — implements A27-DEL-3): A calendar delegation grant (A27-DEL-1) enrolls the delegate's device **only** into the grantor's calendar key-wrapping set (A12's `cal.event_envelopes`, distinct table from `mail.envelopes`, A21) — it MUST NOT be published to the grantor's **mail** device-key directory (§5.2) at all. This differs structurally from resource-principal membership (§3bis.1): a resource principal is its own IAM principal with its own directory; calendar delegation grants a second principal scoped access into an *existing personal principal's* calendar directory only, leaving that principal's mail directory untouched. The directory MUST enforce this at the API level — a calendar-delegation enrollment call has no code path capable of writing a `mail.envelopes`-scoped bundle, making A27-SEC-1's crypto-scope guarantee an enforced directory-API property, not merely a documented convention.

## 5.3 Historical access on device addition

- **A17-KEY-4**: Granting a new device access to historical mail uses **device-delegated re-wrap** (A00 STO-3): an existing active device, online and user-approved, unwraps per-message AES keys locally and re-wraps them for the new device's ML-KEM-768 public key, uploading only re-wrapped envelopes. The server never sees message keys in clear. Batch/background execution and progress semantics are defined in A02; this annex fixes only the trust rule: the server MUST NOT be able to perform the re-wrap itself.

------

# 6. SED Scope Decision (Normative)

The IAM SED chain (*Client Execution and SDK Contract*) enforces one-request-in-flight with a single-use rotating token. This serialization is correct for identity/administrative operations but is architecturally incompatible with high-volume mail synchronization (parallel blob fetches, streaming sync).

- **A17-SED-1**: SED protection is REQUIRED for: all IAM-plane calls made by Diamy Mail clients (enrollment, key-directory publication, entitlement queries) and all mail **control-plane administrative APIs** (A23 allocation, tenant mail policy, webmail enablement, resource-principal/group creation and membership management, A17-RESRC-5/A17-GRP-3).
- **A17-SED-2**: The mail **data plane** (sync, blob fetch, submission via `diamy-maild`/`diamy-submitd`) is NOT SED-chained. It is protected by: mail-plane tokens (§4), TLS 1.3, per-message content encryption (the payload is ciphertext end-to-end by construction), and the request-signing rules of the mail sync API (A04). Rationale: SED's serialization guarantee protects secrets in transit and replay windows on low-volume sensitive calls; mail payloads are already ciphertext, and the threat SED addresses is covered by the envelope model itself.
- **A17-SED-3**: Webmail enablement (the opt-in that activates Blind Index sync, A00 SRCH-2) is a security-posture change and MUST go through a SED-protected call with audit logging (A00 OBS-3).

------

# 7. Level A / Level B Applicability to Mail

Per *Payload Encryption Model v1.1.2*:

- **A17-ENC-1 (Level A)**: Server-side mail **metadata** fields classified `PLAINTEXT_METADATA` in A00 CDM-ENC-1 that are nonetheless sensitive (e.g. folder names if server-visible, delivery source IPs, webmail Blind Index key references) MUST follow the Level A field-encryption-at-rest pattern (AES-256-GCM via `diamy-secretd`-derived DEKs, searchable fields via the IAM polymorphic-hash pattern). Message bodies are NOT Level A material — they are `CIPHERTEXT` under the envelope model, a stronger guarantee that does not depend on `diamy-secretd`.
- **A17-ENC-2 (Level B)**: Mail administrative API responses carrying sensitive fields SHOULD apply Level B response encryption per the IAM model, reusing the exact derivations (`sel_client`, `response_dek`, AAD `response:<request_id>:<field_name>`). Level B is NOT applied to the mail data plane: payloads there are already end-to-end ciphertext, and Level B's honest-but-curious boundary (server can reconstruct the key) would add cost without adding a guarantee.
- **A17-ENC-3**: The AAD immutability rule (*Payload Encryption Model §2.3*) applies to any mail table adopting Level A: the AAD primary key MUST be immutable.

------

# 8. Failure Model

| Failure | Required behavior |
| ------- | ----------------- |
| IAM unreachable at boot | Fail-closed: component refuses to start (A17-P-4) |
| IAM unreachable at runtime — inbound mail | `diamy-mxd` MUST tempfail (SMTP 4xx) RCPT TO it cannot resolve/entitle; it MUST NOT accept-and-queue for unknown principals (backscatter risk) and MUST NOT fail-open deliver |
| IAM unreachable at runtime — client sync | Existing valid mail-plane tokens keep working until expiry (≤ 15 min); token refresh fails → client enters offline mode (A00 OPS-OFF-1) with clear status |
| Key-directory bundle signature invalid | Bundle rejected, event audit-logged, enrolling device notified; NEVER accept an unverified bundle |
| Epoch bump mid-session | Next register/reconnect/refresh fails token verification → client re-authenticates through IAM; in-flight already-authenticated sync operations MAY complete |
| Entitlement revoked while messages queued for delivery | Messages already accepted for the principal are delivered; new RCPT TO rejected per A17-ENT-1 |
| Recipient entitled but zero active device bundles | Gateway hold-queue per A17-DIR-5 — never bounce, never plain tempfail-to-expiry, never store plaintext |

------

# 9. Observability Contract

Per A00 §11:

- counters: `iam_principal_resolutions_total{result}`, `iam_token_verifications_total{plane,result}`, `mail_keydir_bundle_publications_total{result}`, `mail_keydir_signature_failures_total`, `entitlement_denials_total`
- latency: `iam_resolution_duration`, `keydir_read_duration` (hot path, target p99 < 5 ms with cache)
- audit events (append-only, A00 OBS-3): webmail enablement/disablement (A17-SED-3), device bundle publication and revocation (A17-DIR-4), entitlement changes, mass invalidations (mechanism per A17-TOK-2)

------

# 10. Test Scenarios (Normative)

1. **Resolution round-trip**: provision mailbox via A11 → send inbound message → RCPT TO resolves to the same principal UUID that IAM returns for the canonical address. Any mismatch is release-blocking (A17-RES-2).
2. **Revocation propagation**: revoke a principal's session via the confirmed mechanism (A17-TOK-2 — epoch bump, JTI-cache entry, or webhook, whichever is verified against *Auth and Session Model*) → mail-plane token refused at next reconnection ≤ 15 min; cached resolutions invalidated ≤ 60 s. This test's pass criteria depend on the mechanism confirmation in A17-TOK-2 and MUST be updated once that verification is done.
3. **Device lifecycle**: enroll device (IAM) without publishing mail bundle → verify zero envelopes produced and client surfaces "setup incomplete"; publish bundle → envelopes start; revoke device → envelope production stops, other devices unaffected (STO-4).
4. **Signature enforcement**: attempt bundle publication with a signature from a different device's Dilithium key → rejected + audited.
5. **IAM outage — inbound**: stop IAM → inbound RCPT TO receives 4xx tempfail (not 5xx, not accept); restore IAM → queued upstream retries deliver.
6. **SED scope**: verify webmail enablement fails without a valid SED chain, and that data-plane sync succeeds with only a mail-plane token.
7. **Resource-principal membership**: create a shared mailbox, add a viewer and a contributor → both enroll devices against the shared mailbox's directory, signed by their OWN Dilithium identities; the viewer's token carries role=viewer, the contributor's role=contributor (A17-RESRC-3/4).
8. **Orphaned-admin rejection**: attempt to remove the last admin of a shared mailbox or group → API rejects server-side, independent of any client UI guard (A17-RESRC-5, A17-GRP-3).
9. **Calendar-delegation scope enforcement**: grant Bob calendar delegation on Alice's calendar → Bob's device appears in Alice's `cal.event_envelopes` wrapping set; assert Bob's device has NO entry whatsoever in Alice's mail device-key directory, and that the enrollment API has no code path to create one (A17-DIR-6).
10. **Group resolution determinism**: resolve a group address and a mailbox address through the same `resolve_principal()` call path → each returns its correct, distinguishable type (group member-list vs mailbox principal), never ambiguous (A17-GRP-1).
11. **AppKey validated before token**: send a request with a valid mail-plane token but an invalid/revoked AppKey → rejected `401` at step 1, mail-plane token never even parsed (A17-APPKEY-5).
12. **AppKey-token independence**: send a request with a valid AppKey but an expired mail-plane token → rejected at step 2 for the token reason, not conflated with an AppKey failure; and the reverse (valid token, invalid AppKey) is rejected at step 1 (A17-APPKEY-2/5).
13. **Cross-platform AppKey isolation**: a valid `diamy-mail-ios` AppKey MUST NOT authenticate a request declaring `X-App-Platform: web` — mismatch rejected (A17-APPKEY-5b, mirrors the record match check).
14. **Bridge has its own AppKey**: the Bridge (A20) authenticates with its own `diamy-mail-bridge` AppKey, distinct from the native app's — revoking the Bridge's AppKey does not affect the native app's requests (A17-APPKEY-1, consistent with A20-CRED-4b's independent-device principle).
15. **Tier confusion rejected**: a request presenting the Tier 1 IAM AppKey value in the `X-App-Key` header to `diamy-maild` MUST be rejected — Tier 1 and Tier 2 keys are validated against different stores and MUST NOT be interchangeable (A17-TOK-4, A17-APPKEY-4).

------

# 11. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Using the Dilithium identity key to wrap or derive message keys (violates §13bis and the signature/KEM distinction). Mail encryption keys are separate ML-KEM-768 keypairs.
2. ❌ Re-deriving `primary_email_hash` locally with guessed BLAKE2b parameters instead of calling the IAM lookup contract (A17-RES-1).
3. ❌ Feeding a non-canonical address into IAM resolution — the A24 function is mandatory upstream of every lookup (A17-RES-2).
4. ❌ Minting mail-plane tokens inside `diamy-maild` instead of consuming IAM-minted tokens (A17-P-1).
5. ❌ Caching principal or key-directory entries without confirmed-mechanism-keyed invalidation (epoch watermark, JTI cache entry, or whatever A17-TOK-2 confirms), so revocation does not propagate (A17-RES-3, A17-DIR-2).
6. ❌ Applying the SED chain to the high-volume sync path (serializes sync, destroys performance) or, inversely, exposing webmail enablement without SED (A17-SED-1/2/3).
7. ❌ Accepting a device key bundle whose Dilithium signature was not verified against the IAM key directory (A17-DIR-1/3).
8. ❌ Fail-open delivery when IAM is unreachable (accepting mail for unresolvable recipients) — the required behavior is SMTP tempfail (§8).
9. ❌ Implementing a server-side re-wrap of historical envelopes "for convenience" — the server must be structurally unable to do this (A17-KEY-4).
10. ❌ Applying Level B to end-to-end-encrypted data-plane payloads (adds cost, no guarantee) instead of restricting it to administrative responses (A17-ENC-2).
11. ❌ Bouncing or silently expiring mail for a provisioned recipient with no enrolled device, or "solving" it by storing plaintext in the hold queue (A17-DIR-5 — the hold queue is encrypted under a server-side key, a declared bounded exception, never plaintext).
12. ❌ Encoding a shared-mailbox member's role inside the key material itself instead of on the mail-plane token — role is a policy fact, not a crypto fact, and conflating them contradicts A27-SEC-1/2 (A17-RESRC-4).
13. ❌ Publishing a calendar delegate's device bundle to the grantor's mail device-key directory "since it's easier to reuse the enrollment flow" — the whole safety property of delegation depends on this never happening (A17-DIR-6).
14. ❌ Allowing a resource-principal or group admin-removal API call to succeed when it would leave zero admins (A17-RESRC-5, A17-GRP-3) — must fail closed server-side.
15. ❌ Treating a distribution group's `resolve_principal()` result as if it were a mailbox (e.g. attempting to mint a mail-plane token for it) — groups have no token, no directory, no entitlement of their own (A17-GRP-1).
16. ❌ Conflating Tier 1 (IAM AppKey) and Tier 2 (Diamy Mail's own AppKey) — using the same value, the same store, or the same validation path for both (A17-TOK-4). They authenticate different things (Diamy Mail's backend calling IAM, vs. a Diamy Mail client calling Diamy Mail) and MUST be architecturally independent.
17. ❌ Validating the mail-plane token before the AppKey, or treating a valid AppKey as implying a valid token (or vice versa) — the two checks are independent and ordered (AppKey first) per A17-APPKEY-5.
18. ❌ Calling out to IAM to validate the Tier 2 AppKey — Tier 2 validation MUST be a local lookup only; an IAM round-trip for it defeats the IAM-outage-independence guarantee it exists to provide (A17-APPKEY-6).
19. ❌ Sharing one AppKey across platforms or across the native app and the Bridge — each client/platform combination MUST have its own, independently revocable key (A17-APPKEY-1).
20. ❌ Asserting the 10 s epoch-revocation bound (A17-TOK-5) as implemented fact without having confirmed the actual mechanism against *Auth and Session Model* — this annex flags it as unverified (A17-TOK-2); building against an unconfirmed assumption is exactly the invented-behavior error Constitution rule 2 warns against.

------

# 12. Deferred Items

- **[CLOSED by A11 §11 — was HIGH]** Zero-active-device recipient: resolved as — the gateway hold queue (A17-DIR-5 / A01-HOLD) remains the mandatory baseline; per-user first-device enrollment sequencing (A11-SEQ) is an onboarding optimization for interactive paths that narrows the hold queue's routine use but does not replace it (bulk migration and MX-cutover-before-login still require the hold queue). Both mechanisms coexist.
- **[CLOSED by A27/A17 §3bis — was "Shared-mailbox and delegation entitlements"]** Resolved by A27 (Shared Resources) and this annex's §3bis: resource-principal membership entitlements (A17-RESRC-1..5) and calendar-delegation grants (A17-DIR-6) are now fully specified.
- **[NEW — HIGH, open]** **Revocation mechanism confirmation**: A17-TOK-2 flags that this annex's "epoch bump" language, inherited by analogy from the messaging corpus, has not been confirmed against the actual IAM revocation mechanism. The Diamy IAM Integration Specification v1.6 (reviewed July 2026) describes a JTI-revocation-cache model for generic resource servers, with webhook push explicitly optional and a ≤300 s degraded-mode fallback — materially looser than the 10 s bound A17-TOK-5 currently requires. Before implementing revocation, the implementer MUST obtain and review *Diamy IAM – Auth & Session Model v1.2* and *Security Hardening & Runtime Model v1.5* to confirm whether mail-plane tokens use a specialized epoch-based plane (as edge/SFU tokens reportedly do) or the generic JTI-cache model — and MUST revise A17-TOK-2/TOK-5 and the affected test scenario (§10 #2) to match whichever is confirmed. This is release-blocking for any claim of sub-15-second revocation.
- Exact wire contract of the IAM lookup API for `primary_email_hash` (owned by the IAM corpus; referenced here once published as an IAM extension) — also not covered by the Integration Specification v1.6 reviewed here, which governs generic resource-server session validation, not directory-style address-to-principal resolution; still to be confirmed against *Auth and Session Model*.
- Cross-tenant mail routing optimizations (Diamy↔Diamy same-platform delivery path, A00 §3.4) — token/trust model for platform-internal delivery to be defined with A01.

------

*End of document.*
