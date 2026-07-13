# Diamy Mail — Master Architecture Specification

**Document title:** Diamy Mail — Master Architecture Specification
**Version:** 1.14
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 5th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL

------

## Version history

| Version | Date         | Author           | Changelog                                                                 |
| ------- | ------------ | ---------------- | ------------------------------------------------------------------------- |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial master architecture: scope, component map, canonical data-model rules, API design rules, security model, cross-cutting normative rules, document corpus plan, AI implementation guidance |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Added User/identity definition (IAM email as principal identifier) + email normalization rules (§2, §5.5); added outbound resource allocation model binding tenants to sending servers (§10.6, new rules OPS-SEND-*); clarified frontier vs trust-engine responsibility boundary (§4.2); added annex A23 (Outbound Resource Allocation) and A24 (Identity & Address Normalization) to corpus plan (§12); added two AI error entries (§13.1) |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Added internationalization rules (§5.6, CDM-I18N-*): mandatory UTF-8 body support with robust charset recovery; EAI/SMTPUTF8 posture = accept-on-receive / no-generate-on-send for V1; NFC normalization at composition (emoji-capable editor); CDM-ADDR-3 confirmed Unicode-ready from day one; added AI error entry #16 (§13.1) |
| 1.3     | Jul 4th 2026 | Cédric BORNECQUE | Coherence pass after annexes A01–A11, A16, A17, A23, A24 shipped: updated §14 Open Decisions to mark #2 (closed by A05), #3 (closed by A03), #4 (closed by A03), and #6 (closed by A16) as CLOSED with their resolutions; #1 (Bridge/A20) and #5 (external-invitee calendar/A12–A14) remain genuinely open. No normative change to §1–§13; this aligns the master doc's decision log with the shipped annexes. |
| 1.4     | Jul 4th 2026 | Cédric BORNECQUE | Coherence pass after the calendar block (A12–A14): §14 Open Decision #5 (external non-Diamy invitee zero-access) CLOSED by A14 §6 — external invitees receive plaintext iMIP (disclosed, bounded relaxation), Diamy↔Diamy stays E2E-encrypted, at-rest stays zero-access. Only #1 (Bridge/A20) now remains open. No normative change to §1–§13. |
| 1.14    | Jul 5th 2026 | Cédric BORNECQUE | Corpus extension: registered two new annexes in the corpus plan — **A28 (Presence & Calendar-Driven Status v1.0)**, bringing the presence capability previously deferred in A15 §11 into scope (Teams-style states, calendar-driven automatic transitions computed strictly on-device, consented default-deny exposure mirroring A15), and **A29 (Trust UX, Protective Actions & Sandbox Workspace v1.0)**, the client-side behavioral contract for trust (contextual-warning discipline, action×band matrix with high-band save block, sandbox-as-message-state workspace). Companion coherence bumps in the same batch: A09 v1.2, A12 v1.3, A15 v1.2, A16 v1.2 (stale sibling references updated; A15 deferred-presence line now points to A28; A16 notes the A29-SBX-4 sandbox-routing consumer; A12-PART-2 cross-references A28-CAL-2). |
| 1.13    | Jul 4th 2026 | Cédric BORNECQUE | Absolute final sweep: a full-corpus grep after v1.12 still found unqualified "epoch" mentions in six places across five annexes plus this master document itself (A20 AI-error #11, A22 AI-error #2, A24-IAM-1 + one AI error, A26-ISO-5, A27-ROLE-3, and A00's own architecture-diagram comment, API-2, and corpus-plan table row for A17) — all now fixed to reference A17-TOK-2. Re-ran the full-corpus grep a second time after this pass: zero unqualified assertions of the revocation mechanism remain anywhere in the 28-document corpus. This kind of pervasive, easy-to-miss terminology is exactly why the sweep needed two passes — a single edit to the canonical A17-TOK-2 location does not automatically catch every echo of it elsewhere. |
| 1.12    | Jul 4th 2026 | Cédric BORNECQUE | Final sweep of the "epoch bump" correction: A17 v1.5 and A22 v1.6 fixed six and three remaining unqualified mentions respectively (A17-P-1, A17-RES-3, A17-ENT-2, A17-RESRC-2, A17-DIR-2, A17-DIR-4, one audit line; A22-KEY-1, A22-ALERT-2, one AI error) that earlier passes had missed because they were in documents already-edited for other reasons in this same session. A consolidating scope note was added to A17-TOK-2 so all epoch mentions in that document now explicitly point to one canonical, confirmed location rather than each restating or subtly contradicting the flag. Full-corpus grep confirms no remaining unqualified assertion of the revocation mechanism. |
| 1.11    | Jul 4th 2026 | Cédric BORNECQUE | Follow-up sweep: found and fixed two remaining unqualified "epoch bump" assertions missed in the v1.10 pass — A03 v1.2 (A03-SEC-4) and A26 v1.2 (A26-ISO-3 + one test + one AI error). All corpus references to the revocation mechanism are now consistently qualified pending A17-TOK-2's confirmation; verified via full-corpus grep that no unqualified occurrence remains outside the explicitly-flagged discussion in A04/A17/A20/A25/A00 itself. |
| 1.10    | Jul 4th 2026 | Cédric BORNECQUE | Coherence pass following review of the Diamy IAM – Integration Specification v1.6 (external document, uploaded and reviewed): discovered and specified the mandatory **Tier 2 Applicative AppKey model** — every Diamy Mail client (native, webmail, Bridge) MUST present its own Diamy-Mail-issued, locally-validated AppKey on every request, independent of and validated before the mail-plane token, and structurally distinct from the Tier 1 IAM AppKey Diamy Mail's backend uses when calling IAM. Extended across A17 v1.4 (§4.2bis, the primary specification), A04 v1.3 (wire contract — two independent credentials, corrected error codes), A18 v1.2 (server implementation discipline), A19 v1.2 (client SDK storage), A20 v1.3 (Bridge's own AppKey), A21 v1.4 (`keydir.app_keys` DDL, 54 statements validated), and A25 v1.3 (INV-25). Also flagged, rather than silently assumed, a genuine open question: this corpus's "epoch bump" revocation language (A04, A17, A20, A25 INV-11) was inherited by analogy from the messaging corpus and has NOT been confirmed against the actual IAM mechanism — the reviewed Integration Specification describes a JTI-revocation-cache model with optional webhook, materially looser than the corpus's assumed 10s bound. Softened all four affected locations uniformly and logged one consolidated HIGH open item (A25 §6) pending review of *Auth and Session Model* / *Security Hardening & Runtime Model*. No annex now silently asserts an unverified mechanism as fact. |
| 1.9     | Jul 4th 2026 | Cédric BORNECQUE | Coherence pass closing all five A27 (Shared Resources) forward-dependencies: A01 v1.2 (gateway-side distribution-group expansion for external senders), A17 v1.3 (resource-principal type, membership entitlements, calendar-delegation device scoping), A21 v1.3 (`keydir.resource_membership`, `cal.delegation_grants`, `iam.groups`/`iam.group_members` — DDL re-validated, 52 statements, no forward-reference bugs), A22 v1.5 (calendar-delegate-in-mail-directory always-page security indicator), A25 v1.2 (INV-24: scope is crypto-enforced, role is policy-enforced — stated as a named corpus-wide invariant). No annex now carries a pending coherence dependency. |
| 1.8     | Jul 4th 2026 | Cédric BORNECQUE | Registered annex A27 (Shared Resources: Shared Mailboxes, Calendar Delegation & Distribution Groups) in the corpus plan (§12) — role-based shared mailboxes and calendar delegation extending the multi-device envelope model, plus directory-expansion distribution groups. Flags pending coherence extensions to A01 (gateway group expansion), A17 (resource-principal + admin ops), A21 (entitlement/delegation/group DDL), A22 (admin-operation indicators), and A25 (crypto-vs-policy role-enforcement invariant). |
| 1.7     | Jul 4th 2026 | Cédric BORNECQUE | Registered annex A26 (Multi-Account Client) in the corpus plan (§12) — multiple Diamy identities in one native client with strict per-account isolation and a presentation-only unified inbox; Diamy↔Diamy identities only (external accounts out of scope). Additive client-coordination layer over the existing per-principal foundations; no server or crypto change, no new plaintext exception. |
| 1.6     | Jul 4th 2026 | Cédric BORNECQUE | Registered the new root document A25 (Architecture Invariants & Implementation Constitution) in the corpus plan (§12) and added an explicit reading order (A25 first, then A00, then feature annexes, then A18/A19) distinct from the production order. A25 consolidates the corpus-wide invariants and the AI-implementer constitution; no normative change to A00's own rules. |
| 1.5     | Jul 4th 2026 | Cédric BORNECQUE | §14 Open Decision #1 (third-party client support) CLOSED by A20: the Bridge is a committed feature — a loopback-only IMAP/SMTP/CalDAV facade that decrypts locally (bounded plaintext, server zero-access unchanged), enrolls as its own device, and routes sends through A10 controls. Updated the corpus plan (A20 status deferred→shipped) and the component map (Bridge no longer "optional/deferred"). ALL SIX open decisions are now closed; none remain. Added the Bridge non-loopback-refusal security indicator to A22 (v1.3). |

------

# Table of contents

[toc]

------

# 1. Purpose and Scope

## 1.1 Purpose

This document is the **normative umbrella specification** for Diamy Mail. It defines the system boundaries, the component map, the cross-cutting rules that ALL other Diamy Mail documents inherit, and the corpus plan that lists the annex specifications to be produced.

This document plays the same role for Diamy Mail that the *Diamy SIP Network Monitor Architecture* document plays for the SIP Monitor corpus: it is the single source of truth for global rules. Where an annex conflicts with this document on a cross-cutting rule, **this document prevails** unless the annex explicitly declares an override with a version-pinned rationale.

## 1.2 Scope

Diamy Mail is a **secure email client and server platform** composed of:

- an inbound mail gateway (MX) performing **encryption-at-the-frontier**;
- a per-device envelope-encryption storage model (zero-plaintext-at-rest);
- a local-first "vault" client (desktop and mobile) with offline operation;
- an outbound submission path with per-sender rate limiting and DKIM signing;
- a **trust-analysis engine** (message origin, links, attachments);
- a **Tiptap-JSON rendering pipeline** replacing raw HTML rendering;
- a **calendar subsystem** (CalDAV/iTIP/iMIP interoperability);
- integration with **Diamy IAM** for authentication, device identity, and key management.

## 1.3 Out of scope for this document

Detailed algorithms, wire formats, DDL, and endpoint contracts are delegated to the annexes listed in §12. This document specifies only what is global and normative across the whole corpus.

## 1.4 Relationship to existing Diamy systems

Diamy Mail is NOT a standalone product. It REUSES:

- **Diamy IAM** — for user/device identity, JWT planes, key directory, DEK lifecycle. Diamy Mail MUST NOT reimplement identity, session, or key-management primitives already normatively defined in the Diamy IAM corpus.
- **Diamy messaging cryptographic patterns** — per-device public-key envelopes, post-quantum primitives (ML-KEM-768, ML-DSA-65), HKDF derivation discipline. Diamy Mail MUST align its cryptographic choices with the messaging E2EE model where the two overlap.

------

# 2. Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document and in all Diamy Mail annexes are to be interpreted as described in **RFC 2119** and **RFC 8174** when, and only when, they appear in all capitals.

Additional definitions:

| Term | Definition |
| ---- | ---------- |
| **Frontier encryption** | Encryption applied by the inbound gateway immediately after SMTP reception and security checks, before any persistent storage. The plaintext exists only transiently in RAM. |
| **Envelope** | An AES-256 message key wrapped for one specific recipient device public key. One message is encrypted once; the message key is wrapped once per device. |
| **Device** | A single authorized client instance (PC, phone, tablet) holding its own asymmetric key pair. Private keys never leave the device OS secure store. |
| **Vault client** | The local-first Diamy Mail client: encrypted SQLite catalogue + encrypted message blobs + local search index. |
| **Blind Index** | A keyed one-way index (HMAC-based) allowing server-side equality lookup without revealing plaintext. Used ONLY when webmail is enabled. |
| **Trust score** | A computed, explainable confidence value attached to a message, a link, or an attachment. |
| **Tiptap document** | A closed-schema structured JSON representation of message content (ProseMirror model), replacing raw HTML for default rendering. |
| **Tenant** | An organization (enterprise customer). Diamy Mail is B2B; every user belongs to a tenant. A tenant corresponds to a Diamy IAM tenant; the two MUST be the same entity, not a parallel concept. |
| **User** | A Diamy Mail principal. Every user is an existing Diamy IAM principal and is identified by their **email address**, which is the primary human-facing identifier and the join key between Diamy Mail and Diamy IAM (see §5.5). A user MAY own multiple devices. |
| **Webmail mode** | An OPT-IN capability where content is accessed through a browser with server-side Blind-Index search, rather than local-only storage. |
| **Sending server** | A physical or logical outbound MTA resource (`diamy-submitd` instance with an associated IP / IP pool) responsible for delivering outbound mail to the Internet. |
| **Sending pool** | A named, ordered set of sending servers/IPs treated as one reputation and capacity unit, to which tenants are assigned (see §10.6). |

------

# 3. System Boundary and Trust Model

## 3.1 Where plaintext may exist

Diamy Mail defines exactly three zones:

1. **Device zone** — plaintext MAY exist here. This is the only zone where message plaintext, decrypted attachments, and rendered content are permitted.
2. **Frontier zone (inbound MX, transient RAM)** — plaintext exists transiently for inbound Internet mail during SMTP reception and security processing, and MUST be destroyed immediately after frontier encryption. No persistent plaintext.
3. **Ciphertext infrastructure** — all storage (message blobs, catalogue, backups, object storage) holds ciphertext only. Servers hold NO private keys and NO message decryption keys.

## 3.2 Honest-but-curious server assumption

The server infrastructure is modeled as **honest-but-curious**, consistent with the Diamy IAM Payload Encryption Model. Specifically:

- The system MUST guarantee that a full compromise of persistent storage yields no message plaintext.
- The system MUST NOT rely on the server being trustworthy for confidentiality of stored content.
- The frontier zone is a **declared, bounded exception** for inbound Internet mail only: SMTP makes plaintext reception unavoidable. This exception MUST be documented transparently to tenants and MUST NOT be silently widened.

## 3.3 What the server can and cannot see

| Component | MAY see (metadata) | MUST NOT see |
| --------- | ------------------ | ------------ |
| Inbound MX | Envelope sender/recipient, SMTP headers, IP, timestamps; message body transiently in RAM during frontier processing | Persistent plaintext body after frontier encryption |
| Storage / object store | Ciphertext blobs, key envelopes, technical metadata, Blind Index tokens (if webmail enabled) | Plaintext body, private keys, message AES keys |
| Sync service | Message IDs, folder structure, read/state flags, sync cursors, sizes | Plaintext body, subject (unless Blind-Indexed under webmail), attachment content |
| Search (server-side) | Blind Index tokens (webmail only) | Plaintext keywords, plaintext sender/recipient outside routing needs |

## 3.4 Diamy ↔ Diamy vs Internet ↔ Diamy

- **Internet → Diamy**: frontier encryption model (§3.1 zone 2 applies).
- **Diamy → Diamy** (both endpoints on the platform): content SHOULD be encrypted client-side by the sender so the server never sees plaintext, consistent with the messaging E2EE model. Frontier zone is then NOT used for these messages.

------

# 4. Component Map

```
                          INTERNET (SMTP)
                                 │
                                 ▼
   ┌───────────────────────────────────────────────────────┐
   │  INBOUND GATEWAY  (diamy-mxd)                          │
   │  - SMTP reception over TLS                             │
   │  - SPF / DKIM / DMARC / ARC evaluation                 │
   │  - Antispam / antivirus / CDR hooks                    │
   │  - Trust analysis (headers, links, attachments)       │
   │  - Frontier encryption (AES-256 message key)          │
   │  - Per-device envelope wrapping                        │
   │  - Plaintext destruction                              │
   └───────────────────────────────────────────────────────┘
                                 │ ciphertext + envelopes + metadata
                                 ▼
   ┌───────────────────────────────────────────────────────┐
   │  STORAGE / SYNC SERVICE  (diamy-maild)                 │
   │  - Encrypted blob store (object storage)              │
   │  - Catalogue + technical metadata (no plaintext)      │
   │  - Key envelope directory                             │
   │  - Blind Index store (webmail only)                   │
   │  - Native sync API (NOT IMAP)                         │
   │  - Notification signals (no content push)             │
   └───────────────────────────────────────────────────────┘
                    │                          │
        native sync │                          │ optional
        API (WSS/   │                          │ webmail
        HTTPS)      ▼                          ▼
   ┌──────────────────────┐      ┌──────────────────────────┐
   │  VAULT CLIENT        │      │  WEBMAIL CLIENT          │
   │  (desktop / mobile)  │      │  (browser, opt-in)       │
   │  - Encrypted SQLite  │      │  - No local storage      │
   │  - Encrypted blobs   │      │  - WebCrypto decrypt     │
   │  - Local FTS search  │      │  - Blind-Index search    │
   │  - Local AI keyword  │      │                          │
   │    extraction        │      │                          │
   │  - Tiptap rendering  │      │  - Tiptap rendering      │
   │  - Offline operation │      │                          │
   └──────────────────────┘      └──────────────────────────┘

   ┌───────────────────────────────────────────────────────┐
   │  OUTBOUND SUBMISSION  (diamy-submitd)                  │
   │  - Client-side encrypted "Sent" copy                  │
   │  - DKIM signing                                        │
   │  - Per-sender / per-tenant rate limiting              │
   │  - Outbound reputation / IP pool management           │
   └───────────────────────────────────────────────────────┘

   ┌───────────────────────────────────────────────────────┐
   │  CALENDAR SUBSYSTEM  (diamy-cald)                      │
   │  - CalDAV client/server                               │
   │  - iTIP / iMIP invitation flow                        │
   │  - RFC 5545 recurrence + timezone engine              │
   │  - Free/busy                                           │
   │  - Encrypted calendar storage (per-device envelopes)  │
   └───────────────────────────────────────────────────────┘

   ┌───────────────────────────────────────────────────────┐
   │  DIAMY IAM  (external dependency — do not reimplement) │
   │  - User/device identity, JWT planes, key directory    │
   │  - DEK lifecycle, revocation                           │
   └───────────────────────────────────────────────────────┘

   ┌───────────────────────────────────────────────────────┐
   │  BRIDGE (loopback-only)  (diamy-bridged)              │
   │  - Local 127.0.0.1 IMAP/SMTP facade                   │
   │  - Translates to native API for third-party clients   │
   │    (Thunderbird, Outlook)                             │
   └───────────────────────────────────────────────────────┘
```

## 4.1 Process separation

Each server-side component listed above (`diamy-mxd`, `diamy-maild`, `diamy-submitd`, `diamy-cald`) MUST be a separate OS-level service. Components MUST NOT share process memory. Inter-component coordination MUST use authenticated channels only (§10.4).

Rationale and precedent: this mirrors the control-plane / data-plane separation used in the SIP Monitor (`diamy-sipd` / `diamy-apid`), where privilege boundaries and blast-radius containment are enforced at the process level.

## 4.2 Frontier vs trust-engine responsibility boundary

The inbound gateway (`diamy-mxd`) and the trust-analysis engine both operate on the transient plaintext of inbound Internet mail. Their boundary MUST be explicit:

- **CMP-BND-1**: Trust analysis of message origin (headers, IP, SPF/DKIM/DMARC — annex A06) MUST execute inside the frontier zone, on server-visible metadata that remains `PLAINTEXT_METADATA` after encryption. Its outputs are stored as metadata and require no later decryption.
- **CMP-BND-2**: Trust analysis of links and attachments (annex A07) that requires inspecting message *body* or attachment *content* MUST execute in the frontier zone during the transient-plaintext window, before frontier encryption. Its verdicts are stored as metadata; the underlying content MUST NOT be retained in plaintext afterwards.
- **CMP-BND-3**: HTML → Tiptap conversion (annex A08) is a **client-side** operation by default, performed on decrypted content on the device — NOT in the frontier zone. The gateway MUST NOT be assumed to hold a Tiptap representation. (Exception: webmail mode MAY perform conversion server-side within the same honest-but-curious constraints; A08/A09 govern this.)

------

# 5. Canonical Data-Model Rules (Normative, cross-cutting)

These rules apply to EVERY Diamy Mail annex and to all generated code. They exist to make AI-driven implementation coherent across documents.

## 5.1 Identifiers

- **CDM-ID-1**: All primary identifiers MUST be UUIDv7 (time-ordered), consistent with the Diamy messaging and IAM corpora.
- **CDM-ID-2**: When a UUID is used as input to a hash or key-derivation function, the **16-byte big-endian binary form** MUST be used, NEVER the string form. (This is the single most frequent AI error observed in the IAM corpus; see §13.)
- **CDM-ID-3**: Message IDs, folder IDs, device IDs, and calendar object IDs are all UUIDv7 unless an external standard (e.g. RFC 5322 `Message-ID`, iCalendar `UID`) mandates a different format, in which case both the external ID and an internal UUIDv7 MUST be stored.

## 5.2 Timestamps

- **CDM-TS-1**: All internal timestamps MUST be UTC, ISO-8601, millisecond precision.
- **CDM-TS-2**: Timezone-bearing data (calendar events) is the ONLY exception and MUST follow the calendar timezone rules (dedicated annex), NOT this rule.

## 5.3 Nullability and field contracts

- **CDM-NULL-1**: Every field in every data model MUST declare a status: `REQUIRED`, `OPTIONAL`, or `CONDITIONAL` (with the condition stated).
- **CDM-NULL-2**: The physical schema (DDL) is the source of truth where it exists; a document description MUST NOT be treated as authoritative over shipped DDL. (Precedent: SIP Monitor storage schema rule.)

## 5.4 Encryption boundaries in the data model

- **CDM-ENC-1**: Every stored field MUST be classified as one of: `PLAINTEXT_METADATA` (routing/technical, server-visible), `BLIND_INDEX` (webmail only), or `CIPHERTEXT` (never server-readable).
- **CDM-ENC-2**: No field may change classification across versions without an explicit migration entry in the annex changelog.
- **CDM-ENC-3**: Subject lines and message bodies are `CIPHERTEXT` by default. A subject becomes `BLIND_INDEX` only when webmail is enabled for that user AND keyword sync is active.

## 5.5 Identity and email-address normalization

Every Diamy Mail user is a Diamy IAM principal identified by email address. Because the address is simultaneously a routing token, a human identifier, and a join key with IAM, its handling MUST be deterministic.

- **CDM-ADDR-1**: A user's email address is the primary human-facing identifier and the canonical join key to Diamy IAM. Diamy Mail MUST resolve a user via IAM by normalized address (§CDM-ADDR-3); it MUST NOT maintain a private, parallel user registry that could diverge from IAM.
- **CDM-ADDR-2**: Internally, each user also carries the IAM principal UUIDv7. All internal foreign keys (messages, folders, devices, envelopes, calendar objects) MUST reference the UUIDv7, NOT the raw address string, so that an address change does not require rewriting internal references.
- **CDM-ADDR-3**: Address normalization for identity resolution and for sender/recipient Blind Index (SRCH-3) MUST be a single shared function producing a canonical form. The canonical form MUST: lowercase the domain; apply IDN→A-label (punycode) to the domain; NFC-normalize the local part; and trim surrounding whitespace. The function MUST be defined once (annex A24) and reused everywhere — divergent normalization between identity lookup and Blind Index would break search and routing.
- **CDM-ADDR-4**: Sub-addressing (`local+tag@domain`) handling (whether `+tag` is stripped for identity/index purposes) MUST be a tenant-configurable policy, defaulting to **preserve** (`+tag` significant). The chosen policy MUST be applied identically in identity resolution and Blind Index.
- **CDM-ADDR-5**: The local part MUST be treated as case-sensitive per RFC 5321 unless a tenant explicitly opts into case-insensitive local parts; the domain is always case-insensitive. The default SHOULD be case-insensitive local part for usability, but this is a tenant policy and MUST be recorded per tenant so lookups are stable.

## 5.6 Internationalization (message content, addresses, composition)

Internationalization concerns split into three distinct layers that MUST NOT be conflated. Each has its own rule set.

### 5.6.1 Message body (content layer)

- **CDM-I18N-1**: Full UTF-8 support in message bodies, subjects, and attachment filenames is REQUIRED. This includes accented characters and Unicode emoji. There is no restricted character repertoire for content.
- **CDM-I18N-2**: Inbound decoding MUST be robust against mislabeled charsets. The decoder MUST honor the declared MIME charset first; on decode failure or evident mismatch, it MUST fall back to detection heuristics (e.g. UTF-8 validation, then legacy Latin-1/Windows-1252) rather than rejecting the message or storing corrupted text. A message MUST NEVER be lost or blocked because of a charset problem; worst case, it is stored with a best-effort decode and a `charset_recovered` metadata flag.
- **CDM-I18N-3**: RFC 2047 encoded-words in headers (`=?utf-8?B?...?=`) and RFC 2231 parameter encoding (attachment filenames) MUST be decoded on ingestion and re-encoded correctly on emission.

### 5.6.2 Email addresses (EAI / SMTPUTF8 layer)

V1 posture: **accept on receive, do not generate on send.**

- **CDM-I18N-4**: The inbound gateway MUST accept, store, display, and allow replying to internationalized addresses (RFC 6530–6533 EAI, including Unicode local parts and IDN domains) without data loss or rejection. Reply flows reuse the received address verbatim; no address synthesis is required.
- **CDM-I18N-5**: In V1, Diamy Mail MUST NOT provision Unicode local parts for its own tenants and MUST NOT require SMTPUTF8 on the outbound path. Tenant mailbox local parts are ASCII in V1.
- **CDM-I18N-6**: The canonical normalization function (CDM-ADDR-3) MUST be Unicode-ready from day one (NFC on local part, IDN→A-label on domain) even though V1 does not generate EAI addresses — otherwise an inbound EAI sender address would corrupt the sender Blind Index. Full EAI emission support, if later enabled, MUST be a policy switch, not a refactoring.
- **CDM-I18N-7**: Homograph risk: when displaying a sender address containing mixed-script or confusable characters, the client SHOULD surface a visual cue, and the trust engine (A06) SHOULD treat mixed-script local parts / domains as a scoring signal. Unicode addresses are legitimate; silently *confusable* ones are a phishing vector.

### 5.6.3 Composition (editor layer)

- **CDM-I18N-8**: The Tiptap composition editor MUST support direct insertion of Unicode emoji as text codepoints (never as images), matching messaging-app UX. An emoji picker SHOULD be provided; OS-level input methods MUST work unimpeded.
- **CDM-I18N-9**: All composed text MUST be NFC-normalized before signing, encryption, and storage, so that visually identical inputs (precomposed vs combining sequences) have a single canonical byte representation. This protects search consistency and signature stability.

------

# 6. API Design Rules (Normative, cross-cutting)

- **API-1**: The client-server protocol is a **native Diamy Mail API**, NOT IMAP/POP3/SMTP. IMAP compatibility, if ever provided, is delivered exclusively through the optional Bridge (§4, deferred).
- **API-2**: All API calls MUST be authenticated through Diamy IAM tokens (plane-specific, revocable — mechanism per A17-TOK-2, confirmation pending). Diamy Mail MUST NOT mint its own identity tokens.
- **API-3**: Request/response bodies MUST be JSON. Binary blobs (ciphertext, attachments) MUST be transferred as discrete objects referenced by ID, NEVER inlined base64 in catalogue responses.
- **API-4**: All list/search endpoints MUST be paginated with bounded page sizes; unbounded full scans MUST be rejected. (Precedent: APNF Routing API rule.)
- **API-5**: The server MUST NOT push message content. Notifications carry signals only (new message, deletion, state change); the client decides what to fetch. (Precedent: messaging pull model + client architecture doc.)
- **API-6**: Every endpoint MUST define a typed error model with stable machine-readable error codes.
- **API-7**: Every endpoint MUST declare an observability contract (§11).

------

# 7. Security Model (Normative, cross-cutting)

## 7.1 Cryptographic alignment

- **SEC-CRYPT-1**: Message confidentiality MUST use AES-256 with a fresh random key per message, wrapped per device.
- **SEC-CRYPT-2**: Per-device key wrapping MUST use the Diamy IAM / messaging public-key envelope mechanism (post-quantum hybrid where the messaging corpus mandates it). Diamy Mail MUST NOT invent a parallel KEM.
- **SEC-CRYPT-3**: Message authenticity/integrity MUST be provided independently of the confidentiality cipher (e.g. signature or AEAD), so that ciphertext malleability cannot alter delivered content undetectably.
- **SEC-CRYPT-4**: Key-derivation MUST use HKDF with explicit `info` labels; a seed/secret MUST NEVER be used directly as an HMAC or cipher key.

## 7.2 Fail-closed

- **SEC-FC-1**: Every server component MUST refuse to start in production if any required signing secret, encryption key reference, or IAM binding is missing or left at a development default. (Precedent: messaging E2EE overview + IAM boot enforcement.)
- **SEC-FC-2**: If frontier encryption cannot complete for an inbound message, the system MUST NOT store plaintext; it MUST fail the delivery and retain nothing readable.
- **SEC-FC-3**: If a rendering or sanitization step cannot guarantee safety, the client MUST degrade to a safe representation (plain text / blocked content), NEVER render unsafely.

## 7.3 Rendering safety

- **SEC-RENDER-1**: Default rendering MUST use the Tiptap closed-schema pipeline. Raw HTML MUST NOT be rendered directly by default.
- **SEC-RENDER-2**: Any element present in the source HTML (link, image, interactive element) MUST be either represented in the Tiptap JSON or explicitly logged as filtered with a reason. Silent omission is a defect. (Derived from the "view in browser" link observation.)
- **SEC-RENDER-3**: Content hidden in the source (`display:none`, `visibility:hidden`, zero-size, background-colored text) MUST NOT be forwarded to the local AI keyword extractor and SHOULD contribute a negative signal to the trust score.
- **SEC-RENDER-4**: The "view original" path MUST render the raw HTML only inside a sandboxed iframe with a strict CSP and mandatory image proxying; it MUST NOT be the default view and MUST NOT share context with the application.
- **SEC-RENDER-5**: All external image loads MUST pass through a server-side image proxy to prevent IP/user-agent leakage; remote content MUST be blocked by default.

## 7.4 Attachment safety

- **SEC-ATT-1**: Attachment handling MUST be **whitelist-first**: only explicitly approved file types are treated as safe; everything else is treated as untrusted by default.
- **SEC-ATT-2**: Password-protected archives that cannot be inspected MUST be treated as maximum-risk, because their contents cannot be verified.
- **SEC-ATT-3**: Access to non-whitelisted attachments MUST be governed by a configurable per-tenant policy: informed user confirmation, administrator approval, or isolated/sandboxed viewing (CDR / detonation). The isolated-viewing path is a declared exception requiring temporary server-side decryption of that specific file, on explicit user request only, and MUST be documented as such.

## 7.5 Outbound protection

- **SEC-OUT-1**: Outbound submission MUST enforce per-sender and per-tenant rate limits, plus a unique-recipient counter, with an adaptive baseline per account and a circuit-breaker on anomaly. This protects platform sending reputation against a compromised account.
- **SEC-OUT-2**: A tenant MUST NOT be permitted to send until SPF, DKIM, and DMARC are verified aligned for its domain (fail-closed onboarding).

------

# 8. Storage and Multi-Device Model (Normative summary)

Detailed in the dedicated annex; the following are binding at the architecture level.

- **STO-1**: One message is encrypted once (single ciphertext blob). The per-message AES key is wrapped once per authorized device.
- **STO-2**: Servers store: ciphertext blob, per-device key envelopes, technical metadata, Blind Index tokens (webmail only), sync/journal events. Servers store NO private keys.
- **STO-3**: Adding a device MUST make future messages available by producing new envelopes; historical access MUST use a device-delegated re-wrap or background migration that NEVER exposes plaintext to the server.
- **STO-4**: Revoking a device MUST stop envelope production for it; other devices MUST continue unaffected; key rotation MAY be offered.
- **STO-5**: Private keys MUST reside in the OS secure store (DPAPI / Keychain / Keystore / Secure Enclave). The local SQLite catalogue MUST be encrypted (SQLCipher or equivalent) with its key protected by the same OS secure store.

------

# 9. Search Model (Normative summary)

- **SRCH-1**: Search is **local-first by default**. A fully-synced device performs all search locally over decrypted data / local index (SQLite FTS5 or equivalent). No server query is required or issued.
- **SRCH-2**: Server-side search via Blind Index is available ONLY when webmail is enabled for the user. When disabled, keyword indices MUST NOT be uploaded to the server (data minimization).
- **SRCH-3**: Sender/recipient equality search MAY use a Blind Index (HMAC of normalized address) for server-side lookup where routing already requires that metadata.
- **SRCH-4**: Keyword extraction MUST run in a **local AI agent** on-device; only derived keywords (never raw content) may leave the device, and only under webmail mode.
- **SRCH-5**: On a partially-synced device, the client MUST clearly indicate when results are incomplete rather than silently returning partial results.

------

# 10. Cross-Cutting Operational Rules

## 10.1 Failure model

- **OPS-FAIL-1**: Every component MUST define its behavior under: malformed input, partial data, dependency unavailability, and overload. Inbound mail MAY be malformed, duplicated, or partially received; the system MUST remain stable. (Precedent: SIP parser stability requirement.)

## 10.2 Offline operation

- **OPS-OFF-1**: The vault client MUST remain fully functional offline for already-synced content: reading, local search, composing, drafts, filing. Synchronization resumes on reconnection.

## 10.3 Rate limiting and abuse

- **OPS-RL-1**: Both inbound (anti-abuse) and outbound (reputation protection) paths MUST implement rate limiting. Outbound limits are security-critical (§7.5).

## 10.4 Inter-component communication

- **OPS-IPC-1**: Server components MUST communicate only over authenticated channels. Any cross-node relay MUST be integrity-protected (e.g. HMAC-SHA256 with a bounded replay window), consistent with the messaging cross-edge relay model.

## 10.5 Deliverability operations

- **OPS-DELIV-1**: The platform MUST integrate sending-reputation monitoring (postmaster feedback loops, blocklist monitoring) as a product component, not an afterthought.
- **OPS-DELIV-2**: IP pools MUST be segmentable; large tenants SHOULD be assignable to dedicated outbound IPs so that one tenant's behavior cannot degrade another's reputation.

## 10.6 Outbound resource allocation (tenant → sending resources)

Diamy Mail operates **multiple sending servers**. Outbound mail for a tenant MUST be routed to sending resources through an explicit, auditable allocation model, so that capacity and sending reputation can be managed and isolated per tenant.

- **OPS-SEND-1**: The platform MUST maintain a first-class **sending resource inventory**: each sending server is a registered resource with a stable ID (UUIDv7), one or more outbound IPs, a declared capacity envelope (max concurrent connections, max messages/interval), a health state, and the pool(s) it belongs to.
- **OPS-SEND-2**: Sending servers MUST be groupable into named **sending pools** (§2). A pool is the unit of reputation and capacity. A sending server MAY belong to at most one pool at a time.
- **OPS-SEND-3**: Every tenant MUST have an **outbound allocation** binding it to exactly one primary sending pool, with an OPTIONAL ordered list of fallback pools used only when the primary is unavailable or saturated. This binding is control-plane configuration, managed by an administrator (Super Admin scope in IAM terms), and MUST be audit-logged on change.
- **OPS-SEND-4**: The allocation model MUST support three assignment modes, selectable per tenant: **shared** (tenant uses a multi-tenant pool), **dedicated** (tenant is the sole occupant of a pool / IP set), and **hybrid** (dedicated for transactional, shared for bulk, or a similar split defined in A23). Dedicated assignment is the mechanism by which a large tenant's behavior is isolated from others (satisfying OPS-DELIV-2).
- **OPS-SEND-5**: At submission time, `diamy-submitd` MUST resolve the sending pool for the message's tenant via the outbound allocation, select a healthy sending server within that pool according to a documented selection policy (e.g. capacity-weighted round-robin), and record the chosen sending server ID in the message's delivery metadata for observability and troubleshooting.
- **OPS-SEND-6**: The allocation resolver MUST fail closed: if no healthy sending resource is available in the primary pool and no fallback is configured or healthy, the message MUST be queued (not dropped, not sent via an arbitrary unassigned resource), and the condition MUST raise a health/alert signal (§11).
- **OPS-SEND-7**: Per-tenant and per-sender outbound rate limits (SEC-OUT-1) MUST be enforced **in addition to** pool capacity limits. Tenant allocation MUST NOT be used to bypass anti-abuse limits; the two controls are independent and both apply.
- **OPS-SEND-8**: The tenant→pool binding, the sending resource inventory, and their change history are **control-plane data**. They MUST reside in the administrative data store, MUST NOT contain any message plaintext, and MUST be exposed only through authenticated administrative APIs (annex A23).
- **OPS-SEND-9**: SPF alignment interacts with pool assignment: the set of IPs a tenant can send from (its pool) MUST be consistent with the SPF record the tenant publishes during onboarding (A11). Reassigning a tenant to a pool with different egress IPs MUST trigger an SPF re-verification workflow before the new pool is used for that tenant.

The full data model, administrative API, selection policy, and health integration for outbound resource allocation are specified in annex **A23 — Outbound Resource Allocation**.

------

# 11. Observability Contract (Normative, cross-cutting)

- **OBS-1**: Every service MUST expose health indicators distinct from business metrics, interpretable before any business metric is trusted. (Precedent: SIP Monitor health thresholds.)
- **OBS-2**: Every service SHOULD expose request counts, success/error rates, latency, and queue/backlog depth in a Prometheus-compatible form.
- **OBS-3**: Security-relevant events (frontier encryption failures, attachment quarantine, rate-limit trips, trust-score criticals, webmail enablement) MUST be audit-logged in an append-only store.
- **OBS-4**: Health degradation MUST be surfaced such that unreliable metrics are not mistaken for real conditions.

------

# 12. Document Corpus Plan

Diamy Mail is specified by this master document plus the following annexes. Each annex inherits all cross-cutting rules herein. Status legend: **[P]** planned, **[D]** draft exists in prior conversation, **[ ]** not started.

| # | Annex | Covers | Status |
|---|-------|--------|--------|
| A00 | **This document** — Master Architecture | Scope, component map, canonical rules, security model, corpus plan | D |
| A01 | Inbound Gateway & Frontier Encryption | MX pipeline, SPF/DKIM/DMARC/ARC, AV/CDR hooks, frontier crypto, plaintext destruction | P |
| A02 | Storage & Multi-Device Envelope Model | Blob store, per-device envelopes, add/revoke device, re-wrap/migration | P |
| A03 | Vault Client Architecture | Encrypted SQLite catalogue, blob cache, offline, sync consumption, OS secure store | P |
| A04 | Native Sync API | Endpoints, pagination, notifications, sync cursors, conflict resolution | P |
| A05 | Search & Local AI Keyword Extraction | Local FTS, Blind Index (webmail), data-minimization policy, partial-sync UX | P |
| A06 | Trust Analysis — Message Origin | SMTP header analysis, SPF/DKIM/DMARC, IP/ASN/rDNS, scoring, reputation history | P |
| A07 | Trust Analysis — Links & Attachments | Link resolution/typosquatting, attachment whitelist, archive inspection, access policies, CDR/detonation | P |
| A08 | HTML Ingestion & Tiptap Conversion | HTML parse → closed schema, layout-table flattening, CID images, hidden-content rejection, link/image normalization, exhaustiveness rule | P |
| A09 | Rendering Sandbox (View Original) | iframe sandbox, CSP, image proxy, defense-in-depth sanitization | P |
| A10 | Outbound Submission & Deliverability | Client-side Sent copy, DKIM signing, rate limits, IP pools, reputation monitoring, bulk-sender compliance | P |
| A11 | Domain Onboarding Wizard | Guided SPF/DKIM/DMARC provisioning, DNS verification, fail-closed activation, SPF-merge handling | P |
| A12 | Calendar — Core Model & Storage | RFC 5545 model, recurrence engine, exceptions (RECURRENCE-ID), encrypted calendar storage | P |
| A13 | Calendar — Timezone Engine | VTIMEZONE handling, DST, Windows/IANA mapping, cross-client consistency | P |
| A14 | Calendar — iTIP/iMIP Interop | Invitations/replies/updates/cancellations, Outlook/Google quirks, "Known Third-Party Behaviors" registry | P |
| A15 | Calendar — Free/Busy | Availability, CalDAV free/busy, privacy of availability | P |
| A16 | Message Classification | Bulk/marketing detection reusing Tiptap structure + headers, folder routing | P |
| A17 | IAM Integration Contract | Exact binding to Diamy IAM tokens, device identity, key directory, revocation | P |
| A18 | Rust Implementation Guide | Server-side implementation conventions, crate choices, module layout | P |
| A19 | Client SDK / Execution Contract | Client protocol engine invariants (queue, tokens, recovery), TS/mobile guidance | P |
| A20 | Bridge | Local (loopback-only) IMAP/SMTP/CalDAV facade for third-party clients | S |
| A21 | Storage Schema (DDL) | Physical schema, source-of-truth over prose | P |
| A22 | Health Thresholds | Pipeline health indicators and default thresholds | P |
| A23 | **Outbound Resource Allocation** | Sending resource inventory, sending pools, tenant→pool binding, assignment modes (shared/dedicated/hybrid), selection policy, admin API, SPF-consistency, health integration | P |
| A24 | **Identity & Address Normalization** | Canonical email normalization function, IAM principal resolution, sub-addressing policy, case policy, shared use in identity + Blind Index, EAI/SMTPUTF8 receive-side handling, homograph/confusable detection | P |
| A25 | **Architecture Invariants & Implementation Constitution** | The root document — the corpus-wide invariants (INV-*), the implementation constitution (ordered rules for the AI implementer, incl. "never implement an unspecified case — flag the gap"), reading/precedence rules, and the consolidated anti-pattern list. **Read first, before any feature annex.** | S |
| A26 | **Multi-Account Client** | Multiple Diamy identities (principals, possibly cross-tenant) in one native client: strict per-account isolation (separate vaults/keys/sessions, no cross-account decryption or metadata bleed), account lifecycle/switching, unified inbox as a presentation merge (never a data merge), compose-account selection, per-account tenant policy, offboarding. Diamy↔Diamy identities only; external non-Diamy accounts explicitly out of scope. | S |
| A27 | **Shared Resources: Shared Mailboxes, Calendar Delegation & Distribution Groups** | Shared mailboxes as role-based (viewer/contributor/admin) resource principals extending the multi-device envelope model; self-service calendar delegation with crypto-scoped (calendar-only) key wrapping and full delegate write access; distribution groups as pure directory-expansion (client-side for Diamy senders, gateway-side for external senders) with no shared encryption state. Explicit crypto-vs-policy enforcement disclosure for role tiers. | S |
| A28 | **Presence & Calendar-Driven Status** | Teams-style presence states (closed set), consent posture mirroring A15 (default-deny, scoped, separate from free/busy), calendar-driven automatic transitions computed strictly on-device (client publishes the state, never the reason), source precedence (manual > DND > calendar > activity), multi-device aggregation, TTL aging, no-history retention rule. | S |
| A29 | **Trust UX, Protective Actions & Sandbox Workspace** | The client-side behavioral contract for trust: contextual-warning discipline (signal-triggered, explained, never categorical), the normative action×band matrix (save blocked at high band), the sandbox workspace (sandbox as message STATE with forced restriction set; explicit, explained, audited release), progressive-disclosure pedagogy, green-state parity, responsible bypass, the measurable alarm budget. | S |

Document production order for the AI-implementation track SHOULD follow: A24 → A17 → A02 → A01 → A03 → A04 → A05 → A08 → A06 → A07 → A09 → A10 → A11 → A23 → A16 → A21 → A22 → A18 → A19 → A12 → A13 → A14 → A15 → A20. Rationale: identity/address normalization first (A24 — it is the join key everything else depends on), then identity/storage/gateway (the foundation), outbound allocation (A23) alongside the outbound/onboarding annexes since it shares SPF and tenant concerns, calendar last (highest third-party-interop risk, benefits from a stable core).

**Reading order (distinct from production order):** an implementer reads **A25 (root invariants & constitution) first, then this A00 master, then the feature annex(es) for the task, then A18/A19 (implementation discipline), then A21/A22 as needed** (A25-READ-1). A25 and A00 set the frame no annex may violate; the feature annex sets the task; A18/A19 set how to build it. A25 is the invariant floor and the "read first" document.

------

# 13. AI Implementation Guidance (Normative for generation)

This corpus is written to be implemented by an AI coding agent. The following rules capture recurring failure modes observed across prior Diamy corpora and MUST be enforced in every annex and in generated code.

## 13.1 Common AI Implementation Errors (watch list)

1. Hashing a UUID **string** instead of its 16-byte binary form (CDM-ID-2). Verify every hash/KDF input.
2. Using a seed/secret **directly** as an HMAC or cipher key instead of deriving via HKDF with an explicit `info` label (SEC-CRYPT-4).
3. Rendering raw HTML directly instead of going through the Tiptap closed schema (SEC-RENDER-1).
4. Silently dropping a source link/image during Tiptap conversion instead of representing or logging it (SEC-RENDER-2).
5. Forwarding hidden source content to the keyword extractor (SEC-RENDER-3).
6. Storing message plaintext at any persistent layer, including logs, caches, temp files, or backups (§3, §7.2).
7. Treating a password-protected archive as "empty/clean" because it could not be opened, instead of maximum-risk (SEC-ATT-2).
8. Inlining attachment/ciphertext bytes into catalogue JSON instead of referencing discrete objects (API-3).
9. Pushing message content in notifications instead of signals only (API-5).
10. Allowing outbound send before SPF/DKIM/DMARC alignment is verified (SEC-OUT-2).
11. Reimplementing identity/session/key primitives already owned by Diamy IAM (§1.4, API-2).
12. Mapping HTML layout tables to Tiptap "table" nodes instead of flattening them to block sequences (A08).
13. Assuming calendar timezone correctness without exercising DST boundaries and Windows/IANA mapping (A13).
14. Using two different email-normalization implementations for identity lookup vs Blind Index, causing search/routing to silently miss matches (CDM-ADDR-3). There MUST be exactly one normalization function.
15. Selecting an arbitrary or unassigned sending server at submission instead of resolving the tenant's outbound allocation, or using allocation to bypass anti-abuse rate limits (OPS-SEND-5, OPS-SEND-7).
16. Rejecting or corrupting a message due to a mislabeled charset instead of applying fallback decoding with a `charset_recovered` flag (CDM-I18N-2); or comparing/storing composed text without NFC normalization, so that visually identical strings diverge in search, signatures, or the Blind Index (CDM-I18N-6, CDM-I18N-9).

## 13.2 Generation discipline

- **GEN-1**: Each annex MUST be self-contained enough to implement its module, while inheriting (not restating in conflict) the cross-cutting rules here.
- **GEN-2**: Each annex MUST include, at minimum: scope, normative field contracts, endpoint/error contracts where applicable, an observability contract, a failure model, and an annex-specific "common errors" list.
- **GEN-3**: Where an external standard's real-world implementations deviate from the RFC (email HTML, iTIP/iMIP), the annex MUST maintain a versioned **"Known Third-Party Behaviors"** registry, analogous to this watch list, capturing each observed deviation. This is the one area where "zero spec modification" is NOT an achievable target and iteration MUST be budgeted.

------

# 14. Open Decisions (to be resolved in annexes)

The following were raised during design and are recorded here so they are not lost; each MUST be closed in its annex. Status is tracked below and updated as annexes ship.

1. **[CLOSED by A20]** **Third-party client support** — resolved: the Bridge (A20) is a **committed feature**, specified as a strictly-local (loopback-only) IMAP/SMTP/CalDAV facade (`diamy-bridged`) that lets third-party clients access a Diamy mailbox. It decrypts locally on the user's own device (bounded plaintext, server zero-access unchanged), enrolls as its own device with app-scoped revocable Bridge passwords, and routes sends through the standard A10 emission controls. The residual risk (third-party client renders/handles plaintext outside Diamy's Tiptap/sandbox protections) is disclosed; tenants may disable the Bridge org-wide. The native API (A04) is unchanged — the Bridge sits on top of the client SDK (A19), so no day-one Bridge-friendliness constraint on the native protocol was needed.
2. **[CLOSED by A05 §1.1]** **Remote search scope** — resolved: Blind-Index server search activates ONLY when webmail is enabled; a native client without webmail never uploads keyword indices, and a partially-synced native client signals incompleteness rather than falling back to a server query.
3. **[CLOSED by A03 §7.1]** **Multi-device state conflict resolution** — resolved: per-field last-writer-wins by server journal sequence, tag-set union (additive), purge-wins; not whole-record LWW, not vector clocks in V1.
4. **[CLOSED by A03 §6]** **Cache purge policy** — resolved: hybrid pinned/favorite + recency window + LRU-under-quota, user-transparent, with metadata + decrypted summary never evicted (only blobs are evictable).
5. **[CLOSED by A14 §6]** **Calendar for external non-Diamy invitees** — resolved: an external (non-Diamy) invitee necessarily receives a standard plaintext iMIP email (the only way a non-Diamy client can read it), a disclosed, bounded relaxation of zero-access at the external boundary — the same category as sending any plaintext email outside. Diamy↔Diamy scheduling stays end-to-end encrypted (native path), at-rest storage stays zero-access, and internal attendees of a mixed meeting stay encrypted; only the outbound iMIP to an external invitee is plaintext. The boundary is disclosed in the UI (encrypted-native vs plaintext-external), and tenants MAY restrict external invitations.
6. **[CLOSED by A16 §6]** **Marketing classification placement** — resolved: frontier computes a header/origin base class (metadata); the client refines with Tiptap structure (on-device); mirrors the trust two-layer model (A06-COMB-1b).

All six open decisions are now closed by their annexes as noted (#1 by A20, #2 by A05, #3 by A03, #4 by A03, #5 by A14, #6 by A16). No design decisions remain open.

------

*End of document.*
