# Diamy Mail — ANNEX A24: Identity & Address Normalization

**Document title:** Diamy Mail — ANNEX A24: Identity & Address Normalization
**Version:** 1.2
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.2 (A00)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: canonical normalization function `diamy_addr_canon()`, IAM principal resolution, tenant policies (sub-addressing, local-part case), Blind Index derivation inputs, EAI receive-side handling, homograph/confusable scoring interface, test vectors, common AI errors |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Coherence fix following review of the Diamy IAM – Integration Specification v1.6: softened A24-IAM-1 and one AI error's unqualified "epoch" language to reference A17-TOK-2's flagged (unconfirmed) revocation mechanism, completing the corpus-wide sweep. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: fixed pipeline/vector contradiction — added explicit format-class (Cf) codepoint stripping as Step 3b (was implied by vector #12 and §7.1 but absent from the pipeline); defined quoted-local-part × casefold interaction (Step 4); added RFC 5321 local-part 64-octet bound (Step 0); reordered Step 0 (trim before length check); reworded A24-IAM-2 persistence claim; punycode of test vectors verified against reference IDNA2008 implementation |

------

# Table of contents

[toc]

------

# 1. Scope

This annex defines the **single canonical email-address normalization function** used everywhere in Diamy Mail, the resolution path from an address to a Diamy IAM principal, the tenant-level policies that parameterize normalization, and the receive-side handling of internationalized addresses (EAI).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 Why this annex exists

The email address is simultaneously:

1. a **routing token** (SMTP envelope),
2. a **human identifier** (display, composition),
3. the **join key to Diamy IAM** (CDM-ADDR-1),
4. an **input to the sender/recipient Blind Index** (SRCH-3).

If any two of these use different normalization, the system silently misroutes, fails lookups, or misses search matches. Therefore there is exactly **one** normalization function, defined here, and every consumer calls it.

## 1.2 Consumers of this annex (normative dependency)

| Consumer | Uses |
| -------- | ---- |
| Inbound gateway (A01) | Recipient resolution, sender Blind Index input |
| Storage & sync (A02, A04) | Address fields at rest, envelope routing |
| Search (A05) | Sender/recipient Blind Index derivation |
| Trust engine (A06) | Domain alignment checks, homograph signal |
| Outbound submission (A10) | Sender identity verification |
| Onboarding wizard (A11) | Mailbox provisioning validation |
| IAM integration (A17) | Principal resolution |
| Calendar (A12–A15) | Attendee address matching (iTIP) |

------

# 2. Data Model

## 2.1 Address record

Every stored address is represented internally by the following logical structure:

```
{
  "raw": "string",              // as received / as entered, byte-preserved
  "canonical": "string",        // output of diamy_addr_canon() — lookup key
  "display": "string|null",     // display-name part if present ("Jean Dupont")
  "local_part": "string",       // canonical local part
  "domain_alabel": "string",    // canonical domain, A-label (punycode) form
  "domain_ulabel": "string",    // domain, U-label (Unicode) form, for display
  "is_eai": "boolean",          // true if local part contains non-ASCII
  "confusable_flags": "int"     // bitfield, see §7
}
```

### 2.2 Field contract

| Field | Status | Description |
| ----- | ------ | ----------- |
| `raw` | REQUIRED | The address exactly as received. MUST be preserved byte-for-byte for reply flows (CDM-I18N-4) and audit. Never used as a lookup key. |
| `canonical` | REQUIRED | `diamy_addr_canon(raw, tenant_policy)` output. The ONLY form used for equality, joins, and index derivation. |
| `display` | OPTIONAL | RFC 5322 display-name, decoded (RFC 2047) and NFC-normalized. |
| `local_part` | REQUIRED | Canonical local part (post-policy). |
| `domain_alabel` | REQUIRED | Always A-label (ASCII/punycode). Used for routing, SPF/DKIM/DMARC alignment, TLS SNI. |
| `domain_ulabel` | CONDITIONAL | Present when the domain is an IDN; used for display only. |
| `is_eai` | REQUIRED | Drives display cues and outbound-path decisions (CDM-I18N-5). |
| `confusable_flags` | REQUIRED | Default 0. See §7. |

------

# 3. The Canonical Normalization Function

## 3.1 Signature

```
diamy_addr_canon(raw_address: string, policy: TenantAddressPolicy) -> CanonicalAddress | ERR
```

The function MUST be implemented **once per platform** (one Rust crate server-side, one TypeScript module client-side) with **byte-identical outputs** verified by the shared test vectors in §9. It MUST be pure (no I/O, no clock, no randomness).

## 3.2 Pipeline (normative order)

The steps MUST execute in this exact order. Reordering changes outputs.

```
Step 0  INPUT GUARD
        - strip surrounding whitespace
        - reject if raw length > 320 bytes (RFC 5321 practical bound)
        - reject if raw contains control characters (U+0000–U+001F, U+007F)
          → ERR_ADDR_CONTROL_CHARS

Step 1  PARSE
        - split display-name / addr-spec per RFC 5322
        - decode RFC 2047 encoded-words in display-name
        - extract local_part @ domain from addr-spec
        - reject if local part > 64 octets (RFC 5321 §4.5.3.1.1)
          → ERR_ADDR_TOO_LONG
        - exactly one '@' at top level; quoted local parts ("john doe"@x.fr)
          are accepted on receive, preserved in raw, and canonicalized
          with quotes retained
        - ERR_ADDR_SYNTAX on failure

Step 2  DOMAIN NORMALIZATION
        - Unicode domain → IDNA2008 processing (UTS #46, transitional=false)
        - produce domain_alabel (punycode) and domain_ulabel
        - lowercase (A-label is ASCII, so ASCII lowercase)
        - reject empty labels, leading/trailing hyphens per IDNA
        - ERR_ADDR_DOMAIN on failure

Step 3  LOCAL PART UNICODE NORMALIZATION
        a. NFC-normalize (always — even pure ASCII passes through unchanged)
        b. strip format-class codepoints (Unicode category Cf: zero-width
           space U+200B, ZWJ/ZWNJ, bidi controls U+202A–U+202E, etc.)
           from the local part; if any were present, raise the
           INVISIBLE_CHARS confusable flag (§7). This stripping is a
           normalization operation of this pipeline — distinct from
           confusable *flags*, which never alter the canonical form.
        c. is_eai := (local part contains any non-ASCII codepoint)

Step 4  LOCAL PART CASE POLICY          [tenant policy]
        - applies to UNQUOTED local parts only; a quoted local part
          ("Jean Dupont"@x.fr) is always preserved verbatim, byte-for-byte,
          regardless of policy (quoting is an explicit request for literal
          interpretation per RFC 5321)
        - if policy.local_case == "insensitive" (DEFAULT):
              casefold the local part (Unicode full case folding)
        - if policy.local_case == "sensitive":
              preserve case

Step 5  SUB-ADDRESSING POLICY           [tenant policy]
        - if policy.subaddress == "preserve" (DEFAULT):
              keep "+tag" intact
        - if policy.subaddress == "strip":
              remove first '+' and everything after it, in the local part only
              (never inside a quoted local part)

Step 6  ASSEMBLE
        - canonical := local_part + "@" + domain_alabel
        - compute remaining confusable_flags (§7) — flags are metadata,
          they NEVER alter the canonical form (the only content-altering
          operation tied to a flag is Step 3b, which is part of
          normalization itself)
```

## 3.3 Policy resolution rule

- **A24-POL-1**: `TenantAddressPolicy` is resolved from the **recipient's tenant** for recipient addresses, and from the **platform default policy** for external sender addresses (an external sender belongs to no tenant). Platform default: `local_case = insensitive`, `subaddress = preserve`.
- **A24-POL-2**: A tenant's policy is set at tenant creation, is audit-logged on change, and a change MUST trigger re-derivation of that tenant's Blind Index entries (A05 defines the migration job). Changing policy without re-derivation silently breaks search — this is a release-blocking migration, not an online toggle.
- **A24-POL-3**: For **IAM principal resolution**, the tenant is not yet known when only an address is presented. Resolution therefore proceeds: (1) canonicalize with platform default policy → (2) look up domain → tenant mapping (domains are tenant-owned, A11) → (3) if the tenant's policy differs from platform default, re-canonicalize with the tenant policy → (4) resolve principal. This two-pass rule guarantees the domain lookup itself never depends on tenant policy (domains are policy-independent by construction).

## 3.4 Error model

| Code | Meaning |
| ---- | ------- |
| `ERR_ADDR_SYNTAX` | Not parseable as RFC 5322 addr-spec |
| `ERR_ADDR_DOMAIN` | Domain fails IDNA2008 processing |
| `ERR_ADDR_TOO_LONG` | Exceeds length bound |
| `ERR_ADDR_CONTROL_CHARS` | Contains control characters |

Errors are terminal for the address, not for the message: an inbound message with one malformed recipient among several MUST still be delivered to the valid recipients, with the malformed one recorded in delivery metadata.

------

# 4. IAM Principal Resolution

- **A24-IAM-1**: `resolve_principal(canonical_address) -> iam_principal_uuid | NOT_FOUND` is the ONLY path from an address to a user. It queries the Diamy IAM directory through the A17 contract. Diamy Mail MUST NOT cache principal mappings beyond a short TTL (RECOMMENDED ≤ 60 s) because IAM revocation (mechanism per A17-TOK-2 — confirmation pending) must take effect promptly.
- **A24-IAM-2**: All internal foreign keys use the IAM principal UUIDv7 (CDM-ADDR-2). Canonical addresses persist only where the mail function requires them: the IAM directory (identity), per-message routing/delivery metadata (SMTP requires addresses), and the address records of §2. They MUST NOT be duplicated into any other table as a join key — joins go through the UUIDv7.
- **A24-IAM-3**: Address change (rename) is an IAM-side operation. On rename, Diamy Mail MUST: keep delivering mail sent to the old address for a tenant-configurable grace period (RECOMMENDED default 90 days) by maintaining an alias entry; mark the old address as `alias_of` the principal; and never reassign a retired address to a different principal within the same tenant for a minimum quarantine period (RECOMMENDED 12 months) to prevent mail misdelivery and account-takeover-by-recycling.

------

# 5. Blind Index Derivation Inputs

This annex owns the **input** to Blind Index derivation; A05 owns the keyed derivation itself.

- **A24-BI-1**: The Blind Index input for a sender or recipient is exactly the `canonical` field — never `raw`, never a re-normalized variant.
- **A24-BI-2**: The derivation is `BI = HMAC-SHA256(k_bi_user, canonical)` where `k_bi_user` is the per-user Blind Index key defined in A05. This annex mandates only: same `canonical` in → same BI out, across client and server implementations (guaranteed by §3.1 byte-identical requirement).
- **A24-BI-3**: For EAI sender addresses received from the Internet, the canonical form (NFC local part + A-label domain) is what enters the index. This is why CDM-I18N-6 requires Unicode-readiness even in a no-EAI-emission V1.

------

# 6. EAI / SMTPUTF8 Receive-Side Handling

V1 posture (CDM-I18N-4/5): accept on receive, do not generate on send.

- **A24-EAI-1**: The inbound gateway MUST accept SMTPUTF8 sessions and non-ASCII addresses in MAIL FROM / RCPT TO / message headers without rejection or mojibake. `raw` preserves the original bytes.
- **A24-EAI-2**: Reply flows MUST reuse `raw` verbatim in the outbound envelope when replying to an EAI correspondent. If the outbound relay path cannot negotiate SMTPUTF8 with the next hop, the submission MUST fail with a clear user-facing error (`ERR_EAI_RELAY_UNSUPPORTED`) rather than silently downgrading or mangling the address.
- **A24-EAI-3**: Mailbox provisioning (A11) MUST reject non-ASCII local parts in V1 (`ERR_EAI_PROVISIONING_DISABLED`), with the error message noting this is a version limitation, not an invalid address.
- **A24-EAI-4**: Display: `domain_ulabel` is shown to users; `domain_alabel` is what routing and alignment checks consume. The client MUST NOT display raw punycode (`xn--...`) except in the §7 warning context.

------

# 7. Homograph / Confusable Detection

Unicode addresses are legitimate; *confusable* ones are a phishing vector. Detection produces metadata flags consumed by the trust engine (A06) and the client UI. Flags NEVER modify the canonical form.

## 7.1 Flags (bitfield)

| Bit | Flag | Trigger |
| --- | ---- | ------- |
| 0 | `MIXED_SCRIPT_LOCAL` | Local part mixes scripts (e.g. Latin + Cyrillic) per UTS #39 mixed-script detection |
| 1 | `MIXED_SCRIPT_DOMAIN` | Any domain label mixes scripts |
| 2 | `CONFUSABLE_DOMAIN` | Domain's confusable skeleton (UTS #39 `skeleton()`) collides with (a) a domain in the recipient's correspondent history, or (b) the tenant's own domains |
| 3 | `PUNYCODE_LOOKALIKE` | U-label renders visually close to a known-brand ASCII domain in the platform lookalike list |
| 4 | `INVISIBLE_CHARS` | Address contained format-class codepoints (zero-width, ZWJ/ZWNJ, bidi controls) that were stripped by pipeline Step 3b. Control-class characters are rejected outright at Step 0. |

## 7.2 Consumption rules

- **A24-CONF-1**: `CONFUSABLE_DOMAIN` colliding with a correspondent-history domain is a **high-severity** trust signal (A06): "this looks like someone you know, but is not". This check runs on-device against the local reputation history, preserving the per-user privacy boundary (the server does not learn the user's correspondent graph).
- **A24-CONF-2**: When any flag is set, the client MUST display the address with an explicit script/punycode disclosure cue rather than the bare U-label.
- **A24-CONF-3**: The skeleton comparison table (UTS #39 confusables data) is versioned platform data; its version MUST be recorded in message trust metadata so past scores remain interpretable.

------

# 8. Observability Contract

Per A00 §11:

- counters: `addr_canon_total`, `addr_canon_errors_total{code}`, `addr_eai_received_total`, `addr_confusable_flagged_total{flag}`, `principal_resolution_total{result}`
- latency: `addr_canon_duration` (target: p99 < 100 µs — this function is on the hot path of every message), `principal_resolution_duration`
- audit events: tenant policy change (A24-POL-2), address rename/alias lifecycle (A24-IAM-3)

------

# 9. Test Vectors (Normative)

Implementations MUST pass all vectors. Policy = platform default (`insensitive`, `preserve`) unless stated.

| # | Input | Expected canonical | Notes |
| - | ----- | ------------------ | ----- |
| 1 | `Jean.Dupont@Example.FR` | `jean.dupont@example.fr` | Case folding both sides |
| 2 | `user+tag@example.fr` | `user+tag@example.fr` | Default preserves sub-address |
| 3 | `user+tag@example.fr` (policy: strip) | `user@example.fr` | Strip mode |
| 4 | `café@société.fr` (NFC input) | `café@xn--socit-esab.fr` | EAI local + IDN domain, NFC preserved, domain → A-label |
| 5 | `cafe\u0301@société.fr` (combining acute) | `café@xn--socit-esab.fr` | NFC folds U+0065 U+0301 → U+00E9; identical to #4 |
| 6 | `"jean dupont"@example.fr` | `"jean dupont"@example.fr` | Quoted local part preserved with quotes |
| 7 | `USER@EXAMPLE.FR` (policy: sensitive) | `USER@example.fr` | Domain always folds; local preserved |
| 8 | `=?utf-8?B?SsOpcsO0bWU=?= <j@example.fr>` | `j@example.fr` | Display-name decoded to `Jérôme`, canonical from addr-spec only |
| 9 | `user@xn--socit-esab.fr` | `user@xn--socit-esab.fr` | A-label input accepted as-is; `domain_ulabel = société.fr` |
| 10 | `pаypal@example.fr` (Cyrillic `а` U+0430) | `pаypal@example.fr` + `MIXED_SCRIPT_LOCAL` | Canonical keeps the codepoint; flag raised |
| 11 | `user@exam ple.fr` | `ERR_ADDR_SYNTAX` | Space in domain |
| 12 | `us\u200Ber@example.fr` (zero-width space) | `user@example.fr` + `INVISIBLE_CHARS` | Format-class codepoint stripped by Step 3b, flag raised |
| 13 | `"Jean Dupont"@example.fr` (policy: insensitive) | `"Jean Dupont"@example.fr` | Quoted local part preserved verbatim; casefold does NOT apply inside quotes (Step 4) |

Vector #5 equaling #4 is the single most important property in this table: it is what CDM-I18N-9 protects.

------

# 10. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Implementing normalization twice (client TS + server Rust) with divergent Unicode library behavior. The shared test vectors (§9) MUST run in both implementations' CI; a vector mismatch is release-blocking.
2. ❌ Using NFKC instead of NFC. NFKC folds compatibility characters (e.g. `ﬁ` ligature → `fi`) and changes user-visible identity; only NFC is authorized.
3. ❌ Applying IDNA *transitional* processing (which maps `ß` → `ss`); this annex mandates IDNA2008 / UTS #46 with `transitional=false`.
4. ❌ Lowercasing the local part with ASCII `to_lower()` instead of Unicode case folding when policy is `insensitive` — breaks on non-ASCII local parts.
5. ❌ Deriving the Blind Index from `raw` or from a re-parsed address instead of the stored `canonical` field.
6. ❌ Letting confusable detection modify the canonical form. Flags are metadata; canonical is stable.
7. ❌ Caching principal resolution longer than the revocation-invalidation TTL (A24-IAM-1, mechanism per A17-TOK-2), so a revoked IAM principal keeps receiving mail.
8. ❌ Stripping `+tag` in one code path (e.g. delivery) but not the other (e.g. Blind Index) because the policy object wasn't threaded through — the policy MUST be an explicit parameter of `diamy_addr_canon()`, never ambient state.
9. ❌ Rejecting a whole inbound message because one recipient address fails canonicalization (§3.4 — per-address error, not per-message).
10. ❌ Displaying raw punycode to end users outside the confusable-warning context, or conversely displaying a bare U-label when a confusable flag is set.

------

# 11. Deferred Items

- Full EAI emission support (Unicode local-part provisioning) — policy switch prepared by CDM-I18N-6, activation is a future revision of this annex plus A10/A11 changes.
- Platform lookalike/brand list governance (who curates it, update cadence) — to be defined with the A06 threat-intelligence integration.
- Alias graph beyond simple rename (distribution lists, shared mailboxes) — owned by a future annex; this annex only guarantees the alias primitive (A24-IAM-3).

------

*End of document.*
