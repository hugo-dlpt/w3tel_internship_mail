# Diamy Mail — ANNEX A21: Storage Schema DDL

**Document title:** Diamy Mail — ANNEX A21: Storage Schema (Physical DDL)
**Version:** 1.6
**Status:** Internal Draft
**Author:** Cédric BORNECQUE
**Date:** July 4th 2026
**Confidentiality:** Internal document – W3TEL / TEQTEL
**Parent document:** Diamy Mail — Master Architecture Specification v1.3 (A00)
**Sibling dependencies:** A02 (Storage v1.1), A05 (Search v1.1), A11 (Onboarding v1.1), A17 (IAM v1.2), A23 (Outbound Allocation v1.1)

------

## Version history

| Version | Date         | Author           | Changelog                |
| ------- | ------------ | ---------------- | ------------------------ |
| 1.0     | Jul 4th 2026 | Cédric BORNECQUE | Initial document: consolidated physical PostgreSQL DDL for the server data planes — mail catalogue (messages, blobs, envelopes, folders, journal), mail device-key directory, webmail Blind-Index tables, outbound control-plane (servers, pools, allocations), domain onboarding state. Source-of-truth precedence over prose annexes. Field classification annotations, constraints, indexes, FK integrity, plane separation, migration discipline. |
| 1.1     | Jul 4th 2026 | Cédric BORNECQUE | Review pass: executed the DDL against the real PostgreSQL grammar (libpg_query) — caught and fixed a forward-reference bug where `send.servers` referenced `send.pools` before it was defined (`CREATE TABLE send.servers` would have failed); reordered the `send` schema to pools → servers → allocations and added creation-order rule A21-SEND-0. Full DDL now parses cleanly (33 statements). |
| 1.2     | Jul 4th 2026 | Cédric BORNECQUE | Added the `cal` schema (§6bis) closing the pending calendar-DDL dependency flagged by A12: `cal.collections`, `cal.events` (with the event detail incl. RRULE as the single CIPHERTEXT `event_ct`), `cal.event_envelopes` (calendar analogue of mail envelopes), and `cal.freebusy_projection` (consented server-visible metadata per A15-PROJ-6, deliberately NOT ciphertext). Schema-level integrity: `cal_allday_chk` and `cal_tzid_chk` make the two most common timezone bugs (all-day-with-tz, zoned-without-TZID) database-level violations (A21-CAL-2); UNIQUE(principal_id,event_uid,recurrence_id) enforces the master/override model (A21-CAL-3). Added `cal` to plane separation (A21-X-1). Re-validated the full DDL against the real PostgreSQL grammar — 44 statements parse cleanly, no forward-reference bugs. |
| 1.3     | Jul 4th 2026 | Cédric BORNECQUE | Added §6ter closing the pending A27 (Shared Resources) DDL dependency: `keydir.resource_membership` (shared-mailbox role records — reuses the existing `keydir.mail_device_keys` table unchanged, keyed under the resource principal's own `principal_id`), `cal.delegation_grants` (calendar-delegation grant/revocation records, scope constrained to `calendar` only pending future mail-delegation), and `iam.groups`/`iam.group_members` (pure directory tables, no envelope/key linkage — a group is never a decryption target). Re-validated the full DDL against the real PostgreSQL grammar — 52 statements parse cleanly, no forward-reference bugs. |
| 1.4     | Jul 4th 2026 | Cédric BORNECQUE | Added §7ter: `keydir.app_keys`, implementing the Tier 2 Applicative AppKey model discovered on review of the Diamy IAM – Integration Specification v1.6 (A17 v1.4 §4.2bis) — hash-only storage, per-app/platform isolation, structurally independent of `keydir.mail_device_keys` (authenticates the client application, not the user/device). Re-validated the full DDL — 54 statements parse cleanly, no forward-reference bugs. |
| 1.6     | Jul 17th 2026 | Written by: session Claude Code — decided directly with Hugo DELEPORTE (in-session; a purely additive physical-schema decision with no annex conflict, not the kind of divergence that requires Cédric's arbitration per the v1.5 precedent) | **Added §2.7: `mail.journal` (A02 §4.4/A04-SYNC-1) is wired into the migrations for the first time** (the table was already fully specified here in §2.5 since v1.0 but never entered a `diamy-mail-storage` migration — see `SIMPLIFICATIONS.md`); copied verbatim into `0005_journal_and_idempotency.sql`, no change to its DDL. **Added `mail.idempotency_keys`** (new table, not previously in this DDL): required by A04-IDEM-1 ("the server MUST deduplicate: a repeated key returns the original result... without re-applying the effect") for the newly-implemented `/state/flags`/`/state/delete` endpoints (A04 §5.3, v1.4) — physical idempotency-record storage is an implementation detail A04 requires behaviorally but never specifies physically, consistent with A21's own role as "the physical schema source of truth" (§1) for details a prose annex leaves open. Stores the assigned journal sequence + the exact response JSON returned the first time, keyed by the client-supplied idempotency key (UUIDv7, A04-IDEM-1); a replay with the same key returns the stored response without re-executing the mutation, regardless of whether the replayed request body matches byte-for-byte (mismatch detection is not implemented — see `SIMPLIFICATIONS.md`). No retention/pruning job exists yet (A04-IDEM-1's "≥ 24h" is a floor, not a ceiling — rows are simply never deleted in this implementation). |
| 1.5     | Jul 15th 2026 | Written by: session Claude Code — decision arbitrated by: Cédric BORNECQUE (project referent) | **Aligned the `hold_queue` schema (§2.6) on the key-only release design of A01-HOLD-5.** _Authorship vs. arbitration (traceability): this schema edit and its migration were written by a Claude Code session; the underlying design decision was arbitrated by Cédric BORNECQUE. Cédric explicitly validated option (a) of the A01/A21 hold divergence — amend A21 to permit the key-only hold design, per A01-HOLD-5 — following the escalation documented in `SIMPLIFICATIONS.md`. His confirmation was given directly to Hugo (out-of-band communication, outside this repository); this changelog entry records that decision but is not itself the evidence of it._ Reason: A01-HOLD-1/4/5 require hold release to re-wrap **`k_msg` only** and to NEVER reconstruct body plaintext (A01 §13 err.#8 names body reconstruction at release as an error); the prior `hold_queue` DDL (a single `ciphertext` column documented as "full message encrypted under k_hold", with no `message_id`) structurally forced the opposite — the body was sealed whole under `k_hold` and rebuilt at release. This was the A01/A21 divergence escalated on 2026-07-15; the option (a) resolution (amend A21, not A01) is Cédric's, per the confirmation noted above. Changes to §2.6: (1) added `message_id UUID NOT NULL REFERENCES mail.messages(message_id) ON DELETE CASCADE` — a held message is now **catalogued in `mail.messages` and its blobs stored under `k_msg` at reception**, exactly like an ordinary delivery but with zero device envelopes (A01-HOLD-1); (2) the ciphertext column now holds **`k_msg` wrapped under `k_hold`** (renamed `ciphertext`→`wrapped_kmsg`, `hold_nonce`→`wrap_nonce`) — never the body, which lives untouched in `mail.blobs`; (3) `sender_canonical` is now preserved (it is the `mail.messages` row's own column, populated at reception) — the prior design lost it. Release therefore only unwraps `k_msg` from `k_hold` and produces normal per-device envelopes (A02-CRY-4) against the pre-existing `message_id`; the body ciphertext is bit-for-bit unchanged. Rewrote A21-HOLD-1, updated the `CIPHERTEXT`-column lists (A21-X-2, §9.7). This resolves the divergence flagged in the v1.4 code notes and in SIMPLIFICATIONS.md — the physical migration is `0004_hold_queue_key_only.sql` (0003 left intact, already applied; migration discipline A21-X-4). |

------

# Table of contents

[toc]

------

# 1. Scope and Authority

This annex is the **physical schema source of truth** for Diamy Mail's server-side stores (A02-CMP-2, CDM-NULL-2). Where a prose annex describes a field logically and this DDL defines it physically, **this DDL prevails**. It consolidates the tables scattered across A02 (catalogue/blobs/envelopes/folders/journal), A17 (device-key directory), A05 (Blind-Index), A23 (outbound control-plane), and A11 (domain onboarding state) into one coherent schema with constraints, keys, and indexes.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted per RFC 2119 / RFC 8174.

## 1.1 What is NOT here

The **client** local store (A03) is SQLCipher on-device and is deliberately separate — it is not server schema and is defined by A03. The **blob object store** (S3-compatible) is not relational; only its catalogue references live here. IAM's own schema is owned by the IAM corpus; this annex references IAM IDs as external keys, never redefines IAM tables.

## 1.2 Conventions

- All IDs are `UUID` holding UUIDv7 values (CDM-ID-1); time-ordered, index-friendly.
- Timestamps are `TIMESTAMPTZ`, UTC, RFC 3339 on the wire (CDM-TS-1).
- Ciphertext is `BYTEA`; JSON metadata is `JSONB`.
- Every field carries a classification comment: `PLAINTEXT_METADATA`, `CIPHERTEXT`, or `BLIND_INDEX` (CDM-ENC-1). A `CIPHERTEXT` column is opaque to the server (CDM-ENC-2 forbids reclassification without a migration entry).
- Schemas partition the planes: `mail` (data plane), `keydir` (device keys), `search` (Blind-Index, webmail-only), `send` (outbound control-plane), `onboard` (domain state).

------

# 2. Data Plane — schema `mail`

## 2.1 Folders

```sql
CREATE TABLE mail.folders (
    folder_id       UUID PRIMARY KEY,                    -- PLAINTEXT_METADATA, UUIDv7
    principal_id    UUID NOT NULL,                       -- PLAINTEXT_METADATA, IAM principal (external)
    tenant_id       UUID NOT NULL,                       -- PLAINTEXT_METADATA
    parent_id       UUID NULL REFERENCES mail.folders(folder_id) ON DELETE RESTRICT,
    name_ct         BYTEA NOT NULL,                      -- CIPHERTEXT: folder name encrypted client-side (k_folder, A03-KEY-3)
    system_kind     TEXT NULL,                           -- PLAINTEXT_METADATA: 'inbox'|'sent'|'drafts'|'trash'|NULL (well-known marker)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT folders_system_kind_chk
        CHECK (system_kind IS NULL OR system_kind IN ('inbox','sent','drafts','trash','archive','junk'))
);
CREATE INDEX idx_folders_principal ON mail.folders(principal_id);
```

- **A21-FLD-1**: `name_ct` is CIPHERTEXT — the server stores only a UUID and an opaque name (A02-DM-1). `system_kind` is metadata so system folders are addressable without decrypting the name.

## 2.2 Messages (catalogue)

```sql
CREATE TABLE mail.messages (
    message_id              UUID PRIMARY KEY,            -- PLAINTEXT_METADATA, UUIDv7 (CDM-ID-3)
    principal_id            UUID NOT NULL,               -- PLAINTEXT_METADATA, owner (A17-RES)
    tenant_id               UUID NOT NULL,               -- PLAINTEXT_METADATA
    direction               TEXT NOT NULL,               -- PLAINTEXT_METADATA
    folder_id               UUID NOT NULL REFERENCES mail.folders(folder_id) ON DELETE RESTRICT,
    sender_canonical        TEXT NULL,                   -- PLAINTEXT_METADATA (inbound), A24 canonical
    recipients_canonical    TEXT[] NOT NULL DEFAULT '{}',-- PLAINTEXT_METADATA, MINIMIZED (A02-DM-4): owner + routing only, BCC never
    rfc5322_message_id_hash BYTEA NULL,                  -- PLAINTEXT_METADATA, hash only (never raw external Message-ID)
    received_at             TIMESTAMPTZ NULL,            -- PLAINTEXT_METADATA (inbound)
    sent_at                 TIMESTAMPTZ NULL,            -- PLAINTEXT_METADATA (outbound)
    size_bytes              BIGINT NOT NULL,             -- PLAINTEXT_METADATA
    summary_ct              BYTEA NOT NULL,              -- CIPHERTEXT: encrypted summary record (A02-CRY-3)
    summary_nonce           BYTEA NOT NULL,              -- PLAINTEXT_METADATA: GCM nonce for summary_ct
    trust_metadata          JSONB NULL,                  -- PLAINTEXT_METADATA (inbound): A06/A07 verdicts + A16 classification
    state_flags             JSONB NOT NULL DEFAULT '{}', -- PLAINTEXT_METADATA: read/answered/flagged/deleted-tombstone
    blob_alg_version        INT NOT NULL DEFAULT 1,      -- PLAINTEXT_METADATA (A02-CRY-7)
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT messages_direction_chk CHECK (direction IN ('inbound','outbound','internal')),
    CONSTRAINT messages_time_chk
        CHECK ((direction = 'inbound'  AND received_at IS NOT NULL)
            OR (direction IN ('outbound','internal') AND sent_at IS NOT NULL))
);
CREATE INDEX idx_messages_principal_folder ON mail.messages(principal_id, folder_id);
CREATE INDEX idx_messages_principal_received ON mail.messages(principal_id, received_at DESC);
CREATE INDEX idx_messages_tenant ON mail.messages(tenant_id);
CREATE INDEX idx_messages_rfc_hash ON mail.messages(rfc5322_message_id_hash) WHERE rfc5322_message_id_hash IS NOT NULL;
```

- **A21-MSG-1**: `summary_ct` is the ONLY body-derived content in this table and it is CIPHERTEXT (server cannot read, A02-CRY-3). `trust_metadata` and `state_flags` are JSONB metadata by design (they must be queryable/servable without decryption — CMP-BND-1). `trust_metadata` embeds the A16 `classification` object (A16-PLACE-1).
- **A21-MSG-2**: `recipients_canonical` is MINIMIZED (A02-DM-4): it holds the owner + routing-necessary addresses only; full display recipient lists live inside `summary_ct`. A BCC address MUST NEVER be written here for any recipient other than the sender's own Sent copy. This is a schema-enforced privacy rule; the application layer is responsible (Postgres cannot express it), so it is a REQUIRED application invariant referenced here.

## 2.3 Blobs (catalogue references to object store)

```sql
CREATE TABLE mail.blobs (
    blob_id         UUID PRIMARY KEY,                    -- PLAINTEXT_METADATA, UUIDv7 (NOT a content hash, A02-CMP-1)
    message_id      UUID NOT NULL REFERENCES mail.messages(message_id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,                       -- PLAINTEXT_METADATA
    object_key      TEXT NOT NULL,                       -- PLAINTEXT_METADATA: opaque object-store locator
    nonce           BYTEA NOT NULL,                      -- PLAINTEXT_METADATA: GCM nonce (independent per blob, A02-CRY-1b)
    size_bytes      BIGINT NOT NULL,                     -- PLAINTEXT_METADATA
    sha512_ct       BYTEA NOT NULL,                      -- PLAINTEXT_METADATA: digest of CIPHERTEXT (never plaintext, A02)
    blob_alg_version INT NOT NULL DEFAULT 1,
    CONSTRAINT blobs_kind_chk CHECK (kind IN ('body','attachment'))
);
CREATE INDEX idx_blobs_message ON mail.blobs(message_id);
CREATE UNIQUE INDEX idx_blobs_object_key ON mail.blobs(object_key);
```

- **A21-BLOB-1**: `sha512_ct` is a digest of the CIPHERTEXT, for storage-integrity only. A plaintext digest MUST NOT be stored (equality oracle, A02). `blob_id` is a UUIDv7, never a content hash (dedup ban, A02-CMP-1 / A02-CRY-6).

## 2.4 Envelopes (per-message-per-device wrapped keys)

```sql
CREATE TABLE mail.envelopes (
    message_id      UUID NOT NULL REFERENCES mail.messages(message_id) ON DELETE CASCADE,
    device_id       UUID NOT NULL,                       -- PLAINTEXT_METADATA (external, keydir)
    kem_ct          BYTEA NOT NULL,                      -- PLAINTEXT_METADATA¹ (1088 B, ML-KEM-768 ciphertext)
    wrapped_key     BYTEA NOT NULL,                      -- PLAINTEXT_METADATA¹ (k_msg wrapped under k_wrap)
    wrap_nonce      BYTEA NOT NULL,                      -- PLAINTEXT_METADATA
    alg_version     INT NOT NULL DEFAULT 1,              -- PLAINTEXT_METADATA (A02-CRY-7)
    origin          TEXT NOT NULL,                       -- PLAINTEXT_METADATA: 'frontier'|'sender_device'|'rewrap:<device_id>'
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (message_id, device_id)                  -- one active envelope per (message,device), A02-DM-3
);
CREATE INDEX idx_envelopes_device ON mail.envelopes(device_id);
```

¹ `kem_ct` / `wrapped_key` are cryptographically opaque to the server (it holds no ML-KEM private key) but are classified PLAINTEXT_METADATA because the server must serve them per device without any decryption semantics (A02 §4.3 footnote).

- **A21-ENV-1**: Primary key `(message_id, device_id)` enforces at most one active envelope per pair; re-wrap (A02-RW) replaces atomically (an `UPSERT` on the PK). `origin` records provenance for audit.

## 2.5 Sync journal (append-only)

```sql
CREATE TABLE mail.journal (
    seq             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- monotonic sequence; LWW authority (A03-SYNC-1)
    principal_id    UUID NOT NULL,                       -- PLAINTEXT_METADATA
    event_type      TEXT NOT NULL,                       -- PLAINTEXT_METADATA
    message_id      UUID NULL,                           -- PLAINTEXT_METADATA (event target)
    device_id       UUID NULL,                           -- PLAINTEXT_METADATA (for envelope events)
    payload         JSONB NULL,                          -- PLAINTEXT_METADATA: IDs + flags ONLY, NEVER content (API-5)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT journal_event_chk CHECK (event_type IN
        ('message_added','message_deleted','flags_changed','folder_changed','envelope_added','envelope_revoked'))
);
CREATE INDEX idx_journal_principal_seq ON mail.journal(principal_id, seq);
```

- **A21-JRN-1**: `seq` is the monotonic authority for cursor sync (A04-SYNC-1) and per-field LWW conflict resolution (A03-SYNC-1). `payload` MUST contain IDs and flags only, never message content (API-5) — a schema-adjacent application invariant (Postgres cannot enforce "no content", so it is a REQUIRED discipline). Retention/compaction: events MAY be compacted once all devices' cursors passed, floor 30 days (A02 §4.4); a compaction job enforces this.

## 2.6 Gateway hold queue (zero-active-device recipients)

```sql
CREATE TABLE mail.hold_queue (
    hold_id         UUID PRIMARY KEY,                    -- UUIDv7
    principal_id    UUID NOT NULL,                       -- PLAINTEXT_METADATA (recipient with no active device)
    tenant_id       UUID NOT NULL,                       -- PLAINTEXT_METADATA
    message_id      UUID NOT NULL                        -- PLAINTEXT_METADATA: the ALREADY-CATALOGUED message (A01-HOLD-1)
                        REFERENCES mail.messages(message_id) ON DELETE CASCADE,
    wrapped_kmsg    BYTEA NOT NULL,                      -- CIPHERTEXT: k_msg (ONLY) wrapped under server-side k_hold (A01-HOLD-1/5) — NEVER the body
    wrap_nonce      BYTEA NOT NULL,                      -- PLAINTEXT_METADATA: GCM nonce for wrapped_kmsg
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,                -- default +30d (A01-HOLD, tunable per onboarding profile A11-SEQ-4)
    CONSTRAINT hold_expiry_chk CHECK (expires_at > received_at)
);
CREATE INDEX idx_hold_principal ON mail.hold_queue(principal_id);
CREATE INDEX idx_hold_expiry ON mail.hold_queue(expires_at);
CREATE INDEX idx_hold_message ON mail.hold_queue(message_id);
```

- **A21-HOLD-1**: The hold queue is the ONE data-plane store where the server holds a **wrapped `k_msg` it can itself unwrap** (`k_hold`, a declared bounded exception, A01-HOLD / A00 §3.2). It follows the **key-only** discipline of A01-HOLD-1/5 (which mirrors delegated re-wrap, A02-RW-1 — the frontier handles a *key*, never re-decrypts content): a held message is catalogued in `mail.messages` and its body/attachment/summary blobs stored under a fresh `k_msg` **at reception**, exactly like an ordinary delivery but with **zero** rows in `mail.envelopes` (no active device to wrap for yet). The `hold_queue` row carries only `k_msg` wrapped under `k_hold` (`wrapped_kmsg`), linked to that catalogued message by `message_id`. On the recipient's first device enrollment (A01-HOLD-4), release unwraps `k_msg` from `k_hold`, produces normal per-device envelopes (A02-CRY-4) against the **pre-existing** `message_id`, and deletes the hold row — **the body ciphertext in `mail.blobs` is never touched** (bit-for-bit unchanged). `k_hold` is held in the secret store, never here. This is why `message_id` is a real FK with `ON DELETE CASCADE`: deleting the catalogue message removes its hold row too, and the hold row can never reference a message that does not exist. `sender_canonical` and every other catalogue field are the `mail.messages` row's own columns — preserved through hold and release, never lost.

------

## 2.7 Idempotency keys (A04-IDEM-1)

```sql
CREATE TABLE mail.idempotency_keys (
    idempotency_key UUID PRIMARY KEY,                    -- client-supplied UUIDv7 (A04-IDEM-1)
    principal_id    UUID NOT NULL,                       -- PLAINTEXT_METADATA
    endpoint        TEXT NOT NULL,                        -- PLAINTEXT_METADATA: 'state/flags'|'state/delete'
    response_body   JSONB NOT NULL,                       -- PLAINTEXT_METADATA: exact response returned the first time
    journal_seq     BIGINT NOT NULL,                      -- the sequence assigned on first execution (A04-EP-4)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT idempotency_endpoint_chk CHECK (endpoint IN ('state/flags','state/delete'))
);
CREATE INDEX idx_idempotency_principal ON mail.idempotency_keys(principal_id);
```

- **A21-IDEM-1**: One row per client-supplied idempotency key, never overwritten after first insert (`INSERT ... ON CONFLICT DO NOTHING`-style — a second attempt to execute under the same key MUST read the existing row and return it, never re-run the mutation). `response_body` is PLAINTEXT_METADATA: it carries only IDs/sequences/booleans (the same fields the live endpoint response carries), never ciphertext — a state op never touches `summary_ct`/`body_ct`/envelopes (A21-X-2 continues to hold: nothing here is CIPHERTEXT because nothing here is content).
- **A21-IDEM-2** (no request-body equality check): A21-IDEM-1's replay returns the stored response for a given key regardless of whether the replayed request body matches the original — this implementation does not hash/compare the request body to detect a key reused across two different logical requests. This is a known gap, not a silent one (see `SIMPLIFICATIONS.md`); A04-IDEM-1's text does not specify behavior on a body mismatch, so no behavior is invented here beyond "same key → same stored result."

------

# 3. Device-Key Directory — schema `keydir`

```sql
CREATE TABLE keydir.mail_device_keys (
    principal_id    UUID NOT NULL,                       -- PLAINTEXT_METADATA (IAM external)
    device_id       UUID NOT NULL,                       -- PLAINTEXT_METADATA
    mlkem_pub       BYTEA NOT NULL,                      -- PLAINTEXT_METADATA: ML-KEM-768 public key (A17-KEY-2)
    dilithium_sig   BYTEA NOT NULL,                      -- PLAINTEXT_METADATA: signature over the bundle (A17-KEY-3)
    signing_device  UUID NOT NULL,                       -- PLAINTEXT_METADATA: device whose Dilithium identity signed
    validity_state  TEXT NOT NULL DEFAULT 'active',      -- PLAINTEXT_METADATA
    published_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, device_id),
    CONSTRAINT keydir_state_chk CHECK (validity_state IN ('active','revoked'))
);
CREATE INDEX idx_keydir_principal_active ON keydir.mail_device_keys(principal_id) WHERE validity_state = 'active';
```

- **A21-KEY-1**: The directory stores public keys + signatures only (A17-DIR-1). The server verifies `dilithium_sig` against the IAM key directory before accepting a bundle (A17-KEY-3) — a write-time application check. Revocation flips `validity_state`; a revoked device's envelopes are no longer produced and its sessions are severed (A17-TOK-5).

------

# 4. Webmail Blind-Index — schema `search` (webmail-only)

These tables exist and receive rows ONLY when webmail is enabled for the user (A05-BI-1); disabling webmail purges the user's rows (A05-BI-6).

```sql
CREATE TABLE search.blind_index_keyword (
    principal_id    UUID NOT NULL,                       -- PLAINTEXT_METADATA
    message_id      UUID NOT NULL REFERENCES mail.messages(message_id) ON DELETE CASCADE,
    bi_kw           BYTEA NOT NULL,                      -- BLIND_INDEX: HMAC(k_bi_kw_user, normalize_kw(kw)) (A05-BI-2)
    PRIMARY KEY (principal_id, message_id, bi_kw)
);
CREATE INDEX idx_bi_kw_lookup ON search.blind_index_keyword(principal_id, bi_kw);

CREATE TABLE search.blind_index_addr (
    principal_id    UUID NOT NULL,                       -- PLAINTEXT_METADATA
    message_id      UUID NOT NULL REFERENCES mail.messages(message_id) ON DELETE CASCADE,
    bi_addr         BYTEA NOT NULL,                      -- BLIND_INDEX: HMAC(k_bi_addr_user, canonical_address) (A05-ADDR-1)
    direction       TEXT NOT NULL,                       -- PLAINTEXT_METADATA: 'from'|'to'
    PRIMARY KEY (principal_id, message_id, bi_addr, direction)
);
CREATE INDEX idx_bi_addr_lookup ON search.blind_index_addr(principal_id, bi_addr);
```

- **A21-BI-1**: `bi_kw` / `bi_addr` are BLIND_INDEX: HMAC outputs the server matches but cannot invert (the per-user key never reaches the server, A05-KEY-2). The server sees tokens, never keywords or addresses. `ON DELETE CASCADE` from `mail.messages` ensures index rows vanish with their message; webmail-disable purge is a separate bulk delete (A05-BI-6).

------

# 5. Outbound Control-Plane — schema `send`

Pure control-plane infrastructure metadata; NO message content ever (A23-DM-1, OPS-SEND-8).

```sql
CREATE TABLE send.pools (
    pool_id         UUID PRIMARY KEY,                    -- UUIDv7
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL,                       -- 'shared'|'dedicated'|'hybrid-component'
    reputation_state TEXT NOT NULL DEFAULT 'unknown',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pools_kind_chk CHECK (kind IN ('shared','dedicated','hybrid-component'))
);

CREATE TABLE send.servers (
    server_id       UUID PRIMARY KEY,                    -- UUIDv7
    egress_ips      INET[] NOT NULL,                     -- outbound IPs
    pool_id         UUID NULL REFERENCES send.pools(pool_id) ON DELETE SET NULL,  -- at most one pool (OPS-SEND-2)
    max_connections INT NOT NULL,                        -- capacity envelope (OPS-SEND-1)
    max_msgs_interval INT NOT NULL,
    health_state    TEXT NOT NULL DEFAULT 'healthy',
    ptr_verified    BOOLEAN NOT NULL DEFAULT false,      -- forward-confirmed rDNS (A10-BULK-2)
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT servers_health_chk CHECK (health_state IN ('healthy','degraded','unhealthy','draining'))
);

CREATE TABLE send.allocations (
    tenant_id           UUID PRIMARY KEY,                -- one allocation per tenant (OPS-SEND-3)
    primary_pool_id     UUID NOT NULL REFERENCES send.pools(pool_id),
    fallback_pool_ids   UUID[] NOT NULL DEFAULT '{}',    -- ordered
    mode                TEXT NOT NULL,                   -- 'shared'|'dedicated'|'hybrid'
    hybrid_rules        JSONB NULL,                      -- present iff mode='hybrid' (A23-MODE-3)
    bulk_identity_pool_id UUID NULL REFERENCES send.pools(pool_id),
    updated_by          UUID NOT NULL,                   -- admin actor (audit, OPS-SEND-3)
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT alloc_mode_chk CHECK (mode IN ('shared','dedicated','hybrid')),
    CONSTRAINT alloc_hybrid_rules_chk CHECK ((mode = 'hybrid') = (hybrid_rules IS NOT NULL))
);
```

- **A21-SEND-0** (creation order): `send.pools` MUST be created before `send.servers` and `send.allocations`, since both reference it (FK). This DDL is ordered accordingly; a migration tool MUST preserve this order (pools → servers → allocations).

- **A21-SEND-1**: `send.servers.pool_id` enforces at-most-one-pool per server (OPS-SEND-2). `alloc_hybrid_rules_chk` enforces `hybrid_rules` present iff mode is hybrid. The `egress_ips` across a tenant's pools MUST be consistent with its published SPF (A23-SPF-1) — a cross-table invariant enforced by the onboarding/allocation application logic (A11/A23), not expressible as a single CHECK.

------

# 6. Domain Onboarding — schema `onboard`

```sql
CREATE TABLE onboard.domains (
    domain_id       UUID PRIMARY KEY,                    -- UUIDv7
    tenant_id       UUID NOT NULL,                       -- PLAINTEXT_METADATA
    domain_alabel   TEXT NOT NULL,                       -- PLAINTEXT_METADATA: IDNA2008 A-label (A11-CTRL-2 / A24)
    state           TEXT NOT NULL,                       -- onboarding sub-state (A11-PEND-1)
    onboard_profile TEXT NOT NULL DEFAULT 'sequenced',   -- 'sequenced'|'bulk' (A11-SEQ-4)
    spf_verified    BOOLEAN NOT NULL DEFAULT false,
    dkim_verified   BOOLEAN NOT NULL DEFAULT false,
    dmarc_policy    TEXT NULL,                           -- 'none'|'quarantine'|'reject' when present (A11-DMARC)
    mx_verified     BOOLEAN NOT NULL DEFAULT false,
    send_enabled    BOOLEAN NOT NULL DEFAULT false,      -- fail-closed gate (A11-GATE-1)
    receive_enabled BOOLEAN NOT NULL DEFAULT false,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT onboard_state_chk CHECK (state IN
        ('awaiting_domain_control','awaiting_dns_publish','awaiting_propagation',
         'receive_active_send_pending','fully_active')),
    CONSTRAINT onboard_profile_chk CHECK (onboard_profile IN ('sequenced','bulk')),
    CONSTRAINT onboard_dmarc_chk CHECK (dmarc_policy IS NULL OR dmarc_policy IN ('none','quarantine','reject')),
    CONSTRAINT onboard_send_gate_chk
        CHECK (send_enabled = false OR (spf_verified AND dkim_verified AND dmarc_policy IS NOT NULL)),
    UNIQUE (tenant_id, domain_alabel)
);
CREATE INDEX idx_onboard_tenant ON onboard.domains(tenant_id);
```

- **A21-ONB-1**: `onboard_send_gate_chk` **enforces the fail-closed sending gate at the schema level** (A11-GATE-1): `send_enabled` cannot be true unless SPF, DKIM, and DMARC are all present/verified. This makes the most safety-critical onboarding rule a database constraint, not merely application logic — a defense-in-depth win (an application bug cannot flip send-enabled without the DNS prerequisites).

------

# 6bis. Calendar — schema `cal`

The calendar tables (A12–A15) follow the same CIPHERTEXT/metadata classification and envelope-reuse discipline as `mail`. Calendar objects reuse the mail envelope model (A12-STO-1); `cal.event_envelopes` is the calendar analogue of `mail.envelopes`.

```sql
CREATE TABLE cal.collections (
    collection_id   UUID PRIMARY KEY,                    -- UUIDv7
    principal_id    UUID NOT NULL,                       -- PLAINTEXT_METADATA (IAM external)
    tenant_id       UUID NOT NULL,                       -- PLAINTEXT_METADATA
    name_ct         BYTEA NOT NULL,                      -- CIPHERTEXT: collection name (client-encrypted, A12-STO-2)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_cal_collections_principal ON cal.collections(principal_id);

CREATE TABLE cal.events (
    event_row_id    UUID PRIMARY KEY,                    -- UUIDv7 internal row id
    event_uid       TEXT NOT NULL,                       -- PLAINTEXT_METADATA: RFC 5545 UID, immutable (A12-EVT-3), echoed verbatim (A14-MATCH-3)
    principal_id    UUID NOT NULL,                       -- PLAINTEXT_METADATA
    tenant_id       UUID NOT NULL,                       -- PLAINTEXT_METADATA
    collection_id   UUID NOT NULL REFERENCES cal.collections(collection_id) ON DELETE RESTRICT,
    recurrence_id   TEXT NULL,                           -- PLAINTEXT_METADATA: NULL = master; set = override instance (A12-REC-2)
    sequence        INT NOT NULL DEFAULT 0,              -- PLAINTEXT_METADATA: iTIP revision (A14-MATCH-1)
    dtstart         TIMESTAMPTZ NULL,                    -- PLAINTEXT_METADATA: master start (metadata for sync; A12-META). NULL for all-day (see dtstart_date)
    dtend           TIMESTAMPTZ NULL,                    -- PLAINTEXT_METADATA
    dtstart_date    DATE NULL,                           -- PLAINTEXT_METADATA: all-day date-only (A13-VAL-5); mutually exclusive with dtstart
    tzid            TEXT NULL,                            -- PLAINTEXT_METADATA: IANA TZID for zoned events (A13-VAL-1); NULL for UTC/floating/all-day
    time_kind       TEXT NOT NULL DEFAULT 'zoned',       -- PLAINTEXT_METADATA: 'zoned'|'utc'|'floating'|'all_day' (A13-VAL)
    status          TEXT NULL,                           -- PLAINTEXT_METADATA: tentative/confirmed/cancelled (A12)
    transparency    TEXT NOT NULL DEFAULT 'opaque',      -- PLAINTEXT_METADATA: opaque/transparent (free/busy, A15-FB-2)
    class           TEXT NOT NULL DEFAULT 'private',     -- PLAINTEXT_METADATA: public/private/confidential (A12, A15-FB-3)
    event_ct        BYTEA NOT NULL,                      -- CIPHERTEXT: full event detail (title/description/location/attendees/RRULE/alarms) (A12-EVT-2, A12-META-3)
    event_nonce     BYTEA NOT NULL,                      -- PLAINTEXT_METADATA: GCM nonce for event_ct
    alg_version     INT NOT NULL DEFAULT 1,
    created         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_modified   TIMESTAMPTZ NOT NULL DEFAULT now(),
    dtstamp         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT cal_time_kind_chk CHECK (time_kind IN ('zoned','utc','floating','all_day')),
    CONSTRAINT cal_status_chk CHECK (status IS NULL OR status IN ('tentative','confirmed','cancelled')),
    CONSTRAINT cal_transp_chk CHECK (transparency IN ('opaque','transparent')),
    CONSTRAINT cal_class_chk CHECK (class IN ('public','private','confidential')),
    CONSTRAINT cal_allday_chk CHECK (
        (time_kind = 'all_day' AND dtstart_date IS NOT NULL AND dtstart IS NULL)
     OR (time_kind <> 'all_day' AND dtstart IS NOT NULL AND dtstart_date IS NULL)),
    CONSTRAINT cal_tzid_chk CHECK (
        (time_kind = 'zoned' AND tzid IS NOT NULL)
     OR (time_kind <> 'zoned')),
    UNIQUE (principal_id, event_uid, recurrence_id)      -- one master + distinct overrides per (uid, recurrence_id)
);
CREATE INDEX idx_cal_events_principal_collection ON cal.events(principal_id, collection_id);
CREATE INDEX idx_cal_events_uid ON cal.events(principal_id, event_uid);
CREATE INDEX idx_cal_events_dtstart ON cal.events(principal_id, dtstart) WHERE dtstart IS NOT NULL;

CREATE TABLE cal.event_envelopes (
    event_row_id    UUID NOT NULL REFERENCES cal.events(event_row_id) ON DELETE CASCADE,
    device_id       UUID NOT NULL,                       -- PLAINTEXT_METADATA
    kem_ct          BYTEA NOT NULL,                      -- PLAINTEXT_METADATA¹ (ML-KEM-768 ciphertext)
    wrapped_key     BYTEA NOT NULL,                      -- PLAINTEXT_METADATA¹ (k_event wrapped)
    wrap_nonce      BYTEA NOT NULL,                      -- PLAINTEXT_METADATA
    alg_version     INT NOT NULL DEFAULT 1,
    origin          TEXT NOT NULL,                       -- PLAINTEXT_METADATA: frontier/sender_device/rewrap
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (event_row_id, device_id)                -- one active envelope per (event,device), mirrors A21-ENV-1
);
CREATE INDEX idx_cal_env_device ON cal.event_envelopes(device_id);

CREATE TABLE cal.freebusy_projection (
    principal_id    UUID NOT NULL,                       -- PLAINTEXT_METADATA
    tenant_id       UUID NOT NULL,                       -- PLAINTEXT_METADATA
    busy_start      TIMESTAMPTZ NOT NULL,                -- CONSENTED METADATA (A15-PROJ-6): NOT ciphertext — server reads to answer queries
    busy_end        TIMESTAMPTZ NOT NULL,                -- CONSENTED METADATA
    fbtype          TEXT NOT NULL DEFAULT 'busy',        -- PLAINTEXT_METADATA: busy/busy-tentative/busy-unavailable (A15-FB-1)
    scope           TEXT NOT NULL DEFAULT 'internal',    -- PLAINTEXT_METADATA: consent scope 'internal'|'external'|'public' (A15-CONSENT-2)
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fb_interval_chk CHECK (busy_end > busy_start),
    CONSTRAINT fb_type_chk CHECK (fbtype IN ('busy','busy-tentative','busy-unavailable')),
    CONSTRAINT fb_scope_chk CHECK (scope IN ('internal','external','public'))
);
CREATE INDEX idx_cal_fb_principal_window ON cal.freebusy_projection(principal_id, busy_start, busy_end);
```

¹ `kem_ct` / `wrapped_key` are opaque to the server (no ML-KEM private key), classified metadata (mirrors A21 §2.4 footnote).

- **A21-CAL-1**: `cal.events.event_ct` is the ONE ciphertext field carrying all event detail — title, description, location, attendees, **RRULE**, alarms (A12-EVT-2, A12-META-3). The metadata columns (`dtstart`/`dtend`/`tzid`/`status`/`transparency`/`class`) are the minimal scheduling metadata (A12-META-1). The server cannot read `event_ct`; recurrence expansion is client-side (A12-REC-7).
- **A21-CAL-2** (all-day / timezone integrity): `cal_allday_chk` enforces the all-day vs timed mutual exclusion (A13-VAL-5: all-day is date-only, never a timezone-bearing instant); `cal_tzid_chk` enforces that a `zoned` event carries a `tzid` (A13-VAL-1, preserving local intent — a zoned event without its TZID would drift, A13-VAL-4). These make the two most common timezone bugs schema-level violations.
- **A21-CAL-3** (override linkage): `UNIQUE (principal_id, event_uid, recurrence_id)` enforces one master (recurrence_id NULL) plus distinct override instances per series (A12-REC-2); the `event_uid` is immutable (A12-EVT-3) and echoed verbatim for foreign UIDs (A14-MATCH-3).
- **A21-CAL-4** (free/busy is consented metadata, NOT ciphertext): `cal.freebusy_projection.busy_start`/`busy_end` are deliberately **server-readable metadata** (A15-PROJ-6), NOT CIPHERTEXT — the server must read them to answer availability queries from other users. This is the single calendar datum that crosses from ciphertext to consented metadata, populated ONLY when the user enables free/busy (default-deny, A15-CONSENT-1). An implementer MUST NOT encrypt this table (that breaks free/busy); rows exist only for consenting users.

------

# 6ter. Shared Resources — schemas `keydir` (extended), `cal` (extended), `iam`

Implements A27. No new content-encryption model: `keydir.mail_device_keys` (§3) already keys on `principal_id`, so a resource principal's member devices are rows in that SAME table under the resource principal's `principal_id` — no schema change needed there. What's new is the **membership/role**, **delegation grant**, and **group** records, all metadata (who may access what, at what role), never content.

```sql
CREATE TABLE keydir.resource_membership (
    resource_principal_id UUID NOT NULL,                 -- PLAINTEXT_METADATA: the shared mailbox's principal_id
    member_principal_id   UUID NOT NULL,                 -- PLAINTEXT_METADATA: the human member
    role                   TEXT NOT NULL,                -- PLAINTEXT_METADATA: viewer|contributor|admin (A27-ROLE-1)
    granted_by             UUID NOT NULL,                -- PLAINTEXT_METADATA: admin who granted it (audit, INV-20)
    granted_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (resource_principal_id, member_principal_id),
    CONSTRAINT resmem_role_chk CHECK (role IN ('viewer','contributor','admin'))
);
CREATE INDEX idx_resmem_member ON keydir.resource_membership(member_principal_id);
-- fail-closed last-admin guard (A27-ROLE-4): enforced at the admin API (A17-RESRC-5),
-- NOT solely by a DB trigger, since "last admin" is a set-cardinality check the API
-- must serialize; a trigger is a defense-in-depth option, not the primary enforcement.

CREATE TABLE cal.delegation_grants (
    grantor_principal_id UUID NOT NULL,                  -- PLAINTEXT_METADATA: whose calendar
    delegate_principal_id UUID NOT NULL,                 -- PLAINTEXT_METADATA: who was granted access
    scope                 TEXT NOT NULL DEFAULT 'calendar', -- PLAINTEXT_METADATA: 'calendar' only in v1 (A27-DEL-1)
    granted_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at            TIMESTAMPTZ NULL,               -- PLAINTEXT_METADATA: NULL = active grant
    PRIMARY KEY (grantor_principal_id, delegate_principal_id),
    CONSTRAINT deleg_scope_chk CHECK (scope IN ('calendar'))  -- widen when mail delegation ships (A27 §14)
);
CREATE INDEX idx_deleg_delegate_active ON cal.delegation_grants(delegate_principal_id) WHERE revoked_at IS NULL;
-- The delegate's device rows live in cal.event_envelopes (A21 §6bis) keyed on the
-- GRANTOR's events, exactly like any other authorized device for those events —
-- this table only records the GRANT (who/scope/when), not key material. The
-- structural mail-exclusion guarantee (A17-DIR-6) is that no corresponding row
-- for the delegate's device is EVER written to mail.envelopes — there is no
-- "scope check" at read time to bypass, because the row simply does not exist.

CREATE TABLE iam.groups (
    group_principal_id UUID PRIMARY KEY,                 -- UUIDv7
    tenant_id          UUID NOT NULL,                     -- PLAINTEXT_METADATA
    address_canon      TEXT NOT NULL,                     -- PLAINTEXT_METADATA: A24-canonical group address
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, address_canon)
);
CREATE TABLE iam.group_members (
    group_principal_id UUID NOT NULL REFERENCES iam.groups(group_principal_id) ON DELETE CASCADE,
    member_address_canon TEXT NOT NULL,                  -- PLAINTEXT_METADATA: A24-canonical member address
    is_admin            BOOLEAN NOT NULL DEFAULT false,   -- PLAINTEXT_METADATA (A27-GRP-4)
    added_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_principal_id, member_address_canon)
);
CREATE INDEX idx_group_members_admin ON iam.group_members(group_principal_id) WHERE is_admin = true;
-- A group has NO envelope table, NO device-key directory rows, NO mail-plane token
-- row anywhere — it is purely this resolver pair (A17-GRP-1). Resolution returns
-- the member_address_canon list; each is then resolved as an ORDINARY mailbox
-- principal through the normal A17-RES-1 path.
```

- **A21-RESRC-1**: `keydir.resource_membership` is the entitlement record implementing A17-RESRC-2 — it is consulted before a device-bundle publication against a resource principal is accepted (A17-RESRC-3) and before a mail-plane token embeds a role (A17-RESRC-4). It is metadata (who/role/when), never content.
- **A21-DELEG-1**: `cal.delegation_grants` records ONLY the grant, not key material — the actual crypto-scope enforcement (A27-DEL-3, A17-DIR-6) is that the delegate's device simply has no row in `mail.envelopes`, ever, structurally, not because a check filters it out at read time. This table's `revoked_at` gates whether NEW `cal.event_envelopes` rows are produced for the delegate's device going forward (A27-DEL-6) — it does not retroactively remove already-produced envelopes (consistent with A17-DIR-4's revocation semantics elsewhere in the corpus).
- **A21-GRP-1**: `iam.groups`/`iam.group_members` are pure directory tables — no envelope table references them, because a group is never a decryption target (A27-GRP-1). The last-admin-cannot-be-removed rule (A27-GRP-4) is enforced at the admin API (A17-GRP-3), for the same set-cardinality reason noted for `resource_membership`.

------

# 7ter. Tier 2 Applicative AppKey — schema `keydir` (extended)

Implements A17-APPKEY-3. This is **Diamy Mail's own** client-application authentication store (Tier 2, per the Diamy IAM Integration Specification v1.6 §2.4/§11.6) — entirely independent of IAM's own Tier 1 AppKey mechanism, which Diamy Mail does not store or manage. No content, no key material: this table authenticates *which client application* is calling, never a user.

```sql
CREATE TABLE keydir.app_keys (
    app_key_id        UUID PRIMARY KEY,                  -- UUIDv7
    app_key_hash      TEXT NOT NULL UNIQUE,               -- PLAINTEXT_METADATA: SHA-256 hex of the raw key; raw value never stored
    app_name          TEXT NOT NULL,                       -- PLAINTEXT_METADATA: e.g. 'diamy-mail-desktop', 'diamy-mail-ios', 'diamy-mail-webmail', 'diamy-mail-bridge'
    app_platform      TEXT NOT NULL,                       -- PLAINTEXT_METADATA
    app_version_min   TEXT NULL,                           -- PLAINTEXT_METADATA: semver, NULL = no lower bound
    app_version_max   TEXT NULL,                           -- PLAINTEXT_METADATA: semver, NULL = no upper bound
    status            TEXT NOT NULL DEFAULT 'active',      -- PLAINTEXT_METADATA
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NULL,                    -- PLAINTEXT_METADATA: NULL = no forced expiry
    last_used_at      TIMESTAMPTZ NULL,
    revoked_at        TIMESTAMPTZ NULL,
    CONSTRAINT appkey_platform_chk CHECK (app_platform IN ('web','ios','android','windows','macos','linux')),
    CONSTRAINT appkey_status_chk CHECK (status IN ('active','revoked'))
);
CREATE INDEX idx_appkey_hash_active ON keydir.app_keys(app_key_hash) WHERE status = 'active';
-- Dual-slot rotation (A17-APPKEY-7): two active rows with the same app_name/platform
-- and non-overlapping [app_version_min, app_version_max] ranges MAY coexist during a
-- rotation window; the application layer, not a DB constraint, enforces non-overlap
-- (a version-range overlap is a business rule, not a structural one — mirrors the
-- last-admin-cardinality reasoning of A21-RESRC-1/A21-GRP-1: enforced at the admin API).
```

- **A21-APPKEY-1**: `app_key_hash` is the ONLY form of the key ever persisted (A17-APPKEY-3) — the raw value is generated client-side-of-the-admin-action or server-generated-and-shown-once, matching the IAM Integration Specification's own Tier 1 discipline applied here to Tier 2. A schema or code path that stores the raw key value is a critical security defect (mirrors the discipline already applied to `keydir.mail_device_keys` storing only public material).
- **A21-APPKEY-2** (lookup is the hot path): `idx_appkey_hash_active` supports the step-1 lookup of A17-APPKEY-5 (AppKey validated before the mail-plane token, on every request) — this MUST be an O(1)-class lookup (hash index), consistent with A18's hot-path latency discipline (A18-BOUND).
- **A21-APPKEY-3** (independent of `keydir.mail_device_keys`): This table has no foreign key to, and no relationship with, `keydir.mail_device_keys` — a device's mail encryption key bundle (A17-KEY) and a client application's Tier 2 AppKey (A17-APPKEY) authenticate two different things (a device/user vs. an application) and MUST remain structurally independent, per A17-TOK-4's Tier 1/Tier 2 non-conflation rule.

------

# 7. Cross-Cutting Schema Rules

- **A21-X-1** (plane separation): The schemas (`mail`, `keydir`, `search`, `cal`, `send`, `onboard`, `iam`) SHOULD be separable into distinct databases/roles if operational isolation demands it. `send`, `onboard`, and `iam` (group/resource-membership administration, A17-RESRC-5/A17-GRP-3) are control-plane (Super-Admin, SED-gated APIs, A23-API-2); `mail`/`keydir`/`search`/`cal` are data-plane (mail-plane token). DB roles MUST reflect this: the data-plane service role MUST NOT have write access to `send`/`onboard`/`iam`, and vice versa. Note that `keydir.resource_membership` and `cal.delegation_grants` (§6ter), despite living in data-plane schemas, hold entitlement/grant **metadata** consulted by data-plane services at read time — their read path is data-plane, but their write path (granting/revoking) MUST go through the control-plane admin APIs (A17-RESRC-5, A27-DEL-1), not direct data-plane writes.
- **A21-X-2** (classification integrity): Every `CIPHERTEXT` column (`name_ct`, `summary_ct`, `hold_queue.wrapped_kmsg`) is opaque to the server. (`hold_queue.wrapped_kmsg` is `k_msg` wrapped under `k_hold` — server-unwrappable by design, A21-HOLD-1, the one declared exception INV-3; it is still opaque as stored, no index/query depends on its cleartext.) No index, constraint, or query may depend on its plaintext (there is none server-side). `BLIND_INDEX` columns (`bi_kw`, `bi_addr`) are matched by equality only, never inverted. Reclassifying any column requires a migration changelog entry (CDM-ENC-2).
- **A21-X-3** (no plaintext oracles): No table may store a plaintext digest, a content hash used as a key, or any column that would let the server confirm a guessed plaintext (A02-CRY-6, A21-BLOB-1). All digests are over ciphertext.
- **A21-X-4** (migrations): Schema changes ship as ordered, reversible migrations. A column classification change (metadata↔ciphertext↔blind-index) MUST have a corresponding CDM-ENC migration entry and a data-migration plan; it is never an in-place `ALTER` without re-encryption where the classification tightens.
- **A21-X-5** (referential integrity vs privacy): FKs to IAM (`principal_id`, `tenant_id`, `device_id`) are logical/external — IAM owns those rows. This schema MUST NOT create physical FKs into IAM tables (plane coupling); it treats IAM IDs as opaque external references validated by the application/IAM contract (A17).

------

# 8. Indexing & Performance Notes

- **A21-IDX-1**: The hot path is list rendering: `idx_messages_principal_folder` and `idx_messages_principal_received` serve folder listings and recency ordering (A04 catalogue pages, p99 < 100 ms target). Envelope fetch uses the `(message_id, device_id)` PK. Journal sync uses `idx_journal_principal_seq`.
- **A21-IDX-2**: Blind-Index lookups use `idx_bi_kw_lookup` / `idx_bi_addr_lookup` on `(principal_id, token)` — equality match only (A05-BI-7). No range/prefix queries on Blind-Index columns (they are opaque HMACs; prefix has no meaning and could leak structure).
- **A21-IDX-3**: Pagination is cursor-based on `(principal_id, received_at, message_id)` or journal `seq` (A04-PAGE-1), never `OFFSET` (A04 error #5). Indexes support the cursor tuples.

------

# 9. Test / Validation Scenarios (Normative)

1. **Fail-closed gate constraint**: attempt `UPDATE onboard.domains SET send_enabled = true` while `dkim_verified = false` → rejected by `onboard_send_gate_chk` (A21-ONB-1); DB refuses, not just the app.
2. **Envelope uniqueness**: two envelopes for the same `(message_id, device_id)` → PK violation; re-wrap must UPSERT (A21-ENV-1).
3. **Blind-index cascade**: delete a `mail.messages` row → its `search.blind_index_*` rows vanish via CASCADE (A21-BI-1); no orphan tokens.
4. **Plane separation**: data-plane role attempts to write `send.allocations` → denied by role grants (A21-X-1).
5. **One pool per server**: set a server's `pool_id` to a second pool → the column holds one value; membership is single (A21-SEND-1, OPS-SEND-2).
6. **Hybrid rules invariant**: `mode='hybrid'` with `hybrid_rules IS NULL` → rejected by `alloc_hybrid_rules_chk` (A21-SEND-1).
7. **Ciphertext opacity**: verify no index or view exposes `summary_ct`/`name_ct`/hold `wrapped_kmsg` plaintext (there is none; assert no plaintext-derived column exists) (A21-X-2).
8. **Direction/time integrity**: insert inbound message with NULL `received_at` → rejected by `messages_time_chk`.

------

# 10. Common AI Implementation Errors (annex-specific watch list)

1. ❌ Treating a prose annex's field description as authoritative over this DDL when they differ (A21 §1 — this DDL prevails).
2. ❌ Using a content hash as `blob_id` or storing a plaintext digest, creating a cross-user equality oracle (A21-BLOB-1, A21-X-3).
3. ❌ Adding an index/constraint/query that depends on `CIPHERTEXT` plaintext (there is none server-side) (A21-X-2).
4. ❌ Implementing the fail-closed send gate only in application code and omitting `onboard_send_gate_chk`, losing the DB-level defense (A21-ONB-1).
5. ❌ Allowing the data-plane role to write control-plane schemas (`send`/`onboard`) or vice versa (A21-X-1).
6. ❌ Putting message content in `mail.journal.payload` or any `send`/`onboard` table (A21-JRN-1, A23-DM-1).
7. ❌ Writing a BCC address into another recipient's `recipients_canonical` (A21-MSG-2, A02-DM-4).
8. ❌ Creating physical FKs into IAM tables instead of treating IAM IDs as external references (A21-X-5).
9. ❌ Retaining webmail Blind-Index rows after webmail disable instead of purging (A21-BI-1, A05-BI-6).
10. ❌ Range/prefix querying Blind-Index columns instead of equality-only (A21-IDX-2).
11. ❌ `OFFSET` pagination instead of cursor-based on indexed tuples (A21-IDX-3, A04).
12. ❌ In-place `ALTER` that changes a column's classification without a re-encryption migration (A21-X-4, CDM-ENC-2).

------

# 11. Deferred Items

- Partitioning strategy for `mail.messages` / `mail.journal` at scale (by tenant or time) — an operational/performance concern (A22/A18); the logical schema is partition-ready (principal_id/tenant_id present).
- Table-level encryption / TDE at the Postgres layer as defense-in-depth beyond the application `CIPHERTEXT` columns — deferred; the security model does not depend on it (ciphertext columns are already opaque).
- Read-replica / geo-distribution topology — operational.
- Exact `hybrid_rules` JSON schema — fixed alongside A16 classification and A23 hybrid split; kept as JSONB here for flexibility.

------

*End of document.*
