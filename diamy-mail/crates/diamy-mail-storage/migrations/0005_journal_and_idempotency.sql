-- Wire A21 §2.5 (mail.journal — specified since A21 v1.0, never migrated until now, see
-- SIMPLIFICATIONS.md "Stockage (A21)") and A21 §2.7 (mail.idempotency_keys, new in A21 v1.6),
-- needed for the real A04 §3/§5.3/§6 sync-state implementation (read/deleted flags, real
-- server-side idempotency). 0001-0004 are left INTACT (A21-X-4 migration discipline).

-- A21 §2.5 — Sync journal (append-only), copied VERBATIM — "this DDL prevails" (A21 §1).
CREATE TABLE IF NOT EXISTS mail.journal (
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
CREATE INDEX IF NOT EXISTS idx_journal_principal_seq ON mail.journal(principal_id, seq);

-- A21 §2.7 — Idempotency keys (A04-IDEM-1), new table.
CREATE TABLE IF NOT EXISTS mail.idempotency_keys (
    idempotency_key UUID PRIMARY KEY,                    -- client-supplied UUIDv7 (A04-IDEM-1)
    principal_id    UUID NOT NULL,                       -- PLAINTEXT_METADATA
    endpoint        TEXT NOT NULL,                        -- PLAINTEXT_METADATA: 'state/flags'|'state/delete'
    response_body   JSONB NOT NULL,                       -- PLAINTEXT_METADATA: exact response returned the first time
    journal_seq     BIGINT NOT NULL,                      -- the sequence assigned on first execution (A04-EP-4)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT idempotency_endpoint_chk CHECK (endpoint IN ('state/flags','state/delete'))
);
CREATE INDEX IF NOT EXISTS idx_idempotency_principal ON mail.idempotency_keys(principal_id);
