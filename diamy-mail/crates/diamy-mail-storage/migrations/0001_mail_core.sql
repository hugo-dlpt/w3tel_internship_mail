-- Sous-ensemble du schéma `mail` (A21 §2) nécessaire à la tranche verticale de la
-- maquette : folders, messages, blobs, envelopes. Le reste du schéma A21 (journal,
-- hold_queue, keydir, search, send, onboard, cal, iam) est hors périmètre pour
-- l'instant — voir SIMPLIFICATIONS.md. Copié VERBATIM depuis A21 §2.1/2.2/2.3/2.4 :
-- "cette DDL prévaut" sur toute description en prose (A21 §1).

CREATE SCHEMA IF NOT EXISTS mail;

-- A21 §2.1 — Folders
CREATE TABLE IF NOT EXISTS mail.folders (
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
CREATE INDEX IF NOT EXISTS idx_folders_principal ON mail.folders(principal_id);

-- A21 §2.2 — Messages (catalogue)
CREATE TABLE IF NOT EXISTS mail.messages (
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
CREATE INDEX IF NOT EXISTS idx_messages_principal_folder ON mail.messages(principal_id, folder_id);
CREATE INDEX IF NOT EXISTS idx_messages_principal_received ON mail.messages(principal_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_tenant ON mail.messages(tenant_id);
CREATE INDEX IF NOT EXISTS idx_messages_rfc_hash ON mail.messages(rfc5322_message_id_hash) WHERE rfc5322_message_id_hash IS NOT NULL;

-- A21 §2.3 — Blobs (références catalogue vers l'object store)
CREATE TABLE IF NOT EXISTS mail.blobs (
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
CREATE INDEX IF NOT EXISTS idx_blobs_message ON mail.blobs(message_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_blobs_object_key ON mail.blobs(object_key);

-- A21 §2.4 — Envelopes (clé emballée par message x appareil)
CREATE TABLE IF NOT EXISTS mail.envelopes (
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
CREATE INDEX IF NOT EXISTS idx_envelopes_device ON mail.envelopes(device_id);
