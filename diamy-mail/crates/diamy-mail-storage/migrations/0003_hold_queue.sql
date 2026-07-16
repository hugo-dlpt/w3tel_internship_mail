-- File d'attente de hold (A21 §2.5bis / A01-HOLD, ferme A17-DIR-5). Copié VERBATIM
-- depuis A21 (colonnes) : "cette DDL prévaut" sur toute description en prose (A21 §1).
--
-- Note honnête (voir SIMPLIFICATIONS.md) : cette table n'a PAS de colonne `message_id`/
-- `body_blob_id`, et `ciphertext` est documenté par A21 comme "full message encrypted
-- under server-side k_hold" — un design différent de la lecture littérale d'A01-HOLD-1/5
-- ("wrap k_msg under k_hold", body/blobs déjà persistés normalement sous k_msg). Le
-- schéma tel qu'écrit ne peut implémenter QUE le design "message entier sous k_hold,
-- rien dans mail.messages avant la release" — c'est celui suivi ici. Flag pour Cédric :
-- A01 §7 et A21 §2 se contredisent sur ce point précis, à réconcilier.

CREATE TABLE IF NOT EXISTS mail.hold_queue (
    hold_id         UUID PRIMARY KEY,                    -- PLAINTEXT_METADATA, UUIDv7
    principal_id    UUID NOT NULL,                       -- PLAINTEXT_METADATA (recipient with no active device)
    tenant_id       UUID NOT NULL,                       -- PLAINTEXT_METADATA
    ciphertext      BYTEA NOT NULL,                      -- CIPHERTEXT: full message encrypted under server-side k_hold (A01-HOLD)
    hold_nonce      BYTEA NOT NULL,                      -- PLAINTEXT_METADATA
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,                -- default +30d (A01-HOLD, tunable per onboarding profile A11-SEQ-4)
    CONSTRAINT hold_expiry_chk CHECK (expires_at > received_at)
);
CREATE INDEX IF NOT EXISTS idx_hold_principal ON mail.hold_queue(principal_id);
CREATE INDEX IF NOT EXISTS idx_hold_expiry ON mail.hold_queue(expires_at);
