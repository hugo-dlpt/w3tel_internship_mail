-- Annuaire des clés d'appareil (A21 §3, A17-DIR-1). Copié VERBATIM depuis A21 §3 :
-- "cette DDL prévaut" sur toute description en prose (A21 §1).
--
-- Rappel du modèle (A17-KEY-2/A17-DIR-3) : la paire de clés de chiffrement mail
-- (ML-KEM-768) est générée PAR L'APPAREIL, localement. Seule la clé PUBLIQUE, signée
-- par la clé d'identité de l'appareil, est publiée ici. La clé privée ne transite
-- JAMAIS par le serveur — ni par `diamy-maild` (qui héberge cet annuaire), ni par
-- `diamy-mxd` (qui le lit pour chiffrer). Voir `crates/diamy-mail-storage/examples/
-- enroll_test_device.rs` pour la simulation d'un enrôlement d'appareil de test.

CREATE SCHEMA IF NOT EXISTS keydir;

CREATE TABLE IF NOT EXISTS keydir.mail_device_keys (
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
CREATE INDEX IF NOT EXISTS idx_keydir_principal_active ON keydir.mail_device_keys(principal_id) WHERE validity_state = 'active';
