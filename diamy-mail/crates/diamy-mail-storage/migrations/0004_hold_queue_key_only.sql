-- Aligne `mail.hold_queue` sur le design "clé seule" d'A01-HOLD-1/5 (A21 §2.6, v1.5).
-- Arbitrage de Cédric du 2026-07-15 : option (a) de la divergence A01/A21 escaladée —
-- on AMENDE A21 (fait, v1.5 §2.6), pas A01. NE MODIFIE PAS 0003 (déjà appliqué,
-- checksum figé — discipline de migration A21-X-4) : cette migration le supersède.
--
-- Avant (0003) : `hold_queue.ciphertext` = MESSAGE ENTIER scellé sous k_hold, aucune
-- colonne `message_id` → la release devait reconstruire le clair du corps (l'erreur
-- nommée A01 §13 err.#8). Après : le message est catalogué normalement dans
-- `mail.messages` + ses blobs sous `k_msg` DÈS la réception (zéro enveloppe d'appareil),
-- et `hold_queue` ne porte plus que `k_msg` emballé sous `k_hold` (A01-HOLD-1), relié au
-- message par `message_id`. La release ne touche alors JAMAIS le corps (A01-HOLD-5).
--
-- Les lignes de hold éventuellement présentes sont au FORMAT 0003 (corps entier sous
-- k_hold, sans message_id) : structurellement irréconciliables avec le design clé-seule
-- (aucun `mail.messages`/`mail.blobs` correspondant n'existe pour elles). Elles sont donc
-- purgées ici — cohérent avec la discipline "re-provision, pas migration" des données
-- `dev-crypto` (SIMPLIFICATIONS.md) ; en maquette ce sont des données de test transitoires.
-- Purge nécessaire aussi pour poser `message_id NOT NULL` sans valeur par défaut.

DELETE FROM mail.hold_queue;

ALTER TABLE mail.hold_queue
    ADD COLUMN message_id UUID NOT NULL
        REFERENCES mail.messages(message_id) ON DELETE CASCADE;

-- Repurpose (renommage, pas de reclassification silencieuse — CDM-ENC-2 tracé ici) :
-- `ciphertext` (corps entier) devient `wrapped_kmsg` (k_msg seul sous k_hold).
ALTER TABLE mail.hold_queue RENAME COLUMN ciphertext TO wrapped_kmsg;
ALTER TABLE mail.hold_queue RENAME COLUMN hold_nonce TO wrap_nonce;

CREATE INDEX IF NOT EXISTS idx_hold_message ON mail.hold_queue(message_id);
