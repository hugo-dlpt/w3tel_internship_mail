//! # diamy-mail-storage
//!
//! Stockage catalogue Postgres (A21 §2, sous-ensemble : `folders`/`messages`/`blobs`/`envelopes`)
//! plus un object store de développement (A21 §1.1 : le blob store S3-compatible n'est
//! PAS relationnel — Postgres ne garde que la référence catalogue `object_key`).
//!
//! Crate partagée entre `diamy-mxd` (A01, écrit les messages reçus) et `diamy-maild`
//! (A02/A04, sert le catalogue) : les deux daemons DOIVENT écrire dans le même catalogue
//! par le même chemin de code, pas deux implémentations qui pourraient diverger.
//!
//! Inclut aussi l'annuaire de clés d'appareil (A21 §3, `keydir.mail_device_keys`,
//! A17-DIR-1) : la frontière (`diamy-mxd`) DOIT lire une clé publique déjà publiée ici
//! par un appareil réel — elle ne doit JAMAIS générer elle-même une clé d'appareil
//! (A17-KEY-2 : la clé de chiffrement mail est générée par l'appareil, localement, et
//! sa partie privée ne quitte jamais l'appareil). Voir `examples/enroll_test_device.rs`
//! pour la simulation, hors serveur, d'un appareil qui s'enrôle et publie sa clé publique.
//!
//! Portée volontairement minimale (tranche verticale, guide §7) : `journal`, `search`,
//! `send`, `onboard`, `cal`, `iam` restent hors périmètre (voir `SIMPLIFICATIONS.md`).
//! `hold_queue` (A01-HOLD, ferme A17-DIR-5) EST implémentée selon le design **clé seule**
//! d'A01-HOLD-1/5 (A21 §2.6 v1.5, arbitré par Cédric le 2026-07-15) : un message tenu est
//! catalogué normalement (`store_held_message` : ligne `messages` + blob `body` sous
//! `k_msg`, SANS enveloppe d'appareil), et `hold_queue` ne porte que `k_msg` emballé sous
//! `k_hold`. La release (`release_held_messages_for_principal`) ne désemballe que `k_msg`
//! et produit des enveloppes normales — le corps chiffré n'est JAMAIS re-manipulé
//! (A01-HOLD-5). Voir aussi `list_held_for_principal`/`delete_hold`/`purge_expired_holds`.
//!
//! Discipline appliquée (A18 §13 forbidden patterns) :
//! - toutes les requêtes sont paramétrées (`$1, $2, ...`), jamais de SQL concaténé (A18-DB-1) ;
//! - aucun `unwrap()`/`expect()` sur une valeur issue d'E/S ou de la base — tout remonte
//!   en erreur (A18-ERR-1) ;
//! - `body_ciphertext`/`kem_ct`/`wrapped_key` ne sont JAMAIS logués (A18-LOG-1).
#![forbid(unsafe_code)]

use diamy_mail_crypto::{
    AlgVersion, Ciphertext, DeviceEncPublicKey, Envelope, IdentityPublicKey, Signature,
};
use sqlx::postgres::PgPoolOptions;
use std::path::PathBuf;
use uuid::Uuid;

/// Réexporté pour que les appelants (`diamy-mxd`, `diamy-maild`) n'aient pas besoin
/// d'une dépendance directe à `sqlx` : ce module est la SEULE porte vers le catalogue.
pub use sqlx::PgPool;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("base de données : {0}")]
    Db(#[from] sqlx::Error),
    #[error("object store local : {0}")]
    Io(#[from] std::io::Error),
    #[error("migration : {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("message introuvable : {0}")]
    MessageNotFound(Uuid),
    #[error("enveloppe introuvable pour ce message/appareil")]
    EnvelopeNotFound,
    #[error("crypto : {0}")]
    Crypto(#[from] diamy_mail_crypto::CryptoError),
    #[error("signature de paquet d'appareil invalide (A17-KEY-3)")]
    InvalidDeviceBundleSignature,
}

/// Connexion au catalogue Postgres + application des migrations (A21, sous-ensemble `mail`).
pub async fn connect(database_url: &str) -> Result<PgPool, StorageError> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// Stand-in dev de l'object store S3-compatible (A21 §1.1). En production, `object_key`
/// pointerait vers un vrai bucket S3-compatible ; ici, un répertoire local.
pub struct BlobStore {
    dir: PathBuf,
}

impl BlobStore {
    pub fn at(dir: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path_for(&self, object_key: &str) -> PathBuf {
        self.dir.join(object_key)
    }

    fn write(&self, object_key: &str, bytes: &[u8]) -> Result<(), StorageError> {
        let path = self.path_for(object_key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, bytes)?;
        Ok(())
    }

    fn read(&self, object_key: &str) -> Result<Vec<u8>, StorageError> {
        Ok(std::fs::read(self.path_for(object_key))?)
    }

    /// A02-DEL-2 : suppression VÉRIFIÉE (suppression + contrôle d'inexistence), pas un simple
    /// "best effort" silencieux. Idempotent : un objet déjà absent n'est pas une erreur.
    fn delete(&self, object_key: &str) -> Result<(), StorageError> {
        let path = self.path_for(object_key);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        if path.exists() {
            return Err(StorageError::Io(std::io::Error::other(
                "le blob est toujours présent après tentative de suppression (A02-DEL-2)",
            )));
        }
        Ok(())
    }
}

/// Trouve (ou crée) le dossier système `inbox` d'un principal (A21 §2.1).
/// `name_ct` est un placeholder chiffré (A03-KEY-3 : la vraie clé de dossier est côté
/// client). Correction de commentaire (pas de comportement, en attente d'arbitrage) : ce
/// n'est PAS "la même clé de démo" — l'appelant scelle avec une clé CSPRNG FRAÎCHE à
/// chaque appel puis la `drop()` immédiatement (voir `deliver_to_recipients`/
/// `run_vertical_slice_demo`). Ce champ n'est donc JAMAIS relisible dans cette maquette,
/// y compris en debug — voir SIMPLIFICATIONS.md pour l'option en attente (relire ce champ
/// en debug ou non) avant de changer le comportement.
pub async fn ensure_inbox_folder(
    pool: &PgPool,
    principal_id: Uuid,
    tenant_id: Uuid,
    name_ct: &[u8],
) -> Result<Uuid, StorageError> {
    if let Some(row) = sqlx::query_as::<_, (Uuid,)>(
        "SELECT folder_id FROM mail.folders WHERE principal_id = $1 AND system_kind = 'inbox' LIMIT 1",
    )
    .bind(principal_id)
    .fetch_optional(pool)
    .await?
    {
        return Ok(row.0);
    }

    let folder_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO mail.folders (folder_id, principal_id, tenant_id, name_ct, system_kind)
         VALUES ($1, $2, $3, $4, 'inbox')",
    )
    .bind(folder_id)
    .bind(principal_id)
    .bind(tenant_id)
    .bind(name_ct)
    .execute(pool)
    .await?;
    Ok(folder_id)
}

/// Un message entrant prêt à être stocké : contenu déjà chiffré (frontière, A01), une
/// enveloppe par appareil destinataire (A02-DM-3). Aucun champ ici ne porte de clair.
pub struct InboundMessage<'a> {
    /// Généré par l'APPELANT, AVANT le chiffrement (A02-CRY-2/3) : `body_ct`/`summary_ct`
    /// doivent être scellés avec une AAD liée à ce `message_id` (`crypto::aad_for_blob`/
    /// `aad_for_summary`), donc l'id ne peut plus être généré ICI, après coup.
    pub message_id: Uuid,
    /// Idem : l'id du blob de corps doit être connu AVANT le chiffrement pour entrer
    /// dans l'AAD du blob (A02-CRY-2).
    pub body_blob_id: Uuid,
    pub principal_id: Uuid,
    pub tenant_id: Uuid,
    pub folder_id: Uuid,
    pub sender_canonical: &'a str,
    pub recipient_canonical: &'a str,
    pub body_ct: &'a Ciphertext,
    pub summary_ct: &'a Ciphertext,
    pub size_bytes: i64,
    pub envelopes: &'a [(Uuid, &'a Envelope)], // (device_id, enveloppe)
    /// PLAINTEXT_METADATA (A21 §2.2) : verdicts A06/A07 dans la vraie spec ; ici, réduit à
    /// la posture TLS de la session de réception (A01-SMTP-1 : "the TLS version and cipher
    /// of each session MUST be recorded"). Jamais de contenu, jamais de clé (INV-21).
    pub trust_metadata: Option<serde_json::Value>,
}

/// Insère la ligne `messages` + le blob `body` (objet local) DANS une transaction déjà
/// ouverte. Partagé par [`store_inbound_message`] (livraison normale, avec enveloppes) et
/// [`store_held_message`] (mise en hold, SANS enveloppe, A01-HOLD-1) : une seule
/// implémentation du catalogage, jamais deux copies qui pourraient diverger.
async fn insert_message_and_body(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    blob_store: &BlobStore,
    msg: &InboundMessage<'_>,
) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT INTO mail.messages
            (message_id, principal_id, tenant_id, direction, folder_id,
             sender_canonical, recipients_canonical, received_at, size_bytes,
             summary_ct, summary_nonce, trust_metadata, blob_alg_version)
         VALUES ($1, $2, $3, 'inbound', $4, $5, $6, now(), $7, $8, $9, $10, $11)",
    )
    .bind(msg.message_id)
    .bind(msg.principal_id)
    .bind(msg.tenant_id)
    .bind(msg.folder_id)
    .bind(msg.sender_canonical)
    .bind([msg.recipient_canonical]) // A21-MSG-2 : minimisé, owner + routage seulement, jamais de BCC
    .bind(msg.size_bytes)
    .bind(&msg.summary_ct.bytes)
    .bind(msg.summary_ct.nonce.as_slice())
    .bind(&msg.trust_metadata)
    // A02-CRY-7 : version de suite du summary_ct écrite EXPLICITEMENT au scellement (INV-7),
    // plus jamais laissée au DEFAULT implicite de la DDL.
    .bind(msg.summary_ct.alg_version.as_i32())
    .execute(&mut **tx)
    .await?;

    // Le corps chiffré part dans l'object store (A21 §1.1), PAS dans une colonne BYTEA
    // de `mail.messages` — Postgres ne garde que la référence `object_key` + son digest.
    let object_key = format!("blobs/{}", msg.body_blob_id);
    blob_store.write(&object_key, &msg.body_ct.bytes)?;
    let sha512_ct = sha512_of(&msg.body_ct.bytes);

    sqlx::query(
        "INSERT INTO mail.blobs
            (blob_id, message_id, kind, object_key, nonce, size_bytes, sha512_ct, blob_alg_version)
         VALUES ($1, $2, 'body', $3, $4, $5, $6, $7)",
    )
    .bind(msg.body_blob_id)
    .bind(msg.message_id)
    .bind(&object_key)
    .bind(msg.body_ct.nonce.as_slice())
    .bind(msg.size_bytes)
    .bind(sha512_ct.as_slice()) // digest du CHIFFRÉ, jamais du clair (A21-BLOB-1 / A21-X-3)
    .bind(msg.body_ct.alg_version.as_i32()) // A02-CRY-7 : version écrite au scellement (INV-7)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Insère les enveloppes (clé de message emballée PAR appareil, A02-DM-3) d'un message dans
/// une transaction ouverte. `UPSERT` sur la PK `(message_id, device_id)` (A21-ENV-1) : une
/// ré-exécution ne duplique pas (idempotence exigée A01-HOLD-4 / A02-RW-2).
async fn insert_envelopes(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    message_id: Uuid,
    envelopes: &[(Uuid, &Envelope)],
    origin: &str,
) -> Result<(), StorageError> {
    for (device_id, envelope) in envelopes {
        sqlx::query(
            "INSERT INTO mail.envelopes
                (message_id, device_id, kem_ct, wrapped_key, wrap_nonce, alg_version, origin)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (message_id, device_id) DO UPDATE
                SET kem_ct = EXCLUDED.kem_ct,
                    wrapped_key = EXCLUDED.wrapped_key,
                    wrap_nonce = EXCLUDED.wrap_nonce,
                    alg_version = EXCLUDED.alg_version,
                    origin = EXCLUDED.origin",
        )
        .bind(message_id)
        .bind(device_id)
        .bind(&envelope.kem_ct)
        .bind(&envelope.wrapped.bytes)
        .bind(envelope.wrapped.nonce.as_slice())
        .bind(envelope.wrapped.alg_version.as_i32()) // A02-CRY-7 : version écrite au scellement (INV-7)
        .bind(origin)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Stocke un message entrant : ligne `messages` + blob `body` (objet local) + enveloppes.
/// Transactionnel : soit tout est écrit, soit rien (A18-ERR : pas d'état partiel visible).
pub async fn store_inbound_message(
    pool: &PgPool,
    blob_store: &BlobStore,
    msg: &InboundMessage<'_>,
) -> Result<Uuid, StorageError> {
    let mut tx = pool.begin().await?;
    insert_message_and_body(&mut tx, blob_store, msg).await?;
    insert_envelopes(&mut tx, msg.message_id, msg.envelopes, "frontier").await?;
    tx.commit().await?;
    Ok(msg.message_id)
}

/// Ce que l'appareil récupère pour UN message + SON enveloppe (A02 §3, "le client tire").
pub struct FetchedForDevice {
    /// Nécessaire pour reconstruire l'AAD (`crypto::aad_for_blob(message_id, body_blob_id)`,
    /// A02-CRY-2) avant `open_message` — sans cet id, le tag GCM ne peut pas être vérifié
    /// puisque l'AAD ne correspond plus à celle du scellement.
    pub body_blob_id: Uuid,
    pub body_ct: Ciphertext,
    /// Sujet scellé (A20-IMAP-2, Bridge) : sous le MÊME `k_msg` que `body_ct`, AAD distincte
    /// (`crypto::aad_for_summary(message_id)`) — la même enveloppe désemballe les deux.
    pub summary_ct: Ciphertext,
    pub envelope: Envelope,
}

/// Lit le chiffré + l'enveloppe d'un appareil donné (jamais le clair : le serveur ne le voit pas).
///
/// `principal_id` DOIT être vérifié contre le propriétaire réel du message — sans cette
/// jointure, un appelant qui connaît un `message_id` et un `device_id` valides pourrait
/// récupérer le chiffré de N'IMPORTE QUEL principal, pas seulement le sien (trouvé et
/// corrigé pendant la revue de l'API de sync, A04 ; voir `SIMPLIFICATIONS.md`). Ceci reste
/// pertinent même sans authentification réelle (A04-TR-2 non implémentée) : c'est une
/// vérification d'appartenance, pas un contrôle d'accès à la place d'un jeton.
pub async fn fetch_message_for_device(
    pool: &PgPool,
    blob_store: &BlobStore,
    principal_id: Uuid,
    message_id: Uuid,
    device_id: Uuid,
) -> Result<FetchedForDevice, StorageError> {
    // A20-IMAP-2 (Bridge) : `m.summary_ct`/`m.summary_nonce`/`m.blob_alg_version` (le sujet
    // scellé, colonnes déjà présentes en base — voir `insert_message_and_body`) sont lus ICI en
    // plus du blob de corps, via la MÊME jointure déjà nécessaire à la vérification de
    // propriétaire — pas de requête supplémentaire.
    let blob_row = sqlx::query_as::<_, (Uuid, String, Vec<u8>, i32, Vec<u8>, Vec<u8>, i32)>(
        "SELECT b.blob_id, b.object_key, b.nonce, b.blob_alg_version,
                m.summary_ct, m.summary_nonce, m.blob_alg_version
         FROM mail.blobs b
         JOIN mail.messages m ON m.message_id = b.message_id
         WHERE b.message_id = $1 AND b.kind = 'body' AND m.principal_id = $2
         LIMIT 1",
    )
    .bind(message_id)
    .bind(principal_id)
    .fetch_optional(pool)
    .await?
    .ok_or(StorageError::MessageNotFound(message_id))?;

    let (
        body_blob_id,
        object_key,
        nonce,
        body_alg_version,
        summary_ct_bytes,
        summary_nonce,
        summary_alg_version,
    ) = blob_row;
    let body_bytes = blob_store.read(&object_key)?;
    let body_ct = Ciphertext {
        // INV-7 / A02-CRY-7 : la version lue en base est contrôlée ICI (fail-closed sur
        // inconnue, INV-16) avant même que le chiffré ne parte au client — l'`open_message`
        // client la re-dispatchera aussi (défense en profondeur).
        alg_version: AlgVersion::from_i32(body_alg_version)?,
        nonce: nonce_from_vec(&nonce)?,
        bytes: body_bytes,
    };
    let summary_ct = Ciphertext {
        alg_version: AlgVersion::from_i32(summary_alg_version)?,
        nonce: nonce_from_vec(&summary_nonce)?,
        bytes: summary_ct_bytes,
    };

    let env_row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>, i32)>(
        "SELECT e.kem_ct, e.wrapped_key, e.wrap_nonce, e.alg_version
         FROM mail.envelopes e
         JOIN mail.messages m ON m.message_id = e.message_id
         WHERE e.message_id = $1 AND e.device_id = $2 AND m.principal_id = $3",
    )
    .bind(message_id)
    .bind(device_id)
    .bind(principal_id)
    .fetch_optional(pool)
    .await?
    .ok_or(StorageError::EnvelopeNotFound)?;

    let (kem_ct, wrapped_key, wrap_nonce, env_alg_version) = env_row;
    let envelope = Envelope {
        kem_ct,
        wrapped: Ciphertext {
            alg_version: AlgVersion::from_i32(env_alg_version)?, // INV-7, fail-closed
            nonce: nonce_from_vec(&wrap_nonce)?,
            bytes: wrapped_key,
        },
    };

    Ok(FetchedForDevice {
        body_blob_id,
        body_ct,
        summary_ct,
        envelope,
    })
}

/// Résumé catalogue d'un message — PLAINTEXT_METADATA uniquement (A21 §2.2), jamais de
/// contenu. C'est ce qu'un client sync liste avant de tirer un message précis.
///
/// `read`/`deleted` sont lus depuis `state_flags` (A21 §2.2, JSONB) : le VRAI état
/// serveur-autoritaire (A04 §3/§5.3), pas un cache local au Bridge — c'est ce qui rend `\Seen`/
/// `\Deleted` visibles depuis N'IMPORTE QUELLE session/connexion IMAP sur le même principal
/// (A04-SYNC, preuve du test multi-connexion, voir `SIMPLIFICATIONS.md`).
pub struct MessageSummary {
    pub message_id: Uuid,
    pub sender_canonical: Option<String>,
    pub size_bytes: i64,
    pub received_at: Option<sqlx::types::time::OffsetDateTime>,
    pub read: bool,
    pub deleted: bool,
}

fn flag_from_state(state_flags: &serde_json::Value, field: &str) -> bool {
    state_flags.get(field).and_then(|v| v.as_bool()).unwrap_or(false)
}

/// Liste les messages les plus récents d'un principal, bornée (A18-BOUND-1).
/// Simplification assumée (voir `SIMPLIFICATIONS.md`) : borne fixe, pas de curseur de
/// pagination conforme A04-PAGE-1 (pas d'OFFSET malgré tout — tri direct par date desc).
///
/// Un message `\Deleted` (state_flags.deleted = true) reste dans cette liste — IMAP exige
/// qu'un message marqué pour suppression reste visible (avec son flag) jusqu'à l'EXPUNGE qui le
/// PURGE réellement (A02-DEL-1) ; seule la purge fait disparaître la ligne.
pub async fn list_recent_messages(
    pool: &PgPool,
    principal_id: Uuid,
    limit: i64,
) -> Result<Vec<MessageSummary>, StorageError> {
    // Tuple de projection SQL — reconstruit immédiatement en `MessageSummary` juste en dessous
    // (même style que `list_held_for_principal`).
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        Uuid,
        Option<String>,
        i64,
        Option<sqlx::types::time::OffsetDateTime>,
        serde_json::Value,
    )> = sqlx::query_as(
        "SELECT message_id, sender_canonical, size_bytes, received_at, state_flags
         FROM mail.messages
         WHERE principal_id = $1
         ORDER BY received_at DESC NULLS LAST
         LIMIT $2",
    )
    .bind(principal_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(message_id, sender_canonical, size_bytes, received_at, state_flags)| MessageSummary {
            message_id,
            sender_canonical,
            size_bytes,
            received_at,
            read: flag_from_state(&state_flags, "read"),
            deleted: flag_from_state(&state_flags, "deleted"),
        })
        .collect())
}

/// Ajoute un événement au journal append-only (A02 §4.4/A21 §2.5) DANS une transaction déjà
/// ouverte — jamais de contenu dans `payload` (API-5, A21-JRN-1), uniquement des IDs/booléens.
/// Renvoie la séquence assignée : c'est l'autorité d'ordonnancement pour la LWW par champ côté
/// client (A03-SYNC-1) — cette crate ne fait QUE l'assigner atomiquement, elle ne réconcilie
/// aucun état client (aucun vault client n'existe dans ce dépôt, voir `SIMPLIFICATIONS.md`).
async fn journal_append(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    principal_id: Uuid,
    event_type: &str,
    message_id: Option<Uuid>,
    payload: &serde_json::Value,
) -> Result<i64, StorageError> {
    let row: (i64,) = sqlx::query_as(
        "INSERT INTO mail.journal (principal_id, event_type, message_id, payload)
         VALUES ($1, $2, $3, $4)
         RETURNING seq",
    )
    .bind(principal_id)
    .bind(event_type)
    .bind(message_id)
    .bind(payload)
    .fetch_one(&mut **tx)
    .await?;
    Ok(row.0)
}

/// Delta de champs à appliquer via `POST /state/flags` (A04 §5.3/A04-EP-4bis) : `None` = champ
/// non touché par cette requête (jamais "remis à false" par défaut). `deleted` participe à la
/// MÊME discipline per-field LWW que `read` (A04-EP-4bis, v1.4) : c'est un booléen réversible,
/// PAS l'action de purge/déplacement — voir [`purge_message`] pour `/state/delete`.
#[derive(Default)]
pub struct FlagsUpdate {
    pub read: Option<bool>,
    pub deleted: Option<bool>,
}

/// `POST /state/flags` (A04 §5.3) : applique un delta read/deleted à UN message et journalise
/// l'événement `flags_changed` — dans la MÊME transaction (A18-ERR : pas d'état partiel visible
/// entre la mise à jour et son entrée de journal). `principal_id` DOIT posséder le message
/// (même discipline d'appartenance que `fetch_message_for_device`) — pas de mutation
/// cross-principal. Renvoie la séquence de journal assignée (A04-EP-4 : "the response returns
/// the assigned sequence").
pub async fn apply_state_flags(
    pool: &PgPool,
    principal_id: Uuid,
    message_id: Uuid,
    update: &FlagsUpdate,
) -> Result<i64, StorageError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT message_id FROM mail.messages WHERE message_id = $1 AND principal_id = $2 FOR UPDATE")
        .bind(message_id)
        .bind(principal_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::MessageNotFound(message_id))?;

    let mut patch = serde_json::Map::new();
    if let Some(read) = update.read {
        patch.insert("read".to_string(), serde_json::json!(read));
    }
    if let Some(deleted) = update.deleted {
        patch.insert("deleted".to_string(), serde_json::json!(deleted));
    }
    let patch_json = serde_json::Value::Object(patch);

    sqlx::query("UPDATE mail.messages SET state_flags = state_flags || $1::jsonb WHERE message_id = $2")
        .bind(&patch_json)
        .bind(message_id)
        .execute(&mut *tx)
        .await?;

    let seq = journal_append(&mut tx, principal_id, "flags_changed", Some(message_id), &patch_json).await?;
    tx.commit().await?;
    Ok(seq)
}

/// `POST /state/delete` (A04 §5.3), mode **hard** uniquement dans cette implémentation (A04
/// v1.4 changelog : le Bridge, mono-dossier, n'exerce que la purge — voir `SIMPLIFICATIONS.md`
/// pour le mode "soft"/déplacement vers Corbeille, non câblé ici). Purge : ligne `messages` +
/// enveloppes + blobs (cascade FK `ON DELETE CASCADE`), événement `message_deleted` journalisé
/// dans la MÊME transaction que la suppression catalogue (A02-DEL-1). Les objets de l'object
/// store sont supprimés APRÈS le commit, avec vérification (A02-DEL-2) — un échec de suppression
/// de fichier n'invalide pas la purge catalogue déjà actée (laissé au GC, esprit A02-FAIL-2),
/// mais est loggué, jamais silencieux.
pub async fn purge_message(
    pool: &PgPool,
    blob_store: &BlobStore,
    principal_id: Uuid,
    message_id: Uuid,
) -> Result<i64, StorageError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT message_id FROM mail.messages WHERE message_id = $1 AND principal_id = $2 FOR UPDATE")
        .bind(message_id)
        .bind(principal_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StorageError::MessageNotFound(message_id))?;

    let blob_keys: Vec<(String,)> = sqlx::query_as("SELECT object_key FROM mail.blobs WHERE message_id = $1")
        .bind(message_id)
        .fetch_all(&mut *tx)
        .await?;

    // FK ON DELETE CASCADE (A21 §2.3/2.4) : supprime blobs + enveloppes de ce message avec la ligne.
    sqlx::query("DELETE FROM mail.messages WHERE message_id = $1")
        .bind(message_id)
        .execute(&mut *tx)
        .await?;

    let payload = serde_json::json!({ "message_id": message_id });
    let seq = journal_append(&mut tx, principal_id, "message_deleted", Some(message_id), &payload).await?;
    tx.commit().await?;

    for (object_key,) in blob_keys {
        if let Err(e) = blob_store.delete(&object_key) {
            tracing::warn!(
                %object_key, error = %e,
                "échec de suppression vérifiée du blob à la purge (A02-DEL-2) — laissé au GC, catalogue déjà purgé"
            );
        }
    }
    Ok(seq)
}

/// Résultat stocké d'une requête d'état déjà exécutée sous CETTE clé d'idempotence (A04-IDEM-1).
pub struct IdempotentResult {
    pub response_body: serde_json::Value,
    pub journal_seq: i64,
}

/// Étape 1 d'une requête mutante (`/state/flags`/`/state/delete`) : la clé a-t-elle DÉJÀ été
/// exécutée ? Si oui, l'appelant DOIT renvoyer ce résultat SANS ré-appliquer l'effet
/// (A04-IDEM-1). Fenêtre de course connue (voir `SIMPLIFICATIONS.md`) : cette vérification et
/// l'enregistrement ([`record_idempotency`]) ne sont pas atomiques ENTRE EUX — deux requêtes
/// concurrentes sous la MÊME clé pourraient toutes deux passer ce contrôle avant que l'une des
/// deux n'enregistre sa clé. Acceptable pour cette tranche (un Bridge IMAP séquentiel, pas un
/// service exposé à une charge concurrente adversariale), documenté plutôt que caché.
pub async fn check_idempotency(
    pool: &PgPool,
    idempotency_key: Uuid,
) -> Result<Option<IdempotentResult>, StorageError> {
    let row: Option<(serde_json::Value, i64)> = sqlx::query_as(
        "SELECT response_body, journal_seq FROM mail.idempotency_keys WHERE idempotency_key = $1",
    )
    .bind(idempotency_key)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(response_body, journal_seq)| IdempotentResult { response_body, journal_seq }))
}

/// Étape 2 : enregistre le résultat de la PREMIÈRE exécution sous cette clé (A04-IDEM-1 : "the
/// server MUST deduplicate"). `ON CONFLICT DO NOTHING` : si une course a fait gagner un autre
/// appel concurrent (voir la note de [`check_idempotency`]), on ne réécrit jamais un résultat
/// déjà posé — la première réponse enregistrée fait foi.
pub async fn record_idempotency(
    pool: &PgPool,
    idempotency_key: Uuid,
    principal_id: Uuid,
    endpoint: &str,
    response_body: &serde_json::Value,
    journal_seq: i64,
) -> Result<(), StorageError> {
    sqlx::query(
        "INSERT INTO mail.idempotency_keys (idempotency_key, principal_id, endpoint, response_body, journal_seq)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (idempotency_key) DO NOTHING",
    )
    .bind(idempotency_key)
    .bind(principal_id)
    .bind(endpoint)
    .bind(response_body)
    .bind(journal_seq)
    .execute(pool)
    .await?;
    Ok(())
}

/// Vérifie qu'aucune ligne `mail.messages`/`mail.blobs` ne contient le clair d'origine
/// (garde-fou anti-régression INV-1, dans l'esprit du test déjà présent dans `diamy-mxd`).
pub async fn assert_no_plaintext_leak(
    pool: &PgPool,
    blob_store: &BlobStore,
    message_id: Uuid,
    plaintext: &[u8],
) -> Result<(), StorageError> {
    let summary: (Vec<u8>,) =
        sqlx::query_as("SELECT summary_ct FROM mail.messages WHERE message_id = $1")
            .bind(message_id)
            .fetch_one(pool)
            .await?;
    let blob: (String,) =
        sqlx::query_as("SELECT object_key FROM mail.blobs WHERE message_id = $1 AND kind = 'body'")
            .bind(message_id)
            .fetch_one(pool)
            .await?;
    let body_bytes = blob_store.read(&blob.0)?;

    let leaks = contains_subslice(&summary.0, plaintext) || contains_subslice(&body_bytes, plaintext);
    if leaks {
        // Violation d'invariant, pas une erreur récupérable (INV-1) : on arrête tout.
        panic!("FUITE : du clair est présent dans le stockage serveur (Postgres/object store) !");
    }
    Ok(())
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn nonce_from_vec(bytes: &[u8]) -> Result<[u8; 12], StorageError> {
    bytes.try_into().map_err(|_| {
        StorageError::Db(sqlx::Error::Decode(
            "nonce GCM invalide : attendu 12 octets".into(),
        ))
    })
}

fn sha512_of(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha512};
    Sha512::digest(bytes).to_vec()
}

/// Publie le paquet PUBLIC d'un appareil dans l'annuaire (A21 §3, A17-DIR-3 étape 3).
/// L'appelant doit fournir une clé publique de chiffrement DÉJÀ générée par l'appareil
/// lui-même — cette fonction ne génère JAMAIS de clé, elle ne fait qu'accepter et
/// vérifier un paquet déjà produit côté client (A17-KEY-2).
///
/// A17-KEY-3 : la signature Dilithium du paquet DOIT être vérifiée avant acceptation.
/// Simplification assumée (voir `SIMPLIFICATIONS.md`) : la vérification se fait ici
/// contre la clé d'identité fournie par l'appelant, PAS contre un annuaire d'identité
/// IAM réel (qui n'existe pas dans cette maquette) — donc ceci prouve le mécanisme de
/// vérification, pas encore le lien de confiance complet vers IAM.
#[allow(clippy::too_many_arguments)]
pub async fn publish_device_bundle(
    pool: &PgPool,
    principal_id: Uuid,
    device_id: Uuid,
    mlkem_pub: &[u8],
    dilithium_sig: &[u8],
    signing_device: Uuid,
    signing_identity_pub: &IdentityPublicKey,
) -> Result<(), StorageError> {
    let sig = Signature(dilithium_sig.to_vec());
    let verified = diamy_mail_crypto::verify_manifest(signing_identity_pub, mlkem_pub, &sig)?;
    if !verified {
        return Err(StorageError::InvalidDeviceBundleSignature);
    }

    // INV-20 / A18-LOG-3 : état AVANT la publication (pour l'entrée d'audit before/after).
    // Empreinte de la clé PUBLIQUE seulement, jamais la clé brute (INV-21).
    let before = sqlx::query_as::<_, (Vec<u8>, String)>(
        "SELECT mlkem_pub, validity_state FROM keydir.mail_device_keys
         WHERE principal_id = $1 AND device_id = $2",
    )
    .bind(principal_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await?;

    sqlx::query(
        "INSERT INTO keydir.mail_device_keys
            (principal_id, device_id, mlkem_pub, dilithium_sig, signing_device, validity_state)
         VALUES ($1, $2, $3, $4, $5, 'active')
         ON CONFLICT (principal_id, device_id) DO UPDATE
            SET mlkem_pub = EXCLUDED.mlkem_pub,
                dilithium_sig = EXCLUDED.dilithium_sig,
                signing_device = EXCLUDED.signing_device,
                validity_state = 'active'",
    )
    .bind(principal_id)
    .bind(device_id)
    .bind(mlkem_pub)
    .bind(dilithium_sig)
    .bind(signing_device)
    .execute(pool)
    .await?;

    // INV-20 : publication d'annuaire de clés = action privilégiée -> sink d'audit distinct
    // (actor = appareil signataire ; before/after = état + empreinte de clé publique).
    let before_json = match &before {
        Some((prev_pub, prev_state)) => serde_json::json!({
            "existed": true,
            "prev_validity_state": prev_state,
            "prev_mlkem_pub_fp": key_fingerprint(prev_pub),
        }),
        None => serde_json::json!({ "existed": false }),
    };
    diamy_obs::audit::record(
        &format!("device:{signing_device}"),
        "keydir.publish_device_bundle",
        before_json,
        serde_json::json!({
            "principal_id": principal_id,
            "device_id": device_id,
            "signing_device": signing_device,
            "validity_state": "active",
            "mlkem_pub_fp": key_fingerprint(mlkem_pub),
        }),
    );
    Ok(())
}

/// Empreinte courte (8 premiers octets du SHA-512, en hex) d'une clé PUBLIQUE, pour les
/// entrées d'audit (INV-20) : identifie la clé sans en journaliser les octets bruts (INV-21).
fn key_fingerprint(public_key_bytes: &[u8]) -> String {
    sha512_of(public_key_bytes)
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Lit les clés publiques des appareils ACTIFS d'un principal (A17-DIR-2 : la frontière
/// lit cet annuaire au moment du chiffrement — elle ne génère jamais de clé elle-même).
/// Une liste vide signifie "zéro appareil actif" (A17-DIR-5) : l'appelant DOIT alors
/// passer par la file de hold (A01-HOLD, IMPLÉMENTÉE — voir `store_held_message`/
/// `release_held_messages_for_principal` plus bas et `SIMPLIFICATIONS.md`), jamais
/// fabriquer une clé de substitution.
pub async fn active_device_keys(
    pool: &PgPool,
    principal_id: Uuid,
) -> Result<Vec<(Uuid, Vec<u8>)>, StorageError> {
    let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT device_id, mlkem_pub FROM keydir.mail_device_keys
         WHERE principal_id = $1 AND validity_state = 'active'",
    )
    .bind(principal_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Borne de taille de la file de hold PAR PRINCIPAL (A01-HOLD-3 : "size-bounded per
/// principal; overflow tempfails new inbound"). Valeur de maquette, pas configurable par
/// tenant (A01-HOLD-3 le demande ; voir `SIMPLIFICATIONS.md`).
pub const MAX_HELD_PER_PRINCIPAL: i64 = 100;

/// Un message tenu en attente (A01-HOLD-1), design **clé seule** (A21 §2.6 v1.5) : le
/// message est déjà catalogué (`message_id`, blob de corps sous `k_msg` dans `mail.blobs`),
/// et `wrapped_kmsg` ne porte que `k_msg` emballé sous `k_hold` — JAMAIS le corps.
pub struct HeldMessage {
    pub hold_id: Uuid,
    pub tenant_id: Uuid,
    /// Le message déjà catalogué dans `mail.messages` auquel ce hold se rapporte (A01-HOLD-1).
    pub message_id: Uuid,
    /// `k_msg` emballé sous `k_hold` (A01-HOLD-1) — à désemballer via
    /// [`diamy_mail_crypto::unwrap_message_key_from_hold`], jamais `open_with_key` (ce
    /// n'est pas un corps).
    pub wrapped_kmsg: Ciphertext,
}

/// A01-HOLD-1 (design clé seule) : catalogue le message COMME une livraison ordinaire
/// (ligne `messages` + blob `body` sous `k_msg`) mais SANS enveloppe d'appareil (aucun
/// appareil actif), puis dépose en file `k_msg` emballé sous `k_hold` (`wrapped_kmsg`).
/// Tout en UNE transaction (A18-ERR : pas d'état partiel — jamais de message catalogué
/// sans sa ligne de hold, ni l'inverse). `wrapped_kmsg` DOIT être produit par l'appelant
/// via `crypto::wrap_message_key_under_hold` (+ `crypto::aad_for_hold(hold_id)`).
/// Expiration +30 jours calculée en SQL (A01-HOLD-3), pas d'horloge applicative.
#[allow(clippy::too_many_arguments)]
pub async fn store_held_message(
    pool: &PgPool,
    blob_store: &BlobStore,
    msg: &InboundMessage<'_>,
    hold_id: Uuid,
    wrapped_kmsg: &Ciphertext,
) -> Result<(), StorageError> {
    debug_assert!(
        msg.envelopes.is_empty(),
        "un message tenu n'a AUCUNE enveloppe d'appareil (A01-HOLD-1) — sinon il serait déjà livrable"
    );
    let mut tx = pool.begin().await?;
    insert_message_and_body(&mut tx, blob_store, msg).await?;
    sqlx::query(
        "INSERT INTO mail.hold_queue
            (hold_id, principal_id, tenant_id, message_id, wrapped_kmsg, wrap_nonce, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, now() + interval '30 days')",
    )
    .bind(hold_id)
    .bind(msg.principal_id)
    .bind(msg.tenant_id)
    .bind(msg.message_id)
    .bind(&wrapped_kmsg.bytes)
    .bind(wrapped_kmsg.nonce.as_slice())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// A01-HOLD-3 : compte les messages actuellement tenus pour CE principal, pour appliquer
/// la borne de taille avant d'accepter un nouveau message dans la file.
pub async fn count_held_for_principal(pool: &PgPool, principal_id: Uuid) -> Result<i64, StorageError> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM mail.hold_queue WHERE principal_id = $1")
        .bind(principal_id)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// A01-HOLD-4 : les principaux ayant AU MOINS un message tenu — c'est la liste que le job
/// de release (périodique, `diamy-mxd`) parcourt à chaque passage pour savoir qui essayer
/// de relâcher (la fonction de release elle-même est un no-op si toujours zéro appareil).
pub async fn distinct_held_principal_ids(pool: &PgPool) -> Result<Vec<Uuid>, StorageError> {
    let rows: Vec<(Uuid,)> = sqlx::query_as("SELECT DISTINCT principal_id FROM mail.hold_queue")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Profondeur totale de la file de hold, tous principaux confondus (A01 §11 :
/// "gauges: hold-queue depth per tenant" — ici simplifié à une profondeur globale, pas
/// encore par tenant, voir SIMPLIFICATIONS.md). Alimente une jauge Prometheus, pas un
/// compteur : peut monter ET descendre.
pub async fn total_held_count(pool: &PgPool) -> Result<i64, StorageError> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM mail.hold_queue")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// A01-HOLD-4 : tous les messages tenus pour ce principal — appelé par le job de release
/// une fois le premier appareil publié.
pub async fn list_held_for_principal(
    pool: &PgPool,
    principal_id: Uuid,
) -> Result<Vec<HeldMessage>, StorageError> {
    // Tuple de projection SQL (hold_id, tenant_id, message_id, wrapped_kmsg, wrap_nonce) —
    // reconstruit immédiatement en `HeldMessage` juste en dessous.
    #[allow(clippy::type_complexity)]
    let rows: Vec<(Uuid, Uuid, Uuid, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT hold_id, tenant_id, message_id, wrapped_kmsg, wrap_nonce
         FROM mail.hold_queue WHERE principal_id = $1",
    )
    .bind(principal_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|(hold_id, tenant_id, message_id, bytes, nonce)| {
            Ok(HeldMessage {
                hold_id,
                tenant_id,
                message_id,
                wrapped_kmsg: Ciphertext {
                    // `hold_queue` n'a pas de colonne de version (A21 §2.6) : donnée
                    // transitoire, emballée ET désemballée côté serveur dans la même version
                    // de code. On reconstruit avec `CURRENT` (jamais une version inconnue
                    // devinée). Contrairement à la note d'avant l'amendement A21 v1.5, ce
                    // n'est plus rattaché à une divergence ouverte — le design clé-seule est
                    // tranché (voir 0004_hold_queue_key_only.sql).
                    alg_version: AlgVersion::CURRENT,
                    nonce: nonce_from_vec(&nonce)?,
                    bytes,
                },
            })
        })
        .collect()
}

/// A01-HOLD-4 : détruit la copie tenue après release réussie (idempotent : un second
/// appel sur un `hold_id` déjà supprimé ne renvoie pas d'erreur, `DELETE` ne fait rien).
pub async fn delete_hold(pool: &PgPool, hold_id: Uuid) -> Result<(), StorageError> {
    sqlx::query("DELETE FROM mail.hold_queue WHERE hold_id = $1")
        .bind(hold_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// A01-HOLD-3 : purge les messages tenus expirés. Renvoie les `(hold_id, principal_id)`
/// purgés — pour un vrai DSN à l'expéditeur d'origine (A01-HOLD-3), NON implémenté ici
/// (aucun envoi sortant DSN n'existe dans cette maquette, voir `SIMPLIFICATIONS.md) : la
/// purge a lieu, mais sans notification réelle à l'expéditeur.
pub async fn purge_expired_holds(pool: &PgPool) -> Result<Vec<(Uuid, Uuid)>, StorageError> {
    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "DELETE FROM mail.hold_queue WHERE expires_at < now() RETURNING hold_id, principal_id",
    )
    .fetch_all(pool)
    .await?;

    // INV-20 / A18-LOG-3 : la purge est une destruction irréversible -> entrée d'audit
    // distincte (une par lot non vide). Actor = le job de balayage serveur.
    if !rows.is_empty() {
        diamy_obs::audit::record(
            "diamy-mxd:hold-sweep",
            "hold.purge_expired",
            serde_json::json!({ "purged_count": rows.len() }),
            serde_json::json!({
                "hold_ids": rows.iter().map(|(h, _)| h.to_string()).collect::<Vec<_>>(),
                "principal_ids": rows.iter().map(|(_, p)| p.to_string()).collect::<Vec<_>>(),
            }),
        );
    }
    Ok(rows)
}

/// A01-HOLD-4/5 (release) : "upon publication of the recipient's first device bundle...
/// re-derive k_hold, **unwrap `k_msg`** in the frontier trust boundary, produce normal
/// per-device envelopes (A02-CRY-4), persist them, and destroy the hold-queue copy". Vit
/// ICI (pas dans `diamy-mxd`) pour qu'il n'existe qu'UNE implémentation, appelable à la
/// fois par l'exemple d'enrôlement et par les tests d'intégration de `diamy-mxd`.
///
/// Design **clé seule** (A21 §2.6 v1.5, arbitré par Cédric le 2026-07-15) : le message est
/// DÉJÀ catalogué (ligne `mail.messages` + blob de corps sous `k_msg`, écrits à la
/// réception par `store_held_message`). Cette fonction ne fait donc que :
///   1. désemballer `k_msg` depuis `k_hold` (`unwrap_message_key_from_hold` — la clé, JAMAIS
///      le corps) ;
///   2. produire des enveloppes normales de `k_msg` pour les appareils désormais actifs,
///      liées au `message_id` PRÉ-EXISTANT ;
///   3. supprimer la ligne de hold.
///
/// Le corps chiffré (`mail.blobs`) n'est ni lu, ni réécrit, ni re-scellé — bit-à-bit
/// inchangé (A01-HOLD-5, A01 §13 err.#8 : ne PAS reconstruire le clair du corps). Elle
/// n'appelle donc AUCUNE fonction de déchiffrement du corps (`open_message`/`open_with_key`)
/// — vérifié par un test dédié (voir `tests`). `sender_canonical` et tout le catalogue sont
/// préservés (ce sont les colonnes de la ligne `mail.messages`, posées à la réception) :
/// plus de placeholder « expéditeur perdu ». Ni `blob_store` ni `recipient_canonical` ne
/// sont nécessaires (rien du corps ni de l'adresse n'est re-manipulé ici).
pub async fn release_held_messages_for_principal(
    pool: &PgPool,
    hold_master_secret: &[u8],
    principal_id: Uuid,
) -> Result<usize, StorageError> {
    let devices = active_device_keys(pool, principal_id).await?;
    if devices.is_empty() {
        return Ok(0); // A01-HOLD-4 : rien à relâcher tant qu'aucun appareil n'est actif
    }

    let held = list_held_for_principal(pool, principal_id).await?;
    let mut released = 0usize;

    for item in held {
        let k_hold = diamy_mail_crypto::derive_k_hold(hold_master_secret, item.tenant_id, principal_id)?;
        let aad = diamy_mail_crypto::aad_for_hold(item.hold_id);
        // A01-HOLD-4/5 : on désemballe UNIQUEMENT k_msg (la clé), jamais le corps.
        // Fail-closed (INV-8/16) : un tag GCM invalide laisse la copie EN FILE plutôt que de
        // perdre un message qu'on n'a pas pu ouvrir.
        let Ok(message_key) =
            diamy_mail_crypto::unwrap_message_key_from_hold(&item.wrapped_kmsg, &k_hold, &aad)
        else {
            continue;
        };

        // Enveloppes normales (A02-CRY-4) pour le message DÉJÀ catalogué : le corps chiffré
        // dans `mail.blobs` n'est jamais touché (A01-HOLD-5).
        let mut envelopes = Vec::with_capacity(devices.len());
        for (device_id, mlkem_pub_bytes) in &devices {
            let device_pub = DeviceEncPublicKey(mlkem_pub_bytes.clone());
            let envelope = diamy_mail_crypto::wrap_key_for_device(
                &message_key,
                &device_pub,
                &diamy_mail_crypto::aad_for_envelope(item.message_id, *device_id),
            )?;
            envelopes.push((*device_id, envelope));
        }
        drop(message_key); // INV-1/3 : la clé de message ne survit pas au-delà de l'usage
        let envelope_refs: Vec<(Uuid, &Envelope)> = envelopes.iter().map(|(id, e)| (*id, e)).collect();

        // Enveloppes + marquage `released_from_hold` + suppression du hold : UNE transaction
        // atomique. Idempotente/resumable (A01-HOLD-4) : `insert_envelopes` est un UPSERT sur
        // la PK `(message_id, device_id)`, et si la fonction est relancée la ligne de hold
        // aura disparu (ou sera re-traitée sans duplication).
        let mut tx = pool.begin().await?;
        insert_envelopes(&mut tx, item.message_id, &envelope_refs, "frontier").await?;
        sqlx::query(
            "UPDATE mail.messages
             SET trust_metadata = COALESCE(trust_metadata, '{}'::jsonb) || '{\"released_from_hold\": true}'::jsonb
             WHERE message_id = $1",
        )
        .bind(item.message_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM mail.hold_queue WHERE hold_id = $1")
            .bind(item.hold_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        // INV-20 / A18-LOG-3 : la libération de hold est une action privilégiée -> sink
        // d'audit distinct (une entrée par message relâché), comme `publish_device_bundle`
        // et `purge_expired_holds`. Jamais de clé ni de contenu (INV-21) : IDs + compte
        // d'enveloppes seulement.
        diamy_obs::audit::record(
            "diamy-mxd:hold-release",
            "hold.release",
            serde_json::json!({ "hold_id": item.hold_id, "message_id": item.message_id }),
            serde_json::json!({
                "message_id": item.message_id,
                "principal_id": principal_id,
                "envelopes_created": envelope_refs.len(),
            }),
        );
        released += 1;
    }

    Ok(released)
}

#[cfg(test)]
mod tests {
    /// A01-HOLD-5 / A01 §13 err.#8 (PREUVE par analyse statique du call-graph) : la release
    /// de hold ne doit JAMAIS appeler une fonction de déchiffrement du CORPS
    /// (`open_message`/`open_with_key`). Elle ne fait transiter que la clé
    /// (`unwrap_message_key_from_hold`), design clé-seule A01-HOLD-1/5 (mirroir de A02-RW-1).
    ///
    /// On lit le source de CETTE crate et on isole le CORPS de
    /// `release_held_messages_for_principal` (de sa signature jusqu'au module de tests) —
    /// les mentions de `open_message`/`open_with_key` dans les commentaires de doc (AVANT la
    /// signature) sont donc hors périmètre. Un test qui échoue à la compilation si la
    /// fonction réintroduit un déchiffrement de corps : régression impossible en silence.
    #[test]
    fn release_never_decrypts_the_body() {
        let src = include_str!("lib.rs");
        let start = src
            .find("pub async fn release_held_messages_for_principal")
            .expect("la fonction de release doit exister");
        // Fin = début du module de tests (release est le dernier item non-test du fichier).
        let end = src[start..]
            .find("\n#[cfg(test)]")
            .map(|i| start + i)
            .unwrap_or(src.len());
        let body = &src[start..end];

        assert!(
            !body.contains("open_with_key"),
            "release_held_messages_for_principal NE doit PAS appeler open_with_key (A01-HOLD-5)"
        );
        assert!(
            !body.contains("open_message"),
            "release_held_messages_for_principal NE doit PAS appeler open_message (A01-HOLD-5)"
        );
        // Contrôle positif : elle DOIT bien désemballer la clé seule (sinon le test ci-dessus
        // passerait trivialement si la fonction était vidée/renommée).
        assert!(
            body.contains("unwrap_message_key_from_hold"),
            "release doit désemballer k_msg via unwrap_message_key_from_hold (A01-HOLD-4)"
        );
    }
}
