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
//! Portée volontairement minimale (tranche verticale, guide §7) : `journal`, `hold_queue`,
//! `search`, `send`, `onboard`, `cal`, `iam` restent hors périmètre (voir
//! `SIMPLIFICATIONS.md`).
//!
//! Discipline appliquée (A18 §13 forbidden patterns) :
//! - toutes les requêtes sont paramétrées (`$1, $2, ...`), jamais de SQL concaténé (A18-DB-1) ;
//! - aucun `unwrap()`/`expect()` sur une valeur issue d'E/S ou de la base — tout remonte
//!   en erreur (A18-ERR-1) ;
//! - `body_ciphertext`/`kem_ct`/`wrapped_key` ne sont JAMAIS logués (A18-LOG-1).
#![forbid(unsafe_code)]

use diamy_mail_crypto::{Ciphertext, Envelope, IdentityPublicKey, Signature};
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

/// Stocke un message entrant : ligne `messages` + blob `body` (objet local) + enveloppes.
/// Transactionnel : soit tout est écrit, soit rien (A18-ERR : pas d'état partiel visible).
pub async fn store_inbound_message(
    pool: &PgPool,
    blob_store: &BlobStore,
    msg: &InboundMessage<'_>,
) -> Result<Uuid, StorageError> {
    let message_id = msg.message_id;

    let mut tx = pool.begin().await?;

    sqlx::query(
        "INSERT INTO mail.messages
            (message_id, principal_id, tenant_id, direction, folder_id,
             sender_canonical, recipients_canonical, received_at, size_bytes,
             summary_ct, summary_nonce, trust_metadata)
         VALUES ($1, $2, $3, 'inbound', $4, $5, $6, now(), $7, $8, $9, $10)",
    )
    .bind(message_id)
    .bind(msg.principal_id)
    .bind(msg.tenant_id)
    .bind(msg.folder_id)
    .bind(msg.sender_canonical)
    .bind([msg.recipient_canonical]) // A21-MSG-2 : minimisé, owner + routage seulement, jamais de BCC
    .bind(msg.size_bytes)
    .bind(&msg.summary_ct.bytes)
    .bind(msg.summary_ct.nonce.as_slice())
    .bind(&msg.trust_metadata)
    .execute(&mut *tx)
    .await?;

    // Le corps chiffré part dans l'object store (A21 §1.1), PAS dans une colonne BYTEA
    // de `mail.messages` — Postgres ne garde que la référence `object_key` + son digest.
    let blob_id = msg.body_blob_id;
    let object_key = format!("blobs/{blob_id}");
    blob_store.write(&object_key, &msg.body_ct.bytes)?;
    let sha512_ct = sha512_of(&msg.body_ct.bytes);

    sqlx::query(
        "INSERT INTO mail.blobs
            (blob_id, message_id, kind, object_key, nonce, size_bytes, sha512_ct)
         VALUES ($1, $2, 'body', $3, $4, $5, $6)",
    )
    .bind(blob_id)
    .bind(message_id)
    .bind(&object_key)
    .bind(msg.body_ct.nonce.as_slice())
    .bind(msg.size_bytes)
    .bind(sha512_ct.as_slice()) // digest du CHIFFRÉ, jamais du clair (A21-BLOB-1 / A21-X-3)
    .execute(&mut *tx)
    .await?;

    for (device_id, envelope) in msg.envelopes {
        sqlx::query(
            "INSERT INTO mail.envelopes
                (message_id, device_id, kem_ct, wrapped_key, wrap_nonce, origin)
             VALUES ($1, $2, $3, $4, $5, 'frontier')",
        )
        .bind(message_id)
        .bind(device_id)
        .bind(&envelope.kem_ct)
        .bind(&envelope.wrapped.bytes)
        .bind(envelope.wrapped.nonce.as_slice())
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(message_id)
}

/// Ce que l'appareil récupère pour UN message + SON enveloppe (A02 §3, "le client tire").
pub struct FetchedForDevice {
    /// Nécessaire pour reconstruire l'AAD (`crypto::aad_for_blob(message_id, body_blob_id)`,
    /// A02-CRY-2) avant `open_message` — sans cet id, le tag GCM ne peut pas être vérifié
    /// puisque l'AAD ne correspond plus à celle du scellement.
    pub body_blob_id: Uuid,
    pub body_ct: Ciphertext,
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
    let blob_row = sqlx::query_as::<_, (Uuid, String, Vec<u8>)>(
        "SELECT b.blob_id, b.object_key, b.nonce
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

    let (body_blob_id, object_key, nonce) = blob_row;
    let body_bytes = blob_store.read(&object_key)?;
    let body_ct = Ciphertext {
        nonce: nonce_from_vec(&nonce)?,
        bytes: body_bytes,
    };

    let env_row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>)>(
        "SELECT e.kem_ct, e.wrapped_key, e.wrap_nonce
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

    let (kem_ct, wrapped_key, wrap_nonce) = env_row;
    let envelope = Envelope {
        kem_ct,
        wrapped: Ciphertext {
            nonce: nonce_from_vec(&wrap_nonce)?,
            bytes: wrapped_key,
        },
    };

    Ok(FetchedForDevice {
        body_blob_id,
        body_ct,
        envelope,
    })
}

/// Résumé catalogue d'un message — PLAINTEXT_METADATA uniquement (A21 §2.2), jamais de
/// contenu. C'est ce qu'un client sync liste avant de tirer un message précis.
pub struct MessageSummary {
    pub message_id: Uuid,
    pub sender_canonical: Option<String>,
    pub size_bytes: i64,
    pub received_at: Option<sqlx::types::time::OffsetDateTime>,
}

/// Liste les messages les plus récents d'un principal, bornée (A18-BOUND-1).
/// Simplification assumée (voir `SIMPLIFICATIONS.md`) : borne fixe, pas de curseur de
/// pagination conforme A04-PAGE-1 (pas d'OFFSET malgré tout — tri direct par date desc).
pub async fn list_recent_messages(
    pool: &PgPool,
    principal_id: Uuid,
    limit: i64,
) -> Result<Vec<MessageSummary>, StorageError> {
    let rows: Vec<(Uuid, Option<String>, i64, Option<sqlx::types::time::OffsetDateTime>)> = sqlx::query_as(
        "SELECT message_id, sender_canonical, size_bytes, received_at
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
        .map(|(message_id, sender_canonical, size_bytes, received_at)| MessageSummary {
            message_id,
            sender_canonical,
            size_bytes,
            received_at,
        })
        .collect())
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
    Ok(())
}

/// Lit les clés publiques des appareils ACTIFS d'un principal (A17-DIR-2 : la frontière
/// lit cet annuaire au moment du chiffrement — elle ne génère jamais de clé elle-même).
/// Une liste vide signifie "zéro appareil actif" (A17-DIR-5) : l'appelant DOIT alors
/// passer par la file de hold (A01-HOLD, non implémentée dans cette maquette — voir
/// `SIMPLIFICATIONS.md`), jamais fabriquer une clé de substitution.
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
