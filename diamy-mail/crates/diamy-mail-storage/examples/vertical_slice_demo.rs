//! Rejoue le CHEMIN VERTICAL de la maquette de bout en bout, avec un VRAI Postgres (A21,
//! sous-ensemble `mail` : folders/messages/blobs/envelopes + `keydir`) et l'object store de
//! dev sur disque : mail reçu → stocké CHIFFRÉ → synchronisé (relecture) → déchiffré côté
//! « client » avec vérification du tag (INV-8).
//!
//! **Pourquoi c'est un exemple, et pas le `main()` d'un service (INV-4/INV-9/A17-KEY-2).**
//! Cette démo doit enrôler un appareil, donc GÉNÉRER une paire de clés d'identité et une
//! paire de clés d'appareil (`generate_identity_keypair`/`generate_device_keypair`). Or
//! générer une clé d'appareil est un geste EXCLUSIVEMENT CLIENT, jamais serveur : `keydir`
//! ne reçoit que la partie PUBLIQUE (A17-DIR-3). Un binaire de service qui ferait cette
//! génération violerait littéralement A17-KEY-2 — exactement le gap corrigé (voir
//! `SIMPLIFICATIONS.md`, « Correction appliquée — génération de clé isolée hors du binaire
//! de service »). Un exemple Cargo n'est JAMAIS lié dans le binaire de `diamy-maild` : il
//! joue ici le rôle du client de test, comme `enroll_test_device`/`read_test_mail`.
//!
//! Ce programme écrit dans le même Postgres + object store que `diamy-maild` sert : après
//! l'avoir lancé, `diamy-maild` peut exposer ces données via son API de sync, et
//! `read_test_mail` peut les relire par le réseau. Les deux étapes SERVEUR (publication du
//! bundle d'appareil, stockage du message) ne voient jamais que du public/du chiffré.
//!
//! Usage : `cargo run --example vertical_slice_demo -p diamy-mail-storage`
//!   (DATABASE_URL et DIAMY_MAILD_BLOB_DIR reprennent les mêmes défauts que le service.)

use diamy_addr::{diamy_addr_canon, TenantAddressPolicy};
use diamy_mail_crypto as crypto;
use diamy_mail_iam::{DevIamClient, IamClient};
use diamy_mail_storage::{self as storage, BlobStore, InboundMessage};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://diamy:devonly_change_me@localhost:5433/diamymail".to_string()
    });
    let blob_dir =
        std::env::var("DIAMY_MAILD_BLOB_DIR").unwrap_or_else(|_| "./blob_store".to_string());
    let pool = storage::connect(&database_url).await?;
    let blob_store = BlobStore::at(&blob_dir)?;

    println!("== démo chemin vertical (Postgres réel) ==");
    println!("backend crypto : {}", crypto::backend_name());

    // 1) Résolution du destinataire via IAM (adresse canonique, A24/A17) — identique à diamy-mxd.
    let iam = DevIamClient::seeded();
    let recipient = iam.resolve_principal("hugo@w3.tel")?;
    let sender = diamy_addr_canon("expediteur.test@example.fr", TenantAddressPolicy::default())?;
    println!("destinataire résolu via IAM (principal {})", recipient.id);

    // --- Étape CLIENT (A17-DIR-3) : l'appareil génère SES PROPRES clés, localement, et ne
    // publie QUE la partie publique. Ni `diamy-maild` ni `diamy-mxd` ne font JAMAIS cela
    // (A17-KEY-2) — c'est précisément pourquoi cette logique vit dans un exemple, hors du
    // binaire de service. Voir aussi `enroll_test_device.rs`.
    let (identity_pub, identity_sec) = crypto::generate_identity_keypair()?;
    let (device_pub, device_sec) = crypto::generate_device_keypair()?;
    let device_id = Uuid::now_v7();
    // A17-P-3 : dérivation déterministe (UUIDv5 depuis le domaine), même pattern que
    // DevIamClient::seeded() pour principal_id — voir diamy-mxd et SIMPLIFICATIONS.md.
    let tenant_id = diamy_mail_iam::derive_dev_tenant_id(recipient.address.domain_alabel());
    let signature = crypto::sign_manifest(&identity_sec, &device_pub.0)?;

    // --- Étape SERVEUR (A21 §3, A17-DIR-3 étape 3-4) : seule la clé PUBLIQUE + sa
    // signature entrent dans l'annuaire ; la signature est vérifiée avant acceptation
    // (A17-KEY-3).
    storage::publish_device_bundle(
        &pool,
        recipient.id,
        device_id,
        &device_pub.0,
        &signature.0,
        device_id,
        &identity_pub,
    )
    .await?;
    drop(identity_sec); // clé d'identité (stand-in) : jamais persistée, jamais loguée

    let plaintext =
        b"Bonjour Hugo. Ce message a traverse la frontiere et est stocke dans un vrai Postgres.";

    // A02-CRY-2/3 : `message_id`/`body_blob_id` DOIVENT exister AVANT le chiffrement
    // pour entrer dans l'AAD (`crypto::aad_for_blob`/`aad_for_summary`).
    let message_id = Uuid::now_v7();
    let body_blob_id = Uuid::now_v7();

    // 2) Chiffrement (déjà fait à la frontière en réalité ; ici la démo le refait à l'identique).
    // La clé publique utilisée pour l'enveloppe est relue depuis l'annuaire — PAS la variable
    // locale `device_pub` — pour prouver que le chemin de lecture réel (A17-DIR-2) fonctionne.
    let (body_ct, message_key) =
        crypto::seal_message(plaintext, &crypto::aad_for_blob(message_id, body_blob_id))?;
    let directory_devices = storage::active_device_keys(&pool, recipient.id).await?;
    let (_, mlkem_pub_from_directory) = directory_devices
        .into_iter()
        .find(|(id, _)| *id == device_id)
        .expect("l'appareil vient d'être publié dans l'annuaire ci-dessus");
    let device_pub_from_directory = crypto::DeviceEncPublicKey(mlkem_pub_from_directory);
    let envelope = crypto::wrap_key_for_device(
        &message_key,
        &device_pub_from_directory,
        &crypto::aad_for_envelope(message_id, device_id),
    )?;
    drop(message_key); // clair de la clé détruit dès sortie de scope (INV-1/3)

    // summary_ct (A21-MSG-1) : LE seul contenu dérivé du corps dans `mail.messages`, et
    // c'est du CIPHERTEXT (A02-CRY-3). On n'a pas encore de vrai extracteur de résumé
    // (rendu/A08 non fait) : on chiffre un placeholder, documenté en simplification.
    let (summary_ct, summary_key) =
        crypto::seal_message(b"[resume non implemente - A08]", &crypto::aad_for_summary(message_id))?;
    drop(summary_key);

    // 3) Dossier "inbox" du destinataire (créé s'il n'existe pas encore, A21 §2.1).
    // Placeholder HORS MODÈLE A02 (voir la note équivalente dans diamy-mxd) : AAD
    // distincte, non-vide, sans prétendre à une conformité A02-CRY-2/3 qui ne s'applique
    // pas à ce champ.
    let (folder_name_ct, folder_key) =
        crypto::seal_message(b"Inbox", b"mailfolder-placeholder:not-a02-modeled")?;
    drop(folder_key);
    let inbox_id = storage::ensure_inbox_folder(
        &pool,
        recipient.id,
        tenant_id,
        &folder_name_ct.bytes, // placeholder : la vraie clé de dossier est côté client (A03-KEY-3)
    )
    .await?;

    // 4) Stockage RÉEL : ligne `mail.messages` + blob `body` (object store) + `mail.envelopes`.
    storage::store_inbound_message(
        &pool,
        &blob_store,
        &InboundMessage {
            message_id,
            body_blob_id,
            principal_id: recipient.id,
            tenant_id,
            folder_id: inbox_id,
            sender_canonical: sender.as_str(),
            recipient_canonical: recipient.address.as_str(),
            body_ct: &body_ct,
            summary_ct: &summary_ct,
            size_bytes: plaintext.len() as i64,
            envelopes: &[(device_id, &envelope)],
            trust_metadata: None, // démo interne, pas une vraie session SMTP (voir diamy-mxd pour le TLS)
        },
    )
    .await?;
    println!("message {message_id} stocké dans Postgres (chiffré uniquement)");

    // Garde-fou anti-régression : aucune ligne ne contient le clair (INV-1).
    storage::assert_no_plaintext_leak(&pool, &blob_store, message_id, plaintext).await?;
    println!("stockage Postgres + object store : chiffré seulement (aucune fuite de clair) ✔");

    // 5) Sync + client : l'appareil tire le chiffré + SON enveloppe, déchiffre, VÉRIFIE.
    let fetched =
        storage::fetch_message_for_device(&pool, &blob_store, recipient.id, message_id, device_id)
            .await?;
    let recovered_key =
        crypto::unwrap_key(&fetched.envelope, &device_sec, &crypto::aad_for_envelope(message_id, device_id))?;
    let aad = crypto::aad_for_blob(message_id, fetched.body_blob_id);
    let verified = crypto::open_message(&fetched.body_ct, &recovered_key, &aad)?; // tag vérifié (INV-8)

    assert_eq!(verified.as_bytes(), plaintext);
    println!("client : lu depuis Postgres, déchiffré + tag vérifié ✔");
    println!("== chemin vertical (Postgres) OK ==");

    Ok(())
}
