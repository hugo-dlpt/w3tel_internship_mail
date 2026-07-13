//! `diamy-mxd` — passerelle entrante & chiffrement frontière (A01).
//!
//! Ce binaire fait tourner **le chemin vertical de la maquette** de bout en bout, en mémoire,
//! avec le backend `dev-crypto` :
//!   mail entrant → chiffrement frontière → stockage (chiffré) → sync → déchiffrement client → clair vérifié.
//!
//! Il démontre les invariants clés : le serveur ne conserve que du chiffré (INV-1), seul
//! l'appareil déchiffre (zone appareil), le tag est vérifié avant usage (INV-8).
//! Le vrai serveur MX SMTP (avec Aubin) viendra remplacer l'« entrée » simulée ici.

use diamy_mail_crypto as crypto;
use diamy_mail_iam::{DevIamClient, IamClient};
use diamy_mail_model::{StoredEnvelope, StoredMessage};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    diamy_obs::init_tracing();

    // Garde-fou fail-closed : le backend dev ne tourne qu'en dev (A18 SEC-FC-1).
    let env = std::env::var("DIAMY_ENV").unwrap_or_else(|_| "dev".to_string());
    crypto::assert_backend_allowed_for_env(&env)?;

    tracing::info!(
        service = "diamy-mxd",
        backend = crypto::backend_name(),
        env = %env,
        "démarrage — démo du chemin vertical"
    );
    println!("== diamy-mxd — démo chemin vertical ==");
    println!("backend crypto : {}", crypto::backend_name());

    // 1) « Réception » d'un mail entrant pour hugo@w3.tel (simulée ; le vrai MX = A01/Aubin).
    let iam = DevIamClient::seeded();
    let recipient = iam.resolve_principal("hugo@w3.tel")?;
    tracing::info!(recipient_id = %recipient.id, "destinataire résolu via IAM (adresse canonique)");

    // Simule l'appareil du destinataire : sa clé privée reste « sur l'appareil » (INV-4).
    let (device_pub, device_sec) = crypto::generate_device_keypair()?;
    let device_id = Uuid::now_v7();

    let plaintext =
        b"Bonjour Hugo. Ce message a traverse la frontiere, le stockage chiffre et la sync.";

    // 2) Chiffrement frontière : le contenu est scellé, la clé emballée par appareil.
    let (ct, message_key) = crypto::seal_message(plaintext)?;
    let envelope = crypto::wrap_key_for_device(&message_key, &device_pub)?;
    // `message_key` (le clair de la clé) sort du scope juste après -> détruit (zeroize). INV-1/3.
    drop(message_key);

    // 3) Ce que le SERVEUR stocke : uniquement du chiffré + enveloppes + métadonnées.
    let stored = StoredMessage {
        id: StoredMessage::new_id(),
        tenant_id: Uuid::now_v7(),
        recipient_id: recipient.id,
        body_nonce: ct.nonce,
        body_ciphertext: ct.bytes.clone(),
        envelopes: vec![StoredEnvelope {
            device_id,
            kem_ct: envelope.kem_ct.clone(),
            wrap_nonce: envelope.wrapped.nonce,
            wrapped_key: envelope.wrapped.bytes.clone(),
        }],
        size_bytes: plaintext.len() as u64,
        received_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or_default(),
    };
    tracing::info!(message_id = %stored.id, size = stored.size_bytes, "message stocké (chiffré uniquement)");

    // Vérif « le serveur ne voit pas le clair » : le blob stocké ne contient pas le texte.
    let leak = stored
        .body_ciphertext
        .windows(plaintext.len())
        .any(|w| w == plaintext);
    assert!(
        !leak,
        "FUITE : du clair est présent dans le stockage serveur !"
    );
    println!("stockage serveur : chiffré seulement (aucune fuite de clair) ✔");

    // 4) Sync + client : l'appareil tire le chiffré + SON enveloppe, déchiffre, VÉRIFIE, rend.
    let rebuilt_ct = crypto::Ciphertext {
        nonce: stored.body_nonce,
        bytes: stored.body_ciphertext.clone(),
    };
    let rebuilt_env = crypto::Envelope {
        kem_ct: stored.envelopes[0].kem_ct.clone(),
        wrapped: crypto::Ciphertext {
            nonce: stored.envelopes[0].wrap_nonce,
            bytes: stored.envelopes[0].wrapped_key.clone(),
        },
    };
    let recovered_key = crypto::unwrap_key(&rebuilt_env, &device_sec)?;
    let verified = crypto::open_message(&rebuilt_ct, &recovered_key)?; // tag vérifié ici (INV-8)

    assert_eq!(verified.as_bytes(), plaintext);
    println!("client : déchiffré + tag vérifié ✔");
    // stdout de démo (notre propre message de test) — en PROD, aucun contenu en logs (INV-21).
    println!("contenu : {}", String::from_utf8_lossy(verified.as_bytes()));
    println!("== chemin vertical OK ==");

    tracing::info!(service = "diamy-mxd", "chemin vertical terminé avec succès");
    Ok(())
}
