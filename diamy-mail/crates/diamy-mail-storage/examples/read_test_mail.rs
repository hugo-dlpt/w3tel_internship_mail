//! Simule le VAULT CLIENT (A03) qui lit son courrier via l'API de sync (A04, tranche
//! minimale servie par `diamy-maild`). Ce programme est un PROCESSUS SÉPARÉ, qui parle au
//! serveur uniquement par le réseau (HTTPS local, `127.0.0.1:8443`, A04-TR-1) — jamais par
//! accès direct à la base ou au même process. Le certificat est auto-signé (dev) : ce
//! client de test l'accepte explicitement, ce qu'un vrai client ne ferait JAMAIS
//! (voir `SIMPLIFICATIONS.md`).
//!
//! Étapes (miroir de la maquette §4 du kit) :
//!   1. lit SA PROPRE clé privée d'appareil dans `./dev_secrets/` (persistée par
//!      `enroll_test_device` — jamais transmise au serveur) ;
//!   2. liste le catalogue du principal via `GET /v1/mailbox/:principal_id/messages` ;
//!   3. tire le chiffré + SON enveloppe pour le message le plus récent ;
//!   4. déchiffre LOCALEMENT et VÉRIFIE le tag avant tout usage (INV-8) ;
//!   5. affiche le clair — uniquement parce que c'est une démo ; en production, seul
//!      l'appareil affiche, jamais le serveur (INV-1/3).
//!
//! Usage : `cargo run --example read_test_mail -p diamy-mail-storage -- hugo@w3.tel`

use base64::{engine::general_purpose::STANDARD, Engine};
use diamy_addr::{diamy_addr_canon, TenantAddressPolicy};
use diamy_mail_crypto as crypto;
use diamy_mail_iam::{DevIamClient, IamClient};
use serde::Deserialize;
use std::path::PathBuf;
use uuid::Uuid;

fn dev_secret_path(canonical_address: &str) -> PathBuf {
    let safe_name = canonical_address.replace(['@', '.'], "_");
    PathBuf::from("./dev_secrets").join(format!("{safe_name}.devicekey"))
}

/// Lit le fichier "coffre" de dev écrit par `enroll_test_device` : 16 octets de
/// `device_id` puis la clé secrète ML-KEM-768 brute.
fn load_device_secret(path: &PathBuf) -> Result<(Uuid, crypto::DeviceEncSecretKey), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path).map_err(|e| {
        format!(
            "impossible de lire {} ({e}) — as-tu lancé `cargo run --example enroll_test_device` d'abord ?",
            path.display()
        )
    })?;
    if bytes.len() < 16 {
        return Err("fichier de clé corrompu (trop court)".into());
    }
    let device_id = Uuid::from_slice(&bytes[..16])?;
    let secret = crypto::DeviceEncSecretKey::from_bytes(bytes[16..].to_vec());
    Ok((device_id, secret))
}

#[derive(Deserialize, Debug)]
struct MessageSummaryDto {
    message_id: Uuid,
    sender_canonical: Option<String>,
    size_bytes: i64,
    received_at: Option<String>,
}

#[derive(Deserialize)]
struct FetchedDto {
    body_blob_id: Uuid,
    body_nonce_b64: String,
    body_ciphertext_b64: String,
    envelope_kem_ct_b64: String,
    envelope_wrap_nonce_b64: String,
    envelope_wrapped_key_b64: String,
}

fn nonce_from_b64(s: &str) -> Result<[u8; 12], Box<dyn std::error::Error>> {
    let bytes = STANDARD.decode(s)?;
    Ok(bytes.as_slice().try_into()?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sync_base = std::env::var("DIAMY_MAILD_SYNC_URL")
        .unwrap_or_else(|_| "https://127.0.0.1:8443".to_string());
    let address_raw = std::env::args().nth(1).unwrap_or_else(|| "hugo@w3.tel".to_string());

    // 1) Résoudre le principal (A24/A17) — même chemin normatif que le serveur.
    let iam = DevIamClient::seeded();
    let canonical = diamy_addr_canon(&address_raw, TenantAddressPolicy::default())?;
    let principal = iam.resolve_principal(canonical.as_str())?;

    // 2) Charger SA PROPRE clé privée depuis le stand-in de coffre sécurisé (jamais réseau).
    let secret_path = dev_secret_path(canonical.as_str());
    let (device_id, device_sec) = load_device_secret(&secret_path)?;
    println!("Appareil {device_id} (clé privée chargée localement, jamais envoyée au réseau).");

    // Certificat auto-signé de dev (A04-TR-1) : accepté explicitement ici UNIQUEMENT
    // parce que c'est un outil de test local — un vrai client ne ferait jamais ça.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    // Authentification (A17-APPKEY-5) : ce client de démo doit présenter les DEUX
    // informations d'identification que `diamy-maild` valide désormais. Un vrai client
    // recevrait son AppKey à l'installation et son jeton mail-plane d'IAM — ici, doublure
    // de dev alignée sur les mêmes variables d'environnement que le serveur
    // (`DIAMY_MAILD_DEV_APPKEY`/`MAIL_JWT_TOKEN`, voir `services/diamy-maild/src/auth.rs`).
    let app_key = std::env::var("DIAMY_MAILD_DEV_APPKEY")
        .unwrap_or_else(|_| "devonly_change_me_appkey_dev_client".to_string());
    let mail_jwt_secret = std::env::var("MAIL_JWT_TOKEN")
        .unwrap_or_else(|_| "devonly_change_me_mail_jwt_secret".to_string());
    let mail_plane_token =
        diamy_mail_iam::mint_dev_mail_plane_token(mail_jwt_secret.as_bytes(), principal.id, 900);
    let auth_headers = |b: reqwest::RequestBuilder| {
        b.header("x-app-key", &app_key)
            .header("x-app-name", "diamy-mail-dev-client")
            .header("x-app-platform", "dev")
            .header("x-app-version", "0.0.1")
            .header("authorization", format!("Bearer {mail_plane_token}"))
    };

    // 3) Catalogue (A04-EP-1 simplifié) : lister les messages, PLAINTEXT_METADATA seulement.
    let list_url = format!("{sync_base}/v1/mailbox/{}/messages", principal.id);
    let messages: Vec<MessageSummaryDto> =
        auth_headers(client.get(&list_url)).send().await?.json().await?;
    println!("{} message(s) au catalogue pour {address_raw}.", messages.len());

    let Some(latest) = messages.first() else {
        println!("Boîte vide — envoie d'abord un mail via diamy-mxd.");
        return Ok(());
    };
    println!(
        "-> le plus récent : {} (de {:?}, {} octets, reçu {:?})",
        latest.message_id, latest.sender_canonical, latest.size_bytes, latest.received_at
    );

    // 4) Tirer le chiffré + SON enveloppe pour CET appareil (A02 §3, "le client tire").
    let fetch_url = format!(
        "{sync_base}/v1/mailbox/{}/messages/{}?device_id={device_id}",
        principal.id, latest.message_id
    );
    let fetched: FetchedDto = auth_headers(client.get(&fetch_url)).send().await?.json().await?;

    let body_ct = crypto::Ciphertext {
        nonce: nonce_from_b64(&fetched.body_nonce_b64)?,
        bytes: STANDARD.decode(&fetched.body_ciphertext_b64)?,
    };
    let envelope = crypto::Envelope {
        kem_ct: STANDARD.decode(&fetched.envelope_kem_ct_b64)?,
        wrapped: crypto::Ciphertext {
            nonce: nonce_from_b64(&fetched.envelope_wrap_nonce_b64)?,
            bytes: STANDARD.decode(&fetched.envelope_wrapped_key_b64)?,
        },
    };

    // 5) Déchiffrement LOCAL + vérification du tag AVANT tout usage (INV-8). L'AAD
    // (A02-CRY-2) doit être reconstruite à l'identique de celle du scellement.
    let message_key = crypto::unwrap_key(&envelope, &device_sec)?;
    let aad = crypto::aad_for_blob(latest.message_id, fetched.body_blob_id);
    let verified = crypto::open_message(&body_ct, &message_key, &aad)?;

    println!("== déchiffré localement, tag vérifié ✔ ==");
    // Affiché ici uniquement parce que c'est une démo (INV-21 : jamais dans un vrai log).
    println!("--- contenu ---\n{}", String::from_utf8_lossy(verified.as_bytes()));

    Ok(())
}
