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
//!   5. projette le clair vérifié en document Tiptap à schéma fermé (A08,
//!      `diamy-mail-render` — chemin text/plain uniquement, voir SIMPLIFICATIONS.md)
//!      et n'affiche QUE ce document — jamais le clair brut hors schéma. En
//!      production, seul l'appareil affiche, jamais le serveur (INV-1/3).
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
    body_alg_version: i32,
    body_nonce_b64: String,
    body_ciphertext_b64: String,
    envelope_alg_version: i32,
    envelope_kem_ct_b64: String,
    envelope_wrap_nonce_b64: String,
    envelope_wrapped_key_b64: String,
}

fn nonce_from_b64(s: &str) -> Result<[u8; 12], Box<dyn std::error::Error>> {
    let bytes = STANDARD.decode(s)?;
    Ok(bytes.as_slice().try_into()?)
}

/// Charge le jeton mail-plane pré-signé (VALIDE, non expiré) correspondant à ce principal,
/// depuis `tests/fixtures/dev_mail_plane_tokens.json` (embarqué à la compilation). Aucun
/// jeton n'est FABRIQUÉ ici : la capacité de signer un jeton de session a été retirée du code
/// (INV-9 / A17-P-1 — seul IAM en émet). Ce client de démo ne fait que PRÉSENTER un jeton déjà
/// signé, comme un vrai client présenterait celui reçu d'IAM. La fixture ne couvre que les
/// principaux seeded (hugo/cedric/aubin@w3.tel).
fn load_fixture_mail_plane_token(principal_id: Uuid) -> Result<String, Box<dyn std::error::Error>> {
    const FIXTURES: &str = include_str!("../../../tests/fixtures/dev_mail_plane_tokens.json");
    let v: serde_json::Value = serde_json::from_str(FIXTURES)?;
    let tokens = v["tokens"].as_object().ok_or("fixture invalide : champ `tokens` absent")?;
    let wanted = principal_id.to_string();
    for entry in tokens.values() {
        let same_principal = entry["principal_id"].as_str() == Some(wanted.as_str());
        let is_valid = entry["expired"].as_bool() != Some(true);
        if same_principal && is_valid {
            if let Some(tok) = entry["token"].as_str() {
                return Ok(tok.to_string());
            }
        }
    }
    Err(format!(
        "aucun jeton de test pré-signé (valide) pour le principal {principal_id} dans la fixture \
         — elle ne couvre que hugo/cedric/aubin@w3.tel, et aucun jeton ne peut être fabriqué à la \
         volée (INV-9 / A17-P-1 : seul IAM émet des jetons de session)."
    )
    .into())
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
    // Jeton mail-plane : LU depuis la fixture pré-signée, jamais fabriqué (INV-9 / A17-P-1 :
    // seul IAM émet des jetons). Les jetons de la fixture sont signés avec le secret de dev par
    // défaut (`devonly_change_me_mail_jwt_secret`), qui est aussi le défaut du serveur quand
    // `MAIL_JWT_TOKEN` n'est pas surchargé : ils vérifient donc tels quels. (Si tu surcharges
    // `MAIL_JWT_TOKEN` côté serveur, ces jetons figés ne vérifieront plus — attendu.)
    let mail_plane_token = load_fixture_mail_plane_token(principal.id)?;
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

    // INV-7 : le client re-contrôle la version reçue sur le fil (fail-closed sur inconnue)
    // avant `open_message`/`unwrap_key`.
    let body_ct = crypto::Ciphertext {
        alg_version: crypto::AlgVersion::from_i32(fetched.body_alg_version)?,
        nonce: nonce_from_b64(&fetched.body_nonce_b64)?,
        bytes: STANDARD.decode(&fetched.body_ciphertext_b64)?,
    };
    let envelope = crypto::Envelope {
        kem_ct: STANDARD.decode(&fetched.envelope_kem_ct_b64)?,
        wrapped: crypto::Ciphertext {
            alg_version: crypto::AlgVersion::from_i32(fetched.envelope_alg_version)?,
            nonce: nonce_from_b64(&fetched.envelope_wrap_nonce_b64)?,
            bytes: STANDARD.decode(&fetched.envelope_wrapped_key_b64)?,
        },
    };

    // 5) Déchiffrement LOCAL + vérification du tag AVANT tout usage (INV-8). Les AAD
    // (A02-CRY-2, A02-CRY-4) doivent être reconstruites à l'identique de celles du scellement.
    let envelope_aad = crypto::aad_for_envelope(latest.message_id, device_id);
    let message_key = crypto::unwrap_key(&envelope, &device_sec, &envelope_aad)?;
    let aad = crypto::aad_for_blob(latest.message_id, fetched.body_blob_id);
    let verified = crypto::open_message(&body_ct, &message_key, &aad)?;

    println!("== déchiffré localement, tag vérifié ✔ ==");

    // 6) Rendu (A08/INV-17) : jamais le clair brut affiché directement — on
    // projette d'abord en document Tiptap à schéma fermé (A03-READ-1, A19-REND-1),
    // ici via le chemin text/plain seul (A08-TXT-1 ; voir SIMPLIFICATIONS.md pour
    // ce qui n'est pas dans le périmètre de cette maquette : pipeline HTML A08 et
    // sandbox "view original" A09, qui n'ont rien à convertir tant qu'aucun
    // contenu HTML/MIME n'existe encore côté frontière).
    let conversion = diamy_mail_render::convert_plain_text(&String::from_utf8_lossy(verified.as_bytes()));
    println!(
        "--- document Tiptap (schema_version={}) ---\n{}",
        conversion.doc.schema_version,
        serde_json::to_string_pretty(&conversion.doc)?
    );
    // Affiché ici uniquement parce que c'est une démo (INV-21 : jamais dans un vrai log) —
    // c'est la projection texte visible d'A08-OUT-1(b), pas le clair brut non passé au schéma.
    println!("--- projection texte (recherche/IA locale, A05) ---\n{}", conversion.plain_text_projection);

    Ok(())
}
