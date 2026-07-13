//! Simule l'enrôlement d'UN appareil de test (A17-DIR-3) — ce programme joue le rôle du
//! CLIENT, jamais du serveur. Il :
//!   1. génère localement sa propre paire de clés d'identité (stand-in Dilithium/ML-DSA) ;
//!   2. génère localement sa propre paire de clés de chiffrement mail (ML-KEM-768,
//!      A17-KEY-2) — la clé PRIVÉE ne quitte jamais ce processus ;
//!   3. signe sa clé publique de chiffrement avec sa clé d'identité (A17-KEY-3) ;
//!   4. publie SEULEMENT le paquet public dans l'annuaire `keydir` (A21 §3) ;
//!   5. persiste SA PROPRE clé privée dans `./dev_secrets/` — un stand-in de dev pour le
//!      coffre sécurisé de l'OS (INV-4), gitignored, jamais transmis nulle part. C'est ce
//!      qui permet à `read_test_mail` (autre process) de déchiffrer plus tard.
//!
//! `diamy-mxd`/`diamy-maild` ne doivent JAMAIS faire ce que ce programme fait : générer
//! une clé de chiffrement d'appareil est un geste CLIENT, jamais serveur.
//!
//! Usage : `cargo run --example enroll_test_device -p diamy-mail-storage -- hugo@w3.tel`

use diamy_addr::{diamy_addr_canon, TenantAddressPolicy};
use diamy_mail_crypto as crypto;
use diamy_mail_iam::{DevIamClient, IamClient};
use std::path::PathBuf;
use uuid::Uuid;

/// Chemin du fichier "coffre" de dev pour une adresse donnée (voir aussi `read_test_mail.rs`,
/// qui lit exactement ce même format : 16 octets de `device_id` + le reste = clé secrète).
fn dev_secret_path(canonical_address: &str) -> PathBuf {
    let safe_name = canonical_address.replace(['@', '.'], "_");
    PathBuf::from("./dev_secrets").join(format!("{safe_name}.devicekey"))
}

/// Restreint le fichier de clé au seul propriétaire (0600) — un coffre de dev doit rester
/// un coffre, même approximatif (défense en profondeur au-delà du simple gitignore).
#[cfg(unix)]
fn restrict_to_owner(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn restrict_to_owner(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://diamy:devonly_change_me@localhost:5433/diamymail".to_string()
    });
    let address_raw = std::env::args().nth(1).unwrap_or_else(|| "hugo@w3.tel".to_string());

    let pool = diamy_mail_storage::connect(&database_url).await?;

    let iam = DevIamClient::seeded();
    let canonical = diamy_addr_canon(&address_raw, TenantAddressPolicy::default())?;
    let principal = iam.resolve_principal(canonical.as_str())?;

    // --- Ce qui suit se passe UNIQUEMENT sur l'appareil (jamais côté serveur) ---
    let (identity_pub, identity_sec) = crypto::generate_identity_keypair()?;
    let (mail_pub, mail_sec) = crypto::generate_device_keypair()?;
    let device_id = Uuid::now_v7();
    let signature = crypto::sign_manifest(&identity_sec, &mail_pub.0)?;

    // Seule la clé PUBLIQUE (+ signature) part vers le serveur.
    diamy_mail_storage::publish_device_bundle(
        &pool,
        principal.id,
        device_id,
        &mail_pub.0,
        &signature.0,
        device_id,
        &identity_pub,
    )
    .await?;

    println!("Appareil enrôlé pour {address_raw} (principal {}), device_id={device_id}", principal.id);
    println!(
        "Clé publique de chiffrement publiée dans keydir.mail_device_keys ({} octets).",
        mail_pub.0.len()
    );

    // Stand-in de dev pour "le coffre sécurisé de l'OS" (INV-4) : SEUL cet appareil de
    // test lit ce fichier (`read_test_mail`) ; il n'est ni publié ni journalisé, et le
    // répertoire est gitignored.
    let secret_path = dev_secret_path(canonical.as_str());
    if let Some(dir) = secret_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file_bytes = Vec::with_capacity(16 + mail_sec.as_bytes().len());
    file_bytes.extend_from_slice(device_id.as_bytes());
    file_bytes.extend_from_slice(mail_sec.as_bytes());
    std::fs::write(&secret_path, &file_bytes)?;
    restrict_to_owner(&secret_path)?;
    println!(
        "Clé privée ({} octets) persistée dans {} (stand-in de dev pour le coffre sécurisé de l'OS, INV-4).",
        mail_sec.as_bytes().len(),
        secret_path.display()
    );

    Ok(())
}
