//! Enrôle l'appareil **Bridge** (`diamy-bridged`, A20) — quasi-identique à
//! `enroll_test_device.rs`, dont il reprend le même mécanisme (génération locale des clés,
//! publication de la SEULE clé publique dans `keydir`, persistance de la clé privée en dev
//! secret), mais produit un appareil **SÉPARÉ**, avec ses PROPRES clés, distinct de tout
//! appareil déjà enrôlé pour la même adresse.
//!
//! Pourquoi un exemple séparé plutôt que relancer `enroll_test_device` : `dev_secret_path`
//! (dans `enroll_test_device.rs`/`read_test_mail.rs`) dérive son nom de fichier UNIQUEMENT de
//! l'adresse — relancer `enroll_test_device` pour la même adresse écraserait le fichier de
//! l'appareil déjà enrôlé. Le Bridge DOIT être son PROPRE appareil IAM, avec ses propres clés,
//! même co-localisé sur la même machine que le client natif (A20-CRED-4b) : ce programme écrit
//! donc dans un fichier DIFFÉRENT (`*.bridge.devicekey`), pour que les deux appareils coexistent
//! sans collision — le principal se retrouve avec DEUX appareils actifs distincts dans
//! `keydir.mail_device_keys`.
//!
//! Usage : `cargo run --example enroll_bridge_device -p diamy-mail-storage -- hugo@w3.tel`

use diamy_addr::{diamy_addr_canon, TenantAddressPolicy};
use diamy_mail_crypto as crypto;
use diamy_mail_iam::{DevIamClient, IamClient};
use std::path::PathBuf;
use uuid::Uuid;

/// Chemin du coffre de dev de l'appareil BRIDGE — DIFFÉRENT de `dev_secret_path` dans
/// `enroll_test_device.rs`/`read_test_mail.rs` (`{safe_name}.devicekey`), précisément pour ne
/// jamais écraser l'appareil de test déjà enrôlé pour la même adresse.
fn bridge_dev_secret_path(canonical_address: &str) -> PathBuf {
    let safe_name = canonical_address.replace(['@', '.'], "_");
    PathBuf::from("./dev_secrets").join(format!("{safe_name}.bridge.devicekey"))
}

/// Restreint le fichier de clé au seul propriétaire (0600) — même discipline que
/// `enroll_test_device.rs`.
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

    // --- Ce qui suit se passe UNIQUEMENT sur la machine du Bridge (jamais côté serveur) ---
    let (identity_pub, identity_sec) = crypto::generate_identity_keypair()?;
    let (mail_pub, mail_sec) = crypto::generate_device_keypair()?;
    let device_id = Uuid::now_v7();
    let signature = crypto::sign_manifest(&identity_sec, &mail_pub.0)?;

    // Seule la clé PUBLIQUE (+ signature) part vers le serveur — ce nouvel appareil est publié
    // à CÔTÉ de tout appareil déjà enrôlé pour ce principal, pas à sa place (A20-CRED-4b).
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

    println!(
        "Appareil BRIDGE enrôlé pour {address_raw} (principal {}), device_id={device_id}",
        principal.id
    );
    println!(
        "Clé publique de chiffrement publiée dans keydir.mail_device_keys ({} octets) — appareil \
         SÉPARÉ de tout autre déjà enrôlé pour ce principal (A20-CRED-4b).",
        mail_pub.0.len()
    );

    // Stand-in de dev pour "le coffre sécurisé de l'OS" (INV-4) — même discipline que
    // `enroll_test_device.rs`, fichier DIFFÉRENT (voir doc de module).
    let secret_path = bridge_dev_secret_path(canonical.as_str());
    if let Some(dir) = secret_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file_bytes = Vec::with_capacity(16 + mail_sec.as_bytes().len());
    file_bytes.extend_from_slice(device_id.as_bytes());
    file_bytes.extend_from_slice(mail_sec.as_bytes());
    std::fs::write(&secret_path, &file_bytes)?;
    restrict_to_owner(&secret_path)?;
    println!(
        "Clé privée du Bridge ({} octets) persistée dans {} (stand-in de dev pour le coffre \
         sécurisé de l'OS, INV-4) — c'est le fichier que `diamy-bridged` lira au démarrage.",
        mail_sec.as_bytes().len(),
        secret_path.display()
    );
    println!(
        "Si diamy-mxd tourne : tout message tenu en attente pour ce principal sera relâché \
         automatiquement d'ici quelques secondes (balayage périodique côté serveur, A01-HOLD-4)."
    );

    Ok(())
}
