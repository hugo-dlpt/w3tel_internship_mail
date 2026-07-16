//! `diamy-maild` — stockage + sync + annuaire de clés (A02, A04, A17).
//!
//! S'appuie sur un VRAI Postgres (A21, sous-ensemble `mail` :
//! folders/messages/blobs/envelopes + `keydir`) et sert en parallèle : `/metrics`
//! (Prometheus, `:9101`) et une API de sync (A04) minimaliste, **en HTTPS** (A04-TR-1,
//! certificat auto-signé de dev), **authentifiée** (AppKey Tier 2 puis jeton mail-plane,
//! dans cet ordre, A17-APPKEY-5 — voir `auth.rs`), liée à `127.0.0.1` uniquement (voir
//! `sync_api.rs` et `SIMPLIFICATIONS.md` pour le périmètre exact et ce qui manque).
//!
//! **Zéro génération de clé côté serveur (INV-4/INV-9/A17-KEY-2).** Ce binaire ne génère
//! JAMAIS de paire de clés d'identité ou d'appareil : c'est un geste exclusivement CLIENT.
//! La démonstration du chemin vertical (mail chiffré → stocké → synchronisé → déchiffré
//! côté client), qui a besoin d'un appareil enrôlé, vit désormais **hors du binaire de
//! service**, dans l'exemple Cargo `crates/diamy-mail-storage/examples/vertical_slice_demo.rs`
//! (jamais compilé dans ce service). Un test anti-régression
//! (`tests/no_keygen_in_binary.rs`) prouve que ce fichier ne réintroduit aucune génération
//! de clé.
#![forbid(unsafe_code)] // A18-CI-2 : aucun `unsafe` dans ce service (couvre auth.rs/sync_api.rs)

mod auth;
mod sync_api;

use diamy_mail_crypto as crypto;
use diamy_mail_storage::{self as storage, BlobStore};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Génère un certificat auto-signé de dev pour `hostname` (A04-TR-1). **Jamais une PKI
/// réelle** — voir `SIMPLIFICATIONS.md` : la force de la crypto TLS est simplifiée, pas la
/// frontière (la session HTTPS est réellement chiffrée une fois établie).
async fn generate_dev_tls_config(
    hostname: &str,
) -> Result<axum_server::tls_rustls::RustlsConfig, Box<dyn std::error::Error>> {
    // rustls 0.23 exige un fournisseur crypto explicite ; `install_default` est idempotent
    // (Err si déjà posé — par un appel précédent ou un autre composant — on l'ignore).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![hostname.to_string()])?;
    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();
    let config = axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem, key_pem).await?;
    Ok(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    diamy_obs::init_tracing();

    // Fail-closed : refuse de démarrer avec le backend dev hors environnement de dev (A18 SEC-FC-1).
    let env = std::env::var("DIAMY_ENV").unwrap_or_else(|_| "dev".to_string());
    // Fail-closed (A18-ZERO-4) : core dumps désactivés en prod AVANT tout traitement de
    // clair — le dev garde les core dumps.
    diamy_obs::disable_core_dumps_if_prod(&env)?;
    crypto::assert_backend_allowed_for_env(&env)?;

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://diamy:devonly_change_me@localhost:5433/diamymail".to_string()
    });
    let blob_dir =
        std::env::var("DIAMY_MAILD_BLOB_DIR").unwrap_or_else(|_| "./blob_store".to_string());
    let pool = storage::connect(&database_url).await?;
    let blob_store = Arc::new(BlobStore::at(&blob_dir)?);

    // NOTE (INV-4/INV-9/A17-KEY-2) : le service ne génère AUCUNE clé et ne rejoue AUCUNE
    // démo au démarrage. La démonstration du chemin vertical (qui doit enrôler un appareil,
    // donc générer des clés — un geste CLIENT) vit dans l'exemple Cargo séparé
    // `cargo run --example vertical_slice_demo -p diamy-mail-storage`.

    // API de sync (A04, tranche lecture seule minimale) — voir sync_api.rs pour le
    // périmètre exact. HTTPS (A04-TR-1, certificat auto-signé de dev), liée à 127.0.0.1
    // SEULEMENT (défense en profondeur), ET authentifiée (AppKey Tier 2 puis jeton
    // mail-plane, A17-APPKEY-5 — voir `auth.rs`).
    let sync_addr =
        std::env::var("DIAMY_MAILD_SYNC_ADDR").unwrap_or_else(|_| "127.0.0.1:8443".to_string());
    let sync_socket_addr: std::net::SocketAddr = sync_addr.parse()?;
    let tls_config = generate_dev_tls_config("maild.w3.tel").await?;
    let sync_state = sync_api::SyncState {
        pool: pool.clone(),
        blob_store: blob_store.clone(),
    };
    let mail_jwt_secret = std::env::var("MAIL_JWT_TOKEN")
        .unwrap_or_else(|_| "devonly_change_me_mail_jwt_secret".to_string())
        .into_bytes();
    let auth_state = auth::AuthState {
        app_keys: auth::AppKeyStore::seeded_from_env(),
        mail_jwt_secret,
    };
    tracing::info!(addr = %sync_addr, "API de sync (A04, tranche minimale, HTTPS, authentifiée) démarrée");
    println!("== diamy-maild : API de sync (lecture seule, HTTPS, 127.0.0.1 uniquement, authentifiée) sur {sync_addr} ==");
    tokio::spawn(async move {
        if let Err(e) = axum_server::bind_rustls(sync_socket_addr, tls_config)
            .serve(sync_api::router(sync_state, auth_state).into_make_service())
            .await
        {
            tracing::error!(error = %e, "API de sync arrêtée");
        }
    });

    let obs = Arc::new(diamy_obs::Obs::new("diamy-maild"));
    let addr = "0.0.0.0:9101";
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(
        service = "diamy-maild",
        backend = crypto::backend_name(),
        env = %env,
        addr,
        "démarré — /metrics exposé"
    );
    println!("== diamy-maild : /metrics sur {addr} ==");

    loop {
        let (mut sock, _peer) = listener.accept().await?;
        let obs = obs.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await; // requête ignorée (endpoint unique)
            obs.events
                .with_label_values(&["diamy-maild", "metrics_scrape"])
                .inc();
            let body = obs.render();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}
