//! `diamy-submitd` — binaire de service (voir `lib.rs` pour la documentation d'architecture
//! et le périmètre de cette tranche démo).
#![forbid(unsafe_code)] // A18-CI-2 : aucun `unsafe` dans ce service

use diamy_mail_crypto as crypto;
use diamy_submitd::{auth, generate_dev_tls_config, router, SubmitState, SubmitdConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    diamy_obs::init_tracing();

    let env = std::env::var("DIAMY_ENV").unwrap_or_else(|_| "dev".to_string());
    // Fail-closed (A18-ZERO-4) : core dumps désactivés en prod AVANT tout traitement de
    // clair (émission, A10-EMIT-1) — le dev garde les core dumps.
    diamy_obs::disable_core_dumps_if_prod(&env)?;
    crypto::assert_backend_allowed_for_env(&env)?;

    let config = Arc::new(SubmitdConfig::from_env()?);

    let bind_addr =
        std::env::var("DIAMY_SUBMITD_SUBMIT_ADDR").unwrap_or_else(|_| "127.0.0.1:8446".to_string());
    let socket_addr: std::net::SocketAddr = bind_addr.parse()?;
    let tls_config = generate_dev_tls_config("submit.w3.tel").await?;

    let mail_jwt_secret = std::env::var("MAIL_JWT_TOKEN")
        .unwrap_or_else(|_| "devonly_change_me_mail_jwt_secret".to_string())
        .into_bytes();
    let auth_state = auth::AuthState { app_keys: auth::AppKeyStore::seeded_from_env(), mail_jwt_secret };
    let submit_state = SubmitState { config: config.clone() };

    tracing::info!(
        service = "diamy-submitd",
        backend = crypto::backend_name(),
        env = %env,
        addr = %bind_addr,
        local_domains = ?config.local_domains,
        "démarré — /submit (A10 §2, tranche démo minimale), HTTPS, authentifié"
    );
    println!(
        "== diamy-submitd : POST /submit sur {bind_addr} (HTTPS, authentifié, tranche démo — pas de DKIM/SPF/rate-limit) =="
    );

    axum_server::bind_rustls(socket_addr, tls_config)
        .serve(router(submit_state, auth_state).into_make_service())
        .await?;

    Ok(())
}
