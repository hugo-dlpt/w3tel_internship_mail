//! `diamy-maild` — stockage + sync + annuaire de clés (A02, A04, A17).
//!
//! Squelette : au démarrage il applique le garde-fou crypto *fail-closed* (A18 SEC-FC-1)
//! et expose `/metrics` (Prometheus) sur `:9101`. La sync native (A04) et le stockage
//! Postgres (A21, via `sqlx`) sont les prochaines étapes.

use diamy_mail_crypto as crypto;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    diamy_obs::init_tracing();

    // Fail-closed : refuse de démarrer avec le backend dev hors environnement de dev.
    let env = std::env::var("DIAMY_ENV").unwrap_or_else(|_| "dev".to_string());
    crypto::assert_backend_allowed_for_env(&env)?;

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
