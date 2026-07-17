//! `diamy-submitd` — envoi sortant (A10), tranche démo minimale consommée par le Bridge
//! (A20-SMTP-1 : « the Bridge does not bypass A10 » — le Bridge relaie vers ce service via
//! `/submit`, jamais directement vers Internet lui-même).
//!
//! **Décision d'architecture (pas devinée) :** A20-SMTP-1 dit explicitement que le Bridge
//! "runs [le message] through the native outbound path (A04 `/submit` → A10 emission) ...
//! emitting via `diamy-submitd`". A10 §1.1 précise : "The submission API (`/submit`) wire
//! contract is A04 ; this annex [A10, qui documente `diamy-submitd`] owns what `diamy-submitd`
//! does with a submission." Et le pipeline A10 §2 étape 1 ("RECEIVE SUBMIT /submit") est décrit
//! comme la première étape du pipeline de `diamy-submitd` lui-même. Conclusion : `/submit` est
//! l'endpoint de `diamy-submitd`, pas un endpoint proxié par `diamy-maild` — c'est ce service
//! qui l'expose.
//!
//! **Périmètre volontairement réduit pour cette tranche démo** (voir `SIMPLIFICATIONS.md`,
//! section « Sortant (A10/A20-SMTP), nouveau composant ») : PAS de DKIM, PAS de vérification
//! SPF/DKIM/DMARC (SEC-OUT-2 non enforce), PAS de rate limiting/circuit breaker (A10-RL), PAS
//! d'allocation de pool d'envoi (A23), PAS de copie « Envoyés » chiffrée côté client (A02
//! §5.2), PAS de retry/DSN (A10-RETRY). Ce qui EST fait : authentification à deux facteurs
//! (`auth.rs`), un VRAI dialogue SMTP sortant vers `diamy-mxd` pour la démo en boucle fermée
//! (`relay.rs`, réinjection quand le destinataire est local).
//!
//! **Relais externe DÉSACTIVÉ (décision de Cédric, maquette, fail-closed)** : tout destinataire
//! hors des domaines locaux (`w3.tel`) est REJETÉ proprement, jamais relayé vers Internet —
//! aucune connexion sortante externe n'est même tentée. Le chemin externe historique n'est
//! réactivable que par `DIAMY_SUBMITD_ALLOW_EXTERNAL_RELAY=1`, jamais positionnée en maquette
//! (voir `submit_api.rs` et `SIMPLIFICATIONS.md`).
#![forbid(unsafe_code)]

pub mod auth;
pub mod relay;
pub mod submit_api;

pub use submit_api::{router, SubmitState, SubmitdConfig};

/// Certificat auto-signé de dev pour `hostname` (même discipline que `diamy-maild`, A04-TR-1
/// esprit — pas une PKI réelle, voir `SIMPLIFICATIONS.md`).
pub async fn generate_dev_tls_config(
    hostname: &str,
) -> Result<axum_server::tls_rustls::RustlsConfig, Box<dyn std::error::Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![hostname.to_string()])?;
    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();
    let config = axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem, key_pem).await?;
    Ok(config)
}
