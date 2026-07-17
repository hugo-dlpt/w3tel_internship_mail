//! `POST /submit` — A04-EP-6 (wire contract) / A10 §2 (pipeline `diamy-submitd`), réduit à sa
//! forme V1 démo (voir `SIMPLIFICATIONS.md` pour la liste exhaustive de ce qui est ABSENT :
//! pas de copie "Envoyés" chiffrée côté client, pas de DKIM, pas de vérification
//! SPF/DKIM/DMARC, pas de rate limiting/circuit breaker, pas d'allocation de pool d'envoi
//! A23). Ce qui EST fait : authentification à deux facteurs (`auth.rs`, A17-APPKEY-5), un
//! VRAI dialogue SMTP sortant par destinataire (`relay.rs`), l'isolement des échecs par
//! destinataire (esprit A10-RETRY-3 : un destinataire qui échoue ne bloque pas les autres),
//! et zéro contenu de message dans les logs (INV-21).
//!
//! **Boucle fermée de démo** (A20-SMTP-1 : le Bridge ne doit pas contourner A10) : un
//! destinataire dont le domaine appartient à `local_domains` est réinjecté dans `diamy-mxd`
//! comme un message entrant ordinaire — pas de vrai serveur MX externe nécessaire pour la
//! démo "Thunderbird envoie → Thunderbird reçoit".

use crate::relay::{self, RelayOutcome};
use axum::{extract::State, middleware, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroize;

/// Borne défensive (esprit A01-STAB-1) : un message décodé au-delà de cette taille est rejeté
/// avant toute tentative de relais, jamais une allocation proportionnelle non bornée.
const MAX_MESSAGE_BYTES: usize = 10 * 1024 * 1024;

pub struct SubmitdConfig {
    /// Domaines considérés "hébergés localement" par CE `diamy-mxd` de démo — un destinataire
    /// dans cet ensemble est réinjecté en local plutôt que relayé vers Internet (voir le
    /// module doc). Comparaison insensible à la casse, sans le `.` de tête.
    pub local_domains: Vec<String>,
    pub mxd_relay_host: String,
    pub mxd_relay_port: u16,
    /// Port utilisé pour la relance vers un domaine EXTERNE — **simplification assumée** :
    /// connexion directe à `<domaine>:<port>`, PAS de résolution MX (voir `relay.rs`).
    pub external_relay_port: u16,
    pub helo_domain: String,
}

impl SubmitdConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let local_domains = std::env::var("DIAMY_SUBMITD_LOCAL_DOMAINS")
            .unwrap_or_else(|_| "w3.tel".to_string())
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let mxd_addr = std::env::var("DIAMY_MXD_SMTP_ADDR").unwrap_or_else(|_| "127.0.0.1:2525".to_string());
        let (mxd_relay_host, mxd_relay_port) = mxd_addr
            .rsplit_once(':')
            .ok_or("DIAMY_MXD_SMTP_ADDR invalide (attendu host:port)")?;
        let mxd_relay_port: u16 = mxd_relay_port.parse()?;
        // A20-ARCH-2 esprit : `diamy-mxd` de démo n'écoute que sur 127.0.0.1 (voir son propre
        // `SIMPLIFICATIONS.md`) — la valeur par défaut le reflète, mais reste overridable pour
        // les tests (ephemeral port sur 127.0.0.1 également).
        let mxd_relay_host = if mxd_relay_host == "0.0.0.0" { "127.0.0.1" } else { mxd_relay_host };

        let external_relay_port: u16 = std::env::var("DIAMY_SUBMITD_EXTERNAL_SMTP_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(25);

        let helo_domain =
            std::env::var("DIAMY_SUBMITD_HELO_DOMAIN").unwrap_or_else(|_| "submit.w3.tel".to_string());

        Ok(Self {
            local_domains,
            mxd_relay_host: mxd_relay_host.to_string(),
            mxd_relay_port,
            external_relay_port,
            helo_domain,
        })
    }

    fn is_local_domain(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.local_domains.iter().any(|d| d == &domain)
    }
}

#[derive(Clone)]
pub struct SubmitState {
    pub config: Arc<SubmitdConfig>,
}

#[derive(Deserialize)]
struct SubmitRequest {
    mail_from: String,
    rcpt_to: Vec<String>,
    /// Forme d'émission RFC 5322 (A04-EP-6), encodée base64 pour le transport JSON — **pas**
    /// la copie "Envoyés" chiffrée côté client (A02 §5.2), absente de cette V1 (voir
    /// `SIMPLIFICATIONS.md`).
    message_b64: String,
}

#[derive(Serialize)]
struct RecipientOutcome {
    recipient: String,
    status: &'static str,
    detail: Option<String>,
}

#[derive(Serialize)]
struct SubmitResponse {
    /// `true` si AU MOINS un destinataire a été relayé avec succès (esprit A10-RETRY-3 :
    /// l'échec d'UN destinataire n'invalide pas les autres).
    accepted: bool,
    results: Vec<RecipientOutcome>,
}

async fn submit_handler(
    State(state): State<SubmitState>,
    axum::extract::Extension(_identity): axum::extract::Extension<crate::auth::AuthenticatedIdentity>,
    Json(req): Json<SubmitRequest>,
) -> (axum::http::StatusCode, Json<SubmitResponse>) {
    let mut raw_message = match STANDARD.decode(&req.message_b64) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(SubmitResponse { accepted: false, results: vec![] }),
            );
        }
    };
    if raw_message.len() > MAX_MESSAGE_BYTES {
        raw_message.zeroize();
        return (
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            Json(SubmitResponse { accepted: false, results: vec![] }),
        );
    }

    // INV-21 : jamais le contenu, seulement des métadonnées (compte de destinataires, taille).
    tracing::info!(
        recipients = req.rcpt_to.len(),
        size_bytes = raw_message.len(),
        "soumission reçue (A10 §2, tranche démo)"
    );

    let mut results = Vec::with_capacity(req.rcpt_to.len());
    for recipient in &req.rcpt_to {
        let outcome = relay_one_recipient(&state.config, &req.mail_from, recipient, &raw_message).await;
        results.push(outcome);
    }

    raw_message.zeroize(); // A10-EMIT-1 esprit : le clair d'émission ne survit pas au-delà de l'usage

    let accepted = results.iter().any(|r| r.status == "relayed_local" || r.status == "relayed_external");
    let status = if accepted { axum::http::StatusCode::OK } else { axum::http::StatusCode::BAD_GATEWAY };
    (status, Json(SubmitResponse { accepted, results }))
}

async fn relay_one_recipient(
    config: &SubmitdConfig,
    mail_from: &str,
    recipient: &str,
    raw_message: &[u8],
) -> RecipientOutcome {
    let Some((_, domain)) = recipient.split_once('@') else {
        return RecipientOutcome {
            recipient: recipient.to_string(),
            status: "rejected_invalid_address",
            detail: Some("adresse sans domaine".to_string()),
        };
    };

    let (host, port, local): (&str, u16, bool) = if config.is_local_domain(domain) {
        (&config.mxd_relay_host, config.mxd_relay_port, true)
    } else {
        (domain, config.external_relay_port, false)
    };

    let outcome = relay::relay_via_smtp(host, port, &config.helo_domain, mail_from, recipient, raw_message).await;

    // INV-21 : jamais le contenu ni l'hôte/port en clair côté log applicatif au-delà de ce qui
    // est déjà nécessaire au diagnostic opérationnel (aucun corps de message ici).
    match outcome {
        RelayOutcome::Delivered => {
            tracing::info!(local, "relais accepté par le serveur distant");
            RecipientOutcome {
                recipient: recipient.to_string(),
                status: if local { "relayed_local" } else { "relayed_external" },
                detail: None,
            }
        }
        RelayOutcome::TransientFailure(detail) => {
            tracing::warn!(local, %detail, "échec transitoire du relais (pas de retry dans cette V1)");
            RecipientOutcome { recipient: recipient.to_string(), status: "relay_failed_transient", detail: Some(detail) }
        }
        RelayOutcome::PermanentFailure(detail) => {
            tracing::warn!(local, %detail, "échec permanent du relais (pas de DSN dans cette V1)");
            RecipientOutcome { recipient: recipient.to_string(), status: "relay_failed_permanent", detail: Some(detail) }
        }
    }
}

pub fn router(state: SubmitState, auth: crate::auth::AuthState) -> Router {
    Router::new()
        .route("/submit", post(submit_handler))
        .layer(middleware::from_fn_with_state(auth, crate::auth::submit_auth_middleware))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SubmitdConfig {
        SubmitdConfig {
            local_domains: vec!["w3.tel".to_string()],
            mxd_relay_host: "127.0.0.1".to_string(),
            mxd_relay_port: 2525,
            external_relay_port: 25,
            helo_domain: "submit.w3.tel".to_string(),
        }
    }

    #[test]
    fn local_domain_routes_locally_case_insensitive() {
        let cfg = test_config();
        assert!(cfg.is_local_domain("W3.TEL"));
        assert!(!cfg.is_local_domain("example.fr"));
    }
}
