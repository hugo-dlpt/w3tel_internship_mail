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
//!
//! **Relais externe DÉSACTIVÉ (décision de Cédric, maquette — fail-closed)** : un destinataire
//! hors des `local_domains` est REJETÉ proprement (`rejected_external_relay_disabled`), jamais
//! relayé vers Internet — aucune connexion SMTP sortante n'est même tentée. Tout envoi est
//! strictement confiné à `w3.tel`. Le chemin de relais externe historique n'est réactivable que
//! par `DIAMY_SUBMITD_ALLOW_EXTERNAL_RELAY=1`, jamais positionnée en maquette (voir
//! `SIMPLIFICATIONS.md`).

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
    /// N'a d'effet QUE si `allow_external_relay` est `true` (jamais le cas en maquette).
    pub external_relay_port: u16,
    pub helo_domain: String,
    /// **Décision de Cédric (maquette) : relais externe DÉSACTIVÉ, fail-closed.** Par défaut
    /// `false` — un destinataire hors des `local_domains` est REJETÉ proprement, jamais relayé
    /// vers l'extérieur (aucune connexion SMTP sortante vers Internet n'est même tentée). Le
    /// chemin de relais externe historique reste dans le code mais n'est réactivable QUE par
    /// `DIAMY_SUBMITD_ALLOW_EXTERNAL_RELAY=1` — une variable qui n'est JAMAIS positionnée en
    /// maquette (absence de variable = pas de relais externe possible, jamais l'inverse). Voir
    /// `SIMPLIFICATIONS.md`.
    pub allow_external_relay: bool,
}

/// Décision de routage pour UN destinataire — extraite en fonction pure (sans I/O réseau) pour
/// être testable directement : c'est ici que la garde fail-closed du relais externe est prise
/// (décision de Cédric, voir `SubmitdConfig::allow_external_relay`).
#[derive(Debug, PartialEq, Eq)]
enum RelayRoute<'a> {
    /// Domaine local → réinjection dans `diamy-mxd` (boucle fermée de démo).
    Local { host: &'a str, port: u16 },
    /// Domaine externe AVEC relais explicitement autorisé (jamais en maquette).
    External { host: &'a str, port: u16 },
    /// Domaine externe SANS autorisation (cas par défaut, fail-closed) → rejet, pas de connexion.
    RejectedExternalDisabled,
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

        // Fail-closed : SEULES les valeurs `1`/`true` (insensibles à la casse) réactivent le
        // relais externe. Toute autre valeur — et surtout l'ABSENCE de la variable — laisse le
        // relais externe désactivé. On ne peut donc jamais l'activer "par erreur" (faute de
        // frappe dans une adresse, mauvaise config) : il faut un geste délibéré et explicite.
        let allow_external_relay = std::env::var("DIAMY_SUBMITD_ALLOW_EXTERNAL_RELAY")
            .map(|v| {
                let v = v.trim().to_ascii_lowercase();
                v == "1" || v == "true"
            })
            .unwrap_or(false);

        Ok(Self {
            local_domains,
            mxd_relay_host: mxd_relay_host.to_string(),
            mxd_relay_port,
            external_relay_port,
            helo_domain,
            allow_external_relay,
        })
    }

    fn is_local_domain(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.local_domains.iter().any(|d| d == &domain)
    }

    /// Décide où (ou si) relayer pour ce `domain`. Fonction PURE — aucune connexion réseau, tout
    /// le fail-closed du relais externe est décidé ici (voir `RelayRoute`).
    fn route_for<'a>(&'a self, domain: &'a str) -> RelayRoute<'a> {
        if self.is_local_domain(domain) {
            RelayRoute::Local { host: &self.mxd_relay_host, port: self.mxd_relay_port }
        } else if self.allow_external_relay {
            RelayRoute::External { host: domain, port: self.external_relay_port }
        } else {
            RelayRoute::RejectedExternalDisabled
        }
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

    let (host, port, local): (&str, u16, bool) = match config.route_for(domain) {
        RelayRoute::Local { host, port } => (host, port, true),
        RelayRoute::External { host, port } => (host, port, false),
        RelayRoute::RejectedExternalDisabled => {
            // Fail-closed (décision de Cédric, maquette) : AUCUNE connexion SMTP sortante n'est
            // ouverte pour un destinataire hors des domaines locaux — on rejette proprement
            // AVANT tout dialogue réseau. Le message n'est ni relayé, ni silencieusement ignoré.
            tracing::warn!(
                %domain,
                "destinataire hors domaines locaux REJETÉ (relais externe désactivé en maquette)"
            );
            return RecipientOutcome {
                recipient: recipient.to_string(),
                status: "rejected_external_relay_disabled",
                detail: Some(format!(
                    "relais externe désactivé en maquette (décision Cédric) : le domaine « {domain} » \
                     n'est pas dans les domaines locaux ({}) — tout envoi est confiné à ces domaines, \
                     aucun relais vers l'extérieur n'est possible",
                    config.local_domains.join(", ")
                )),
            };
        }
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
            // Maquette : fail-closed par défaut (décision de Cédric).
            allow_external_relay: false,
        }
    }

    #[test]
    fn local_domain_routes_locally_case_insensitive() {
        let cfg = test_config();
        assert!(cfg.is_local_domain("W3.TEL"));
        assert!(!cfg.is_local_domain("example.fr"));
    }

    /// La garde fail-closed est décidée par `route_for` — testée ici PUREMENT (aucun réseau) :
    /// un domaine local est routé en local ; un domaine externe est REJETÉ par défaut ; et n'est
    /// routé vers l'extérieur QUE si le relais externe a été explicitement réactivé.
    #[test]
    fn route_for_rejects_external_by_default() {
        let cfg = test_config();
        // Domaine local → réinjection locale (boucle fermée de démo).
        assert!(matches!(cfg.route_for("w3.tel"), RelayRoute::Local { .. }));
        // Domaine externe, relais désactivé (défaut maquette) → rejet, jamais de route externe.
        assert_eq!(cfg.route_for("gmail.com"), RelayRoute::RejectedExternalDisabled);
    }

    #[test]
    fn route_for_allows_external_only_when_explicitly_enabled() {
        let cfg = SubmitdConfig { allow_external_relay: true, ..test_config() };
        // Le chemin externe n'existe QUE derrière le flag jamais activé en maquette.
        assert_eq!(
            cfg.route_for("gmail.com"),
            RelayRoute::External { host: "gmail.com", port: 25 }
        );
        // Un domaine local reste local même flag activé.
        assert!(matches!(cfg.route_for("w3.tel"), RelayRoute::Local { .. }));
    }

    /// Preuve du Point 1 (fail-closed) : une soumission vers une adresse HORS w3.tel est REJETÉE,
    /// pas silencieusement ignorée ni relayée. `relay_one_recipient` retourne le statut de rejet
    /// SANS ouvrir de connexion SMTP sortante — c'est justement ce qui rend ce test hermétique
    /// (aucun accès réseau vers gmail.com : le rejet est prononcé avant tout dialogue).
    #[tokio::test]
    async fn external_recipient_is_rejected_not_relayed() {
        let cfg = test_config(); // fail-closed (défaut maquette)
        let outcome =
            relay_one_recipient(&cfg, "hugo@w3.tel", "test@gmail.com", b"From: hugo@w3.tel\r\n\r\nx\r\n").await;

        assert_eq!(
            outcome.status, "rejected_external_relay_disabled",
            "un destinataire hors w3.tel doit être REJETÉ (jamais relayé ni ignoré)"
        );
        assert_ne!(outcome.status, "relayed_external", "aucun relais externe ne doit avoir lieu");
        assert_ne!(outcome.status, "relayed_local", "gmail.com n'est pas un domaine local");
        let detail = outcome.detail.expect("le rejet doit porter un message d'erreur explicite");
        assert!(
            detail.contains("relais externe désactivé"),
            "le message doit indiquer clairement que le relais externe est désactivé : {detail}"
        );
        assert_eq!(outcome.recipient, "test@gmail.com");
    }

    /// Un destinataire sans domaine reste rejeté comme adresse invalide (comportement inchangé) —
    /// on vérifie que la garde fail-closed ne l'a pas masqué.
    #[tokio::test]
    async fn recipient_without_domain_is_rejected_as_invalid() {
        let cfg = test_config();
        let outcome = relay_one_recipient(&cfg, "hugo@w3.tel", "pas-de-domaine", b"x").await;
        assert_eq!(outcome.status, "rejected_invalid_address");
    }
}
