//! # diamy-obs
//!
//! Observabilité partagée : init des logs structurés (`tracing`) et métriques Prometheus.
//!
//! Règle absolue (INV-21, A18-LOG-1) : la télémétrie ne porte JAMAIS de contenu, sujet,
//! adresse (au-delà du routage), clé ni jeton. Uniquement des compteurs, des IDs, des métadonnées.
#![forbid(unsafe_code)]

use prometheus::{Encoder, IntCounterVec, Opts, Registry, TextEncoder};

/// Poignée d'observabilité d'un service.
pub struct Obs {
    pub registry: Registry,
    /// Événements comptés par (service, type d'événement). Métadonnées uniquement.
    pub events: IntCounterVec,
}

impl Obs {
    /// Crée le registre + les compteurs de base pour un service.
    pub fn new(service: &str) -> Self {
        let registry = Registry::new();
        let events = IntCounterVec::new(
            Opts::new(
                "diamy_events_total",
                "Événements par service (métadonnées seules)",
            ),
            &["service", "event"],
        )
        .expect("compteur valide");
        registry
            .register(Box::new(events.clone()))
            .expect("enregistrement compteur");
        // amorce la série pour ce service
        events.with_label_values(&[service, "startup"]).inc();
        Self { registry, events }
    }

    /// Rend les métriques au format texte Prometheus (exposition sur `/metrics`).
    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        let mf = self.registry.gather();
        TextEncoder::new()
            .encode(&mf, &mut buf)
            .expect("encodage prometheus");
        String::from_utf8(buf).unwrap_or_default()
    }
}

/// Initialise les logs structurés. `RUST_LOG` pilote le niveau (défaut : info).
pub fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // `try_init` pour ne pas paniquer si déjà initialisé (tests).
    let _ = fmt().with_env_filter(filter).try_init();
}

/// Désactive les core dumps (`RLIMIT_CORE = 0`) AU DÉMARRAGE, en mode **prod uniquement**
/// (A18-ZERO-4) : un crash ne doit pas pouvoir déposer un core dump contenant du clair
/// (message, `k_msg`, jeton...) sur disque (A01-DESTROY-2, A10-EMIT-1). Le dev GARDE les
/// core dumps (débogage) — `env` vient de `DIAMY_ENV`, comme
/// `crypto::assert_backend_allowed_for_env`.
///
/// **Fail-closed** (A00 SEC-FC, forbidden pattern #12 d'A18 §13) : si la désactivation
/// échoue en prod — y compris parce que la plateforme n'expose pas `RLIMIT_CORE` — cette
/// fonction renvoie une erreur ; l'appelant DOIT refuser de démarrer plutôt que de tourner
/// avec un risque de fuite de clair non maîtrisé au crash.
pub fn disable_core_dumps_if_prod(env: &str) -> Result<(), String> {
    if env != "prod" {
        return Ok(());
    }
    #[cfg(unix)]
    {
        rlimit::setrlimit(rlimit::Resource::CORE, 0, 0)
            .map_err(|e| format!("désactivation de RLIMIT_CORE impossible en prod (fail-closed) : {e}"))
    }
    #[cfg(not(unix))]
    {
        Err("RLIMIT_CORE non applicable sur cette plateforme : désactivation des core dumps \
             non garantie en prod (fail-closed, A18-ZERO-4)"
            .to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_env_leaves_core_dumps_untouched() {
        // Ne doit RIEN toucher hors prod (le dev garde les core dumps pour déboguer).
        let before = rlimit::getrlimit(rlimit::Resource::CORE).unwrap();
        assert!(disable_core_dumps_if_prod("dev").is_ok());
        let after = rlimit::getrlimit(rlimit::Resource::CORE).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    #[cfg(unix)]
    fn prod_env_actually_sets_rlimit_core_to_zero() {
        assert!(disable_core_dumps_if_prod("prod").is_ok());
        let (soft, _hard) = rlimit::getrlimit(rlimit::Resource::CORE).unwrap();
        assert_eq!(soft, 0, "RLIMIT_CORE (soft) doit être 0 après désactivation en prod");
    }
}
