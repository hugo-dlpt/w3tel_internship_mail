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
