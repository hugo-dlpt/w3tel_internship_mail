//! Preuve anti-régression (INV-4/INV-9/A17-KEY-2) : le binaire de service `diamy-maild`
//! ne doit JAMAIS générer de clé d'identité ou d'appareil, ni rejouer la démo du chemin
//! vertical, sur son chemin d'exécution normal.
//!
//! Générer une clé d'appareil est un geste EXCLUSIVEMENT CLIENT (A17-KEY-2) ; un service
//! qui le ferait violerait littéralement l'invariant, indépendamment du fait que le backend
//! `messaging-crypto` renvoie aujourd'hui `not_wired()` (un hasard temporaire, pas une
//! garantie). Cette démonstration vit désormais dans l'exemple Cargo séparé
//! `crates/diamy-mail-storage/examples/vertical_slice_demo.rs`, jamais lié dans ce binaire.
//!
//! Ce test lit la SOURCE de `main.rs` à la compilation (`include_str!`) et échoue si l'un
//! des points d'entrée de génération de clé — ou l'ancienne fonction de démo — y réapparaît.
//! Les jetons recherchés vivent dans CE fichier de test (dans `tests/`), jamais dans
//! `src/main.rs`, ce qui évite tout faux positif par auto-référence.

/// Source de `services/diamy-maild/src/main.rs`, capturée à la compilation.
const MAIN_RS_SOURCE: &str = include_str!("../src/main.rs");

/// Symboles interdits sur le chemin de production du service (le point d'entrée `main.rs`).
const FORBIDDEN_IN_SERVICE_MAIN: &[&str] = &[
    "generate_device_keypair",   // A17-KEY-2 : clé d'appareil = geste client uniquement
    "generate_identity_keypair", // idem, clé d'identité
    "run_vertical_slice_demo",   // ancienne démo au démarrage : déplacée dans un exemple Cargo
];

#[test]
fn service_main_never_generates_keys() {
    for needle in FORBIDDEN_IN_SERVICE_MAIN {
        assert!(
            !MAIN_RS_SOURCE.contains(needle),
            "INV-4/INV-9/A17-KEY-2 : `{needle}` réapparaît dans services/diamy-maild/src/main.rs. \
             Le binaire de service ne doit générer AUCUNE clé ni rejouer la démo du chemin vertical. \
             Cette logique appartient à l'exemple Cargo \
             `crates/diamy-mail-storage/examples/vertical_slice_demo.rs` (jamais lié dans ce binaire)."
        );
    }
}
