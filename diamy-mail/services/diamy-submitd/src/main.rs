//! `diamy-submitd` — envoi sortant (A10) : copie « Envoyés » chiffrée côté client,
//! signature DKIM, rate limits par expéditeur/tenant, gestion de réputation/pools d'IP.
//!
//! Squelette. Rappels normatifs à respecter dès l'implémentation :
//!   - SEC-OUT-2 : pas d'envoi tant que SPF/DKIM/DMARC ne sont pas alignés (fail-closed).
//!   - SEC-OUT-1 : rate limit par expéditeur + compteur de destinataires uniques + circuit-breaker.
#![forbid(unsafe_code)] // A18-CI-2 : aucun `unsafe` dans ce service (comme les 8 crates)

use diamy_mail_crypto as crypto;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    diamy_obs::init_tracing();
    let env = std::env::var("DIAMY_ENV").unwrap_or_else(|_| "dev".to_string());
    // Fail-closed (A18-ZERO-4) : core dumps désactivés en prod AVANT tout traitement de
    // clair (émission, A04-EP-6) — le dev garde les core dumps.
    diamy_obs::disable_core_dumps_if_prod(&env)?;
    crypto::assert_backend_allowed_for_env(&env)?;
    tracing::info!(
        service = "diamy-submitd",
        backend = crypto::backend_name(),
        env = %env,
        "squelette — chemin sortant non implémenté (A10)"
    );
    println!("diamy-submitd : squelette. À implémenter : A10 (DKIM, rate limit, pools). SEC-OUT-2 fail-closed.");
    Ok(())
}
