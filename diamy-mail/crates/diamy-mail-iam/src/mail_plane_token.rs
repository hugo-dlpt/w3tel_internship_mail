//! Vérification du jeton mail-plane (A17 §4, A17-TOK-1) : signature HS256 (secret
//! `MAIL_JWT_TOKEN`, A17 §4 tableau) + expiration. Ce module fait UNIQUEMENT ce que ces
//! deux règles imposent — voir les deux gaps signalés ci-dessous, volontairement PAS
//! comblés par hypothèse (A25 Constitution règle 2).
//!
//! **Gap 1 — schéma des claims** : ni A04 ni A17 ne spécifient les claims internes du
//! jeton mail-plane (seulement l'algorithme, le nom du secret, la durée de vie 15 min).
//! Ce module utilise le minimum de claims JWT enregistrées (`sub` = `principal_id`,
//! `exp`, `iat`) — un choix de convention, pas une lecture du corpus. À reconcilier avec
//! le schéma réel une fois le jeton mail-plane IAM branché.
//!
//! **Gap 2 — révocation** : A17-TOK-2 flague le mécanisme de révocation comme un point
//! ouvert HIGH, non confirmé contre *Auth and Session Model*/*Security Hardening &
//! Runtime Model* (JTI-cache vs epoch-bump). Ce module NE vérifie PAS la révocation —
//! l'implémenter maintenant serait inventer un comportement non spécifié. Voir
//! `SIMPLIFICATIONS.md`.
#![allow(clippy::result_large_err)]

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum MailPlaneTokenError {
    #[error("jeton mail-plane absent, malformé ou signature invalide")]
    Invalid,
    #[error("jeton mail-plane expiré")]
    Expired,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: Uuid,
    exp: i64,
    iat: i64,
}

/// Vérifie la signature HS256 et l'expiration (A17-TOK-1, étape 2 de A17-APPKEY-5).
/// Ne vérifie PAS l'état de révocation — voir le gap documenté en tête de module
/// (A17-TOK-2). Renvoie le `principal_id` (`sub`) porté par le jeton.
pub fn verify_mail_plane_token(token: &str, secret: &[u8]) -> Result<Uuid, MailPlaneTokenError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["exp", "sub"]);
    validation.validate_exp = true;
    // Pas de tolérance d'horloge implicite : ni A04 ni A17 n'en spécifient pour
    // l'expiration du jeton (A04-SIG-2 définit ±120 s, mais pour la SIGNATURE de
    // requête, un mécanisme distinct — pas pour `exp`). Zéro leeway plutôt qu'une
    // valeur inventée (A25 Constitution règle 2).
    validation.leeway = 0;

    decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
        .map(|data| data.claims.sub)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => MailPlaneTokenError::Expired,
            _ => MailPlaneTokenError::Invalid,
        })
}

// NOTE (INV-9 / A17-P-1) : il n'existe DÉLIBÉRÉMENT aucune fonction d'ÉMISSION de jeton
// mail-plane dans ce module (ni ailleurs dans le repo). « Diamy Mail MUST NOT mint identity
// or session tokens » — seul IAM est autorité d'émission. Ce module ne fait que VÉRIFIER
// (`verify_mail_plane_token`, clé de décodage `jsonwebtoken` uniquement, jamais de clé de
// signature). Les tests et exemples qui ont besoin d'un jeton valide en LISENT un, pré-signé
// une fois hors du code de production, dans `tests/fixtures/dev_mail_plane_tokens.json` — ils
// n'en fabriquent jamais. Un test anti-régression (`tests/no_token_minting_in_repo.rs`) échoue
// si une capacité de signature de jeton réapparaît n'importe où dans le repo.

#[cfg(test)]
mod tests {
    use super::*;

    /// Jetons de test pré-signés, embarqués À LA COMPILATION (aucune lecture disque ni
    /// fabrication à l'exécution). Voir l'en-tête du fichier de fixtures pour la discipline.
    const FIXTURES: &str =
        include_str!("../../../tests/fixtures/dev_mail_plane_tokens.json");

    fn fixtures() -> serde_json::Value {
        serde_json::from_str(FIXTURES).expect("fixture de jetons JSON valide")
    }

    /// Secret HS256 avec lequel les jetons de la fixture ont été signés (source unique).
    fn fixture_secret() -> Vec<u8> {
        fixtures()["secret"]
            .as_str()
            .expect("champ `secret` présent dans la fixture")
            .as_bytes()
            .to_vec()
    }

    fn fixture_token(name: &str) -> String {
        fixtures()["tokens"][name]["token"]
            .as_str()
            .unwrap_or_else(|| panic!("jeton `{name}` présent dans la fixture"))
            .to_string()
    }

    fn fixture_principal(name: &str) -> Uuid {
        fixtures()["tokens"][name]["principal_id"]
            .as_str()
            .unwrap_or_else(|| panic!("principal_id de `{name}` présent dans la fixture"))
            .parse()
            .expect("principal_id de la fixture est un UUID valide")
    }

    #[test]
    fn round_trip_valid_token() {
        // Jeton valide PRÉ-SIGNÉ (jamais fabriqué ici) : la vérification doit réussir et
        // rendre le `principal_id` (`sub`) figé dans la fixture.
        let resolved = verify_mail_plane_token(&fixture_token("valid_hugo"), &fixture_secret()).unwrap();
        assert_eq!(resolved, fixture_principal("valid_hugo"));
    }

    #[test]
    fn expired_token_is_rejected() {
        // Jeton PRÉ-SIGNÉ dont l'`exp` est figé dans le passé (2020) : rejet par expiration.
        let err = verify_mail_plane_token(&fixture_token("expired"), &fixture_secret()).unwrap_err();
        assert!(matches!(err, MailPlaneTokenError::Expired));
    }

    #[test]
    fn wrong_secret_is_rejected() {
        // Même jeton valide, mais vérifié avec un AUTRE secret : la signature ne colle plus.
        let err = verify_mail_plane_token(&fixture_token("valid_hugo"), b"un-autre-secret-de-dev")
            .unwrap_err();
        assert!(matches!(err, MailPlaneTokenError::Invalid));
    }

    #[test]
    fn garbage_token_is_rejected() {
        let err = verify_mail_plane_token("not.a.jwt", b"secret").unwrap_err();
        assert!(matches!(err, MailPlaneTokenError::Invalid));
    }
}
