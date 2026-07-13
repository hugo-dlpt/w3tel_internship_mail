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

/// Doublure de DEV UNIQUEMENT (`dev-token-issuer`, jamais compilée dans un binaire de
/// prod) : émet un jeton mail-plane pour les tests, en l'absence d'un IAM réel capable
/// d'en émettre un (A17-TOK-1 : "minted by the IAM backend"). Un vrai IAM reste la SEULE
/// autorité d'émission (A17-P-1) — ceci ne le remplace pas, ça imite juste sa sortie
/// pour débloquer les tests d'intégration de `diamy-maild`.
#[cfg(any(test, feature = "dev-token-issuer"))]
pub fn mint_dev_mail_plane_token(secret: &[u8], principal_id: Uuid, ttl_secs: i64) -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("horloge système valide")
        .as_secs() as i64;
    let claims = Claims {
        sub: principal_id,
        iat: now,
        exp: now + ttl_secs,
    };
    encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(secret))
        .expect("encodage HS256 du jeton de test")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_valid_token() {
        let secret = b"test-secret-do-not-use-in-prod";
        let principal_id = Uuid::now_v7();
        let token = mint_dev_mail_plane_token(secret, principal_id, 900);
        let resolved = verify_mail_plane_token(&token, secret).unwrap();
        assert_eq!(resolved, principal_id);
    }

    #[test]
    fn expired_token_is_rejected() {
        let secret = b"test-secret-do-not-use-in-prod";
        let token = mint_dev_mail_plane_token(secret, Uuid::now_v7(), -60);
        let err = verify_mail_plane_token(&token, secret).unwrap_err();
        assert!(matches!(err, MailPlaneTokenError::Expired));
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let token = mint_dev_mail_plane_token(b"secret-a", Uuid::now_v7(), 900);
        let err = verify_mail_plane_token(&token, b"secret-b").unwrap_err();
        assert!(matches!(err, MailPlaneTokenError::Invalid));
    }

    #[test]
    fn garbage_token_is_rejected() {
        let err = verify_mail_plane_token("not.a.jwt", b"secret").unwrap_err();
        assert!(matches!(err, MailPlaneTokenError::Invalid));
    }
}
