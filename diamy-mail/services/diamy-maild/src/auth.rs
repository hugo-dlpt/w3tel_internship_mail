//! Middleware d'authentification PARTAGÉ de l'API de sync (INV-25, A17-APPKEY-5,
//! A18-ERR-5) — comble le NO-GO d'audit "aucune authentification sur l'API de sync"
//! (SIMPLIFICATIONS.md, A04-TR-2).
//!
//! Deux informations d'identification INDÉPENDANTES, validées DANS CET ORDRE PRÉCIS
//! (A17-APPKEY-5, jamais l'inverse — anti-pattern #22, A25) :
//!   1. **AppKey Tier 2** (`X-App-Key`/`X-App-Name`/`X-App-Platform`/`X-App-Version`,
//!      A17-APPKEY-4) : lookup LOCAL, jamais d'appel IAM (A17-APPKEY-6). Échec →
//!      `ERR_APPKEY_INVALID` générique, sans révéler LEQUEL des sous-checks a échoué
//!      (A04-ERR-2, A17-APPKEY-5 étape 1).
//!   2. **Jeton mail-plane** (`Authorization: Bearer ...`, A17 §4) : signature HS256 +
//!      expiration (A17-TOK-1), via `diamy_mail_iam::verify_mail_plane_token`. Échec →
//!      `ERR_TOKEN_INVALID`.
//!
//! L'étape 3 (autorisation : ce principal a-t-il le droit sur CETTE ressource) reste
//! dans les handlers (`sync_api.rs`) — elle est intrinsèquement spécifique à l'endpoint
//! (A17-APPKEY-5 étape 3), contrairement aux étapes 1-2 qui sont identiques partout et
//! DOIVENT donc être centralisées ici (forbidden pattern #14, A18-ERR-5).
//!
//! Appliqué comme UNE seule couche `axum::middleware` sur TOUT le routeur (`.layer(...)`
//! dans `sync_api::router`), pas un extracteur par handler : une route future ajoutée à
//! ce routeur hérite automatiquement des deux vérifications, sans rien faire de spécial —
//! impossible de l'oublier ou de l'inverser sur un nouvel endpoint.
//!
//! **Gap signalé (pas comblé par hypothèse, A25 Constitution règle 2)** : la révocation
//! du jeton (A17-TOK-1 mentionne "revocation state") N'EST PAS vérifiée — le mécanisme
//! est un point ouvert HIGH non résolu dans le corpus (A17-TOK-2). Voir
//! `diamy-mail-iam::mail_plane_token` et `SIMPLIFICATIONS.md`.

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

/// Identité validée par le middleware — ne peut être construite QUE par
/// `mail_plane_auth_middleware` après les étapes 1 et 2 (A18-TYPE, type-state) ; aucun
/// handler ne peut la fabriquer à la main.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedIdentity {
    pub principal_id: Uuid,
}

#[derive(Clone)]
struct AppKeyRecord {
    app_name: String,
    app_platform: String,
    active: bool,
}

/// Magasin local `app_keys` (A17-APPKEY-3) : hash SHA-256 de la clé brute -> enregistrement.
/// Jamais la valeur brute au repos ; jamais d'appel IAM pour cette vérification
/// (A17-APPKEY-6, disponibilité indépendante d'IAM).
#[derive(Clone)]
pub struct AppKeyStore {
    by_hash: HashMap<[u8; 32], AppKeyRecord>,
}

impl AppKeyStore {
    /// Doublure de DEV (voir `SIMPLIFICATIONS.md`) : amorce UNE AppKey Tier 2 lue depuis
    /// `DIAMY_MAILD_DEV_APPKEY` (valeur de dev par défaut sinon, même discipline que le
    /// mot de passe Postgres de ce projet). Un vrai déploiement gère un cycle de vie
    /// complet (création/rotation/révocation par plateforme, A17-APPKEY-1/7) — hors
    /// périmètre de cette maquette à tranche unique.
    pub fn seeded_from_env() -> Self {
        let raw = std::env::var("DIAMY_MAILD_DEV_APPKEY")
            .unwrap_or_else(|_| "devonly_change_me_appkey_dev_client".to_string());
        let mut by_hash = HashMap::new();
        by_hash.insert(
            hash_key(raw.as_bytes()),
            AppKeyRecord {
                app_name: "diamy-mail-dev-client".to_string(),
                app_platform: "dev".to_string(),
                active: true,
            },
        );
        Self { by_hash }
    }

    /// Vérification complète A17-APPKEY-5b : le hash ET le nom/plateforme déclarés
    /// doivent correspondre à l'enregistrement — une clé volée déclarant une autre
    /// plateforme que celle pour laquelle elle a été émise est rejetée.
    fn matches(&self, raw_key: &[u8], app_name: &str, app_platform: &str) -> bool {
        match self.by_hash.get(&hash_key(raw_key)) {
            Some(rec) => rec.active && rec.app_name == app_name && rec.app_platform == app_platform,
            None => false,
        }
    }
}

/// Comparaison de l'AppKey par **hash-then-compare** : on hache la clé brute en SHA-256
/// puis on cherche le hash dans la `HashMap`. C'est un choix DÉFENDABLE face à A18-ERR-4 /
/// forbidden-pattern #7 (« jamais `==` sur un secret »), PAS un raccourci de sécurité : la
/// comparaison finale porte sur le *digest* de 32 octets, jamais sur la clé brute. Un canal
/// temporel sur la comparaison du hash ne révèle pas la clé (l'attaquant ne contrôle pas le
/// hash stocké et ne peut pas remonter un préimage SHA-256 depuis un timing). Le tag GCM et
/// la signature HS256 du jeton, eux, sont vérifiés en temps constant par `aes-gcm` /
/// `jsonwebtoken`. Voir `SIMPLIFICATIONS.md`.
fn hash_key(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}

#[derive(Clone)]
pub struct AuthState {
    pub app_keys: AppKeyStore,
    pub mail_jwt_secret: Vec<u8>,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

fn error_response(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(ErrorBody { code, message })).into_response()
}

/// Étape 1 (A17-APPKEY-5) : lookup local, AUCUN appel IAM. `X-App-Version` est exigé
/// présent (A17-APPKEY-4) mais son intervalle n'est pas encore vérifié dans cette
/// maquette à une seule AppKey de dev (voir `SIMPLIFICATIONS.md`) — simplification de
/// périmètre, pas une faille de l'ordre/localité qui, elles, sont bien implémentées.
fn check_app_key(headers: &HeaderMap, store: &AppKeyStore) -> bool {
    let header_str = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let (Some(key), Some(name), Some(platform), Some(_version)) = (
        header_str("x-app-key"),
        header_str("x-app-name"),
        header_str("x-app-platform"),
        header_str("x-app-version"),
    ) else {
        return false;
    };
    store.matches(key.as_bytes(), name, platform)
}

/// Étape 2 (A17-APPKEY-5) : atteinte SEULEMENT si l'étape 1 a réussi.
fn check_mail_plane_token(
    headers: &HeaderMap,
    secret: &[u8],
) -> Result<Uuid, diamy_mail_iam::MailPlaneTokenError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(diamy_mail_iam::MailPlaneTokenError::Invalid)?;
    diamy_mail_iam::verify_mail_plane_token(token, secret)
}

/// Middleware partagé — voir la documentation de module pour l'ordre et sa justification.
pub async fn mail_plane_auth_middleware(
    State(auth): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    // Étape 1, TOUJOURS première (A17-APPKEY-5) : un jeton mail-plane valide ne doit
    // jamais être examiné si l'AppKey est absente/invalide.
    if !check_app_key(req.headers(), &auth.app_keys) {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "ERR_APPKEY_INVALID",
            "application non reconnue",
        );
    }

    // Étape 2, atteinte seulement après l'étape 1.
    let principal_id = match check_mail_plane_token(req.headers(), &auth.mail_jwt_secret) {
        Ok(id) => id,
        Err(_) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "ERR_TOKEN_INVALID",
                "jeton mail-plane invalide ou expiré",
            );
        }
    };

    // L'identité validée est déposée dans les extensions de la requête : les handlers la
    // lisent via `Extension<AuthenticatedIdentity>`, jamais en la reconstruisant eux-mêmes.
    req.extensions_mut().insert(AuthenticatedIdentity { principal_id });
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(key: &str, name: &str, platform: &str, version: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-app-key", HeaderValue::from_str(key).unwrap());
        h.insert("x-app-name", HeaderValue::from_str(name).unwrap());
        h.insert("x-app-platform", HeaderValue::from_str(platform).unwrap());
        h.insert("x-app-version", HeaderValue::from_str(version).unwrap());
        h
    }

    #[test]
    fn valid_dev_appkey_matches() {
        let store = AppKeyStore::seeded_from_env();
        let raw = std::env::var("DIAMY_MAILD_DEV_APPKEY")
            .unwrap_or_else(|_| "devonly_change_me_appkey_dev_client".to_string());
        let headers = headers_with(&raw, "diamy-mail-dev-client", "dev", "0.0.1");
        assert!(check_app_key(&headers, &store));
    }

    #[test]
    fn wrong_platform_for_a_valid_key_is_rejected() {
        // A17-APPKEY-5b : le hash peut correspondre mais la plateforme déclarée doit
        // aussi correspondre à l'enregistrement — sinon une clé volée pourrait
        // s'authentifier en se déclarant sur une autre plateforme.
        let store = AppKeyStore::seeded_from_env();
        let raw = std::env::var("DIAMY_MAILD_DEV_APPKEY")
            .unwrap_or_else(|_| "devonly_change_me_appkey_dev_client".to_string());
        let headers = headers_with(&raw, "diamy-mail-dev-client", "ios", "0.0.1");
        assert!(!check_app_key(&headers, &store));
    }

    #[test]
    fn missing_appkey_headers_are_rejected() {
        let store = AppKeyStore::seeded_from_env();
        assert!(!check_app_key(&HeaderMap::new(), &store));
    }
}
