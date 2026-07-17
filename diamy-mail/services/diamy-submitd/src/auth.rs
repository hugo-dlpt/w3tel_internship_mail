//! Authentification de `/submit` (A20-CRED-5, A17-APPKEY-5) — même discipline à deux
//! facteurs, dans le même ordre, que `diamy-maild/src/auth.rs` (qu'il n'était pas dans le
//! périmètre de cette tranche de toucher) : AppKey Tier 2 (lookup local, jamais d'appel IAM)
//! validée AVANT le jeton mail-plane (signature HS256 + expiration), jamais l'inverse.
//!
//! **Une seule AppKey amorcée dans cette V1** (`diamy-mail-bridge`) : le Bridge est le SEUL
//! appelant de `/submit` dans cette tranche (A20-SMTP-1) ; A20-CRED-5 précise que c'est la
//! MÊME AppKey Tier 2 que le Bridge envoie à `diamy-maild` ET à `diamy-submitd` — donc
//! `DIAMY_SUBMITD_DEV_BRIDGE_APPKEY` DOIT être configurée à la MÊME valeur que
//! `DIAMY_MAILD_DEV_BRIDGE_APPKEY` côté `diamy-maild` (deux variables d'env distinctes par
//! service, même convention douze-facteurs qu'ailleurs dans le projet, mais une seule valeur
//! de secret). Un futur client natif ajouterait une seconde entrée, comme
//! `AppKeyStore::seeded_from_env` de `diamy-maild` le fait déjà pour son propre cas à deux
//! AppKeys — la structure ci-dessous (`HashMap` par hash) le permettrait sans redesign.
//!
//! **Gap signalé, pas comblé (A25 Constitution règle 2)** : comme dans `diamy-maild`, la
//! révocation du jeton mail-plane n'est PAS vérifiée (mécanisme non confirmé, A17-TOK-2) ;
//! et A10-AUTH-4 (vérifier que l'expéditeur authentifié possède réellement l'identité `From`
//! envoyée dans la requête) n'est PAS implémenté ici — l'authentification prouve "un appareil
//! Bridge enrôlé avec une session valide", pas "ce principal possède exactement cette adresse
//! `mail_from`". Voir `SIMPLIFICATIONS.md`.

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
/// `submit_auth_middleware` après les étapes 1 et 2 (type-state, même discipline que
/// `diamy-maild::auth::AuthenticatedIdentity`).
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

#[derive(Clone)]
pub struct AppKeyStore {
    by_hash: HashMap<[u8; 32], AppKeyRecord>,
}

impl AppKeyStore {
    pub fn seeded_from_env() -> Self {
        let bridge_raw = std::env::var("DIAMY_SUBMITD_DEV_BRIDGE_APPKEY")
            .unwrap_or_else(|_| "devonly_change_me_appkey_bridge_dev_client".to_string());
        let mut by_hash = HashMap::new();
        by_hash.insert(
            hash_key(bridge_raw.as_bytes()),
            AppKeyRecord {
                app_name: "diamy-mail-bridge".to_string(),
                app_platform: "dev".to_string(),
                active: true,
            },
        );
        Self { by_hash }
    }

    fn matches(&self, raw_key: &[u8], app_name: &str, app_platform: &str) -> bool {
        match self.by_hash.get(&hash_key(raw_key)) {
            Some(rec) => rec.active && rec.app_name == app_name && rec.app_platform == app_platform,
            None => false,
        }
    }
}

/// Hash-then-compare (même choix défendable que `diamy-maild::auth::hash_key`, voir
/// `SIMPLIFICATIONS.md` : la comparaison finale porte sur le digest 32o, jamais la clé brute).
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

/// Middleware partagé, appliqué en `.layer(...)` sur tout le routeur `/submit` (jamais par
/// endpoint) — même raison qu'ailleurs dans le projet : impossible d'oublier ou d'inverser
/// l'ordre sur une route future.
pub async fn submit_auth_middleware(
    State(auth): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    if !check_app_key(req.headers(), &auth.app_keys) {
        return error_response(StatusCode::UNAUTHORIZED, "ERR_APPKEY_INVALID", "application non reconnue");
    }

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
    fn valid_bridge_appkey_matches() {
        let store = AppKeyStore::seeded_from_env();
        let raw = std::env::var("DIAMY_SUBMITD_DEV_BRIDGE_APPKEY")
            .unwrap_or_else(|_| "devonly_change_me_appkey_bridge_dev_client".to_string());
        let headers = headers_with(&raw, "diamy-mail-bridge", "dev", "0.0.1");
        assert!(check_app_key(&headers, &store));
    }

    #[test]
    fn missing_appkey_headers_are_rejected() {
        let store = AppKeyStore::seeded_from_env();
        assert!(!check_app_key(&HeaderMap::new(), &store));
    }

    #[test]
    fn wrong_app_name_for_a_valid_key_is_rejected() {
        let store = AppKeyStore::seeded_from_env();
        let raw = std::env::var("DIAMY_SUBMITD_DEV_BRIDGE_APPKEY")
            .unwrap_or_else(|_| "devonly_change_me_appkey_bridge_dev_client".to_string());
        let headers = headers_with(&raw, "diamy-mail-dev-client", "dev", "0.0.1");
        assert!(!check_app_key(&headers, &store));
    }
}
