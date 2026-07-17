//! API de sync minimaliste (A04) — tranche volontairement fine, lecture seule.
//!
//! Ce qui EST implémenté ici, fidèlement à A04 : le modèle "pull" (le client tire, A04 §1.2
//! / INV-12), le catalogue par référence (endpoint séparé de la liste), le principe qu'un
//! message n'est lisible qu'avec l'enveloppe de SON appareil, et — désormais —
//! l'authentification à deux facteurs indépendants (AppKey Tier 2 puis jeton mail-plane,
//! dans cet ordre, A17-APPKEY-5/A04-TR-2/INV-25) via le middleware partagé `auth.rs`.
//!
//! Ce qui N'EST PAS implémenté (voir `SIMPLIFICATIONS.md`, à ne jamais confondre avec la
//! vraie API A04) :
//! - Pas de WSS ni de notifications signal-seul (A04 §1.2, journal non implémenté) : le
//!   client interroge directement la liste, il n'y a pas de signal à écouter.
//! - Pas de pagination par curseur (A04-PAGE-1) : une borne fixe (LIMIT 50) à la place.
//! - Le chiffré est renvoyé encodé en base64 dans le JSON, pas "par référence" comme
//!   l'exige A00 API-3 pour une vraie implémentation à l'échelle.
//! - Pas de signature de requête (A04-SIG-1), pas d'idempotence (A04-EP-4) : lecture
//!   seule, aucune mutation d'état n'est exposée ici.
//! - La révocation du jeton mail-plane (A17-TOK-1) n'est pas vérifiée — mécanisme non
//!   confirmé, point ouvert HIGH (A17-TOK-2) ; voir `auth.rs` et `SIMPLIFICATIONS.md`.

use crate::auth::{AuthState, AuthenticatedIdentity};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    middleware,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use diamy_mail_storage::{self as storage, BlobStore, FlagsUpdate};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct SyncState {
    pub pool: storage::PgPool,
    pub blob_store: Arc<BlobStore>,
}

#[derive(Serialize)]
struct MessageSummaryDto {
    message_id: Uuid,
    sender_canonical: Option<String>,
    size_bytes: i64,
    received_at: Option<String>,
    /// A04 §3/§5.3 : état réel serveur-autoritaire (`mail.messages.state_flags`), pas un stand-in
    /// local au Bridge — c'est ce champ qui rend `\Seen`/`\Deleted` visibles depuis N'IMPORTE
    /// QUELLE session IMAP sur le même principal (preuve du test multi-connexion).
    read: bool,
    deleted: bool,
}

type ApiError = (StatusCode, String);

/// `GET /v1/mailbox/:principal_id/messages` — catalogue borné (A04-EP-1 simplifié).
/// PLAINTEXT_METADATA uniquement (A21 §2.2) : jamais de contenu.
async fn list_messages(
    Extension(identity): Extension<AuthenticatedIdentity>,
    State(state): State<SyncState>,
    Path(principal_id): Path<Uuid>,
) -> Result<Json<Vec<MessageSummaryDto>>, ApiError> {
    // Étape 3 (autorisation, A17-APPKEY-5) : le principal authentifié par le jeton
    // mail-plane DOIT être celui de la boîte demandée — sans ça, un jeton valide pour
    // N'IMPORTE QUEL principal suffirait à lister la boîte de N'IMPORTE QUEL autre
    // (A04-EP-3, INV-25). Pas de fuite d'existence (A04-ERR-1) : 404 générique.
    if identity.principal_id != principal_id {
        tracing::debug!(
            token_principal_id = %identity.principal_id,
            requested_principal_id = %principal_id,
            "SELECT/list_messages : principal du jeton != principal de l'URL, rejet 404"
        );
        return Err((StatusCode::NOT_FOUND, "introuvable".to_string()));
    }
    let messages = storage::list_recent_messages(&state.pool, principal_id, 50)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Diagnostic SELECT (0 EXISTS inattendu côté Bridge) : le principal effectivement
    // interrogé et le nombre de lignes trouvées en base — visible avec
    // RUST_LOG=diamy_maild=debug.
    tracing::debug!(
        %principal_id,
        messages_found = messages.len(),
        "SELECT/list_messages : catalogue interrogé"
    );
    Ok(Json(
        messages
            .into_iter()
            .map(|m| MessageSummaryDto {
                message_id: m.message_id,
                sender_canonical: m.sender_canonical,
                size_bytes: m.size_bytes,
                received_at: m.received_at.map(|t| t.to_string()),
                read: m.read,
                deleted: m.deleted,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct FetchQuery {
    device_id: Uuid,
}

#[derive(Serialize)]
struct FetchedDto {
    /// Nécessaire côté client pour reconstruire l'AAD (`aad_for_blob(message_id,
    /// body_blob_id)`, A02-CRY-2) avant de vérifier/ouvrir `body_ciphertext_b64` — sans
    /// cet id, `open_message` échoue par construction (AAD différente de celle du
    /// scellement, fail-closed INV-8/16).
    body_blob_id: Uuid,
    /// A02-CRY-7 : la version de suite voyage avec le chiffré pour que le client puisse la
    /// re-contrôler avant `open_message` (INV-7). Le serveur l'a déjà validée (fail-closed)
    /// en lisant `mail.blobs.blob_alg_version` / `mail.envelopes.alg_version`.
    body_alg_version: i32,
    body_nonce_b64: String,
    body_ciphertext_b64: String,
    /// Sujet scellé (A20-IMAP-2, Bridge) : sous le MÊME `k_msg` que le corps, AAD distincte
    /// (`aad_for_summary(message_id)`) — l'enveloppe ci-dessous désemballe les deux.
    summary_alg_version: i32,
    summary_nonce_b64: String,
    summary_ciphertext_b64: String,
    envelope_alg_version: i32,
    envelope_kem_ct_b64: String,
    envelope_wrap_nonce_b64: String,
    envelope_wrapped_key_b64: String,
}

/// `GET /v1/mailbox/:principal_id/messages/:message_id?device_id=...` — le chiffré +
/// l'enveloppe de CET appareil (A02 §3, "le client tire ce qu'il décide"). Le serveur ne
/// déchiffre jamais : il sert des octets opaques. `principal_id` est vérifié contre le
/// propriétaire réel du message (pas seulement `message_id`/`device_id`) : sans ça,
/// n'importe quel appelant connaissant ces deux UUID pourrait lire le courrier d'un AUTRE
/// principal que celui de l'URL — trouvé en relisant ce code, corrigé dans
/// `fetch_message_for_device`.
async fn fetch_message(
    Extension(identity): Extension<AuthenticatedIdentity>,
    State(state): State<SyncState>,
    Path((principal_id, message_id)): Path<(Uuid, Uuid)>,
    Query(q): Query<FetchQuery>,
) -> Result<Json<FetchedDto>, ApiError> {
    // Étape 3 (autorisation) — même garde qu'au-dessus, voir `list_messages`.
    if identity.principal_id != principal_id {
        return Err((StatusCode::NOT_FOUND, "introuvable".to_string()));
    }
    let fetched = storage::fetch_message_for_device(
        &state.pool,
        &state.blob_store,
        principal_id,
        message_id,
        q.device_id,
    )
    .await
    .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    Ok(Json(FetchedDto {
        body_blob_id: fetched.body_blob_id,
        body_alg_version: fetched.body_ct.alg_version.as_i32(),
        body_nonce_b64: STANDARD.encode(fetched.body_ct.nonce),
        body_ciphertext_b64: STANDARD.encode(&fetched.body_ct.bytes),
        summary_alg_version: fetched.summary_ct.alg_version.as_i32(),
        summary_nonce_b64: STANDARD.encode(fetched.summary_ct.nonce),
        summary_ciphertext_b64: STANDARD.encode(&fetched.summary_ct.bytes),
        envelope_alg_version: fetched.envelope.wrapped.alg_version.as_i32(),
        envelope_kem_ct_b64: STANDARD.encode(&fetched.envelope.kem_ct),
        envelope_wrap_nonce_b64: STANDARD.encode(fetched.envelope.wrapped.nonce),
        envelope_wrapped_key_b64: STANDARD.encode(&fetched.envelope.wrapped.bytes),
    }))
}

/// Corps commun aux deux opérations d'état mutantes (A04 §5.3/§6) : `message_id` la cible,
/// `idempotency_key` un UUIDv7 généré CLIENT (A04-IDEM-1) — jamais par ce serveur. Le format
/// exact du corps JSON n'est pas normatif dans A04 (seul le comportement l'est : idempotence,
/// séquence renvoyée) — un choix de convention documenté (voir `SIMPLIFICATIONS.md`), dans le
/// même esprit que le schéma des claims du jeton mail-plane.
#[derive(Deserialize)]
struct StateFlagsRequest {
    message_id: Uuid,
    idempotency_key: Uuid,
    /// A04-EP-4bis (v1.4) : `\Seen` — booléen réversible, LWW par champ (A03-SYNC-1/2).
    read: Option<bool>,
    /// A04-EP-4bis (v1.4) : `deleted` — booléen réversible, PAS l'action de purge/déplacement
    /// (qui reste `/state/delete`, ci-dessous) — c'est le tombstone IMAP `\Deleted` AVANT EXPUNGE.
    deleted: Option<bool>,
}

#[derive(Deserialize)]
struct StateDeleteRequest {
    message_id: Uuid,
    idempotency_key: Uuid,
    /// Cette implémentation ne câble QUE `"hard"` (A04 v1.4 changelog : le Bridge, mono-dossier,
    /// n'exerce que la purge). `"soft"` est un mode valide d'A04 §5.3 mais rejeté ICI en
    /// `ERR_VALIDATION` plutôt que silencieusement mal exécuté (fail-closed, INV-16).
    mode: String,
}

#[derive(Serialize)]
struct StateOpResponse {
    /// A04-EP-4 : "the response returns the assigned sequence so the client can order local
    /// state" — la séquence de journal assignée à CET événement.
    sequence: i64,
}

/// Point commun aux deux handlers ci-dessous : vérifie la clé d'idempotence AVANT d'exécuter
/// quoi que ce soit (A04-IDEM-1) — `None` si c'est la PREMIÈRE exécution sous cette clé (au
/// handler d'exécuter puis d'enregistrer via `record_idempotency`), `Some(...)` si la requête a
/// déjà été traitée (l'appelant DOIT alors renvoyer ce résultat SANS réappliquer l'effet).
async fn already_applied(pool: &storage::PgPool, idempotency_key: Uuid) -> Result<Option<Json<serde_json::Value>>, ApiError> {
    let existing = storage::check_idempotency(pool, idempotency_key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(existing.map(|r| Json(r.response_body)))
}

/// `POST /v1/mailbox/:principal_id/state/flags` (A04 §5.3/A04-EP-4bis) : delta read/deleted,
/// idempotent, journalisé (`flags_changed`). Jamais de contenu déchiffré/re-chiffré ici — cette
/// opération ne touche QUE `mail.messages.state_flags` (métadonnée), jamais `summary_ct`/
/// `body_ct`/les enveloppes (A25 INV-1/2, périmètre non négociable de cette fonctionnalité).
async fn state_flags(
    Extension(identity): Extension<AuthenticatedIdentity>,
    State(state): State<SyncState>,
    Path(principal_id): Path<Uuid>,
    Json(req): Json<StateFlagsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if identity.principal_id != principal_id {
        return Err((StatusCode::NOT_FOUND, "introuvable".to_string()));
    }
    if let Some(cached) = already_applied(&state.pool, req.idempotency_key).await? {
        return Ok(cached);
    }

    let update = FlagsUpdate { read: req.read, deleted: req.deleted };
    let sequence = storage::apply_state_flags(&state.pool, principal_id, req.message_id, &update)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    let body = serde_json::to_value(StateOpResponse { sequence })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    storage::record_idempotency(&state.pool, req.idempotency_key, principal_id, "state/flags", &body, sequence)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(body))
}

/// `POST /v1/mailbox/:principal_id/state/delete` (A04 §5.3) : purge (mode `"hard"` uniquement
/// dans cette implémentation, voir `StateDeleteRequest`), idempotente, journalisée
/// (`message_deleted`).
async fn state_delete(
    Extension(identity): Extension<AuthenticatedIdentity>,
    State(state): State<SyncState>,
    Path(principal_id): Path<Uuid>,
    Json(req): Json<StateDeleteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if identity.principal_id != principal_id {
        return Err((StatusCode::NOT_FOUND, "introuvable".to_string()));
    }
    if req.mode != "hard" {
        return Err((
            StatusCode::BAD_REQUEST,
            "ERR_VALIDATION: seul mode=\"hard\" est câblé dans cette implémentation (A04 v1.4 changelog)".to_string(),
        ));
    }
    if let Some(cached) = already_applied(&state.pool, req.idempotency_key).await? {
        return Ok(cached);
    }

    let sequence = storage::purge_message(&state.pool, &state.blob_store, principal_id, req.message_id)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    let body = serde_json::to_value(StateOpResponse { sequence })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    storage::record_idempotency(&state.pool, req.idempotency_key, principal_id, "state/delete", &body, sequence)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(body))
}

/// Le middleware d'auth (`auth.rs`) est appliqué en `.layer(...)` sur TOUT le routeur,
/// pas par endpoint (A18-ERR-5, forbidden pattern #14) : toute route ajoutée ici plus
/// tard hérite automatiquement des deux vérifications, dans l'ordre, sans rien faire de
/// spécial.
pub fn router(state: SyncState, auth: AuthState) -> Router {
    Router::new()
        .route("/v1/mailbox/:principal_id/messages", get(list_messages))
        .route(
            "/v1/mailbox/:principal_id/messages/:message_id",
            get(fetch_message),
        )
        .route("/v1/mailbox/:principal_id/state/flags", post(state_flags))
        .route("/v1/mailbox/:principal_id/state/delete", post(state_delete))
        .layer(middleware::from_fn_with_state(auth, crate::auth::mail_plane_auth_middleware))
        .with_state(state)
}

/// Tests d'intégration de l'API de sync, contre un VRAI Postgres de dev et un VRAI
/// serveur HTTP (pas d'appel direct aux handlers) — remplacent la vérification manuelle
/// faite pendant le développement, y compris celle du bug d'autorisation trouvé et
/// corrigé en session (voir `SIMPLIFICATIONS.md`).
///
/// Même discipline d'isolation que `diamy-mxd` (base partagée, tests potentiellement
/// concurrents avec d'autres binaires de test) : jamais de `TRUNCATE`, chaque test génère
/// son propre principal/appareil/message et retrouve SON message par un marqueur unique.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AppKeyStore;
    use diamy_mail_crypto as crypto;
    use diamy_mail_iam::IamClient;
    use tokio::net::TcpListener;

    fn test_database_url() -> String {
        std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://diamy:devonly_change_me@localhost:5433/diamymail".to_string()
        })
    }

    // --- Fixtures d'authentification de test (A17-APPKEY-5) : valeurs fixes, jamais
    // lues depuis un secret réel — voir `auth.rs`/`SIMPLIFICATIONS.md` pour la doublure
    // de dev qu'elles alimentent.
    const TEST_APPKEY_RAW: &str = "test-only-appkey-do-not-use-elsewhere";
    const TEST_APPKEY_NAME: &str = "diamy-mail-dev-client";
    const TEST_APPKEY_PLATFORM: &str = "dev";

    // --- Jetons mail-plane PRÉ-SIGNÉS (INV-9 / A17-P-1 : seul IAM émet des jetons ; aucune
    // fonction du repo ne sait en fabriquer). Ces tests LISENT un jeton figé dans la fixture,
    // ils n'en fabriquent jamais. Le secret HS256 de la fixture DOIT être celui avec lequel le
    // middleware d'auth vérifie (`test_auth_state`) — d'où la source unique ci-dessous.
    const MAIL_PLANE_FIXTURES: &str =
        include_str!("../../../tests/fixtures/dev_mail_plane_tokens.json");

    fn fixtures() -> serde_json::Value {
        serde_json::from_str(MAIL_PLANE_FIXTURES).expect("fixture de jetons JSON valide")
    }
    fn fixture_secret() -> Vec<u8> {
        fixtures()["secret"].as_str().expect("champ `secret`").as_bytes().to_vec()
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
            .unwrap_or_else(|| panic!("principal_id de `{name}`"))
            .parse()
            .expect("principal_id UUID valide")
    }

    fn test_auth_state() -> AuthState {
        std::env::set_var("DIAMY_MAILD_DEV_APPKEY", TEST_APPKEY_RAW);
        AuthState {
            app_keys: AppKeyStore::seeded_from_env(),
            // MÊME secret que celui utilisé pour pré-signer les jetons de la fixture.
            mail_jwt_secret: fixture_secret(),
        }
    }

    /// Requête GET portant les DEUX informations d'identification valides (A17-APPKEY-5) :
    /// l'AppKey Tier 2 et un jeton mail-plane pré-signé (fourni tel quel par l'appelant, lu
    /// depuis la fixture — jamais fabriqué). Le chemin heureux que la plupart des tests exercent.
    fn authed_get(client: &reqwest::Client, url: &str, token: &str) -> reqwest::RequestBuilder {
        client
            .get(url)
            .header("x-app-key", TEST_APPKEY_RAW)
            .header("x-app-name", TEST_APPKEY_NAME)
            .header("x-app-platform", TEST_APPKEY_PLATFORM)
            .header("x-app-version", "0.0.1")
            .header("authorization", format!("Bearer {token}"))
    }

    /// Démarre une instance du VRAI routeur axum, EN HTTPS (A04-TR-1, certificat
    /// auto-signé de dev — comme le vrai `main()`), sur un port choisi par l'OS. Renvoie
    /// l'URL de base (`https://127.0.0.1:PORT`) à utiliser par le client de test.
    async fn spawn_test_api(state: SyncState) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let std_listener = listener.into_std().expect("conversion en std::net::TcpListener");
        let tls_config = crate::generate_dev_tls_config("maild.w3.tel")
            .await
            .expect("certificat de dev");
        tokio::spawn(async move {
            let server = axum_server::from_tcp_rustls(std_listener, tls_config)
                .expect("configuration TLS de test");
            let _ = server
                .serve(router(state, test_auth_state()).into_make_service())
                .await;
        });
        format!("https://{addr}")
    }

    /// Client HTTP de test : accepte le certificat auto-signé de dev — UNIQUEMENT parce
    /// que ce test se connecte à son propre serveur éphémère, jamais en production.
    fn test_https_client() -> reqwest::Client {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("client de test")
    }

    /// Enrôle un appareil de test (comme `enroll_test_device`), en local au test.
    async fn enroll_device_for_test(
        pool: &storage::PgPool,
        principal_id: Uuid,
    ) -> (Uuid, crypto::DeviceEncSecretKey) {
        let (identity_pub, identity_sec) = crypto::generate_identity_keypair().unwrap();
        let (mail_pub, mail_sec) = crypto::generate_device_keypair().unwrap();
        let device_id = Uuid::now_v7();
        let signature = crypto::sign_manifest(&identity_sec, &mail_pub.0).unwrap();
        storage::publish_device_bundle(
            pool,
            principal_id,
            device_id,
            &mail_pub.0,
            &signature.0,
            device_id,
            &identity_pub,
        )
        .await
        .unwrap();
        (device_id, mail_sec)
    }

    /// Stocke directement un message de test (sans passer par SMTP) pour CE principal et
    /// CET appareil, avec `marker` dans le corps chiffré — renvoie le `message_id`.
    async fn store_test_message(
        pool: &storage::PgPool,
        blob_store: &BlobStore,
        principal_id: Uuid,
        domain_alabel: &str,
        device_id: Uuid,
        marker: &str,
    ) -> Uuid {
        let plaintext = format!("Subject: test\r\n\r\nContenu {marker}");
        // A02-CRY-2/3 : générés AVANT le chiffrement pour entrer dans l'AAD.
        let message_id = Uuid::now_v7();
        let body_blob_id = Uuid::now_v7();
        let (body_ct, message_key) =
            crypto::seal_message(plaintext.as_bytes(), &crypto::aad_for_blob(message_id, body_blob_id))
                .unwrap();
        let (summary_ct, summary_key) =
            crypto::seal_message(b"[resume]", &crypto::aad_for_summary(message_id)).unwrap();
        drop(summary_key);

        let devices = storage::active_device_keys(pool, principal_id).await.unwrap();
        let (_, mlkem_pub) = devices.into_iter().find(|(id, _)| *id == device_id).unwrap();
        let envelope = crypto::wrap_key_for_device(
            &message_key,
            &crypto::DeviceEncPublicKey(mlkem_pub),
            &crypto::aad_for_envelope(message_id, device_id),
        )
        .unwrap();
        drop(message_key);

        let (folder_name_ct, folder_key) =
            crypto::seal_message(b"Inbox", b"mailfolder-placeholder:not-a02-modeled").unwrap();
        drop(folder_key);
        // A17-P-3 : dérivation déterministe depuis le domaine, même pattern que
        // DevIamClient::seeded() pour principal_id — voir SIMPLIFICATIONS.md.
        let tenant_id = diamy_mail_iam::derive_dev_tenant_id(domain_alabel);
        let folder_id =
            storage::ensure_inbox_folder(pool, principal_id, tenant_id, &folder_name_ct.bytes)
                .await
                .unwrap();

        storage::store_inbound_message(
            pool,
            blob_store,
            &storage::InboundMessage {
                message_id,
                body_blob_id,
                principal_id,
                tenant_id,
                folder_id,
                sender_canonical: "expediteur.test@example.fr",
                recipient_canonical: "test@w3.tel",
                body_ct: &body_ct,
                summary_ct: &summary_ct,
                size_bytes: plaintext.len() as i64,
                envelopes: &[(device_id, &envelope)],
                trust_metadata: None, // test de stockage direct, pas une vraie session SMTP
            },
        )
        .await
        .unwrap()
    }

    async fn test_state() -> (SyncState, storage::PgPool) {
        let pool = storage::connect(&test_database_url())
            .await
            .expect("Postgres de dev doit tourner (`docker compose up`) pour ces tests");
        let blob_store = Arc::new(BlobStore::at("./blob_store").expect("object store local"));
        (
            SyncState {
                pool: pool.clone(),
                blob_store,
            },
            pool,
        )
    }

    /// Chemin heureux : lister le catalogue, tirer le chiffré + l'enveloppe par le VRAI
    /// réseau HTTP, déchiffrer localement et vérifier le contenu (A02 §3, "le client tire").
    #[tokio::test]
    async fn list_and_fetch_round_trip_over_http() {
        let (state, pool) = test_state().await;
        let iam = diamy_mail_iam::DevIamClient::seeded();
        let principal = iam.resolve_principal("cedric@w3.tel").unwrap();
        // Le jeton pré-signé `valid_cedric` porte le principal_id de cedric@w3.tel : c'est le
        // MÊME UUIDv5 que celui dérivé par DevIamClient::seeded(), donc la fixture reste
        // cohérente avec l'IAM de dev sans qu'aucune fabrication de jeton ne soit nécessaire.
        assert_eq!(principal.id, fixture_principal("valid_cedric"));
        let (device_id, device_sec) = enroll_device_for_test(&pool, principal.id).await;

        let marker = format!("marqueur-{}", Uuid::now_v7());
        let message_id =
            store_test_message(&pool, &state.blob_store, principal.id, principal.address.domain_alabel(), device_id, &marker).await;

        let base_url = spawn_test_api(state).await;
        let client = test_https_client();

        let list_url = format!("{base_url}/v1/mailbox/{}/messages", principal.id);
        let messages: Vec<serde_json::Value> = authed_get(&client, &list_url, &fixture_token("valid_cedric"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(
            messages.iter().any(|m| m["message_id"] == message_id.to_string()),
            "le message stocké doit apparaître dans le catalogue"
        );

        let fetch_url = format!(
            "{base_url}/v1/mailbox/{}/messages/{message_id}?device_id={device_id}",
            principal.id
        );
        let resp = authed_get(&client, &fetch_url, &fixture_token("valid_cedric")).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let dto: serde_json::Value = resp.json().await.unwrap();

        use base64::{engine::general_purpose::STANDARD, Engine};
        let nonce: [u8; 12] = STANDARD
            .decode(dto["body_nonce_b64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        // INV-7 : le client re-contrôle la version reçue sur le fil avant tout `open_*`.
        let body_ct = crypto::Ciphertext {
            alg_version: crypto::AlgVersion::from_i32(dto["body_alg_version"].as_i64().unwrap() as i32).unwrap(),
            nonce,
            bytes: STANDARD.decode(dto["body_ciphertext_b64"].as_str().unwrap()).unwrap(),
        };
        let wrap_nonce: [u8; 12] = STANDARD
            .decode(dto["envelope_wrap_nonce_b64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let envelope = crypto::Envelope {
            kem_ct: STANDARD.decode(dto["envelope_kem_ct_b64"].as_str().unwrap()).unwrap(),
            wrapped: crypto::Ciphertext {
                alg_version: crypto::AlgVersion::from_i32(dto["envelope_alg_version"].as_i64().unwrap() as i32).unwrap(),
                nonce: wrap_nonce,
                bytes: STANDARD
                    .decode(dto["envelope_wrapped_key_b64"].as_str().unwrap())
                    .unwrap(),
            },
        };

        let body_blob_id: Uuid = dto["body_blob_id"].as_str().unwrap().parse().unwrap();
        let key = crypto::unwrap_key(&envelope, &device_sec, &crypto::aad_for_envelope(message_id, device_id))
            .unwrap();
        let aad = crypto::aad_for_blob(message_id, body_blob_id);
        let verified = crypto::open_message(&body_ct, &key, &aad).unwrap();
        assert!(String::from_utf8_lossy(verified.as_bytes()).contains(&marker));
    }

    /// La correction d'autorisation appliquée en session : un `principal_id` qui ne
    /// correspond PAS au vrai propriétaire du message doit être rejeté (404), même avec
    /// un `message_id`/`device_id` par ailleurs valides ET une authentification par
    /// ailleurs VALIDE pour le vrai propriétaire — c'est désormais l'étape 3
    /// (autorisation, A17-APPKEY-5) qui l'attrape, plus tôt que la jointure DB.
    #[tokio::test]
    async fn fetch_with_wrong_principal_id_is_rejected() {
        let (state, pool) = test_state().await;
        let iam = diamy_mail_iam::DevIamClient::seeded();
        let principal = iam.resolve_principal("cedric@w3.tel").unwrap();
        // Cohérence fixture↔IAM (voir round-trip) : `valid_cedric` == principal_id de cedric.
        assert_eq!(principal.id, fixture_principal("valid_cedric"));
        let (device_id, _device_sec) = enroll_device_for_test(&pool, principal.id).await;
        let marker = format!("marqueur-{}", Uuid::now_v7());
        let message_id =
            store_test_message(&pool, &state.blob_store, principal.id, principal.address.domain_alabel(), device_id, &marker).await;

        let base_url = spawn_test_api(state).await;
        let client = test_https_client();

        let wrong_principal = Uuid::now_v7();
        let fetch_url =
            format!("{base_url}/v1/mailbox/{wrong_principal}/messages/{message_id}?device_id={device_id}");
        // Authentifié comme le VRAI propriétaire (`principal.id`), mais l'URL demande la
        // boîte d'un AUTRE principal (`wrong_principal`) : doit échouer malgré une
        // authentification par ailleurs valide.
        let resp = authed_get(&client, &fetch_url, &fixture_token("valid_cedric")).send().await.unwrap();
        assert_eq!(resp.status(), 404, "un mauvais principal_id doit être rejeté");
    }

    /// Un `message_id` qui n'existe pas du tout est aussi un 404 (pas une 500 qui
    /// laisserait fuiter des détails internes), pour un appelant par ailleurs authentifié
    /// et autorisé sur SA PROPRE boîte (vide).
    #[tokio::test]
    async fn fetch_unknown_message_is_404() {
        let (state, _pool) = test_state().await;
        let base_url = spawn_test_api(state).await;
        let client = test_https_client();

        // Principal AUTHENTIFIÉ et AUTORISÉ sur SA PROPRE boîte (aubin, jeton pré-signé lu dans
        // la fixture), mais demandant un message inexistant : l'autorisation passe (sub ==
        // principal de l'URL), puis la recherche échoue -> 404 générique (pas de 500, pas de fuite).
        let principal_id = fixture_principal("valid_aubin");
        let random_message = Uuid::now_v7();
        let random_device = Uuid::now_v7();
        let fetch_url = format!(
            "{base_url}/v1/mailbox/{principal_id}/messages/{random_message}?device_id={random_device}"
        );
        let resp = authed_get(&client, &fetch_url, &fixture_token("valid_aubin")).send().await.unwrap();
        assert_eq!(resp.status(), 404);
    }

    /// INV-25 / A04-TR-2 : aucune information d'identification -> 401, jamais un 200
    /// silencieux. C'est le test qui aurait dû échouer avant ce correctif (l'API de sync
    /// n'avait AUCUNE authentification, voir `SIMPLIFICATIONS.md`).
    #[tokio::test]
    async fn unauthenticated_request_is_rejected() {
        let (state, _pool) = test_state().await;
        let base_url = spawn_test_api(state).await;
        let client = test_https_client();

        let principal_id = Uuid::now_v7();
        let resp = client
            .get(format!("{base_url}/v1/mailbox/{principal_id}/messages"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], "ERR_APPKEY_INVALID");
    }

    /// A17-APPKEY-5 test #10/#11 : l'AppKey est vérifiée EN PREMIER, localement, avant
    /// même que le jeton mail-plane soit examiné. Preuve par l'observable : un jeton
    /// syntaxiquement invalide (qui échouerait lui aussi) ET une AppKey invalide
    /// renvoient `ERR_APPKEY_INVALID`, jamais `ERR_TOKEN_INVALID` — si le jeton avait été
    /// vérifié en premier, l'erreur observée serait différente.
    #[tokio::test]
    async fn invalid_appkey_is_rejected_before_token_is_examined() {
        let (state, _pool) = test_state().await;
        let base_url = spawn_test_api(state).await;
        let client = test_https_client();

        let principal_id = Uuid::now_v7();
        let resp = client
            .get(format!("{base_url}/v1/mailbox/{principal_id}/messages"))
            .header("x-app-key", "cle-invalide-qui-ne-matche-rien")
            .header("x-app-name", TEST_APPKEY_NAME)
            .header("x-app-platform", TEST_APPKEY_PLATFORM)
            .header("x-app-version", "0.0.1")
            .header("authorization", "Bearer ceci-nest-pas-un-jwt-valide")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["code"], "ERR_APPKEY_INVALID",
            "l'AppKey invalide doit être détectée avant que le jeton (lui aussi invalide) ne soit examiné"
        );
    }

    /// A17-APPKEY-5 étape 2 : AppKey valide + jeton mail-plane invalide/absent -> rejeté
    /// pour la raison du jeton, PAS conflaté avec une erreur d'AppKey (A17 test #12).
    #[tokio::test]
    async fn valid_appkey_but_invalid_token_is_rejected_at_token_step() {
        let (state, _pool) = test_state().await;
        let base_url = spawn_test_api(state).await;
        let client = test_https_client();

        let principal_id = Uuid::now_v7();
        let resp = client
            .get(format!("{base_url}/v1/mailbox/{principal_id}/messages"))
            .header("x-app-key", TEST_APPKEY_RAW)
            .header("x-app-name", TEST_APPKEY_NAME)
            .header("x-app-platform", TEST_APPKEY_PLATFORM)
            .header("x-app-version", "0.0.1")
            // Pas de header Authorization du tout.
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], "ERR_TOKEN_INVALID");
    }

    /// A17-APPKEY-5b : une AppKey valide déclarant une AUTRE plateforme que celle de son
    /// enregistrement (`X-App-Platform` mismatch) est rejetée, même si le hash correspond.
    #[tokio::test]
    async fn appkey_valid_hash_but_wrong_platform_is_rejected() {
        let (state, _pool) = test_state().await;
        let base_url = spawn_test_api(state).await;
        let client = test_https_client();

        // Jeton mail-plane pré-signé valide (lu dans la fixture), mais il ne sera JAMAIS
        // examiné : l'étape 1 (AppKey, plateforme "ios" != "dev") échoue d'abord — ordre
        // strict A17-APPKEY-5. Le `sub` du jeton est donc sans importance ici.
        let principal_id = fixture_principal("valid_hugo");
        let token = fixture_token("valid_hugo");
        let resp = client
            .get(format!("{base_url}/v1/mailbox/{principal_id}/messages"))
            .header("x-app-key", TEST_APPKEY_RAW)
            .header("x-app-name", TEST_APPKEY_NAME)
            .header("x-app-platform", "ios") // enregistré pour "dev", pas "ios"
            .header("x-app-version", "0.0.1")
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["code"], "ERR_APPKEY_INVALID");
    }

    // --- Tests A04 §3/§5.3/§6 réels (état lu/supprimé, journal, idempotence) ---------------

    /// Requête POST authentifiée (même en-têtes que `authed_get`).
    fn authed_post(client: &reqwest::Client, url: &str, token: &str, body: &serde_json::Value) -> reqwest::RequestBuilder {
        client
            .post(url)
            .header("x-app-key", TEST_APPKEY_RAW)
            .header("x-app-name", TEST_APPKEY_NAME)
            .header("x-app-platform", TEST_APPKEY_PLATFORM)
            .header("x-app-version", "0.0.1")
            .header("authorization", format!("Bearer {token}"))
            .json(body)
    }

    /// Preuve n°1 (mission §6, point 1) : marquer `\Seen` via `/state/flags` sur une session,
    /// puis vérifier via un GET depuis une AUTRE connexion HTTP (un second `reqwest::Client`,
    /// pas de réutilisation de socket/état) que le flag est bien persisté CÔTÉ SERVEUR — pas
    /// seulement en mémoire de la session qui a émis la requête.
    #[tokio::test]
    async fn state_flags_read_persists_across_a_separate_connection() {
        let (state, pool) = test_state().await;
        let iam = diamy_mail_iam::DevIamClient::seeded();
        let principal = iam.resolve_principal("cedric@w3.tel").unwrap();
        let (device_id, _device_sec) = enroll_device_for_test(&pool, principal.id).await;
        let marker = format!("marqueur-{}", Uuid::now_v7());
        let message_id = store_test_message(
            &pool, &state.blob_store, principal.id, principal.address.domain_alabel(), device_id, &marker,
        )
        .await;

        let base_url = spawn_test_api(state).await;
        let token = fixture_token("valid_cedric");

        // Session 1 : marque \Seen.
        let client_a = test_https_client();
        let flags_url = format!("{base_url}/v1/mailbox/{}/state/flags", principal.id);
        let resp = authed_post(
            &client_a,
            &flags_url,
            &token,
            &serde_json::json!({ "message_id": message_id, "idempotency_key": Uuid::now_v7(), "read": true }),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(body["sequence"].as_i64().unwrap() > 0, "A04-EP-4 : la séquence assignée doit être renvoyée");

        // Session 2 : un `reqwest::Client` INDÉPENDANT (aucun état partagé avec client_a) relit
        // le catalogue — c'est la preuve que l'état vit en base, pas dans le processus HTTP émetteur.
        let client_b = test_https_client();
        let list_url = format!("{base_url}/v1/mailbox/{}/messages", principal.id);
        let messages: Vec<serde_json::Value> = authed_get(&client_b, &list_url, &token).send().await.unwrap().json().await.unwrap();
        let found = messages.iter().find(|m| m["message_id"] == message_id.to_string()).expect("message présent");
        assert_eq!(found["read"], true, "le flag \\Seen doit être visible depuis une AUTRE connexion (A04 §3)");
        assert_eq!(found["deleted"], false);
    }

    /// Preuve n°2 (mission §6, point 2) : rejouer la MÊME requête d'état avec la MÊME clé
    /// d'idempotence ne doit produire AUCUN effet dupliqué (A04-IDEM-1) — même si le corps
    /// rejoué prétend changer la valeur, le résultat retourné (et l'état réel) reste celui de
    /// la PREMIÈRE exécution.
    #[tokio::test]
    async fn state_flags_idempotency_key_replay_has_no_duplicate_effect() {
        let (state, pool) = test_state().await;
        let iam = diamy_mail_iam::DevIamClient::seeded();
        let principal = iam.resolve_principal("hugo@w3.tel").unwrap();
        let (device_id, _device_sec) = enroll_device_for_test(&pool, principal.id).await;
        let marker = format!("marqueur-{}", Uuid::now_v7());
        let message_id = store_test_message(
            &pool, &state.blob_store, principal.id, principal.address.domain_alabel(), device_id, &marker,
        )
        .await;

        let base_url = spawn_test_api(state).await;
        let token = fixture_token("valid_hugo");
        let client = test_https_client();
        let flags_url = format!("{base_url}/v1/mailbox/{}/state/flags", principal.id);
        let idempotency_key = Uuid::now_v7();

        // Premier appel : read=true.
        let first = authed_post(
            &client, &flags_url, &token,
            &serde_json::json!({ "message_id": message_id, "idempotency_key": idempotency_key, "read": true }),
        )
        .send().await.unwrap();
        assert_eq!(first.status(), 200);
        let first_body: serde_json::Value = first.json().await.unwrap();
        let first_seq = first_body["sequence"].as_i64().unwrap();

        // Rejeu : MÊME clé, corps prétendant AU CONTRAIRE remettre read=false — s'il était
        // ré-appliqué, le message redeviendrait non-lu.
        let replay = authed_post(
            &client, &flags_url, &token,
            &serde_json::json!({ "message_id": message_id, "idempotency_key": idempotency_key, "read": false }),
        )
        .send().await.unwrap();
        assert_eq!(replay.status(), 200);
        let replay_body: serde_json::Value = replay.json().await.unwrap();
        assert_eq!(
            replay_body["sequence"].as_i64().unwrap(), first_seq,
            "un rejeu sous la même clé DOIT renvoyer la séquence de la PREMIÈRE exécution, jamais en assigner une nouvelle"
        );

        // État réel : toujours read=true (le rejeu n'a RIEN changé), preuve par une nouvelle
        // lecture du catalogue.
        let list_url = format!("{base_url}/v1/mailbox/{}/messages", principal.id);
        let messages: Vec<serde_json::Value> = authed_get(&client, &list_url, &token).send().await.unwrap().json().await.unwrap();
        let found = messages.iter().find(|m| m["message_id"] == message_id.to_string()).expect("message présent");
        assert_eq!(found["read"], true, "le rejeu sous la même clé d'idempotence ne doit PAS avoir remis read à false (A04-IDEM-1)");
    }

    /// Preuve n°3 (mission §6, point 3) : marquer `\Deleted` puis `/state/delete` (mode hard)
    /// purge réellement le message — un nouveau GET (l'équivalent SELECT/STATUS du Bridge) ne
    /// le voit plus, et cet état est bien persisté en base (pas local à une session Bridge).
    #[tokio::test]
    async fn state_delete_hard_purges_and_removal_is_persisted() {
        // NB isolation de test (voir SIMPLIFICATIONS.md) : `aubin@w3.tel` est réservé comme
        // principal "jamais enrôlé" dans toute la suite (tests de hold-queue de `diamy-mxd`
        // s'appuient sur zéro appareil actif pour ce principal) — on utilise `cedric` ici.
        let (state, pool) = test_state().await;
        let iam = diamy_mail_iam::DevIamClient::seeded();
        let principal = iam.resolve_principal("cedric@w3.tel").unwrap();
        let (device_id, _device_sec) = enroll_device_for_test(&pool, principal.id).await;
        let marker = format!("marqueur-{}", Uuid::now_v7());
        let message_id = store_test_message(
            &pool, &state.blob_store, principal.id, principal.address.domain_alabel(), device_id, &marker,
        )
        .await;

        let base_url = spawn_test_api(state).await;
        let token = fixture_token("valid_cedric");
        let client = test_https_client();

        // \Deleted d'abord (réversible, A04-EP-4bis) — puis la purge terminale.
        let flags_url = format!("{base_url}/v1/mailbox/{}/state/flags", principal.id);
        authed_post(
            &client, &flags_url, &token,
            &serde_json::json!({ "message_id": message_id, "idempotency_key": Uuid::now_v7(), "deleted": true }),
        )
        .send().await.unwrap();

        let delete_url = format!("{base_url}/v1/mailbox/{}/state/delete", principal.id);
        let resp = authed_post(
            &client, &delete_url, &token,
            &serde_json::json!({ "message_id": message_id, "idempotency_key": Uuid::now_v7(), "mode": "hard" }),
        )
        .send().await.unwrap();
        assert_eq!(resp.status(), 200);

        // Nouveau GET (nouvelle requête HTTP, équivalent d'un nouveau SELECT/STATUS Bridge) :
        // le message ne doit plus apparaître — état persisté, pas un artefact de session.
        let list_url = format!("{base_url}/v1/mailbox/{}/messages", principal.id);
        let messages: Vec<serde_json::Value> = authed_get(&client, &list_url, &token).send().await.unwrap().json().await.unwrap();
        assert!(
            !messages.iter().any(|m| m["message_id"] == message_id.to_string()),
            "le message purgé ne doit plus apparaître dans le catalogue (A02-DEL-1)"
        );
    }

    /// Preuve n°4 (mission §6, point 4) : deux "appareils" (deux `device_id` enrôlés
    /// séparément) sur le MÊME `principal_id`, simulant deux connexions IMAP distinctes — l'un
    /// marque un message comme lu, l'autre, en re-listant, voit bien le changement. C'est la
    /// preuve d'une synchronisation RÉELLE (état serveur-autoritaire), pas d'un état local à
    /// un appareil.
    #[tokio::test]
    async fn two_devices_same_principal_see_each_others_state_changes() {
        let (state, pool) = test_state().await;
        let iam = diamy_mail_iam::DevIamClient::seeded();
        let principal = iam.resolve_principal("cedric@w3.tel").unwrap();
        // Deux appareils DISTINCTS enrôlés pour le MÊME principal (deux "connexions IMAP").
        let (device_a, _sec_a) = enroll_device_for_test(&pool, principal.id).await;
        let (device_b, _sec_b) = enroll_device_for_test(&pool, principal.id).await;
        assert_ne!(device_a, device_b);

        let marker = format!("marqueur-{}", Uuid::now_v7());
        // Livré à device_a (peu importe pour l'état lu/supprimé, qui est une métadonnée de
        // PRINCIPAL — A21 §2.2 — pas une métadonnée par appareil).
        let message_id = store_test_message(
            &pool, &state.blob_store, principal.id, principal.address.domain_alabel(), device_a, &marker,
        )
        .await;

        let base_url = spawn_test_api(state).await;
        let token = fixture_token("valid_cedric");

        // "Appareil A" marque le message comme lu.
        let client_device_a = test_https_client();
        let flags_url = format!("{base_url}/v1/mailbox/{}/state/flags", principal.id);
        let resp = authed_post(
            &client_device_a, &flags_url, &token,
            &serde_json::json!({ "message_id": message_id, "idempotency_key": Uuid::now_v7(), "read": true }),
        )
        .send().await.unwrap();
        assert_eq!(resp.status(), 200);

        // "Appareil B" (connexion HTTP totalement indépendante) re-sélectionne et doit voir le
        // changement — la synchronisation passe par le serveur, jamais par un canal local.
        let client_device_b = test_https_client();
        let list_url = format!("{base_url}/v1/mailbox/{}/messages", principal.id);
        let messages: Vec<serde_json::Value> =
            authed_get(&client_device_b, &list_url, &token).send().await.unwrap().json().await.unwrap();
        let found = messages.iter().find(|m| m["message_id"] == message_id.to_string()).expect("message présent");
        assert_eq!(
            found["read"], true,
            "l'appareil B doit voir l'état marqué par l'appareil A en re-sélectionnant (A04 §3, sync réelle)"
        );
    }

    /// `/state/delete` ne câble QUE le mode `"hard"` (A04 v1.4 changelog) : `"soft"` est
    /// rejeté explicitement (fail-closed, INV-16), jamais silencieusement mal exécuté.
    #[tokio::test]
    async fn state_delete_soft_mode_is_rejected_not_silently_mishandled() {
        let (state, pool) = test_state().await;
        let iam = diamy_mail_iam::DevIamClient::seeded();
        let principal = iam.resolve_principal("hugo@w3.tel").unwrap();
        let (device_id, _device_sec) = enroll_device_for_test(&pool, principal.id).await;
        let marker = format!("marqueur-{}", Uuid::now_v7());
        let message_id = store_test_message(
            &pool, &state.blob_store, principal.id, principal.address.domain_alabel(), device_id, &marker,
        )
        .await;

        let base_url = spawn_test_api(state).await;
        let token = fixture_token("valid_hugo");
        let client = test_https_client();
        let delete_url = format!("{base_url}/v1/mailbox/{}/state/delete", principal.id);
        let resp = authed_post(
            &client, &delete_url, &token,
            &serde_json::json!({ "message_id": message_id, "idempotency_key": Uuid::now_v7(), "mode": "soft" }),
        )
        .send().await.unwrap();
        assert_eq!(resp.status(), 400);
    }
}
