//! `diamy-mxd` — passerelle entrante & chiffrement frontière (A01).
//!
//! Sert un VRAI serveur SMTP (un client mail réel peut s'y connecter et envoyer un
//! message) et rejoue le pipeline A01 sur ce qu'il reçoit : RECEIVE → **PARSE**
//! (MIME/RFC 5322, `diamy-mail-mime`, A01-PARSE) → RESOLVE (A24+A17) → ENCRYPT →
//! ENVELOPE → PERSIST (le même Postgres réel que `diamy-maild`) → DESTROY.
//!
//! Portée volontairement minimale (tranche verticale, guide §7) — voir `SIMPLIFICATIONS.md` :
//! pas d'AUTH SPF/DKIM/DMARC/ARC (A01 §5), pas d'antivirus/CDR (A01 §6), pas d'annuaire de
//! clés par appareil réel autre que `keydir` déjà implémenté. Le parsing MIME (step 2)
//! sélectionne UN corps textuel (texte brut authentique, sinon source HTML non convertie) ;
//! les pièces jointes sont détectées mais pas conservées séparément (A01-AV n'existe pas
//! encore — voir `diamy-mail-mime` et `SIMPLIFICATIONS.md`). La file de hold (A01-HOLD,
//! ferme A17-DIR-5) EST implémentée : `hold_recipient`/`hold_release_sweep_loop`.
//!
//! Ce qui EST du vrai A01 : un vrai dialogue SMTP (EHLO/MAIL FROM/RCPT TO/DATA/QUIT),
//! **STARTTLS réel** (A01-SMTP-1, certificat auto-signé de dev — voir `SIMPLIFICATIONS.md`),
//! des tailles bornées (A01-STAB-1), l'isolation des échecs par destinataire (A01-PIPE-3),
//! le SMTP 250 envoyé seulement APRÈS que la persistance a committé (A01-PIPE-1), et la
//! destruction du clair reçu après usage (A01-DESTROY-1).
#![forbid(unsafe_code)] // A18-CI-2 : aucun `unsafe` dans ce service (comme les 8 crates)

use diamy_addr::{diamy_addr_canon, TenantAddressPolicy};
use diamy_mail_crypto as crypto;
use diamy_mail_iam::{DevIamClient, IamClient};
use diamy_mail_storage::{self as storage, BlobStore, InboundMessage};
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;
use zeroize::Zeroize;

/// A01-STAB-1 : bornes de traitement — aucun message ne doit pouvoir épuiser la mémoire.
const MAX_LINE_LEN: usize = 8 * 1024;
/// Valeur par défaut ACTUELLE (10 Mo), overridable via `DIAMY_MXD_MAX_DATA_BYTES` (voir
/// `main()`). A02-QOS-2 recommande 50 Mo par défaut — **pas changé ici** : préparation de
/// l'option pour Cédric, en attente de confirmer si 10 Mo était un choix volontaire de
/// maquette avant d'activer une valeur différente. Voir `SIMPLIFICATIONS.md`.
const DEFAULT_MAX_DATA_BYTES: usize = 10 * 1024 * 1024;
const MAX_RECIPIENTS: usize = 50;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    diamy_obs::init_tracing();

    let env = std::env::var("DIAMY_ENV").unwrap_or_else(|_| "dev".to_string());
    // Fail-closed (A18-ZERO-4) : core dumps désactivés en prod AVANT tout traitement de
    // clair — le dev garde les core dumps.
    diamy_obs::disable_core_dumps_if_prod(&env)?;
    crypto::assert_backend_allowed_for_env(&env)?;

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://diamy:devonly_change_me@localhost:5433/diamymail".to_string()
    });
    let blob_dir =
        std::env::var("DIAMY_MAILD_BLOB_DIR").unwrap_or_else(|_| "./blob_store".to_string());
    let smtp_addr = std::env::var("DIAMY_MXD_SMTP_ADDR").unwrap_or_else(|_| "0.0.0.0:2525".to_string());
    // A01-HOLD-2 : secret-maître dont dérive `k_hold` par (tenant, principal) — un vrai
    // `diamy-secretd` (Level A pattern, A17-ENC-1) n'existe pas dans cette maquette ; ce
    // secret d'env joue le même rôle que `MAIL_JWT_TOKEN` dans `diamy-maild` (voir
    // SIMPLIFICATIONS.md). Protégé par le MÊME garde-fou fail-closed que `dev-crypto`
    // (`assert_backend_allowed_for_env` ci-dessus) : il n'y a pas de chemin de production
    // dans cette maquette où ce placeholder serait actif.
    let hold_seed = std::env::var("DIAMY_MXD_DEV_HOLD_SEED")
        .unwrap_or_else(|_| "devonly_change_me_hold_seed".to_string())
        .into_bytes();
    // Option B en préparation (A02-QOS-2) : configurable, mais valeur par défaut
    // INCHANGÉE (10 Mo) — voir la note sur `DEFAULT_MAX_DATA_BYTES`.
    let max_data_bytes: usize = std::env::var("DIAMY_MXD_MAX_DATA_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_DATA_BYTES);

    let pool = storage::connect(&database_url).await?;
    let blob_store = Arc::new(BlobStore::at(&blob_dir)?);
    let iam = Arc::new(DevIamClient::seeded());
    let tls_acceptor = build_dev_tls_acceptor("mx.w3.tel")?;
    let obs = Arc::new(diamy_obs::Obs::new("diamy-mxd"));

    let listener = TcpListener::bind(&smtp_addr).await?;
    tracing::info!(
        service = "diamy-mxd",
        backend = crypto::backend_name(),
        env = %env,
        addr = %smtp_addr,
        max_data_bytes,
        "démarré — SMTP réel (STARTTLS dev), persistance Postgres"
    );
    println!("== diamy-mxd : SMTP sur {smtp_addr} — STARTTLS dispo (essaie : swaks --to hugo@w3.tel --server 127.0.0.1:2525 -tls) ==");

    // A22 : observabilité dès le départ, même pipeline que `diamy-maild` (compteurs
    // d'événements + jauges, JAMAIS de contenu — INV-21, A18-LOG-1).
    let metrics_addr =
        std::env::var("DIAMY_MXD_METRICS_ADDR").unwrap_or_else(|_| "0.0.0.0:9102".to_string());
    let metrics_listener = TcpListener::bind(&metrics_addr).await?;
    tracing::info!(addr = %metrics_addr, "démarré — /metrics exposé");
    println!("== diamy-mxd : /metrics sur {metrics_addr} ==");
    {
        let obs = obs.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            loop {
                let Ok((mut sock, _peer)) = metrics_listener.accept().await else {
                    break;
                };
                let obs = obs.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await; // requête ignorée (endpoint unique)
                    obs.events.with_label_values(&["diamy-mxd", "metrics_scrape"]).inc();
                    let body = obs.render();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
    }

    // A01-HOLD-4 (release) : "upon publication of the recipient's first device bundle...
    // a release job MUST...". Rien dans cette maquette n'expose un vrai point d'entrée
    // serveur pour la publication d'un appareil (`enroll_test_device` écrit directement en
    // base, en simulant un CLIENT — jamais côté serveur, voir sa doc) : il n'y a donc pas
    // de signal synchrone à observer ici. Un balayage périodique reste dans la zone de
    // confiance frontière (contrairement à un déclenchement depuis le client, qui exigerait
    // que le client connaisse `hold_seed`, un secret serveur — violation de zone). Un vrai
    // système événementiel (webhook depuis le vrai endpoint d'enrôlement A17-DIR-3, absent
    // ici) remplacerait ce sondage — voir SIMPLIFICATIONS.md.
    tokio::spawn(hold_release_sweep_loop(
        pool.clone(),
        iam.clone(),
        hold_seed.clone(),
        obs.clone(),
    ));

    loop {
        let (socket, peer) = listener.accept().await?;
        let pool = pool.clone();
        let blob_store = blob_store.clone();
        let iam = iam.clone();
        let tls_acceptor = tls_acceptor.clone();
        let hold_seed = hold_seed.clone();
        let obs = obs.clone();
        tokio::spawn(async move {
            tracing::info!(%peer, "connexion SMTP entrante");
            if let Err(e) = handle_connection(
                socket,
                &pool,
                &blob_store,
                &iam,
                &tls_acceptor,
                max_data_bytes,
                &hold_seed,
                &obs,
            )
            .await
            {
                tracing::warn!(%peer, error = %e, "session SMTP interrompue");
            }
        });
    }
}

/// Intervalle du balayage de release (A01-HOLD-4). Valeur de maquette — un vrai système
/// serait événementiel (déclenché par la publication réelle d'un appareil), pas un sondage.
const HOLD_RELEASE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// A01-HOLD-3/4 : purge périodiquement les messages tenus expirés, puis tente de relâcher
/// tout principal ayant de la file en attente (`release_held_messages_for_principal` est
/// un no-op si le principal n'a toujours aucun appareil actif — sûr à ré-essayer à chaque
/// passage). Tourne indéfiniment en tâche de fond, jamais dans le chemin de la boucle SMTP.
async fn hold_release_sweep_loop(
    pool: storage::PgPool,
    iam: Arc<DevIamClient>,
    hold_seed: Vec<u8>,
    obs: Arc<diamy_obs::Obs>,
) {
    let mut ticker = tokio::time::interval(HOLD_RELEASE_SWEEP_INTERVAL);
    loop {
        ticker.tick().await;

        // A01 §11 / A22 : jauge de profondeur AVANT ce passage (pas un compteur — peut
        // monter ET descendre). Best-effort : une erreur de lecture ne doit pas arrêter le
        // balayage lui-même.
        if let Ok(depth) = storage::total_held_count(&pool).await {
            obs.gauges.with_label_values(&["diamy-mxd", "hold_queue_depth"]).set(depth);
        }

        match storage::purge_expired_holds(&pool).await {
            Ok(purged) if !purged.is_empty() => {
                // A01-HOLD-3 : un vrai DSN à l'expéditeur d'origine n'existe pas dans cette
                // maquette (aucun envoi sortant, voir SIMPLIFICATIONS.md) — la purge a bien
                // lieu (rien ne reste indéfiniment en base), seule la notification manque.
                obs.events
                    .with_label_values(&["diamy-mxd", "hold_expired_purged"])
                    .inc_by(purged.len() as u64);
                tracing::warn!(count = purged.len(), "messages tenus expirés purgés (DSN non envoyé, non implémenté)");
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "échec purge de la file de hold"),
        }

        let principal_ids = match storage::distinct_held_principal_ids(&pool).await {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!(error = %e, "échec lecture des principaux en attente");
                continue;
            }
        };
        for principal_id in principal_ids {
            // La release n'a plus besoin de résoudre l'adresse (design clé seule, A21 v1.5) :
            // le message est déjà catalogué avec son `sender_canonical`/destinataire réels.
            // On garde toutefois le filtre "principal connu de la doublure IAM" pour ne pas
            // tenter de relâcher un principal résiduel d'un autre test (défense en profondeur).
            if iam.find_by_id(principal_id).is_none() {
                continue;
            }
            match storage::release_held_messages_for_principal(&pool, &hold_seed, principal_id).await
            {
                Ok(0) => {} // toujours zéro appareil actif — normal, on réessaiera au prochain passage
                Ok(n) => {
                    obs.events.with_label_values(&["diamy-mxd", "hold_released"]).inc_by(n as u64);
                    tracing::info!(%principal_id, released = n, "messages relâchés depuis la file de hold");
                }
                Err(e) => tracing::warn!(%principal_id, error = %e, "échec release depuis la file de hold"),
            }
        }
    }
}

/// Génère un certificat auto-signé de dev pour `hostname` et construit l'accepteur TLS
/// (A01-SMTP-1). **Jamais une PKI réelle** — voir `SIMPLIFICATIONS.md` : c'est la force de
/// la crypto TLS qui est simplifiée (certificat non vérifiable par un vrai client externe),
/// pas la frontière (la session est réellement chiffrée de bout en bout une fois négociée).
fn build_dev_tls_acceptor(hostname: &str) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    // rustls 0.23 exige un fournisseur crypto explicite ; `install_default` est idempotent
    // (Err si déjà posé par un autre composant du même binaire — on l'ignore sciemment).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![hostname.to_string()])?;
    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    // Défauts rustls : TLS 1.2 accepté, 1.3 préféré — conforme à A01-SMTP-1 sans réglage
    // supplémentaire (minimum 1.2, 1.3 recommandé).
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], rustls::pki_types::PrivateKeyDer::Pkcs8(key_der))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Version et suite de chiffrement négociées — enregistrées en métadonnées de livraison
/// (A01-SMTP-1 : "the TLS version and cipher of each session MUST be recorded").
struct TlsSessionInfo {
    version: String,
    cipher: String,
}

fn extract_tls_info<IO>(tls_stream: &tokio_rustls::server::TlsStream<IO>) -> TlsSessionInfo {
    let (_, conn) = tls_stream.get_ref();
    TlsSessionInfo {
        version: conn
            .protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_else(|| "inconnue".to_string()),
        cipher: conn
            .negotiated_cipher_suite()
            .map(|c| format!("{:?}", c.suite()))
            .unwrap_or_else(|| "inconnue".to_string()),
    }
}

struct Session {
    mail_from: Option<String>,
    recipients: Vec<diamy_mail_iam::Principal>,
}

/// Accepte la connexion en clair, propose STARTTLS (A01-SMTP-1), puis — si le client
/// l'utilise — renégocie la session sur un canal chiffré et y poursuit le MÊME dialogue
/// (RFC 3207 : l'état de session précédent est abandonné, on repart d'une session propre).
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    socket: TcpStream,
    pool: &storage::PgPool,
    blob_store: &BlobStore,
    iam: &DevIamClient,
    tls_acceptor: &TlsAcceptor,
    max_data_bytes: usize,
    hold_seed: &[u8],
    obs: &diamy_obs::Obs,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(socket);
    reader
        .get_mut()
        .write_all(b"220 mx.w3.tel Diamy Mail (maquette) ESMTP pret\r\n")
        .await?;

    match run_command_loop(&mut reader, pool, blob_store, iam, None, true, max_data_bytes, hold_seed, obs).await? {
        LoopOutcome::Done => Ok(()),
        LoopOutcome::StartTls => {
            let socket = reader.into_inner(); // pas de saut de ligne en attente (RFC 3207)
            let tls_stream = tls_acceptor
                .accept(socket)
                .await
                .map_err(std::io::Error::other)?;
            let tls_info = extract_tls_info(&tls_stream);
            tracing::info!(
                tls_version = %tls_info.version,
                tls_cipher = %tls_info.cipher,
                "session STARTTLS établie"
            );
            let mut tls_reader = BufReader::new(tls_stream);
            run_command_loop(
                &mut tls_reader,
                pool,
                blob_store,
                iam,
                Some(tls_info),
                false,
                max_data_bytes,
                hold_seed,
                obs,
            )
            .await?;
            Ok(())
        }
    }
}

enum LoopOutcome {
    Done,
    StartTls,
}

/// Boucle de commandes SMTP, générique sur le flux sous-jacent (`TcpStream` en clair ou
/// `TlsStream<TcpStream>` après STARTTLS) — UNE seule implémentation du protocole, jamais
/// deux copies qui pourraient diverger.
#[allow(clippy::too_many_arguments)]
async fn run_command_loop<S>(
    reader: &mut BufReader<S>,
    pool: &storage::PgPool,
    blob_store: &BlobStore,
    iam: &DevIamClient,
    tls_info: Option<TlsSessionInfo>,
    allow_starttls: bool,
    max_data_bytes: usize,
    hold_seed: &[u8],
    obs: &diamy_obs::Obs,
) -> std::io::Result<LoopOutcome>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut session = Session {
        mail_from: None,
        recipients: Vec::new(),
    };

    loop {
        let line = match read_line_bounded(reader).await? {
            LineRead::Eof => return Ok(LoopOutcome::Done), // connexion fermée par le client
            LineRead::TooLong => {
                // A01-STAB-1 : une ligne anormalement longue est un rejet contrôlé,
                // jamais une allocation illimitée (le lecteur borné a déjà tout drainé).
                reader.get_mut().write_all(b"500 ligne trop longue\r\n").await?;
                continue;
            }
            LineRead::Line(l) => l,
        };
        let line = line.as_str();
        let upper = line.to_ascii_uppercase();

        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            if allow_starttls {
                reader
                    .get_mut()
                    .write_all(b"250-mx.w3.tel\r\n250 STARTTLS\r\n")
                    .await?;
            } else {
                reader.get_mut().write_all(b"250 mx.w3.tel\r\n").await?;
            }
        } else if upper.starts_with("STARTTLS") {
            if allow_starttls {
                reader
                    .get_mut()
                    .write_all(b"220 pret pour la negociation TLS\r\n")
                    .await?;
                return Ok(LoopOutcome::StartTls);
            } else {
                reader.get_mut().write_all(b"503 deja en TLS\r\n").await?;
            }
        } else if upper.starts_with("MAIL FROM:") {
            match extract_addr(line) {
                Some(addr) => {
                    session.mail_from = Some(addr);
                    session.recipients.clear();
                    reader.get_mut().write_all(b"250 OK\r\n").await?;
                }
                None => {
                    reader
                        .get_mut()
                        .write_all(b"501 syntaxe MAIL FROM invalide\r\n")
                        .await?
                }
            }
        } else if upper.starts_with("RCPT TO:") {
            if session.mail_from.is_none() {
                reader
                    .get_mut()
                    .write_all(b"503 MAIL FROM requis avant RCPT TO\r\n")
                    .await?;
                continue;
            }
            if session.recipients.len() >= MAX_RECIPIENTS {
                reader
                    .get_mut()
                    .write_all(b"452 trop de destinataires\r\n")
                    .await?;
                continue;
            }
            match extract_addr(line).and_then(|raw| {
                diamy_addr_canon(&raw, TenantAddressPolicy::default())
                    .ok()
                    .map(|c| c.as_str().to_string())
            }) {
                None => {
                    reader
                        .get_mut()
                        .write_all(b"501 adresse destinataire invalide\r\n")
                        .await?
                }
                Some(canonical) => match iam.resolve_principal(&canonical) {
                    Ok(principal) if principal.mail_enabled => {
                        session.recipients.push(principal);
                        reader.get_mut().write_all(b"250 OK\r\n").await?;
                    }
                    _ => {
                        // A17-ENT-1 : destinataire inconnu ou non entitled -> rejet, PAS de fail-open.
                        obs.events.with_label_values(&["diamy-mxd", "recipient_rejected"]).inc();
                        reader
                            .get_mut()
                            .write_all(b"550 destinataire inconnu ou non autorise\r\n")
                            .await?;
                    }
                },
            }
        } else if upper.starts_with("DATA") {
            if session.recipients.is_empty() {
                reader
                    .get_mut()
                    .write_all(b"554 aucun destinataire valide\r\n")
                    .await?;
                continue;
            }
            reader
                .get_mut()
                .write_all(b"354 Terminez par <CRLF>.<CRLF>\r\n")
                .await?;
            let read = read_data_bounded(reader, max_data_bytes).await?;
            match read {
                DataOutcome::TooLarge => {
                    obs.events.with_label_values(&["diamy-mxd", "message_rejected_oversized"]).inc();
                    reader
                        .get_mut()
                        .write_all(b"552 message trop volumineux\r\n")
                        .await?;
                    session.mail_from = None;
                    session.recipients.clear();
                }
                DataOutcome::Body(mut plaintext) => {
                    obs.events.with_label_values(&["diamy-mxd", "message_received"]).inc();
                    let sender = session
                        .mail_from
                        .clone()
                        .unwrap_or_else(|| "inconnu@invalide".to_string());
                    // PARSE (step 2, A01-PARSE) : le corps DATA brut (en-têtes compris)
                    // n'est plus traité comme un bloc opaque — on en extrait le corps
                    // textuel réel (`diamy-mail-mime`), qui devient LE clair scellé.
                    let mut parsed = diamy_mail_mime::parse_inbound_message(&plaintext);
                    let outcome = deliver_to_recipients(
                        pool,
                        blob_store,
                        &sender,
                        &session.recipients,
                        &parsed,
                        tls_info.as_ref(),
                        hold_seed,
                        obs,
                    )
                    .await;
                    parsed.body.zeroize(); // A01-DESTROY-1 : le clair parsé ne survit pas non plus
                    plaintext.zeroize(); // A01-DESTROY-1 : le clair reçu ne survit pas au-delà de l'usage

                    match outcome {
                        DeliveryOutcome::All(n) => {
                            tracing::info!(delivered = n, "message accepté et persisté");
                            reader.get_mut().write_all(b"250 message accepte\r\n").await?;
                        }
                        DeliveryOutcome::Partial(ok, failed) => {
                            // A01-PIPE-3 : un échec par destinataire ne doit pas invalider les autres.
                            tracing::warn!(delivered = ok, failed, "livraison partielle");
                            reader
                                .get_mut()
                                .write_all(b"250 message accepte (partiellement)\r\n")
                                .await?;
                        }
                        DeliveryOutcome::Failed => {
                            reader
                                .get_mut()
                                .write_all(b"451 echec temporaire de stockage, reessayez\r\n")
                                .await?;
                        }
                    }
                    session.mail_from = None;
                    session.recipients.clear();
                }
            }
        } else if upper.starts_with("RSET") {
            session.mail_from = None;
            session.recipients.clear();
            reader.get_mut().write_all(b"250 OK\r\n").await?;
        } else if upper.starts_with("NOOP") {
            reader.get_mut().write_all(b"250 OK\r\n").await?;
        } else if upper.starts_with("QUIT") {
            reader.get_mut().write_all(b"221 au revoir\r\n").await?;
            return Ok(LoopOutcome::Done);
        } else {
            reader.get_mut().write_all(b"500 commande non reconnue\r\n").await?;
        }
    }
}

enum DeliveryOutcome {
    All(usize),
    Partial(usize, usize),
    Failed,
}

/// ENCRYPT (une fois) → ENVELOPE + PERSIST (par destinataire, isolation A01-PIPE-3).
#[allow(clippy::too_many_arguments)]
async fn deliver_to_recipients(
    pool: &storage::PgPool,
    blob_store: &BlobStore,
    sender_raw: &str,
    recipients: &[diamy_mail_iam::Principal],
    parsed: &diamy_mail_mime::ParsedMessage,
    tls_info: Option<&TlsSessionInfo>,
    hold_seed: &[u8],
    obs: &diamy_obs::Obs,
) -> DeliveryOutcome {
    let sender_canonical = diamy_addr_canon(sender_raw, TenantAddressPolicy::default())
        .map(|c| c.as_str().to_string())
        .unwrap_or_else(|_| sender_raw.to_string());

    // A01-SMTP-1 : la posture TLS de CETTE session est enregistrée en métadonnées —
    // jamais de contenu, jamais de clé (INV-21), juste le fait et les paramètres TLS.
    let mut trust_metadata = match tls_info {
        Some(info) => serde_json::json!({
            "tls_used": true,
            "tls_version": info.version,
            "tls_cipher": info.cipher,
        }),
        None => serde_json::json!({ "tls_used": false }),
    };
    // A01-PARSE (step 2) : verdicts de parsing, jamais de contenu (INV-21) — d'où vient
    // le corps sélectionné, s'il a fallu se replier, s'il y avait un souci d'encodage,
    // combien de pièces jointes ont été vues (et donc PAS conservées, voir `diamy-mail-mime`).
    if let Some(obj) = trust_metadata.as_object_mut() {
        obj.insert("mime_body_source".to_string(), serde_json::json!(format!("{:?}", parsed.body_source)));
        obj.insert("mime_malformed".to_string(), serde_json::json!(parsed.malformed));
        obj.insert("mime_charset_recovered".to_string(), serde_json::json!(parsed.charset_recovered));
        obj.insert("mime_attachments_seen".to_string(), serde_json::json!(parsed.attachments_seen));
    }
    let trust_metadata = Some(trust_metadata);

    let mut delivered = 0usize;
    let mut failed = 0usize;

    for recipient in recipients {
        // A17-DIR-2 : la frontière LIT l'annuaire — elle ne génère JAMAIS de clé
        // d'appareil elle-même (A17-KEY-2 : la clé de chiffrement mail est générée par
        // l'appareil, localement ; sa partie privée ne quitte jamais l'appareil).
        let devices = match storage::active_device_keys(pool, recipient.id).await {
            Ok(d) => d,
            Err(e) => {
                // A01-FAIL-1 : "cannot check" (annuaire injoignable) DOIT tempfailer, PAS
                // passer par le hold — distinct de "zéro appareil, vérifié avec succès"
                // ci-dessous. Les conflater tiendrait du courrier qui devrait tempfailer,
                // ou tempfailerait du courrier qui devrait être tenu.
                tracing::warn!(recipient_id = %recipient.id, error = %e, "échec lecture annuaire keydir");
                obs.events.with_label_values(&["diamy-mxd", "tempfail_directory_error"]).inc();
                failed += 1;
                continue;
            }
        };

        // A17-P-3 : un tenant Diamy Mail EST un tenant IAM. Un `Uuid::now_v7()` frais à
        // chaque livraison rendrait ce champ non déterministe (deux messages au même
        // domaine, deux tenants différents) : dérivation UUIDv5 depuis le domaine, même
        // pattern que `DevIamClient::seeded()` pour `principal_id`. Reste un holder
        // INERTE tant qu'A11 (vrai mapping domaine→tenant) n'existe pas — voir
        // `SIMPLIFICATIONS.md`. Calculé ICI (avant la branche hold) : les deux chemins
        // (hold et livraison normale) en ont besoin.
        let tenant_id = diamy_mail_iam::derive_dev_tenant_id(recipient.address.domain_alabel());

        if devices.is_empty() {
            // A01-HOLD-1 : zéro appareil actif (vérifié avec succès, ce n'est PAS un échec
            // de lecture d'annuaire, cf. le `match` ci-dessus) -> accepter et tenir, jamais
            // bounce/tempfail (ferme A17-DIR-5).
            match hold_recipient(
                pool,
                blob_store,
                recipient,
                tenant_id,
                &sender_canonical,
                parsed,
                trust_metadata.clone(),
                hold_seed,
            )
            .await
            {
                HoldOutcome::Held => {
                    obs.events.with_label_values(&["diamy-mxd", "message_held"]).inc();
                    delivered += 1;
                }
                HoldOutcome::QueueFull => {
                    tracing::warn!(
                        recipient_id = %recipient.id,
                        "file de hold pleine pour ce principal (A01-HOLD-3) — tempfail"
                    );
                    obs.events.with_label_values(&["diamy-mxd", "tempfail_hold_full"]).inc();
                    failed += 1;
                }
                HoldOutcome::Failed => {
                    obs.events.with_label_values(&["diamy-mxd", "tempfail_hold_error"]).inc();
                    failed += 1;
                }
            }
            continue;
        }

        // A02-CRY-2/3 : `message_id`/`body_blob_id` DOIVENT exister AVANT le
        // chiffrement pour entrer dans l'AAD (`crypto::aad_for_blob`/`aad_for_summary`) —
        // donc ENCRYPT se fait ICI, PAR DESTINATAIRE, plus une seule fois pour tous au-
        // dessus de la boucle. Effet de bord bénéfique trouvé en implémentant ce
        // correctif (A02-CRY-6) : chaque destinataire d'un même envoi SMTP multi-RCPT
        // reçoit maintenant son propre `k_msg`/ciphertext indépendant (`seal_message`
        // tire une clé fraîche à chaque appel) — AVANT ce correctif, un envoi à N
        // destinataires leur faisait TOUS partager le même `k_msg`/ciphertext, ce qui
        // aurait permis à l'appareil compromis d'UN destinataire de déchiffrer la copie
        // d'un AUTRE si leur contenu coïncidait. Signalé et corrigé, voir
        // `SIMPLIFICATIONS.md`.
        let message_id = Uuid::now_v7();
        let body_blob_id = Uuid::now_v7();
        let (body_ct, message_key) = match crypto::seal_message(
            &parsed.body,
            &crypto::aad_for_blob(message_id, body_blob_id),
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(recipient_id = %recipient.id, error = %e, "échec du chiffrement frontière (step 7)");
                obs.events.with_label_values(&["diamy-mxd", "tempfail_crypto_error"]).inc();
                failed += 1;
                continue;
            }
        };
        let (summary_ct, summary_key) = match crypto::seal_message(
            b"[resume non implemente - A08]",
            &crypto::aad_for_summary(message_id),
        ) {
            Ok(v) => v,
            Err(_) => {
                obs.events.with_label_values(&["diamy-mxd", "tempfail_crypto_error"]).inc();
                failed += 1;
                continue;
            }
        };
        drop(summary_key);

        let mut envelopes = Vec::with_capacity(devices.len());
        let mut envelope_error = false;
        for (device_id, mlkem_pub_bytes) in &devices {
            let device_pub = crypto::DeviceEncPublicKey(mlkem_pub_bytes.clone());
            let envelope_aad = crypto::aad_for_envelope(message_id, *device_id);
            match crypto::wrap_key_for_device(&message_key, &device_pub, &envelope_aad) {
                Ok(envelope) => envelopes.push((*device_id, envelope)),
                Err(e) => {
                    tracing::warn!(recipient_id = %recipient.id, %device_id, error = %e, "échec enveloppe");
                    envelope_error = true;
                }
            }
        }
        drop(message_key); // INV-1/3 : le clair de la clé de message ne survit pas au-delà de l'usage
        if envelopes.is_empty() {
            obs.events.with_label_values(&["diamy-mxd", "tempfail_crypto_error"]).inc();
            failed += 1;
            let _ = envelope_error;
            continue;
        }

        // Nom de dossier "Inbox" : placeholder HORS MODÈLE A02 (la vraie clé de dossier
        // est côté client, A03-KEY-3) — aucun `message_id`/`blob_id` n'y correspond, donc
        // ni `aad_for_blob` ni `aad_for_summary` ne s'appliquent. AAD non-vide mais
        // distincte, sans prétendre à une conformité A02-CRY-2/3 qui ne s'applique pas ici.
        let (folder_name_ct, folder_key) =
            match crypto::seal_message(b"Inbox", b"mailfolder-placeholder:not-a02-modeled") {
                Ok(v) => v,
                Err(_) => {
                    obs.events.with_label_values(&["diamy-mxd", "tempfail_crypto_error"]).inc();
                    failed += 1;
                    continue;
                }
            };
        drop(folder_key);

        let folder_id =
            match storage::ensure_inbox_folder(pool, recipient.id, tenant_id, &folder_name_ct.bytes)
                .await
            {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!(recipient_id = %recipient.id, error = %e, "échec dossier inbox");
                    obs.events.with_label_values(&["diamy-mxd", "tempfail_storage_error"]).inc();
                    failed += 1;
                    continue;
                }
            };

        let envelope_refs: Vec<(Uuid, &crypto::Envelope)> =
            envelopes.iter().map(|(id, e)| (*id, e)).collect();
        let result = storage::store_inbound_message(
            pool,
            blob_store,
            &InboundMessage {
                message_id,
                body_blob_id,
                principal_id: recipient.id,
                tenant_id,
                folder_id,
                sender_canonical: &sender_canonical,
                recipient_canonical: recipient.address.as_str(),
                body_ct: &body_ct,
                summary_ct: &summary_ct,
                size_bytes: parsed.body.len() as i64,
                envelopes: &envelope_refs,
                trust_metadata: trust_metadata.clone(),
            },
        )
        .await;

        match result {
            Ok(message_id) => {
                tracing::info!(recipient_id = %recipient.id, %message_id, devices = envelopes.len(), "message persisté (chiffré)");
                obs.events.with_label_values(&["diamy-mxd", "message_delivered"]).inc();
                delivered += 1;
            }
            Err(e) => {
                tracing::warn!(recipient_id = %recipient.id, error = %e, "échec de persistance");
                obs.events.with_label_values(&["diamy-mxd", "tempfail_storage_error"]).inc();
                failed += 1;
            }
        }
    }

    if delivered > 0 && failed == 0 {
        DeliveryOutcome::All(delivered)
    } else if delivered > 0 {
        DeliveryOutcome::Partial(delivered, failed)
    } else {
        DeliveryOutcome::Failed
    }
}

enum HoldOutcome {
    /// Accepté et tenu (A01-HOLD-1) — compte comme livré du point de vue SMTP (250).
    Held,
    /// Borne de taille par principal dépassée (A01-HOLD-3) — tempfail CE destinataire.
    QueueFull,
    /// Échec de dérivation/chiffrement/persistance — tempfail CE destinataire.
    Failed,
}

/// A01-HOLD-1 (design **clé seule**, A21 §2.6 v1.5) : le message est catalogué EXACTEMENT
/// comme une livraison ordinaire — corps/summary scellés sous un `k_msg` frais, ligne
/// `mail.messages` (avec le VRAI `sender_canonical`) + blob de corps dans `mail.blobs` —
/// mais SANS enveloppe d'appareil (aucun appareil actif). Seul `k_msg` est ensuite emballé
/// sous `k_hold` et déposé en file (`store_held_message`, une seule transaction). Le corps
/// chiffré ne sera plus jamais re-manipulé : la release ne re-wrappe que `k_msg` (A01-HOLD-5).
#[allow(clippy::too_many_arguments)]
async fn hold_recipient(
    pool: &storage::PgPool,
    blob_store: &BlobStore,
    recipient: &diamy_mail_iam::Principal,
    tenant_id: Uuid,
    sender_canonical: &str,
    parsed: &diamy_mail_mime::ParsedMessage,
    trust_metadata: Option<serde_json::Value>,
    hold_seed: &[u8],
) -> HoldOutcome {
    let principal_id = recipient.id;
    match storage::count_held_for_principal(pool, principal_id).await {
        Ok(n) if n >= storage::MAX_HELD_PER_PRINCIPAL => return HoldOutcome::QueueFull,
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(%principal_id, error = %e, "échec lecture file de hold");
            return HoldOutcome::Failed;
        }
    }

    // Catalogage identique à la livraison normale (A01-HOLD-1 : "encrypt the
    // body/attachment/summary blobs under k_msg as normal"). `message_id`/`body_blob_id`
    // AVANT le chiffrement pour entrer dans l'AAD (A02-CRY-2/3).
    let message_id = Uuid::now_v7();
    let body_blob_id = Uuid::now_v7();
    let (body_ct, message_key) =
        match crypto::seal_message(&parsed.body, &crypto::aad_for_blob(message_id, body_blob_id)) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(%principal_id, error = %e, "échec chiffrement frontière (hold)");
                return HoldOutcome::Failed;
            }
        };
    let (summary_ct, summary_key) = match crypto::seal_message(
        b"[resume non implemente - A08]",
        &crypto::aad_for_summary(message_id),
    ) {
        Ok(v) => v,
        Err(_) => return HoldOutcome::Failed,
    };
    drop(summary_key);

    // Nom de dossier "Inbox" : placeholder HORS MODÈLE A02 (même traitement que la livraison
    // normale — la vraie clé de dossier est côté client, A03-KEY-3).
    let (folder_name_ct, folder_key) =
        match crypto::seal_message(b"Inbox", b"mailfolder-placeholder:not-a02-modeled") {
            Ok(v) => v,
            Err(_) => return HoldOutcome::Failed,
        };
    drop(folder_key);
    let folder_id = match storage::ensure_inbox_folder(pool, principal_id, tenant_id, &folder_name_ct.bytes).await {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(%principal_id, error = %e, "échec dossier inbox (hold)");
            return HoldOutcome::Failed;
        }
    };

    // A01-HOLD-1 : SEUL `k_msg` est emballé sous `k_hold` — jamais le corps.
    let hold_id = Uuid::now_v7();
    let k_hold = match crypto::derive_k_hold(hold_seed, tenant_id, principal_id) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(%principal_id, error = %e, "échec dérivation k_hold");
            return HoldOutcome::Failed;
        }
    };
    let wrapped_kmsg =
        match crypto::wrap_message_key_under_hold(&message_key, &k_hold, &crypto::aad_for_hold(hold_id)) {
            Ok(ct) => ct,
            Err(e) => {
                tracing::error!(%principal_id, error = %e, "échec emballage de k_msg sous k_hold");
                return HoldOutcome::Failed;
            }
        };
    drop(message_key); // INV-1/3 : k_msg ne survit pas au-delà de l'usage (le serveur ne le garde pas en clair)

    // Marqueur `held` en métadonnées (jamais de contenu, INV-21) — la release y ajoutera
    // `released_from_hold`.
    let mut trust_metadata = trust_metadata.unwrap_or_else(|| serde_json::json!({}));
    if let Some(obj) = trust_metadata.as_object_mut() {
        obj.insert("held".to_string(), serde_json::json!(true));
    }

    let result = storage::store_held_message(
        pool,
        blob_store,
        &InboundMessage {
            message_id,
            body_blob_id,
            principal_id,
            tenant_id,
            folder_id,
            sender_canonical, // A21 v1.5 : le VRAI expéditeur est catalogué et préservé (plus de placeholder)
            recipient_canonical: recipient.address.as_str(),
            body_ct: &body_ct,
            summary_ct: &summary_ct,
            size_bytes: parsed.body.len() as i64,
            envelopes: &[], // A01-HOLD-1 : zéro enveloppe tant qu'aucun appareil n'est actif
            trust_metadata: Some(trust_metadata),
        },
        hold_id,
        &wrapped_kmsg,
    )
    .await;

    match result {
        Ok(()) => {
            tracing::info!(%principal_id, %hold_id, %message_id, "message catalogué et tenu en attente (A01-HOLD-1, clé seule)");
            HoldOutcome::Held
        }
        Err(e) => {
            tracing::warn!(%principal_id, error = %e, "échec persistance de la file de hold");
            HoldOutcome::Failed
        }
    }
}

enum DataOutcome {
    Body(Vec<u8>),
    TooLarge,
}

/// Lit le corps DATA jusqu'à la ligne terminatrice `.` (dot-stuffing géré), borné en taille
/// (A01-STAB-1) : un message trop gros — y compris via une seule ligne géante sans saut de
/// ligne — est rejeté proprement, jamais une allocation illimitée.
async fn read_data_bounded<S>(reader: &mut BufReader<S>, max_data_bytes: usize) -> std::io::Result<DataOutcome>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut body = Vec::new();
    let mut too_large = false;
    loop {
        let (content, line_too_long) = match read_line_bounded(reader).await? {
            LineRead::Eof => break, // connexion fermée prématurément
            LineRead::TooLong => (String::new(), true),
            LineRead::Line(l) => (l, false),
        };
        if !line_too_long && content == "." {
            break;
        }
        too_large |= line_too_long;
        let unstuffed = content.strip_prefix('.').filter(|_| content.starts_with("..")).unwrap_or(&content);
        if !too_large {
            if body.len() + unstuffed.len() + 1 > max_data_bytes {
                too_large = true;
            } else {
                body.extend_from_slice(unstuffed.as_bytes());
                body.push(b'\n');
            }
        }
    }
    if too_large {
        body.zeroize();
        Ok(DataOutcome::TooLarge)
    } else {
        Ok(DataOutcome::Body(body))
    }
}

enum LineRead {
    /// Une ligne complète, sans le terminateur `\n`/`\r\n`.
    Line(String),
    /// Ligne dépassant `MAX_LINE_LEN` : déjà entièrement drainée jusqu'au `\n`, RIEN
    /// n'a été accumulé au-delà de la borne (A01-STAB-1 : pas d'allocation illimitée).
    TooLong,
    /// Connexion fermée par le client.
    Eof,
}

/// Lecture de ligne réellement bornée en mémoire (A01-STAB-1). Contrairement à
/// `AsyncBufReadExt::read_line`, qui accumule jusqu'au premier `\n` quelle que soit sa
/// distance, cette fonction lit octet par octet et arrête de stocker dès `MAX_LINE_LEN`
/// atteint — elle continue de DRAINER le flux jusqu'au `\n` (pour rester synchronisée
/// avec le protocole) mais sans plus jamais faire croître le buffer. Une ligne unique de
/// plusieurs Mo sans retour à la ligne (ex. un corps de message mal formé ou hostile) ne
/// peut donc jamais faire grossir la mémoire au-delà de `MAX_LINE_LEN`.
async fn read_line_bounded<S>(reader: &mut BufReader<S>) -> std::io::Result<LineRead>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut buf: Vec<u8> = Vec::new();
    let mut too_long = false;
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Ok(LineRead::Eof);
        }
        if byte[0] == b'\n' {
            break;
        }
        if buf.len() < MAX_LINE_LEN {
            buf.push(byte[0]);
        } else {
            too_long = true; // drainage sans croissance du buffer
        }
    }
    if too_long {
        Ok(LineRead::TooLong)
    } else {
        let s = String::from_utf8_lossy(&buf).trim_end_matches('\r').to_string();
        Ok(LineRead::Line(s))
    }
}

/// Extrait l'adresse entre `<` et `>` d'une commande `MAIL FROM:<...>` / `RCPT TO:<...>`.
fn extract_addr(line: &str) -> Option<String> {
    let start = line.find('<')?;
    let end = line[start..].find('>')? + start;
    let addr = line[start + 1..end].trim();
    if addr.is_empty() {
        None
    } else {
        Some(addr.to_string())
    }
}

/// Tests d'intégration du VRAI serveur SMTP (même `handle_connection` que `main()`),
/// contre un VRAI Postgres de dev (voir `docker compose up`). Remplacent la vérification
/// manuelle faite pendant le développement — désormais rejouable via `cargo test`.
///
/// Discipline d'isolation (base partagée, plusieurs binaires de test peuvent tourner en
/// parallèle avec `cargo test --workspace`) :
/// - **jamais de `TRUNCATE`** sur les tables partagées (`mail.*`) — un autre crate de test
///   (`diamy-maild`) peut écrire dedans en même temps ;
/// - chaque test génère son propre `device_id` frais et cherche SON message par un
///   marqueur unique dans le contenu déchiffré, jamais par "le plus récent" ni par un
///   comptage — robuste même si plusieurs tests/exemples ciblent le même principal ;
/// - `aubin@w3.tel` est réservé comme principal "JAMAIS enrôlé" dans toute la suite de
///   tests/exemples de ce projet ; le test qui en a besoin nettoie explicitement (et
///   seulement) ses propres lignes `keydir` par défense en profondeur.
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncBufReadExt, BufReader as TokioBufReader};

    /// Secret de test fixe (A01-HOLD-2) : le serveur de test ET `release_held_messages_for_principal`
    /// appelé directement par un test doivent dériver le MÊME k_hold pour s'accorder.
    const TEST_HOLD_SEED: &[u8] = b"test-hold-seed-not-real";

    fn test_database_url() -> String {
        std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://diamy:devonly_change_me@localhost:5433/diamymail".to_string()
        })
    }

    async fn test_pool_and_store() -> (storage::PgPool, Arc<BlobStore>) {
        let pool = storage::connect(&test_database_url())
            .await
            .expect("Postgres de dev doit tourner (`docker compose up`) pour ces tests");
        let blob_store = Arc::new(BlobStore::at("./blob_store").expect("object store local"));
        (pool, blob_store)
    }

    /// Démarre une instance du VRAI serveur (même `handle_connection` que `main()`) sur un
    /// port choisi par l'OS — isolé des autres tests et de toute instance déjà lancée.
    async fn spawn_test_server(pool: storage::PgPool, blob_store: Arc<BlobStore>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let iam = Arc::new(DevIamClient::seeded());
        let tls_acceptor = build_dev_tls_acceptor("mx.w3.tel").expect("cert de dev");
        let obs = Arc::new(diamy_obs::Obs::new("diamy-mxd-test"));
        tokio::spawn(async move {
            loop {
                let Ok((socket, _peer)) = listener.accept().await else {
                    break;
                };
                let pool = pool.clone();
                let blob_store = blob_store.clone();
                let iam = iam.clone();
                let tls_acceptor = tls_acceptor.clone();
                let obs = obs.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(
                        socket,
                        &pool,
                        &blob_store,
                        &iam,
                        &tls_acceptor,
                        DEFAULT_MAX_DATA_BYTES,
                        TEST_HOLD_SEED,
                        &obs,
                    )
                    .await;
                });
            }
        });
        addr
    }

    /// Simule l'enrôlement d'un appareil de test (comme `enroll_test_device`), en local
    /// au test : génère ses propres clés, publie SEULEMENT la clé publique dans `keydir`.
    async fn enroll_device_for_test(
        pool: &storage::PgPool,
        principal_id: Uuid,
    ) -> (Uuid, diamy_mail_crypto::DeviceEncSecretKey) {
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

    /// Cherche, parmi les messages du principal, celui qui déchiffre (avec NOTRE clé
    /// d'appareil) sur un contenu contenant `marker`. Ne suppose JAMAIS "le plus récent" :
    /// avec des principaux de test partagés entre plusieurs tests concurrents, d'autres
    /// messages peuvent exister pour le même principal au même moment.
    async fn find_own_message_by_marker(
        pool: &storage::PgPool,
        blob_store: &BlobStore,
        principal_id: Uuid,
        device_id: Uuid,
        device_sec: &diamy_mail_crypto::DeviceEncSecretKey,
        marker: &str,
    ) -> Option<serde_json::Value> {
        let Ok(messages) = storage::list_recent_messages(pool, principal_id, 50).await else {
            return None;
        };
        for m in &messages {
            let Ok(fetched) =
                storage::fetch_message_for_device(pool, blob_store, principal_id, m.message_id, device_id)
                    .await
            else {
                continue;
            };
            let envelope_aad = crypto::aad_for_envelope(m.message_id, device_id);
            let Ok(key) = crypto::unwrap_key(&fetched.envelope, device_sec, &envelope_aad) else {
                continue;
            };
            let aad = crypto::aad_for_blob(m.message_id, fetched.body_blob_id);
            let Ok(verified) = crypto::open_message(&fetched.body_ct, &key, &aad) else {
                continue;
            };
            if String::from_utf8_lossy(verified.as_bytes()).contains(marker) {
                let row: (Option<serde_json::Value>,) = sqlx::query_as(
                    "SELECT trust_metadata FROM mail.messages WHERE message_id = $1",
                )
                .bind(m.message_id)
                .fetch_one(pool)
                .await
                .unwrap();
                return row.0;
            }
        }
        None
    }

    /// Petit client SMTP de test : écrit une commande, lit UNE ligne de réponse.
    struct SmtpTestClient {
        writer: tokio::net::tcp::OwnedWriteHalf,
        reader: TokioBufReader<tokio::net::tcp::OwnedReadHalf>,
    }

    impl SmtpTestClient {
        async fn connect(addr: SocketAddr) -> Self {
            let stream = TcpStream::connect(addr).await.expect("connexion au serveur de test");
            let (r, w) = stream.into_split();
            let mut client = Self {
                writer: w,
                reader: TokioBufReader::new(r),
            };
            client.read_line().await; // bannière 220
            client
        }

        async fn read_line(&mut self) -> String {
            let mut line = String::new();
            self.reader.read_line(&mut line).await.expect("lecture réponse");
            line.trim_end().to_string()
        }

        /// Lit une réponse SMTP complète : les lignes de continuation ("250-...") sont
        /// consommées et ignorées, seule la ligne finale ("250 ...", espace) est retournée
        /// — sinon une réponse multi-ligne (EHLO + STARTTLS) désynchronise le client.
        async fn read_response(&mut self) -> String {
            loop {
                let line = self.read_line().await;
                if line.len() >= 4 && line.as_bytes()[3] == b'-' {
                    continue;
                }
                return line;
            }
        }

        async fn cmd(&mut self, line: &str) -> String {
            self.writer.write_all(line.as_bytes()).await.expect("écriture commande");
            self.writer.write_all(b"\r\n").await.expect("écriture CRLF");
            self.read_response().await
        }

        /// Envoie `DATA`, le corps, puis le terminateur `.` — renvoie la réponse finale.
        async fn send_data(&mut self, body: &str) -> String {
            let interm = self.cmd("DATA").await;
            assert!(interm.starts_with("354"), "attendu 354, reçu : {interm}");
            self.writer.write_all(body.as_bytes()).await.expect("écriture corps");
            self.writer.write_all(b"\r\n.\r\n").await.expect("écriture terminateur");
            self.read_response().await
        }
    }

    /// Vérificateur de certificat "accepte tout" — UNIQUEMENT pour les tests, où le client
    /// se connecte à son propre serveur éphémère avec un certificat auto-signé (aucune PKI
    /// réelle à vérifier). Jamais utilisé côté production (voir `SIMPLIFICATIONS.md`).
    #[derive(Debug)]
    struct AcceptAnyCert;

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    /// Chemin heureux (A01, test scenario #1 simplifié) : un destinataire enrôlé reçoit
    /// bien un message, persisté chiffré, déchiffrable avec SA clé d'appareil.
    #[tokio::test]
    async fn happy_path_delivers_to_enrolled_recipient() {
        let (pool, blob_store) = test_pool_and_store().await;
        let iam = DevIamClient::seeded();
        let recipient = iam.resolve_principal("hugo@w3.tel").unwrap();
        let (device_id, device_sec) = enroll_device_for_test(&pool, recipient.id).await;

        let addr = spawn_test_server(pool.clone(), blob_store.clone()).await;
        let mut client = SmtpTestClient::connect(addr).await;
        assert!(client.cmd("EHLO test-client").await.starts_with("250"));
        assert!(client
            .cmd("MAIL FROM:<expediteur.test@example.fr>")
            .await
            .starts_with("250"));
        assert!(client.cmd("RCPT TO:<hugo@w3.tel>").await.starts_with("250"));

        let marker = format!("marqueur-{}", Uuid::now_v7());
        let body = format!("Subject: test automatise\r\n\r\nContenu {marker}");
        let resp = client.send_data(&body).await;
        assert!(resp.starts_with("250"), "attendu 250, reçu : {resp}");

        let trust_metadata =
            find_own_message_by_marker(&pool, &blob_store, recipient.id, device_id, &device_sec, &marker)
                .await;
        let trust_metadata = trust_metadata.expect("le message envoyé par SMTP doit être retrouvé et déchiffrable");
        assert_eq!(trust_metadata["tls_used"], false, "session en clair, pas de STARTTLS ici");
    }

    /// A01-SMTP-1 : STARTTLS doit être proposé, fonctionner, et la session continuer sur
    /// le canal chiffré — avec la version/le chiffrement enregistrés en métadonnées.
    #[tokio::test]
    async fn starttls_session_delivers_and_records_tls_metadata() {
        let (pool, blob_store) = test_pool_and_store().await;
        let iam = DevIamClient::seeded();
        let recipient = iam.resolve_principal("hugo@w3.tel").unwrap();
        let (device_id, device_sec) = enroll_device_for_test(&pool, recipient.id).await;

        let addr = spawn_test_server(pool.clone(), blob_store.clone()).await;

        // --- Phase en clair : EHLO doit annoncer STARTTLS, puis on négocie ---
        let stream = TcpStream::connect(addr).await.unwrap();
        let (r, mut w) = stream.into_split();
        let mut reader = TokioBufReader::new(r);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap(); // bannière 220

        w.write_all(b"EHLO test-client\r\n").await.unwrap();
        let mut ehlo_resp = String::new();
        reader.read_line(&mut ehlo_resp).await.unwrap();
        let mut ehlo_last = String::new();
        reader.read_line(&mut ehlo_last).await.unwrap();
        assert!(ehlo_resp.contains("250-"), "EHLO doit être multi-ligne : {ehlo_resp}");
        assert!(ehlo_last.contains("STARTTLS"), "STARTTLS doit être annoncé : {ehlo_last}");

        w.write_all(b"STARTTLS\r\n").await.unwrap();
        let mut starttls_resp = String::new();
        reader.read_line(&mut starttls_resp).await.unwrap();
        assert!(starttls_resp.starts_with("220"), "attendu 220, reçu : {starttls_resp}");

        // --- Négociation TLS côté client (certificat auto-signé -> vérificateur permissif de test) ---
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let plain_stream = reader.into_inner().reunite(w).unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("mx.w3.tel").unwrap();
        let tls_stream = connector.connect(server_name, plain_stream).await.unwrap();

        // --- Session SMTP normale, mais chiffrée ---
        let mut tls_reader = TokioBufReader::new(tls_stream);
        tls_reader.get_mut().write_all(b"EHLO test-client\r\n").await.unwrap();
        let mut resp = String::new();
        tls_reader.read_line(&mut resp).await.unwrap();
        assert!(resp.starts_with("250"), "EHLO post-TLS : {resp}");

        tls_reader
            .get_mut()
            .write_all(b"MAIL FROM:<expediteur.test@example.fr>\r\n")
            .await
            .unwrap();
        resp.clear();
        tls_reader.read_line(&mut resp).await.unwrap();
        assert!(resp.starts_with("250"));

        tls_reader.get_mut().write_all(b"RCPT TO:<hugo@w3.tel>\r\n").await.unwrap();
        resp.clear();
        tls_reader.read_line(&mut resp).await.unwrap();
        assert!(resp.starts_with("250"));

        let marker = format!("marqueur-tls-{}", Uuid::now_v7());
        let body = format!("Subject: test tls\r\n\r\nContenu {marker}\r\n.\r\n");
        tls_reader.get_mut().write_all(b"DATA\r\n").await.unwrap();
        resp.clear();
        tls_reader.read_line(&mut resp).await.unwrap();
        assert!(resp.starts_with("354"));
        tls_reader.get_mut().write_all(body.as_bytes()).await.unwrap();
        resp.clear();
        tls_reader.read_line(&mut resp).await.unwrap();
        assert!(resp.starts_with("250"), "attendu 250 apres DATA en TLS, reçu : {resp}");

        let trust_metadata =
            find_own_message_by_marker(&pool, &blob_store, recipient.id, device_id, &device_sec, &marker)
                .await;
        let trust_metadata = trust_metadata.expect("le message envoyé via STARTTLS doit être retrouvé et déchiffrable");
        assert_eq!(trust_metadata["tls_used"], true);
        assert!(trust_metadata["tls_version"].is_string());
        assert!(trust_metadata["tls_cipher"].is_string());
    }

    /// A17-ENT-1 : un destinataire qui ne résout à AUCUN principal IAM est rejeté, jamais
    /// accepté "au cas où" (fail-closed, INV-16).
    #[tokio::test]
    async fn unknown_recipient_is_rejected() {
        let (pool, blob_store) = test_pool_and_store().await;
        let addr = spawn_test_server(pool, blob_store).await;
        let mut client = SmtpTestClient::connect(addr).await;
        assert!(client.cmd("EHLO test-client").await.starts_with("250"));
        assert!(client
            .cmd("MAIL FROM:<expediteur.test@example.fr>")
            .await
            .starts_with("250"));
        let resp = client.cmd("RCPT TO:<personne-de-connu@w3.tel>").await;
        assert!(resp.starts_with("550"), "attendu 550, reçu : {resp}");
    }

    /// A17-DIR-5 / A01-HOLD-1 : un principal IAM valide MAIS sans appareil actif dans
    /// `keydir` fait ACCEPTER le message (250) et le TENIR en file d'attente — jamais de
    /// bounce/tempfail, jamais de clé fabriquée à la place (A01-HOLD-1 ferme A17-DIR-5).
    /// Avant l'implémentation de la file de hold, ce test attendait un `451` : voir
    /// `SIMPLIFICATIONS.md` pour l'historique de ce changement de comportement.
    #[tokio::test]
    async fn known_but_unenrolled_recipient_is_held_not_tempfailed() {
        let (pool, blob_store) = test_pool_and_store().await;
        let iam = DevIamClient::seeded();
        // aubin@w3.tel : réservé "jamais enrôlé" dans toute la suite — nettoyage défensif
        // borné à CE SEUL principal (jamais un TRUNCATE global, voir doc du module).
        let aubin = iam.resolve_principal("aubin@w3.tel").unwrap();
        sqlx::query("DELETE FROM keydir.mail_device_keys WHERE principal_id = $1")
            .bind(aubin.id)
            .execute(&pool)
            .await
            .unwrap();
        let held_before: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM mail.hold_queue WHERE principal_id = $1")
                .bind(aubin.id)
                .fetch_one(&pool)
                .await
                .unwrap();

        let addr = spawn_test_server(pool.clone(), blob_store).await;
        let mut client = SmtpTestClient::connect(addr).await;
        assert!(client.cmd("EHLO test-client").await.starts_with("250"));
        assert!(client
            .cmd("MAIL FROM:<expediteur.test@example.fr>")
            .await
            .starts_with("250"));
        assert!(client.cmd("RCPT TO:<aubin@w3.tel>").await.starts_with("250"));
        let resp = client.send_data("Subject: x\r\n\r\ncontenu").await;
        assert!(resp.starts_with("250"), "attendu 250 (accepté, tenu), reçu : {resp}");

        let held_after: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM mail.hold_queue WHERE principal_id = $1")
                .bind(aubin.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(held_after.0, held_before.0 + 1, "le message doit atterrir dans la file de hold");
    }

    /// A01-HOLD-3/4/5 (test scenario #3 de l'annexe, simplifié) : un message tenu doit
    /// devenir lisible et déchiffrable une fois le PREMIER appareil du principal enrôlé,
    /// et la copie tenue doit disparaitre. Utilise `cedric@w3.tel` (jamais utilisé comme
    /// destinataire ailleurs dans CETTE suite, contrairement à `hugo`/`aubin` — voir la
    /// doc du module) ; nettoyage défensif borné à ce seul principal, jamais un TRUNCATE.
    #[tokio::test]
    async fn held_message_is_released_on_first_device_enrollment() {
        let (pool, blob_store) = test_pool_and_store().await;
        let iam = DevIamClient::seeded();
        let cedric = iam.resolve_principal("cedric@w3.tel").unwrap();
        sqlx::query("DELETE FROM keydir.mail_device_keys WHERE principal_id = $1")
            .bind(cedric.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM mail.hold_queue WHERE principal_id = $1")
            .bind(cedric.id)
            .execute(&pool)
            .await
            .unwrap();

        let addr = spawn_test_server(pool.clone(), blob_store.clone()).await;
        let mut client = SmtpTestClient::connect(addr).await;
        assert!(client.cmd("EHLO test-client").await.starts_with("250"));
        assert!(client
            .cmd("MAIL FROM:<expediteur.test@example.fr>")
            .await
            .starts_with("250"));
        assert!(client.cmd("RCPT TO:<cedric@w3.tel>").await.starts_with("250"));
        let marker = format!("hold-release-marqueur-{}", Uuid::now_v7());
        let resp = client
            .send_data(&format!("Subject: hold\r\n\r\nContenu {marker}"))
            .await;
        assert!(resp.starts_with("250"), "attendu 250, reçu : {resp}");

        // A01-HOLD-1 (design clé seule, A21 v1.5) : le message EST catalogué dès la
        // réception (ligne `mail.messages` + blob de corps), mais SANS enveloppe d'appareil.
        // La preuve "rien de lisible avant release" tient structurellement : sans enveloppe,
        // `fetch_message_for_device` renverrait `EnvelopeNotFound`. On capture ici le
        // `message_id` catalogué et le chiffré du corps AU REPOS, pour prouver plus bas que
        // la release NE LE TOUCHE PAS (A01-HOLD-5, A01 §13 err.#8).
        let held: (Uuid,) =
            sqlx::query_as("SELECT message_id FROM mail.hold_queue WHERE principal_id = $1")
                .bind(cedric.id)
                .fetch_one(&pool)
                .await
                .expect("le message tenu doit être catalogué dès la réception (A01-HOLD-1)");
        let held_message_id = held.0;
        // hold_queue ne porte PAS le corps : seulement k_msg emballé (colonne wrapped_kmsg).
        let no_body_row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mail.blobs WHERE message_id = $1 AND kind = 'body'",
        )
        .bind(held_message_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(no_body_row.0, 1, "le corps est un blob catalogué sous k_msg, pas dans hold_queue");
        let object_key: (String,) = sqlx::query_as(
            "SELECT object_key FROM mail.blobs WHERE message_id = $1 AND kind = 'body'",
        )
        .bind(held_message_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let blob_path = std::path::Path::new("./blob_store").join(&object_key.0);
        let body_ct_before =
            std::fs::read(&blob_path).expect("le blob de corps existe au repos dès la réception");

        // Enrôlement du PREMIER appareil (A01-HOLD-4 : "upon publication of the
        // recipient's first device bundle") -> déclenche la release.
        let (device_id, device_sec) = enroll_device_for_test(&pool, cedric.id).await;
        let released =
            storage::release_held_messages_for_principal(&pool, TEST_HOLD_SEED, cedric.id)
                .await
                .expect("la release ne doit pas échouer");
        assert_eq!(released, 1);

        let held_after: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM mail.hold_queue WHERE principal_id = $1")
                .bind(cedric.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(held_after.0, 0, "la copie tenue doit être détruite après release (A01-HOLD-4)");

        let trust_metadata =
            find_own_message_by_marker(&pool, &blob_store, cedric.id, device_id, &device_sec, &marker)
                .await;
        let trust_metadata =
            trust_metadata.expect("le message relâché doit être lisible et déchiffrable par l'appareil");
        assert_eq!(trust_metadata["released_from_hold"], true);

        // A01-HOLD-5 / A01 §13 err.#8 : le corps chiffré au repos est bit-à-bit IDENTIQUE
        // avant/après la release — preuve que la release ne l'a jamais lu, ré-scellé ni
        // reconstruit (seule la clé k_msg a transité, A02-RW-1).
        let body_ct_after = std::fs::read(&blob_path).expect("le blob de corps existe toujours après release");
        assert_eq!(
            body_ct_before, body_ct_after,
            "le corps chiffré NE doit PAS changer à la release (A01-HOLD-5, design clé seule)"
        );
        // Le message relâché est bien le MÊME message catalogué à la réception (pas un nouveau).
        assert!(
            find_own_message_by_marker(&pool, &blob_store, cedric.id, device_id, &device_sec, &marker)
                .await
                .is_some()
        );

        // A21 v1.5 : `sender_canonical` est PRÉSERVÉ de bout en bout (le vrai expéditeur,
        // jamais l'ancien placeholder "expediteur-perdu-lors-du-hold@invalide").
        let sender: (Option<String>,) =
            sqlx::query_as("SELECT sender_canonical FROM mail.messages WHERE message_id = $1")
                .bind(held_message_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            sender.0.as_deref(),
            Some("expediteur.test@example.fr"),
            "l'expéditeur d'origine doit être préservé à travers le hold (A21 v1.5)"
        );
        assert_ne!(sender.0.as_deref(), Some("expediteur-perdu-lors-du-hold@invalide"));

        // Idempotence (A01-HOLD-4) : un second appel ne doit rien re-relâcher (déjà vide).
        let released_again =
            storage::release_held_messages_for_principal(&pool, TEST_HOLD_SEED, cedric.id)
                .await
                .expect("un second appel sur une file vide ne doit pas échouer");
        assert_eq!(released_again, 0);
    }

    /// A01-STAB-1 (reproduit le bug trouvé/corrigé en session) : un corps DATA au-delà de
    /// la borne — même en une seule ligne géante sans retour à la ligne — est rejeté
    /// proprement (552), jamais accepté ni ne fait planter le serveur.
    #[tokio::test]
    async fn oversized_message_is_rejected() {
        let (pool, blob_store) = test_pool_and_store().await;
        let addr = spawn_test_server(pool, blob_store).await;
        let mut client = SmtpTestClient::connect(addr).await;
        assert!(client.cmd("EHLO test-client").await.starts_with("250"));
        assert!(client
            .cmd("MAIL FROM:<expediteur.test@example.fr>")
            .await
            .starts_with("250"));
        assert!(client.cmd("RCPT TO:<hugo@w3.tel>").await.starts_with("250"));

        let too_big = "A".repeat(DEFAULT_MAX_DATA_BYTES + 1024); // > 10 Mo, une seule ligne géante
        let resp = client.send_data(&too_big).await;
        assert!(resp.starts_with("552"), "attendu 552, reçu : {resp}");
    }

    /// A01-STAB-1 : une ligne SMTP (hors DATA) au-delà de `MAX_LINE_LEN` est drainée sans
    /// être stockée, rejetée proprement (500) — la connexion reste utilisable ensuite.
    #[tokio::test]
    async fn overlong_command_line_is_rejected_without_crashing() {
        let (pool, blob_store) = test_pool_and_store().await;
        let addr = spawn_test_server(pool, blob_store).await;
        let mut client = SmtpTestClient::connect(addr).await;

        let overlong = format!("MAIL FROM:<{}@example.fr>", "a".repeat(MAX_LINE_LEN + 100));
        let resp = client.cmd(&overlong).await;
        assert!(resp.starts_with("500"), "attendu 500, reçu : {resp}");

        // La connexion doit rester saine après le drainage (pas de désynchronisation).
        assert!(client.cmd("NOOP").await.starts_with("250"));
    }
}
