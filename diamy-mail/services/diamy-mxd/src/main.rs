//! `diamy-mxd` — passerelle entrante & chiffrement frontière (A01).
//!
//! Sert un VRAI serveur SMTP (un client mail réel peut s'y connecter et envoyer un
//! message) et rejoue le pipeline A01 sur ce qu'il reçoit : RECEIVE → RESOLVE (A24+A17)
//! → ENCRYPT → ENVELOPE → PERSIST (le même Postgres réel que `diamy-maild`) → DESTROY.
//!
//! Portée volontairement minimale (tranche verticale, guide §7) — voir `SIMPLIFICATIONS.md` :
//! pas d'AUTH SPF/DKIM/DMARC/ARC (A01 §5), pas d'antivirus/CDR (A01 §6), pas de file
//! d'attente de hold (A01 §7), pas d'annuaire de clés par appareil réel autre que `keydir`
//! déjà implémenté.
//!
//! Ce qui EST du vrai A01 : un vrai dialogue SMTP (EHLO/MAIL FROM/RCPT TO/DATA/QUIT),
//! **STARTTLS réel** (A01-SMTP-1, certificat auto-signé de dev — voir `SIMPLIFICATIONS.md`),
//! des tailles bornées (A01-STAB-1), l'isolation des échecs par destinataire (A01-PIPE-3),
//! le SMTP 250 envoyé seulement APRÈS que la persistance a committé (A01-PIPE-1), et la
//! destruction du clair reçu après usage (A01-DESTROY-1).

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

    loop {
        let (socket, peer) = listener.accept().await?;
        let pool = pool.clone();
        let blob_store = blob_store.clone();
        let iam = iam.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            tracing::info!(%peer, "connexion SMTP entrante");
            if let Err(e) =
                handle_connection(socket, &pool, &blob_store, &iam, &tls_acceptor, max_data_bytes).await
            {
                tracing::warn!(%peer, error = %e, "session SMTP interrompue");
            }
        });
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
) -> std::io::Result<()> {
    let mut reader = BufReader::new(socket);
    reader
        .get_mut()
        .write_all(b"220 mx.w3.tel Diamy Mail (maquette) ESMTP pret\r\n")
        .await?;

    match run_command_loop(&mut reader, pool, blob_store, iam, None, true, max_data_bytes).await? {
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
            run_command_loop(&mut tls_reader, pool, blob_store, iam, Some(tls_info), false, max_data_bytes)
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
                    reader
                        .get_mut()
                        .write_all(b"552 message trop volumineux\r\n")
                        .await?;
                    session.mail_from = None;
                    session.recipients.clear();
                }
                DataOutcome::Body(mut plaintext) => {
                    let sender = session
                        .mail_from
                        .clone()
                        .unwrap_or_else(|| "inconnu@invalide".to_string());
                    let outcome = deliver_to_recipients(
                        pool,
                        blob_store,
                        &sender,
                        &session.recipients,
                        &plaintext,
                        tls_info.as_ref(),
                    )
                    .await;
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
async fn deliver_to_recipients(
    pool: &storage::PgPool,
    blob_store: &BlobStore,
    sender_raw: &str,
    recipients: &[diamy_mail_iam::Principal],
    plaintext: &[u8],
    tls_info: Option<&TlsSessionInfo>,
) -> DeliveryOutcome {
    let sender_canonical = diamy_addr_canon(sender_raw, TenantAddressPolicy::default())
        .map(|c| c.as_str().to_string())
        .unwrap_or_else(|_| sender_raw.to_string());

    // A01-SMTP-1 : la posture TLS de CETTE session est enregistrée en métadonnées —
    // jamais de contenu, jamais de clé (INV-21), juste le fait et les paramètres TLS.
    let trust_metadata = Some(match tls_info {
        Some(info) => serde_json::json!({
            "tls_used": true,
            "tls_version": info.version,
            "tls_cipher": info.cipher,
        }),
        None => serde_json::json!({ "tls_used": false }),
    });

    let mut delivered = 0usize;
    let mut failed = 0usize;

    for recipient in recipients {
        // A17-DIR-2 : la frontière LIT l'annuaire — elle ne génère JAMAIS de clé
        // d'appareil elle-même (A17-KEY-2 : la clé de chiffrement mail est générée par
        // l'appareil, localement ; sa partie privée ne quitte jamais l'appareil).
        let devices = match storage::active_device_keys(pool, recipient.id).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(recipient_id = %recipient.id, error = %e, "échec lecture annuaire keydir");
                failed += 1;
                continue;
            }
        };
        if devices.is_empty() {
            // A17-DIR-5 : zéro appareil actif -> devrait passer par la file de hold
            // (A01-HOLD), NON implémentée dans cette maquette (voir SIMPLIFICATIONS.md).
            // On échoue proprement CE destinataire plutôt que de fabriquer une clé.
            tracing::warn!(
                recipient_id = %recipient.id,
                "aucun appareil actif dans keydir — hold queue non implémentée (A01-HOLD), \
                 enrôle un appareil de test avec `cargo run --example enroll_test_device`"
            );
            failed += 1;
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
            plaintext,
            &crypto::aad_for_blob(message_id, body_blob_id),
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(recipient_id = %recipient.id, error = %e, "échec du chiffrement frontière (step 7)");
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
                failed += 1;
                continue;
            }
        };
        drop(summary_key);

        // A17-P-3 : un tenant Diamy Mail EST un tenant IAM. Un `Uuid::now_v7()` frais à
        // chaque livraison rendrait ce champ non déterministe (deux messages au même
        // domaine, deux tenants différents) : dérivation UUIDv5 depuis le domaine,
        // même pattern que `DevIamClient::seeded()` pour `principal_id`. Reste un holder
        // INERTE tant qu'A11 (vrai mapping domaine→tenant) n'existe pas — voir
        // `SIMPLIFICATIONS.md`.
        let tenant_id = diamy_mail_iam::derive_dev_tenant_id(recipient.address.domain_alabel());

        let mut envelopes = Vec::with_capacity(devices.len());
        let mut envelope_error = false;
        for (device_id, mlkem_pub_bytes) in &devices {
            let device_pub = crypto::DeviceEncPublicKey(mlkem_pub_bytes.clone());
            match crypto::wrap_key_for_device(&message_key, &device_pub) {
                Ok(envelope) => envelopes.push((*device_id, envelope)),
                Err(e) => {
                    tracing::warn!(recipient_id = %recipient.id, %device_id, error = %e, "échec enveloppe");
                    envelope_error = true;
                }
            }
        }
        drop(message_key); // INV-1/3 : le clair de la clé de message ne survit pas au-delà de l'usage
        if envelopes.is_empty() {
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
                size_bytes: plaintext.len() as i64,
                envelopes: &envelope_refs,
                trust_metadata: trust_metadata.clone(),
            },
        )
        .await;

        match result {
            Ok(message_id) => {
                tracing::info!(recipient_id = %recipient.id, %message_id, devices = envelopes.len(), "message persisté (chiffré)");
                delivered += 1;
            }
            Err(e) => {
                tracing::warn!(recipient_id = %recipient.id, error = %e, "échec de persistance");
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
        tokio::spawn(async move {
            loop {
                let Ok((socket, _peer)) = listener.accept().await else {
                    break;
                };
                let pool = pool.clone();
                let blob_store = blob_store.clone();
                let iam = iam.clone();
                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(
                        socket,
                        &pool,
                        &blob_store,
                        &iam,
                        &tls_acceptor,
                        DEFAULT_MAX_DATA_BYTES,
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
            let Ok(key) = crypto::unwrap_key(&fetched.envelope, device_sec) else {
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

    /// A17-DIR-5 : un principal IAM valide MAIS sans appareil actif dans `keydir` fait
    /// échouer la livraison (tempfail), jamais de clé fabriquée à la place (voir la
    /// correction appliquée au chemin d'origine de ce bug, `SIMPLIFICATIONS.md`).
    #[tokio::test]
    async fn known_but_unenrolled_recipient_tempfails() {
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

        let addr = spawn_test_server(pool, blob_store).await;
        let mut client = SmtpTestClient::connect(addr).await;
        assert!(client.cmd("EHLO test-client").await.starts_with("250"));
        assert!(client
            .cmd("MAIL FROM:<expediteur.test@example.fr>")
            .await
            .starts_with("250"));
        assert!(client.cmd("RCPT TO:<aubin@w3.tel>").await.starts_with("250"));
        let resp = client.send_data("Subject: x\r\n\r\ncontenu").await;
        assert!(resp.starts_with("451"), "attendu 451 (tempfail), reçu : {resp}");
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
