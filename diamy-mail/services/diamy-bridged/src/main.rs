//! `diamy-bridged` — Bridge IMAP local (A20), tranche **démo minimale**.
//!
//! Ce composant n'existait pas avant cette tranche. Il joue le rôle du "Bridge" décrit par
//! A20 : un processus qui tourne EN LOCAL, sur la machine de l'utilisateur (JAMAIS côté
//! serveur — ni dans `diamy-mxd`, ni `diamy-maild`, ni `diamy-submitd`), qui détient sa propre
//! clé privée d'appareil (A20-CRED-4b : appareil IAM séparé, enrôlé via
//! `cargo run --example enroll_bridge_device -p diamy-mail-storage`), parle le protocole natif
//! chiffré à `diamy-maild` (le MÊME chemin que `read_test_mail.rs` : catalogue, tirage du
//! chiffré + son enveloppe, déchiffrement LOCAL avec vérification du tag AVANT tout usage —
//! INV-8), et expose IMAP en clair standard à un client tiers (Thunderbird) UNIQUEMENT sur
//! `127.0.0.1` (A20-ARCH-2). C'est l'exception "Bridge local" listée dans INV-3 : le
//! déchiffrement ici n'est PAS une violation de zéro-accès, tant que ce code tourne sur la
//! machine du client, jamais côté serveur.
//!
//! Périmètre volontairement réduit pour cette démo (voir `SIMPLIFICATIONS.md`) : une seule
//! boîte INBOX, pas de flags/`\Seen`/multi-dossier, pas de STARTTLS, pas de SMTP/CalDAV, un
//! seul compte préconfiguré (pas de mot de passe Bridge révocable par client, A20-CRED-1) — ce
//! qui EST honoré en revanche : le Bridge est son PROPRE appareil enrôlé avec sa PROPRE AppKey
//! Tier 2 (A20-CRED-4b/5), et le déchiffrement passe par le même chemin vérifié qu'A02/INV-8.
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD, Engine};
use diamy_addr::{diamy_addr_canon, TenantAddressPolicy};
use diamy_mail_crypto as crypto;
use diamy_mail_iam::{DevIamClient, IamClient, Principal};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

/// A01-STAB-1 esprit (INV-15) : une ligne de commande IMAP anormalement longue est bornée,
/// jamais une allocation illimitée — même discipline que `diamy-mxd::read_line_bounded`.
const MAX_LINE_LEN: usize = 8 * 1024;
/// Borne défensive sur l'expansion d'un sequence-set/uid-set (INV-15 : tout scan est borné).
const MAX_SET_EXPANSION: usize = 10_000;
/// Borne défensive sur un littéral IMAP `{N}` (RFC 3501 §4.3) — jamais une allocation
/// proportionnelle à un N annoncé par le client sans contrôle (INV-15).
const MAX_LITERAL_LEN: usize = MAX_LINE_LEN;
/// Nombre max de littéraux enchaînés dans une seule commande — borne la PROFONDEUR de
/// continuation, pas seulement la taille (INV-15 : un client ne doit jamais pouvoir garder la
/// session en attente de littéral indéfiniment).
const MAX_LITERALS_PER_COMMAND: usize = 8;
/// UIDVALIDITY fixe (V1 démo, pas de stockage persistant d'UID côté Bridge) — voir
/// `SIMPLIFICATIONS.md` : un vrai Bridge devrait la garder stable entre sessions.
const UID_VALIDITY: u32 = 1;

struct BridgeConfig {
    imap_bind_addr: SocketAddr,
    imap_user: String,
    imap_password: String,
    sync_base: String,
    app_key: String,
}

impl BridgeConfig {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let raw_addr =
            std::env::var("DIAMY_BRIDGED_IMAP_ADDR").unwrap_or_else(|_| "127.0.0.1:1143".to_string());
        // A20-NET-1 (non négociable) : on ne retient QUE le PORT de la valeur fournie — l'IP
        // est TOUJOURS 127.0.0.1, câblée en dur ci-dessous. Aucune variable d'environnement,
        // aucun flag ne permet d'élargir l'écoute à une interface routable.
        let port: u16 = raw_addr
            .rsplit(':')
            .next()
            .ok_or("DIAMY_BRIDGED_IMAP_ADDR invalide")?
            .parse()?;
        Ok(Self {
            imap_bind_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            imap_user: std::env::var("DIAMY_BRIDGED_IMAP_USER")
                .unwrap_or_else(|_| "hugo@w3.tel".to_string()),
            imap_password: std::env::var("DIAMY_BRIDGED_IMAP_PASSWORD")
                .unwrap_or_else(|_| "devonly_change_me_bridge_password".to_string()),
            sync_base: std::env::var("DIAMY_MAILD_SYNC_URL")
                .unwrap_or_else(|_| "https://127.0.0.1:8443".to_string()),
            // A20-CRED-5 : AppKey Tier 2 PROPRE au Bridge, distincte de celle du client natif
            // de test — doit correspondre à `DIAMY_MAILD_DEV_BRIDGE_APPKEY` côté `diamy-maild`.
            app_key: std::env::var("DIAMY_MAILD_DEV_BRIDGE_APPKEY")
                .unwrap_or_else(|_| "devonly_change_me_appkey_bridge_dev_client".to_string()),
        })
    }
}

/// Chemin du coffre de dev de l'appareil BRIDGE — voir
/// `crates/diamy-mail-storage/examples/enroll_bridge_device.rs` (même format que
/// `enroll_test_device.rs` : 16 octets de `device_id` + clé secrète ML-KEM-768 brute), mais un
/// fichier DIFFÉRENT (`*.bridge.devicekey`) puisque le Bridge est son PROPRE appareil enrôlé
/// (A20-CRED-4b), pas celui du client de test natif.
fn bridge_dev_secret_path(canonical_address: &str) -> PathBuf {
    let safe_name = canonical_address.replace(['@', '.'], "_");
    PathBuf::from("./dev_secrets").join(format!("{safe_name}.bridge.devicekey"))
}

fn load_device_secret(
    path: &PathBuf,
) -> Result<(Uuid, crypto::DeviceEncSecretKey), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path).map_err(|e| {
        format!(
            "impossible de lire {} ({e}) — as-tu lancé \
             `cargo run --example enroll_bridge_device -p diamy-mail-storage -- <adresse>` d'abord ?",
            path.display()
        )
    })?;
    if bytes.len() < 16 {
        return Err("fichier de clé corrompu (trop court)".into());
    }
    let device_id = Uuid::from_slice(&bytes[..16])?;
    let secret = crypto::DeviceEncSecretKey::from_bytes(bytes[16..].to_vec());
    Ok((device_id, secret))
}

/// Jeton mail-plane pré-signé (INV-9/A17-P-1 : jamais fabriqué ici, seulement lu) — même
/// fixture et même discipline que `read_test_mail.rs`. Ne couvre que hugo/cedric/aubin@w3.tel.
fn load_fixture_mail_plane_token(principal_id: Uuid) -> Result<String, Box<dyn std::error::Error>> {
    const FIXTURES: &str = include_str!("../../../tests/fixtures/dev_mail_plane_tokens.json");
    let v: serde_json::Value = serde_json::from_str(FIXTURES)?;
    let tokens = v["tokens"].as_object().ok_or("fixture invalide : champ `tokens` absent")?;
    let wanted = principal_id.to_string();
    for entry in tokens.values() {
        let same_principal = entry["principal_id"].as_str() == Some(wanted.as_str());
        let is_valid = entry["expired"].as_bool() != Some(true);
        if same_principal && is_valid {
            if let Some(tok) = entry["token"].as_str() {
                return Ok(tok.to_string());
            }
        }
    }
    Err(format!(
        "aucun jeton de test pré-signé (valide) pour le principal {principal_id} dans la \
         fixture — elle ne couvre que hugo/cedric/aubin@w3.tel."
    )
    .into())
}

#[derive(Deserialize, Debug, Clone)]
struct MessageSummaryDto {
    message_id: Uuid,
    sender_canonical: Option<String>,
    #[allow(dead_code)]
    size_bytes: i64,
    received_at: Option<String>,
}

#[derive(Deserialize)]
struct FetchedDto {
    body_blob_id: Uuid,
    body_alg_version: i32,
    body_nonce_b64: String,
    body_ciphertext_b64: String,
    summary_alg_version: i32,
    summary_nonce_b64: String,
    summary_ciphertext_b64: String,
    envelope_alg_version: i32,
    envelope_kem_ct_b64: String,
    envelope_wrap_nonce_b64: String,
    envelope_wrapped_key_b64: String,
}

fn nonce_from_b64(s: &str) -> Result<[u8; 12], Box<dyn std::error::Error>> {
    let bytes = STANDARD.decode(s)?;
    Ok(bytes.as_slice().try_into()?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    diamy_obs::init_tracing();
    let config = Arc::new(BridgeConfig::from_env()?);
    let obs = Arc::new(diamy_obs::Obs::new("diamy-bridged"));

    let listener = TcpListener::bind(config.imap_bind_addr).await?;

    // A20-NET-2 (fail-closed, normatif) : revérifie APRÈS bind que l'adresse effective est
    // bien loopback. Une mauvaise config réseau (conteneur, port-forwarding shim...) ne doit
    // JAMAIS faire tourner le Bridge sur une interface routable — refuse de démarrer sinon.
    let local_addr = listener.local_addr()?;
    if !local_addr.ip().is_loopback() {
        obs.events.with_label_values(&["diamy-bridged", "startup_refusal_nonloopback"]).inc();
        return Err(format!(
            "refus de démarrer (A20-NET-2) : {local_addr} n'est PAS une adresse loopback"
        )
        .into());
    }

    println!("== diamy-bridged : IMAP sur {local_addr} (loopback uniquement, A20-ARCH-2) ==");
    println!(
        "   Compte de démo : utilisateur=\"{}\" — voir DIAMY_BRIDGED_IMAP_USER/DIAMY_BRIDGED_IMAP_PASSWORD",
        config.imap_user
    );
    tracing::info!(addr = %local_addr, "diamy-bridged démarré (loopback uniquement)");

    let http = reqwest::Client::builder()
        // Certificat auto-signé de dev (A04-TR-1) : accepté explicitement ici UNIQUEMENT
        // parce que c'est un outil de démo local — un vrai Bridge ne ferait jamais ça (même
        // discipline que `read_test_mail.rs`, voir SIMPLIFICATIONS.md).
        .danger_accept_invalid_certs(true)
        .build()?;

    loop {
        let (socket, peer) = listener.accept().await?;

        // A20-NET-3 (défense en profondeur) : rejette toute connexion dont le PAIR n'est pas
        // loopback, même si le bind lui-même l'était (belt-and-braces avec la restriction de
        // bind ci-dessus).
        if !peer.ip().is_loopback() {
            tracing::warn!(%peer, "connexion refusée : pair non-loopback (A20-NET-3)");
            obs.events.with_label_values(&["diamy-bridged", "nonloopback_peer_refusal"]).inc();
            drop(socket);
            continue;
        }

        obs.events.with_label_values(&["diamy-bridged", "session_started"]).inc();
        let config = config.clone();
        let http = http.clone();
        let obs = obs.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, config, http, obs).await {
                tracing::warn!(%peer, error = %e, "session IMAP interrompue");
            }
        });
    }
}

/// Session authentifiée : tout ce qu'il faut pour parler à `diamy-maild` comme le ferait un
/// vrai appareil (A20-ARCH-1 : le Bridge est un consommateur du SDK client, pas une nouvelle
/// implémentation de protocole — ici, en miroir direct de `read_test_mail.rs`).
struct AuthedSession {
    principal: Principal,
    device_id: Uuid,
    device_sec: crypto::DeviceEncSecretKey,
    mail_plane_token: String,
}

/// Boîte "INBOX" sélectionnée : instantané du catalogue au moment du SELECT, avec des UID de
/// SESSION (1..N, ordre chronologique croissant) — pas de persistance entre sessions (V1
/// démo, lecture seule, voir `SIMPLIFICATIONS.md`).
struct SelectedMailbox {
    messages: Vec<(u32, MessageSummaryDto)>, // (uid, résumé)
}

struct Session {
    authed: Option<AuthedSession>,
    mailbox: Option<SelectedMailbox>,
}

async fn handle_connection(
    socket: TcpStream,
    config: Arc<BridgeConfig>,
    http: reqwest::Client,
    obs: Arc<diamy_obs::Obs>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(socket);
    reader.get_mut().write_all(b"* OK diamy-bridged ready (A20, demo)\r\n").await?;

    let mut session = Session { authed: None, mailbox: None };

    loop {
        let line = match read_command(&mut reader).await? {
            LineRead::Eof => return Ok(()),
            LineRead::TooLong => {
                reader
                    .get_mut()
                    .write_all(b"* BAD ligne trop longue ou litteral trop grand\r\n")
                    .await?;
                continue;
            }
            LineRead::Line(l) => l,
        };
        if line.trim().is_empty() {
            continue;
        }

        let mut parts = line.trim_end().splitn(2, char::is_whitespace);
        let tag = parts.next().unwrap_or("*").to_string();
        let rest = parts.next().unwrap_or("").trim_start();
        let mut cmd_parts = rest.splitn(2, char::is_whitespace);
        let command = cmd_parts.next().unwrap_or("").to_ascii_uppercase();
        let args = cmd_parts.next().unwrap_or("").trim();

        // Visible avec RUST_LOG=diamy_bridged=debug : la commande telle qu'interprétée juste
        // avant le dispatch (littéraux déjà résolus par `read_command`, donc `args` reflète ce
        // qui sera réellement traité — utile pour comparer avec la ligne brute logguée plus
        // bas dans `read_command`, ligne par ligne, AVANT tout parsing).
        tracing::debug!(%tag, %command, %args, "commande IMAP interpretee");
        obs.events.with_label_values(&["diamy-bridged", "imap_op"]).inc();

        let outcome = match command.as_str() {
            "CAPABILITY" => {
                reader.get_mut().write_all(b"* CAPABILITY IMAP4rev1\r\n").await?;
                format!("{tag} OK CAPABILITY completed\r\n")
            }
            "LOGIN" => cmd_login(&mut reader, &config, &mut session, &tag, args).await?,
            "LIST" => {
                reader
                    .get_mut()
                    .write_all(b"* LIST (\\HasNoChildren) \"/\" INBOX\r\n")
                    .await?;
                format!("{tag} OK LIST completed\r\n")
            }
            "SELECT" => {
                // Le nom de boîte peut arriver quoté (`SELECT "INBOX"`, ce qu'envoie
                // Thunderbird) ou en atome nu (`SELECT INBOX`) — comparer `args` tel quel
                // (comme avant) ne matchait QUE la forme nue : toute variante quotée tombait
                // dans le NO ci-dessous SANS jamais appeler `cmd_select`, donc sans JAMAIS
                // interroger diamy-maild. C'est la cause du "0 EXISTS" observé avec
                // Thunderbird. `tokenize_args` (déjà utilisé par LOGIN) gère les deux formes.
                let mailbox = tokenize_args(args).into_iter().next().unwrap_or_default();
                if mailbox.eq_ignore_ascii_case("INBOX") {
                    cmd_select(&mut reader, &config, &http, &mut session, &tag).await?
                } else {
                    format!("{tag} NO seule INBOX existe (V1 démo)\r\n")
                }
            }
            "FETCH" => cmd_fetch(&mut reader, &config, &http, &session, &tag, args, false).await?,
            "UID" => {
                let mut uid_parts = args.splitn(2, char::is_whitespace);
                let sub = uid_parts.next().unwrap_or("").to_ascii_uppercase();
                let sub_args = uid_parts.next().unwrap_or("").trim();
                if sub == "FETCH" {
                    cmd_fetch(&mut reader, &config, &http, &session, &tag, sub_args, true).await?
                } else {
                    format!("{tag} BAD sous-commande UID non supportée\r\n")
                }
            }
            "NOOP" => {
                cmd_noop(&mut reader, &config, &http, &mut session).await?;
                String::new()
            }
            "STATUS" => cmd_status(&mut reader, &config, &http, &session, &tag, args).await?,
            "CLOSE" => String::new(),
            "LOGOUT" => {
                reader.get_mut().write_all(b"* BYE diamy-bridged fermeture\r\n").await?;
                reader.get_mut().write_all(format!("{tag} OK LOGOUT completed\r\n").as_bytes()).await?;
                return Ok(());
            }
            // Réponses explicites (jamais un panic ni une fermeture brutale) pour deux commandes
            // que Thunderbird peut envoyer même en configuration "Aucune sécurité"/"LOGIN" : ni
            // STARTTLS ni SASL ne sont supportés en V1 (voir SIMPLIFICATIONS.md), mais le client
            // DOIT recevoir une réponse IMAP standard taguée pour ne pas rester bloqué en attente.
            "STARTTLS" => format!("{tag} BAD STARTTLS non supporté (IMAP en clair uniquement, V1 démo)\r\n"),
            "AUTHENTICATE" => format!("{tag} NO AUTHENTICATE non supporté, utiliser LOGIN (V1 démo)\r\n"),
            "" => format!("{tag} BAD commande vide\r\n"),
            other => {
                let _ = other;
                format!("{tag} BAD commande non reconnue\r\n")
            }
        };

        if !outcome.is_empty() {
            write_logged(&mut reader, &outcome).await?;
        } else {
            write_logged(&mut reader, &format!("{tag} OK {command} completed\r\n")).await?;
        }
    }
}

/// Tokenise les arguments IMAP en respectant les chaînes entre guillemets (ex. `LOGIN "a b" c`).
fn tokenize_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '"' {
            chars.next();
            let mut tok = String::new();
            for c2 in chars.by_ref() {
                if c2 == '"' {
                    break;
                }
                tok.push(c2);
            }
            out.push(tok);
        } else {
            let mut tok = String::new();
            while let Some(&c2) = chars.peek() {
                if c2.is_whitespace() {
                    break;
                }
                tok.push(c2);
                chars.next();
            }
            out.push(tok);
        }
    }
    out
}

async fn cmd_login<S>(
    reader: &mut BufReader<S>,
    config: &BridgeConfig,
    session: &mut Session,
    tag: &str,
    args: &str,
) -> std::io::Result<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Les littéraux `{N}`/`{N+}` (ex. Thunderbird envoie systématiquement LOGIN sous cette
    // forme) sont déjà résolus en amont par `read_command`, qui les réinjecte ici sous forme de
    // chaînes entre guillemets — `args` est donc toujours une ligne "à plat" classique.
    let _ = reader;
    let tokens = tokenize_args(args);
    let (Some(user), Some(pass)) = (tokens.first(), tokens.get(1)) else {
        return Ok(format!("{tag} BAD LOGIN requiert utilisateur et mot de passe\r\n"));
    };

    // A20-CRED-1 (simplifié, documenté) : un seul compte préconfiguré, PAS un mot de passe
    // Bridge révocable par client — voir SIMPLIFICATIONS.md.
    if user != &config.imap_user || pass != &config.imap_password {
        return Ok(format!("{tag} NO identifiants invalides\r\n"));
    }

    let iam = DevIamClient::seeded();
    let canonical = match diamy_addr_canon(user, TenantAddressPolicy::default()) {
        Ok(c) => c,
        Err(e) => return Ok(format!("{tag} NO adresse invalide : {e}\r\n")),
    };
    let principal = match iam.resolve_principal(canonical.as_str()) {
        Ok(p) => p,
        Err(_) => return Ok(format!("{tag} NO principal introuvable\r\n")),
    };

    let secret_path = bridge_dev_secret_path(canonical.as_str());
    let (device_id, device_sec) = match load_device_secret(&secret_path) {
        Ok(v) => v,
        Err(e) => return Ok(format!("{tag} NO clé de l'appareil Bridge introuvable : {e}\r\n")),
    };

    let mail_plane_token = match load_fixture_mail_plane_token(principal.id) {
        Ok(t) => t,
        Err(e) => return Ok(format!("{tag} NO jeton mail-plane indisponible : {e}\r\n")),
    };

    session.authed = Some(AuthedSession { principal, device_id, device_sec, mail_plane_token });
    Ok(format!("{tag} OK LOGIN completed\r\n"))
}

fn auth_headers(builder: reqwest::RequestBuilder, config: &BridgeConfig, token: &str) -> reqwest::RequestBuilder {
    // A20-CRED-5 : `x-app-name` distinct du client natif de test — c'est CETTE distinction,
    // combinée à l'AppKey propre du Bridge, qui matérialise l'indépendance de révocation
    // (A20-CRED-4b/5) côté `diamy-maild` (voir `auth.rs::AppKeyStore::seeded_from_env`).
    builder
        .header("x-app-key", &config.app_key)
        .header("x-app-name", "diamy-mail-bridge")
        .header("x-app-platform", "dev")
        .header("x-app-version", "0.0.1")
        .header("authorization", format!("Bearer {token}"))
}

/// Interroge FRAÎCHEMENT diamy-maild et reconstruit la liste NUMÉROTÉE (ordre chronologique
/// ascendant, UID = position 1..N) — appelée à CHAQUE SELECT/STATUS/NOOP, JAMAIS mise en cache
/// d'une commande à l'autre. C'est cette re-interrogation systématique qui garantit qu'un mail
/// arrivé pendant que la connexion IMAP reste ouverte est vu à la prochaine commande, sans
/// avoir à fermer/rouvrir la session. `context` identifie l'appelant dans les logs debug
/// (visible avec RUST_LOG=diamy_bridged=debug) pour voir, commande par commande, si le compte
/// reste bloqué ou progresse bien.
async fn fetch_mailbox_catalog(
    config: &BridgeConfig,
    http: &reqwest::Client,
    authed: &AuthedSession,
    context: &str,
) -> Result<Vec<(u32, MessageSummaryDto)>, String> {
    let list_url = format!("{}/v1/mailbox/{}/messages", config.sync_base, authed.principal.id);
    tracing::debug!(
        %context,
        principal_id = %authed.principal.id,
        device_id = %authed.device_id,
        url = %list_url,
        "interrogation du catalogue diamy-maild"
    );
    let resp = auth_headers(http.get(&list_url), config, &authed.mail_plane_token)
        .send()
        .await
        .map_err(|e| format!("échec de la synchronisation : {e}"))?;
    let status = resp.status();
    let body_text = resp.text().await.map_err(|e| format!("échec de lecture de la réponse : {e}"))?;
    tracing::debug!(%context, %status, body = %body_text, "réponse brute du catalogue diamy-maild");
    let messages: Vec<MessageSummaryDto> = serde_json::from_str(&body_text)
        .map_err(|e| format!("réponse de synchronisation invalide ({status}) : {e}"))?;
    // Exigence de debug : le nombre de messages vu par CETTE commande précisément (SELECT,
    // STATUS, ou NOOP) — pour vérifier qu'il progresse d'une tentative à l'autre plutôt que de
    // rester figé sur une valeur mise en cache.
    tracing::debug!(
        %context,
        principal_id = %authed.principal.id,
        messages_count = messages.len(),
        "nombre de messages reçus du catalogue (avant EXISTS/STATUS)"
    );

    // Le catalogue serveur est trié DESC par `received_at` (`list_recent_messages`) — IMAP
    // veut l'UID croissant en ordre chronologique (le plus ancien = UID 1) : on inverse. Les
    // messages déjà vus gardent le même UID d'une commande à l'autre (les nouveaux arrivent
    // forcément plus tard chronologiquement, donc s'ajoutent à la fin avec un UID plus grand).
    let mut ascending = messages;
    ascending.reverse();
    Ok(ascending.into_iter().enumerate().map(|(i, m)| ((i as u32) + 1, m)).collect())
}

async fn cmd_select<S>(
    reader: &mut BufReader<S>,
    config: &BridgeConfig,
    http: &reqwest::Client,
    session: &mut Session,
    tag: &str,
) -> std::io::Result<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some(authed) = &session.authed else {
        return Ok(format!("{tag} NO not authenticated\r\n"));
    };

    let numbered = match fetch_mailbox_catalog(config, http, authed, "SELECT").await {
        Ok(n) => n,
        Err(e) => return Ok(format!("{tag} NO {e}\r\n")),
    };
    let count = numbered.len() as u32;
    session.mailbox = Some(SelectedMailbox { messages: numbered });

    write_logged(reader, &format!("* {count} EXISTS\r\n")).await?;
    write_logged(reader, "* 0 RECENT\r\n").await?;
    write_logged(reader, "* FLAGS ()\r\n").await?;
    write_logged(reader, "* OK [PERMANENTFLAGS ()] pas d'ecriture (V1 demo)\r\n").await?;
    write_logged(reader, &format!("* OK [UIDVALIDITY {UID_VALIDITY}]\r\n")).await?;
    write_logged(reader, &format!("* OK [UIDNEXT {}]\r\n", count + 1)).await?;
    Ok(format!("{tag} OK [READ-ONLY] SELECT completed\r\n"))
}

/// `STATUS INBOX (MESSAGES UIDNEXT ...)` — comme `SELECT`, interroge diamy-maild à CHAQUE
/// appel (jamais de cache), mais SANS changer la boîte actuellement sélectionnée (RFC 3501
/// §6.3.10 : STATUS ne modifie jamais l'état de session courant). Certains clients (et
/// Thunderbird, selon la version) l'utilisent pour vérifier les nouveaux messages sans re-
/// sélectionner INBOX en entier.
async fn cmd_status<S>(
    reader: &mut BufReader<S>,
    config: &BridgeConfig,
    http: &reqwest::Client,
    session: &Session,
    tag: &str,
    args: &str,
) -> std::io::Result<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some(authed) = &session.authed else {
        return Ok(format!("{tag} NO not authenticated\r\n"));
    };

    let mut top = args.splitn(2, char::is_whitespace);
    let mailbox_raw = top.next().unwrap_or("");
    let items_raw = top.next().unwrap_or("").trim();
    let mailbox_name = tokenize_args(mailbox_raw).into_iter().next().unwrap_or_default();
    if !mailbox_name.eq_ignore_ascii_case("INBOX") {
        return Ok(format!("{tag} NO seule INBOX existe (V1 démo)\r\n"));
    }

    let numbered = match fetch_mailbox_catalog(config, http, authed, "STATUS").await {
        Ok(n) => n,
        Err(e) => return Ok(format!("{tag} NO {e}\r\n")),
    };
    let count = numbered.len() as u32;

    let requested = items_raw.trim_start_matches('(').trim_end_matches(')');
    let mut parts: Vec<String> = Vec::new();
    for tok in requested.split_whitespace() {
        match tok.to_ascii_uppercase().as_str() {
            "MESSAGES" => parts.push(format!("MESSAGES {count}")),
            "RECENT" => parts.push("RECENT 0".to_string()),
            "UIDNEXT" => parts.push(format!("UIDNEXT {}", count + 1)),
            "UIDVALIDITY" => parts.push(format!("UIDVALIDITY {UID_VALIDITY}")),
            // V1 démo : aucun flag \Seen n'est jamais posé (lecture seule, pas de
            // persistance d'état) — tout message est donc "non lu" du point de vue du Bridge.
            "UNSEEN" => parts.push(format!("UNSEEN {count}")),
            _ => {}
        }
    }
    write_logged(reader, &format!("* STATUS INBOX ({})\r\n", parts.join(" "))).await?;
    Ok(format!("{tag} OK STATUS completed\r\n"))
}

/// `NOOP` re-interroge le catalogue SI une boîte est déjà sélectionnée — RFC 3501 §7.3.1 :
/// "the NOOP command can be used as a periodic poll for new messages [...] during a period of
/// inactivity". C'est le mécanisme standard par lequel un client DÉJÀ connecté et sur INBOX
/// détecte du nouveau courrier SANS refaire un SELECT complet — Thunderbird s'appuie dessus
/// pour "Récupérer les messages" sur une connexion déjà établie. Sans ce rafraîchissement, un
/// mail arrivé APRÈS le SELECT initial ne serait jamais vu tant que la connexion reste ouverte
/// (c'était le bug : le compte restait figé à la valeur du premier SELECT).
async fn cmd_noop<S>(
    reader: &mut BufReader<S>,
    config: &BridgeConfig,
    http: &reqwest::Client,
    session: &mut Session,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if session.authed.is_none() || session.mailbox.is_none() {
        return Ok(());
    }
    let authed = session.authed.as_ref().expect("vérifié ci-dessus");
    let numbered = match fetch_mailbox_catalog(config, http, authed, "NOOP").await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "NOOP : échec du rafraîchissement du catalogue");
            return Ok(());
        }
    };
    let new_count = numbered.len() as u32;
    let old_count = session.mailbox.as_ref().map(|m| m.messages.len() as u32).unwrap_or(0);
    session.mailbox = Some(SelectedMailbox { messages: numbered });
    if new_count != old_count {
        write_logged(reader, &format!("* {new_count} EXISTS\r\n")).await?;
        write_logged(reader, "* 0 RECENT\r\n").await?;
    }
    Ok(())
}

/// Borne défensive (INV-15) : expanse un sequence-set/uid-set IMAP (`1`, `1:5`, `1:*`,
/// `1,3,5:7`) en une liste triée, dédupliquée, bornée à `[1, max]`.
fn parse_number_set(spec: &str, max: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once(':') {
            let start: u32 = a.parse().unwrap_or(1).max(1);
            let end: u32 = if b == "*" { max } else { b.parse().unwrap_or(max) };
            let (lo, hi) = if start <= end { (start, end) } else { (end, start) };
            for n in lo..=hi {
                if out.len() >= MAX_SET_EXPANSION {
                    break;
                }
                if n >= 1 && n <= max {
                    out.push(n);
                }
            }
        } else if part == "*" {
            if max >= 1 {
                out.push(max);
            }
        } else if let Ok(n) = part.parse::<u32>() {
            if n >= 1 && n <= max {
                out.push(n);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FetchItem {
    Uid,
    Flags,
    InternalDate,
    Rfc822Size,
    Envelope,
    Rfc822,
    Rfc822Header,
    Body,
    BodyPeek,
    /// `BODY[HEADER.FIELDS (...)]` / `BODY.PEEK[HEADER.FIELDS (...)]` — `fields` préserve la
    /// casse et l'ordre exacts envoyés par le client (ex. Thunderbird : `From To Cc Bcc
    /// Subject Date Message-ID ...`), pour ré-échoer le même libellé dans la réponse (RFC
    /// 3501 §6.4.5 : le nom de section renvoyé DOIT refléter ce qui a été demandé, même pour
    /// les champs qu'on ne sait pas fournir — RFC 3501 autorise explicitement à omettre du
    /// TEXTE les champs absents/non gérés sans que ce soit une erreur).
    HeaderFields { fields: Vec<String> },
}

/// Découpe une liste d'items FETCH par ESPACE de premier niveau SEULEMENT — tout ce qui est
/// entre `[...]`/`(...)` reste un seul item (ex. `BODY.PEEK[HEADER.FIELDS (From Subject)]` ne
/// doit PAS être coupé sur l'espace avant "Subject", sans quoi ce serait lu comme plusieurs
/// items indépendants et la section demandée serait perdue).
fn tokenize_bracket_aware(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth: i32 = 0;
    for c in s.chars() {
        match c {
            '[' | '(' => {
                depth += 1;
                current.push(c);
            }
            ']' | ')' => {
                depth -= 1;
                current.push(c);
            }
            c if c.is_whitespace() && depth <= 0 => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Reconnaît `BODY[HEADER.FIELDS (...)]` / `BODY.PEEK[HEADER.FIELDS (...)]` — mots-clés
/// comparés insensibles à la casse, mais la liste de champs renvoyée garde la casse ORIGINALE
/// du client (utile pour ré-échoer le même libellé exact dans la réponse).
fn parse_header_fields_item(token: &str) -> Option<Vec<String>> {
    let upper = token.to_ascii_uppercase();
    let prefix_len = if upper.starts_with("BODY.PEEK[") {
        "BODY.PEEK[".len()
    } else if upper.starts_with("BODY[") {
        "BODY[".len()
    } else {
        return None;
    };
    if !token.ends_with(']') || token.len() < prefix_len + 1 {
        return None;
    }
    // Même longueur en octets que `token` (transformation ASCII pure) : les indices calculés
    // sur `upper` restent valides pour trancher `token` en conservant sa casse d'origine.
    let inner = &token[prefix_len..token.len() - 1];
    let inner_upper = &upper[prefix_len..upper.len() - 1];
    if !inner_upper.starts_with("HEADER.FIELDS") {
        return None;
    }
    let rest = inner["HEADER.FIELDS".len()..].trim();
    let rest = rest.strip_prefix('(')?.strip_suffix(')')?;
    Some(rest.split_whitespace().map(|s| s.to_string()).collect())
}

/// Tokenise la liste d'items FETCH par mot exact (jamais par sous-chaîne : "RFC822.SIZE"
/// contient "RFC822" en tant que texte, mais ce sont des items DIFFÉRENTS) — items non
/// supportés dans cette V1 ignorés, jamais une erreur bloquante (Postel's law côté serveur).
fn parse_fetch_items(spec: &str) -> Vec<FetchItem> {
    let inner = spec.trim().trim_start_matches('(').trim_end_matches(')');
    tokenize_bracket_aware(inner)
        .into_iter()
        .filter_map(|tok| {
            if let Some(fields) = parse_header_fields_item(&tok) {
                return Some(FetchItem::HeaderFields { fields });
            }
            match tok.to_ascii_uppercase().as_str() {
                "UID" => Some(FetchItem::Uid),
                "FLAGS" => Some(FetchItem::Flags),
                "INTERNALDATE" => Some(FetchItem::InternalDate),
                "RFC822.SIZE" => Some(FetchItem::Rfc822Size),
                "ENVELOPE" => Some(FetchItem::Envelope),
                "RFC822.HEADER" => Some(FetchItem::Rfc822Header),
                "RFC822" => Some(FetchItem::Rfc822),
                "BODY[]" => Some(FetchItem::Body),
                "BODY.PEEK[]" => Some(FetchItem::BodyPeek),
                _ => None,
            }
        })
        .collect()
}

fn imap_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Date/heure décomposée, telle que reçue de `diamy-maild` (affichage par défaut de
/// `time::OffsetDateTime`, ex. "2026-07-17 8:05:35.053648 +00:00:00" — notez l'heure locale
/// SANS zéro de tête et les fractions de seconde).
struct RawDateTime {
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    tz_negative: bool,
    tz_hour: u32,
    tz_minute: u32,
}

/// Isole la partie fuseau horaire (toujours introduite par un `+`/`-` après un espace) de la
/// partie heure locale — sépare sur le DERNIER espace pour rester correct même si l'heure
/// locale contenait elle-même des espaces (elle n'en a pas ici, mais c'est plus robuste).
fn split_time_and_tz(s: &str) -> Option<(&str, &str)> {
    let idx = s.rfind(' ')?;
    let (time_part, tz_part) = (s[..idx].trim(), s[idx + 1..].trim());
    if tz_part.starts_with('+') || tz_part.starts_with('-') {
        Some((time_part, tz_part))
    } else {
        None
    }
}

/// Parse le format renvoyé par `diamy-maild` (voir `RawDateTime`). Retourne `None` — jamais un
/// panic — sur toute entrée qui ne correspond pas exactement à ce format (Postel's law côté
/// serveur, même esprit que `parse_fetch_items`) : l'appelant garde alors la chaîne brute.
fn parse_maild_datetime(raw: &str) -> Option<RawDateTime> {
    let mut top = raw.trim().splitn(2, ' ');
    let date_part = top.next()?;
    let rest = top.next()?.trim();

    let mut date_nums = date_part.splitn(3, '-');
    let year: i32 = date_nums.next()?.parse().ok()?;
    let month: u32 = date_nums.next()?.parse().ok()?;
    let day: u32 = date_nums.next()?.parse().ok()?;

    let (time_part, tz_part) = split_time_and_tz(rest)?;
    let time_only = time_part.split('.').next().unwrap_or(time_part);
    let mut time_nums = time_only.splitn(3, ':');
    let hour: u32 = time_nums.next()?.parse().ok()?;
    let minute: u32 = time_nums.next()?.parse().ok()?;
    let second: u32 = time_nums.next()?.parse().ok()?;

    let tz_negative = tz_part.starts_with('-');
    let tz_body = &tz_part[1..];
    let mut tz_nums = tz_body.splitn(3, ':');
    let tz_hour: u32 = tz_nums.next()?.parse().ok()?;
    let tz_minute: u32 = tz_nums.next().unwrap_or("0").parse().ok()?;

    Some(RawDateTime { year, month, day, hour, minute, second, tz_negative, tz_hour, tz_minute })
}

const MONTH_NAMES: [&str; 12] =
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAY_NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/// Jour de la semaine (algorithme de Sakamoto, sans dépendance externe) — `0` = dimanche.
fn day_of_week(year: i32, month: u32, day: u32) -> usize {
    const T: [i32; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let y = if month < 3 { year - 1 } else { year };
    let w = (y + y / 4 - y / 100 + y / 400 + T[(month - 1) as usize] + day as i32) % 7;
    w as usize
}

/// Convertit le format de date renvoyé par `diamy-maild` en RFC 2822/5322 (ex. `"Fri, 17 Jul
/// 2026 08:05:35 +0000"`), le format attendu pour `ENVELOPE` (RFC 3501 §7.4.2) et l'en-tête
/// `Date:` (RFC 5322 §3.3) par un client IMAP standard. Une entrée non reconnue est renvoyée
/// telle quelle plutôt que de faire échouer le FETCH (Postel's law côté serveur).
fn to_rfc2822_date(raw: &str) -> String {
    let Some(d) = parse_maild_datetime(raw) else {
        return raw.to_string();
    };
    let dow = DAY_NAMES[day_of_week(d.year, d.month, d.day)];
    let mon = MONTH_NAMES[(d.month.clamp(1, 12) - 1) as usize];
    let tz_sign = if d.tz_negative { '-' } else { '+' };
    format!(
        "{dow}, {:02} {mon} {:04} {:02}:{:02}:{:02} {tz_sign}{:02}{:02}",
        d.day, d.year, d.hour, d.minute, d.second, d.tz_hour, d.tz_minute
    )
}

/// Construit un RFC 5322 minimal à partir du contenu déchiffré LOCALEMENT (A20-IMAP-2) — pas
/// le blob original (qui, dans cette maquette, ne contient QUE le corps + désormais le sujet,
/// jamais les autres en-têtes : voir `diamy-mail-mime`/`SIMPLIFICATIONS.md`). `date` DOIT déjà
/// être au format RFC 5322 (voir `to_rfc2822_date`) — c'est l'appelant qui convertit.
fn build_rfc5322(sender: &str, date: &str, message_id: Uuid, subject: &str, body: &str) -> String {
    let subject_line = if subject.is_empty() { "(no subject)" } else { subject };
    format!(
        "From: {sender}\r\nDate: {date}\r\nMessage-ID: <{message_id}@diamy-bridge>\r\nSubject: {subject_line}\r\n\r\n{body}"
    )
}

/// Structure ENVELOPE IMAP minimale (RFC 3501 §7.4.2) — To/Cc/Bcc/In-Reply-To à NIL (le
/// catalogue de synchronisation ne porte pas le destinataire, seulement l'expéditeur).
fn build_envelope(date: &str, subject: &str, sender: &str, message_id: Uuid) -> String {
    let (local, domain) = sender.split_once('@').unwrap_or((sender, ""));
    let subject_display = if subject.is_empty() { "(no subject)" } else { subject };
    let addr = format!("(NIL NIL {} {})", imap_quote(local), imap_quote(domain));
    format!(
        "({} {} ({addr}) ({addr}) ({addr}) NIL NIL NIL NIL {})",
        imap_quote(date),
        imap_quote(subject_display),
        imap_quote(&format!("<{message_id}@diamy-bridge>")),
    )
}

struct DecryptedMessage {
    sender: String,
    date: String,
    subject: String,
    body: String,
}

/// Tire le chiffré (corps + sujet + enveloppe) via la MÊME API de sync que `read_test_mail.rs`,
/// puis déchiffre LOCALEMENT et VÉRIFIE le tag avant tout usage (INV-8) — jamais le serveur.
async fn fetch_and_decrypt(
    config: &BridgeConfig,
    http: &reqwest::Client,
    authed: &AuthedSession,
    summary: &MessageSummaryDto,
) -> Result<DecryptedMessage, Box<dyn std::error::Error>> {
    let fetch_url = format!(
        "{}/v1/mailbox/{}/messages/{}?device_id={}",
        config.sync_base, authed.principal.id, summary.message_id, authed.device_id
    );
    tracing::debug!(
        message_id = %summary.message_id,
        device_id = %authed.device_id,
        url = %fetch_url,
        "FETCH : interrogation de diamy-maild pour ce message"
    );
    let resp = auth_headers(http.get(&fetch_url), config, &authed.mail_plane_token).send().await?;
    let status = resp.status();
    let body_text = resp.text().await?;
    tracing::debug!(message_id = %summary.message_id, %status, body = %body_text, "FETCH : réponse brute de diamy-maild");
    let fetched: FetchedDto = serde_json::from_str(&body_text).map_err(|e| {
        format!("désérialisation FetchedDto échouée (status {status}) : {e} — corps reçu : {body_text}")
    })?;

    // INV-7 : re-contrôle des versions reçues sur le fil AVANT tout `open_message`/`unwrap_key`.
    let body_ct = crypto::Ciphertext {
        alg_version: crypto::AlgVersion::from_i32(fetched.body_alg_version)?,
        nonce: nonce_from_b64(&fetched.body_nonce_b64)?,
        bytes: STANDARD.decode(&fetched.body_ciphertext_b64)?,
    };
    let summary_ct = crypto::Ciphertext {
        alg_version: crypto::AlgVersion::from_i32(fetched.summary_alg_version)?,
        nonce: nonce_from_b64(&fetched.summary_nonce_b64)?,
        bytes: STANDARD.decode(&fetched.summary_ciphertext_b64)?,
    };
    let envelope = crypto::Envelope {
        kem_ct: STANDARD.decode(&fetched.envelope_kem_ct_b64)?,
        wrapped: crypto::Ciphertext {
            alg_version: crypto::AlgVersion::from_i32(fetched.envelope_alg_version)?,
            nonce: nonce_from_b64(&fetched.envelope_wrap_nonce_b64)?,
            bytes: STANDARD.decode(&fetched.envelope_wrapped_key_b64)?,
        },
    };

    // Déchiffrement LOCAL + vérification du tag AVANT tout usage (INV-8). Les AAD doivent
    // être reconstruites à l'identique de celles du scellement (A02-CRY-2/CRY-3).
    let envelope_aad = crypto::aad_for_envelope(summary.message_id, authed.device_id);
    let message_key = crypto::unwrap_key(&envelope, &authed.device_sec, &envelope_aad)?;
    let body_aad = crypto::aad_for_blob(summary.message_id, fetched.body_blob_id);
    let verified_body = crypto::open_message(&body_ct, &message_key, &body_aad)?;
    let summary_aad = crypto::aad_for_summary(summary.message_id);
    let verified_subject = crypto::open_message(&summary_ct, &message_key, &summary_aad)?;

    Ok(DecryptedMessage {
        sender: summary.sender_canonical.clone().unwrap_or_else(|| "inconnu@invalide".to_string()),
        date: summary.received_at.as_deref().map(to_rfc2822_date).unwrap_or_default(),
        subject: String::from_utf8_lossy(verified_subject.as_bytes()).to_string(),
        body: String::from_utf8_lossy(verified_body.as_bytes()).to_string(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn cmd_fetch<S>(
    reader: &mut BufReader<S>,
    config: &BridgeConfig,
    http: &reqwest::Client,
    session: &Session,
    tag: &str,
    args: &str,
    is_uid: bool,
) -> std::io::Result<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some(authed) = &session.authed else {
        return Ok(format!("{tag} NO not authenticated\r\n"));
    };
    let Some(mailbox) = &session.mailbox else {
        return Ok(format!("{tag} NO aucune boite selectionnee\r\n"));
    };

    let mut split = args.splitn(2, char::is_whitespace);
    let set_spec = split.next().unwrap_or("");
    let items_spec = split.next().unwrap_or("").trim();
    let items = parse_fetch_items(items_spec);

    let count = mailbox.messages.len() as u32;
    let selected_numbers = if is_uid {
        // UID FETCH : le set porte des UID, pas des numéros de séquence — on borne à l'UID
        // maximal (== count ici, puisque nos UID sont 1..count).
        parse_number_set(set_spec, count)
    } else {
        parse_number_set(set_spec, count)
    };

    for n in selected_numbers {
        let (seq, (uid, summary)) = if is_uid {
            // Retrouve la position de séquence correspondant à cet UID.
            match mailbox.messages.iter().enumerate().find(|(_, (u, _))| *u == n) {
                Some((idx, entry)) => (idx as u32 + 1, entry.clone()),
                None => continue,
            }
        } else {
            match mailbox.messages.get((n - 1) as usize) {
                Some(entry) => (n, entry.clone()),
                None => continue,
            }
        };

        let decrypted = match fetch_and_decrypt(config, http, authed, &summary).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(message_id = %summary.message_id, error = %e, "échec fetch/déchiffrement");
                continue; // INV-8/16 : ne sert jamais un message non vérifié — on l'omet plutôt.
            }
        };

        let rfc5322 = build_rfc5322(&decrypted.sender, &decrypted.date, summary.message_id, &decrypted.subject, &decrypted.body);
        let header_only = rfc5322.split("\r\n\r\n").next().unwrap_or("").to_string();

        let mut attrs: Vec<String> = Vec::new();
        // RFC 3501 §6.4.8 : une réponse à `UID FETCH` DOIT toujours inclure l'item UID, que le
        // client l'ait demandé ou non dans la liste — sinon un vrai client (Thunderbird) ne
        // peut pas relier la ligne FETCH reçue à l'UID qu'il suit, et abandonne silencieusement
        // la suite du protocole (jamais d'ENVELOPE/BODY après un premier FETCH FLAGS boiteux).
        if is_uid && !items.contains(&FetchItem::Uid) {
            attrs.push(format!("UID {uid}"));
        }
        for item in &items {
            match item {
                FetchItem::Uid => attrs.push(format!("UID {uid}")),
                FetchItem::Flags => attrs.push("FLAGS ()".to_string()),
                FetchItem::InternalDate => attrs.push(format!("INTERNALDATE {}", imap_quote(&decrypted.date))),
                FetchItem::Rfc822Size => attrs.push(format!("RFC822.SIZE {}", rfc5322.len())),
                FetchItem::Envelope => attrs.push(format!(
                    "ENVELOPE {}",
                    build_envelope(&decrypted.date, &decrypted.subject, &decrypted.sender, summary.message_id)
                )),
                FetchItem::Rfc822 | FetchItem::Body | FetchItem::BodyPeek => {
                    // RFC 3501 §6.4.5 : la réponse affiche toujours "BODY[...]", jamais
                    // "BODY.PEEK[...]" — PEEK ne modifie que la pose du flag \Seen (ici sans
                    // effet, V1 démo sans écriture), jamais le libellé de la section renvoyée.
                    let label = match item {
                        FetchItem::Rfc822 => "RFC822",
                        _ => "BODY[]",
                    };
                    attrs.push(format!("{label} {{{}}}\r\n{}", rfc5322.len(), rfc5322));
                }
                FetchItem::Rfc822Header => {
                    attrs.push(format!("RFC822.HEADER {{{}}}\r\n{}", header_only.len(), header_only));
                }
                FetchItem::HeaderFields { fields } => {
                    // Champs demandés que ce Bridge sait fournir depuis le "summary" déjà
                    // déchiffré (sender_canonical/subject, disponibles depuis le SELECT/FETCH
                    // sans re-parsing) : From, Subject, Date sont les 3 indispensables pour
                    // qu'un client affiche le message dans sa liste ; Message-ID est aussi
                    // déjà construit ailleurs (ENVELOPE) donc réutilisé ici gratuitement.
                    // Le reste (Cc, Bcc, References, ...) est omis — RFC 3501 §6.4.5 l'autorise
                    // explicitement : un champ demandé mais absent n'est pas une erreur, il est
                    // simplement omis du texte renvoyé.
                    let mut content = String::new();
                    for f in fields {
                        match f.to_ascii_lowercase().as_str() {
                            "from" => content.push_str(&format!("From: {}\r\n", decrypted.sender)),
                            "subject" => {
                                let subj = if decrypted.subject.is_empty() {
                                    "(no subject)"
                                } else {
                                    decrypted.subject.as_str()
                                };
                                content.push_str(&format!("Subject: {subj}\r\n"));
                            }
                            "date" => content.push_str(&format!("Date: {}\r\n", decrypted.date)),
                            "message-id" => content
                                .push_str(&format!("Message-ID: <{}@diamy-bridge>\r\n", summary.message_id)),
                            _ => {}
                        }
                    }
                    content.push_str("\r\n"); // ligne vide terminant le bloc d'en-têtes (RFC 5322 §2.1)
                    attrs.push(format!(
                        "BODY[HEADER.FIELDS ({})] {{{}}}\r\n{}",
                        fields.join(" "),
                        content.len(),
                        content
                    ));
                }
            }
        }

        let line = format!("* {seq} FETCH ({})\r\n", attrs.join(" "));
        write_logged(reader, &line).await?;
    }

    Ok(format!("{tag} OK {} completed\r\n", if is_uid { "UID FETCH" } else { "FETCH" }))
}

enum LineRead {
    Line(String),
    TooLong,
    Eof,
}

/// Écrit une ligne IMAP sur le fil ET logue le texte EXACT envoyé au client, AVANT l'envoi —
/// visible avec RUST_LOG=diamy_bridged=debug. Sert à auditer la réponse réellement posée sur
/// le socket (pas seulement les échanges internes avec diamy-maild), notamment pour SELECT et
/// FETCH où un défaut de format IMAP (UID manquant, CRLF absent...) ne se voit qu'ici.
async fn write_logged<S>(reader: &mut BufReader<S>, line: &str) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tracing::debug!(imap_response = %line, "reponse IMAP envoyee au client (brute)");
    reader.get_mut().write_all(line.as_bytes()).await
}

/// Détecte un littéral IMAP `{N}` ou `{N+}` (RFC 7888, non-synchronisant) en toute fin de
/// ligne — retourne `(préfixe sans le littéral, taille annoncée, non-synchronisant?)`. `None`
/// si la ligne ne se termine pas par une spécification de littéral valide.
fn parse_trailing_literal(line: &str) -> Option<(&str, usize, bool)> {
    let trimmed = line.trim_end();
    if !trimmed.ends_with('}') {
        return None;
    }
    let open = trimmed.rfind('{')?;
    let inner = &trimmed[open + 1..trimmed.len() - 1];
    let (digits, non_sync) = match inner.strip_suffix('+') {
        Some(d) => (d, true),
        None => (inner, false),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let len: usize = digits.parse().ok()?;
    Some((&trimmed[..open], len, non_sync))
}

/// Draine (lit et jette) exactement `remaining` octets par blocs bornés — jamais une seule
/// allocation proportionnelle à une taille annoncée par le client (INV-15). Sert à rester
/// synchronisé sur le flux quand un littéral non-synchronisant `{N+}` (RFC 7888) dépasse nos
/// bornes : le client l'envoie de toute façon, avec ou sans notre accord.
async fn drain_bytes<S>(reader: &mut BufReader<S>, mut remaining: usize) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut chunk = [0u8; 4096];
    while remaining > 0 {
        let take = remaining.min(chunk.len());
        reader.read_exact(&mut chunk[..take]).await?;
        remaining -= take;
    }
    Ok(())
}

/// Assemble une commande IMAP complète en gérant les littéraux `{N}`/`{N+}`. Beaucoup de
/// clients réels — Thunderbird en tête — envoient systématiquement `LOGIN` sous cette forme :
/// `a1 LOGIN {11}\r\nhugo@w3.tel {8}\r\nmotdepasse\r\n`. Un parseur ligne-par-ligne qui ignore
/// cette syntaxe relit chaque segment de littéral comme s'il s'agissait d'une commande à part
/// entière : le flux se désynchronise totalement, et c'est précisément ce qui provoquait la
/// coupure "Connection reset by peer" observée avec Thunderbird alors qu'un test manuel au `nc`
/// (sans littéral) fonctionnait. Ici, chaque littéral est lu intégralement puis réinjecté sous
/// forme de chaîne entre guillemets, de sorte que `tokenize_args`/`cmd_login` etc. reçoivent une
/// commande "à plat" identique à celle qu'un client sans littéraux aurait envoyée.
async fn read_command<S>(reader: &mut BufReader<S>) -> std::io::Result<LineRead>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut assembled = String::new();
    for _ in 0..MAX_LITERALS_PER_COMMAND {
        let segment = match read_line_bounded(reader).await? {
            LineRead::Eof => return Ok(LineRead::Eof),
            LineRead::TooLong => return Ok(LineRead::TooLong),
            LineRead::Line(l) => l,
        };
        // Exigence de debug : CHAQUE ligne brute reçue du client, avant tout parsing, y
        // compris pour une commande finalement non reconnue. Visible avec
        // RUST_LOG=diamy_bridged=debug.
        tracing::debug!(raw = %segment, "ligne IMAP brute recue (avant parsing)");

        match parse_trailing_literal(&segment) {
            None => {
                assembled.push_str(&segment);
                return Ok(LineRead::Line(assembled));
            }
            Some((prefix, len, non_sync)) => {
                assembled.push_str(prefix);
                if len > MAX_LITERAL_LEN {
                    if non_sync {
                        drain_bytes(reader, len).await?;
                    }
                    // Littéral synchronisant trop grand : on NE répond PAS "+ ", donc le client
                    // (RFC 3501 §7) ne doit pas envoyer les octets — rejet sûr, sans lire N
                    // octets potentiellement énormes.
                    return Ok(LineRead::TooLong);
                }
                reader.get_mut().write_all(b"+ OK\r\n").await?;
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf).await?;
                let literal_str = String::from_utf8_lossy(&buf);
                tracing::debug!(literal_len = len, "litteral IMAP recu (avant parsing)");
                assembled.push_str(&imap_quote(&literal_str));
            }
        }
    }
    // Trop de littéraux enchaînés dans une seule commande (INV-15 : borne de profondeur).
    Ok(LineRead::TooLong)
}

/// Lecture de ligne bornée en mémoire (INV-15) — même discipline que
/// `diamy-mxd::read_line_bounded` : continue de DRAINER jusqu'au `\n` sans plus jamais faire
/// croître le buffer une fois `MAX_LINE_LEN` atteint.
async fn read_line_bounded<S>(reader: &mut BufReader<S>) -> std::io::Result<LineRead>
where
    S: tokio::io::AsyncRead + Unpin,
{
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
            too_long = true;
        }
    }
    if too_long {
        Ok(LineRead::TooLong)
    } else {
        let s = String::from_utf8_lossy(&buf).trim_end_matches('\r').to_string();
        Ok(LineRead::Line(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_sequence_ranges() {
        assert_eq!(parse_number_set("1:3", 10), vec![1, 2, 3]);
        assert_eq!(parse_number_set("1:*", 5), vec![1, 2, 3, 4, 5]);
        assert_eq!(parse_number_set("2,4,6", 10), vec![2, 4, 6]);
        assert_eq!(parse_number_set("*", 7), vec![7]);
    }

    #[test]
    fn sequence_set_is_clamped_to_bounds() {
        // Un client demandant hors bornes ne doit jamais faire déborder l'expansion (INV-15).
        assert_eq!(parse_number_set("1:1000", 3), vec![1, 2, 3]);
        assert_eq!(parse_number_set("0:5", 3), vec![1, 2, 3]);
    }

    #[test]
    fn fetch_items_are_matched_by_exact_token_not_substring() {
        // "RFC822.SIZE" contient "RFC822" comme sous-chaîne mais ce sont des items distincts —
        // un tokenizer par sous-chaîne aurait déclenché RFC822 (corps complet) à tort ici.
        let items = parse_fetch_items("(UID RFC822.SIZE FLAGS)");
        assert_eq!(items, vec![FetchItem::Uid, FetchItem::Rfc822Size, FetchItem::Flags]);
        assert!(!items.contains(&FetchItem::Rfc822));
    }

    #[test]
    fn header_fields_item_is_not_split_on_its_internal_spaces() {
        // Forme exacte envoyée par Thunderbird : une liste de champs imbriquée entre
        // parenthèses, elle-même entre crochets — un split_whitespace naïf la couperait en
        // plusieurs items indépendants et perdrait la section demandée.
        let items = parse_fetch_items(
            "(UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From To Cc Bcc Subject Date \
             Message-ID Priority X-Priority References Newsgroups In-Reply-To Content-Type \
             Reply-To Received)])",
        );
        assert_eq!(items.len(), 4, "un seul item HeaderFields, pas un par champ");
        let fields = match &items[3] {
            FetchItem::HeaderFields { fields } => fields,
            other => panic!("attendu HeaderFields, trouvé {other:?}"),
        };
        assert_eq!(fields[0], "From");
        assert_eq!(fields[4], "Subject");
        assert_eq!(fields.last().unwrap(), "Received");
        assert_eq!(fields.len(), 15);
    }

    #[test]
    fn header_fields_peek_and_non_peek_both_parse_to_the_same_variant() {
        // BODY[...] et BODY.PEEK[...] ne diffèrent que par la pose du flag \Seen (sans effet
        // ici, V1 démo sans écriture) — jamais par la structure de données qu'on en tire.
        assert_eq!(
            parse_fetch_items("(BODY.PEEK[HEADER.FIELDS (Subject)])"),
            parse_fetch_items("(BODY[HEADER.FIELDS (Subject)])")
        );
    }

    #[test]
    fn tokenize_args_respects_quoted_strings_with_spaces() {
        let toks = tokenize_args("\"hugo@w3.tel\" \"a password\"");
        assert_eq!(toks, vec!["hugo@w3.tel".to_string(), "a password".to_string()]);
    }

    #[test]
    fn rfc5322_falls_back_to_placeholder_subject_when_empty() {
        let msg = build_rfc5322("a@b.fr", "2024-01-01", Uuid::nil(), "", "corps");
        assert!(msg.contains("Subject: (no subject)"));
        assert!(msg.contains("corps"));
    }

    #[test]
    fn detects_synchronizing_and_nonsynchronizing_literals() {
        // Forme exacte envoyée par Thunderbird pour LOGIN : `a1 LOGIN {11}`.
        assert_eq!(parse_trailing_literal("a1 LOGIN {11}"), Some(("a1 LOGIN ", 11, false)));
        // RFC 7888 : littéral non-synchronisant, le client n'attend pas de "+ OK".
        assert_eq!(parse_trailing_literal("a1 LOGIN {11+}"), Some(("a1 LOGIN ", 11, true)));
        // Deuxième segment d'une commande LOGIN à deux littéraux : juste le littéral suivant.
        assert_eq!(parse_trailing_literal(" {8}"), Some((" ", 8, false)));
    }

    #[test]
    fn does_not_mistake_a_plain_line_for_a_literal() {
        assert_eq!(parse_trailing_literal("a1 LOGIN user pass"), None);
        assert_eq!(parse_trailing_literal("a1 CAPABILITY"), None);
        // Accolades non numériques ou vides : jamais interprétées comme un littéral.
        assert_eq!(parse_trailing_literal("a1 LOGIN {}"), None);
        assert_eq!(parse_trailing_literal("a1 LOGIN {abc}"), None);
    }

    #[test]
    fn converts_maild_datetime_to_rfc2822() {
        // L'exemple exact observé en logue (heure locale SANS zéro de tête, fractions de
        // seconde, fuseau "+00:00:00") — 2026-07-17 est bien un vendredi, vérifié indépendamment.
        assert_eq!(
            to_rfc2822_date("2026-07-17 8:05:35.053648 +00:00:00"),
            "Fri, 17 Jul 2026 08:05:35 +0000"
        );
        // Heure à deux chiffres, sans fraction de seconde.
        assert_eq!(
            to_rfc2822_date("2026-07-16 14:49:01.061013 +00:00:00"),
            "Thu, 16 Jul 2026 14:49:01 +0000"
        );
        // Fuseau négatif.
        assert_eq!(
            to_rfc2822_date("2024-01-01 0:00:00 -05:00:00"),
            "Mon, 01 Jan 2024 00:00:00 -0500"
        );
    }

    #[test]
    fn unparseable_date_is_returned_unchanged() {
        // Postel's law côté serveur : jamais un panic, jamais une chaîne vide surprenante —
        // l'entrée d'origine ressort telle quelle si le format ne correspond pas.
        assert_eq!(to_rfc2822_date("n'importe quoi"), "n'importe quoi");
        assert_eq!(to_rfc2822_date(""), "");
    }
}
