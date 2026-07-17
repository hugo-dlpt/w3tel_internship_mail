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
//! boîte INBOX, pas de flags/`\Seen`/multi-dossier, pas de STARTTLS, pas de CalDAV, un seul
//! compte préconfiguré (pas de mot de passe Bridge révocable par client, A20-CRED-1) — ce qui
//! EST honoré en revanche : le Bridge est son PROPRE appareil enrôlé avec sa PROPRE AppKey
//! Tier 2 (A20-CRED-4b/5), le déchiffrement passe par le même chemin vérifié qu'A02/INV-8, ET
//! (nouveau) l'ENVOI SMTP (A20-SMTP-1) : le Bridge expose un second listener SMTP loopback-only
//! et délègue TOUJOURS l'émission à `diamy-submitd` via `POST /submit` — il ne relaie jamais
//! lui-même vers Internet (voir la section "SMTP (A20-SMTP-1)" plus bas dans ce fichier).
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD, Engine};
use diamy_addr::{diamy_addr_canon, TenantAddressPolicy};
use diamy_mail_crypto as crypto;
use diamy_mail_iam::{DevIamClient, IamClient, Principal};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;
use zeroize::Zeroize;

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
/// Répertoire par défaut de l'état d'UID IMAP persisté (Point 2 — correction de l'instabilité
/// d'UID). Overridable par `DIAMY_BRIDGED_UID_STATE_DIR`. Chemin relatif au cwd, MÊME convention
/// que `./dev_secrets` / `./blob_store`. C'est une notion PROPRE au protocole IMAP (RFC 3501),
/// pas une donnée métier du serveur mail : elle vit donc côté Bridge, jamais côté `diamy-maild`
/// (voir la justification d'architecture dans `SIMPLIFICATIONS.md`).
const DEFAULT_UID_STATE_DIR: &str = "./bridge_state";
/// Borne défensive (esprit A01-STAB-1 / INV-15) sur un corps SMTP `DATA` — même valeur par
/// défaut que `diamy-mxd::DEFAULT_MAX_DATA_BYTES`.
const MAX_SMTP_DATA_BYTES: usize = 10 * 1024 * 1024;
const MAX_SMTP_RECIPIENTS: usize = 50;

struct BridgeConfig {
    imap_bind_addr: SocketAddr,
    /// A20-SMTP-1 : écoute SMTP locale du Bridge — MÊME règle de sécurité que l'IMAP
    /// (A20-ARCH-2/NET-1/2/3), voir `smtp_bind_addr` dans `from_env` et son usage dans `main`.
    smtp_bind_addr: SocketAddr,
    imap_user: String,
    imap_password: String,
    sync_base: String,
    app_key: String,
    /// URL de `POST /submit` sur `diamy-submitd` (A20-SMTP-1 : le Bridge ne relaie JAMAIS
    /// lui-même vers Internet — il délègue au chemin sortant natif, A10).
    submit_url: String,
    /// Domaines locaux connus du Bridge — MIROIR de `DIAMY_SUBMITD_LOCAL_DOMAINS` côté
    /// `diamy-submitd` (défaut `w3.tel`). Sert à rejeter un destinataire externe DÈS le `RCPT TO`
    /// (RFC 5321 : rejeter au plus tôt quand on sait que le destinataire ne sera jamais accepté),
    /// plutôt que d'accepter la commande puis découvrir le rejet après le `DATA` (mauvaise UX
    /// côté client : "Envoi..." bloqué). Comparaison insensible à la casse, sans le `.` de tête.
    local_domains: Vec<String>,
}

impl BridgeConfig {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        // A20-NET-1 (non négociable) : ces variables ne portent QUE le port — l'IP est
        // TOUJOURS 127.0.0.1, câblée en dur ci-dessous. Aucune variable d'environnement, aucun
        // flag ne permet d'élargir l'écoute à une interface routable. Une variable PAR port
        // (plutôt qu'une adresse "ip:port" dont seul le port compterait) permet de lancer
        // plusieurs instances du Bridge en parallèle — une par utilisateur de démo — chacune
        // sur ses propres ports IMAP/SMTP (voir DEMO_GUIDE.md "Plusieurs comptes de démo").
        let port: u16 = std::env::var("DIAMY_BRIDGED_IMAP_PORT")
            .unwrap_or_else(|_| "1143".to_string())
            .parse()
            .map_err(|_| "DIAMY_BRIDGED_IMAP_PORT invalide (attendu un port numérique)")?;
        let smtp_port: u16 = std::env::var("DIAMY_BRIDGED_SMTP_PORT")
            .unwrap_or_else(|_| "1587".to_string())
            .parse()
            .map_err(|_| "DIAMY_BRIDGED_SMTP_PORT invalide (attendu un port numérique)")?;

        Ok(Self {
            imap_bind_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            smtp_bind_addr: SocketAddr::from(([127, 0, 0, 1], smtp_port)),
            imap_user: std::env::var("DIAMY_BRIDGED_IMAP_USER")
                .unwrap_or_else(|_| "hugo@w3.tel".to_string()),
            imap_password: std::env::var("DIAMY_BRIDGED_IMAP_PASSWORD")
                .unwrap_or_else(|_| "devonly_change_me_bridge_password".to_string()),
            sync_base: std::env::var("DIAMY_MAILD_SYNC_URL")
                .unwrap_or_else(|_| "https://127.0.0.1:8443".to_string()),
            // A20-CRED-5 : AppKey Tier 2 PROPRE au Bridge, distincte de celle du client natif
            // de test — doit correspondre à `DIAMY_MAILD_DEV_BRIDGE_APPKEY` côté `diamy-maild`
            // ET à `DIAMY_SUBMITD_DEV_BRIDGE_APPKEY` côté `diamy-submitd` (MÊME valeur de
            // secret, A20-CRED-5 : "MUST send it on every request to diamy-maild/diamy-submitd").
            app_key: std::env::var("DIAMY_MAILD_DEV_BRIDGE_APPKEY")
                .unwrap_or_else(|_| "devonly_change_me_appkey_bridge_dev_client".to_string()),
            submit_url: std::env::var("DIAMY_SUBMITD_SUBMIT_URL")
                .unwrap_or_else(|_| "https://127.0.0.1:8446/submit".to_string()),
            local_domains: std::env::var("DIAMY_BRIDGED_LOCAL_DOMAINS")
                .unwrap_or_else(|_| "w3.tel".to_string())
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }

    /// Un destinataire de ce domaine est-il relayable en boucle fermée (local) ? Si NON, le
    /// Bridge le rejette dès le `RCPT TO` — le relais externe est désactivé en maquette (décision
    /// de Cédric ; voir `diamy-submitd`). Même règle de comparaison que `SubmitdConfig`.
    fn is_local_domain(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        self.local_domains.iter().any(|d| d == &domain)
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
    /// A04 §3/§5.3 : état réel serveur-autoritaire (`mail.messages.state_flags`), lu à CHAQUE
    /// interrogation du catalogue (`fetch_mailbox_catalog`) — jamais un cache qui remplacerait
    /// l'appel réseau (voir `cmd_store`/`cmd_expunge`).
    #[serde(default)]
    read: bool,
    #[serde(default)]
    deleted: bool,
}

/// Rendu IMAP des flags supportés par cette V1 (périmètre explicite : `\Seen`/`\Deleted`
/// uniquement, voir `SIMPLIFICATIONS.md`) — factorisé pour FETCH FLAGS et les réponses FETCH
/// non-SILENT de STORE, qui doivent afficher exactement la même chose.
fn render_flags(read: bool, deleted: bool) -> String {
    let mut parts = Vec::new();
    if read {
        parts.push("\\Seen");
    }
    if deleted {
        parts.push("\\Deleted");
    }
    parts.join(" ")
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

    // Point 2 : registre d'UID stables PERSISTÉS, partagé par toutes les connexions IMAP. Vit
    // côté Bridge (notion propre au protocole IMAP), sous `bridge_state/` par défaut.
    let uid_state_dir = std::env::var("DIAMY_BRIDGED_UID_STATE_DIR")
        .unwrap_or_else(|_| DEFAULT_UID_STATE_DIR.to_string());
    let uid_registry = Arc::new(UidRegistry::new(PathBuf::from(uid_state_dir)));

    // A20-SMTP-1 : écoute SMTP locale du Bridge, MÊME discipline loopback-only que l'IMAP
    // ci-dessus (A20-ARCH-2/NET-1/2) — bind puis re-vérification fail-closed AVANT de servir.
    let smtp_listener = TcpListener::bind(config.smtp_bind_addr).await?;
    let smtp_local_addr = smtp_listener.local_addr()?;
    if !smtp_local_addr.ip().is_loopback() {
        obs.events.with_label_values(&["diamy-bridged", "smtp_startup_refusal_nonloopback"]).inc();
        return Err(format!(
            "refus de démarrer le serveur SMTP (A20-NET-2) : {smtp_local_addr} n'est PAS une adresse loopback"
        )
        .into());
    }
    println!("== diamy-bridged : SMTP sur {smtp_local_addr} (loopback uniquement, A20-SMTP-1) ==");
    tracing::info!(addr = %smtp_local_addr, "diamy-bridged : serveur SMTP démarré (loopback uniquement)");

    {
        let config = config.clone();
        let http = http.clone();
        let obs = obs.clone();
        tokio::spawn(async move {
            loop {
                let (socket, peer) = match smtp_listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "échec accept() SMTP");
                        continue;
                    }
                };
                // A20-NET-3 (défense en profondeur) : même vérification par-pair que l'IMAP.
                if !peer.ip().is_loopback() {
                    tracing::warn!(%peer, "connexion SMTP refusée : pair non-loopback (A20-NET-3)");
                    obs.events.with_label_values(&["diamy-bridged", "smtp_nonloopback_peer_refusal"]).inc();
                    drop(socket);
                    continue;
                }
                obs.events.with_label_values(&["diamy-bridged", "smtp_session_started"]).inc();
                let config = config.clone();
                let http = http.clone();
                let obs = obs.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_smtp_connection(socket, config, http, obs).await {
                        tracing::warn!(%peer, error = %e, "session SMTP interrompue");
                    }
                });
            }
        });
    }

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
        let uid_registry = uid_registry.clone();
        let obs = obs.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, config, http, uid_registry, obs).await {
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

/// Boîte "INBOX" sélectionnée : instantané du catalogue au moment du SELECT, avec des UID
/// STABLES et PERSISTÉS (Point 2 — plus des positions 1..N recalculées à chaque fetch). Chaque
/// UID vient de `UidRegistry` et ne bouge JAMAIS de la vie du message ; le Vec est trié par UID
/// croissant (== ordre chronologique d'arrivée), donc le numéro de séquence IMAP (position 1..N
/// dans ce Vec) reste cohérent avec l'ordre des UID (RFC 3501 : UID strictement croissants).
struct SelectedMailbox {
    messages: Vec<(u32, MessageSummaryDto)>, // (uid stable, résumé)
}

struct Session {
    authed: Option<AuthedSession>,
    mailbox: Option<SelectedMailbox>,
}

/// Vue d'une boîte fraîchement tirée du catalogue de `diamy-maild`, avec ses UID stables
/// résolus. Portée par `fetch_mailbox_catalog` vers `cmd_select`/`cmd_status`/`cmd_noop`.
struct MailboxView {
    /// RFC 3501 §2.3.1.1 — constante tant que les UID sont stables (voir `MailboxUidState`).
    uid_validity: u32,
    /// UID qui sera attribué au PROCHAIN nouveau message (`UIDNEXT`) — jamais `count + 1`, car
    /// un EXPUNGE laisse des trous : `uid_next` reste strictement au-dessus de tout UID déjà vu.
    uid_next: u32,
    messages: Vec<(u32, MessageSummaryDto)>, // (uid stable, résumé), trié par UID croissant
}

// ============================ Point 2 : UID stables et persistés =============================
//
// **Constat de l'audit** : les UID étaient POSITIONNELS (position 1..N recalculée à chaque
// `fetch_mailbox_catalog`), alors qu'`UIDVALIDITY` restait fixe = 1. C'est contradictoire avec
// la RFC 3501 §2.3.1.1 : une `UIDVALIDITY` constante PROMET des UID stables qu'un vrai client
// peut mettre en cache entre sessions. Scénario de bug : après un EXPUNGE retirant un message du
// milieu, les suivants glissaient, et un nouveau message pouvait hériter de l'UID qu'un client
// avait mis en cache pour un AUTRE message — une action ultérieure aurait touché le mauvais.
//
// **Correction (option a de l'audit)** : une table de correspondance PERSISTÉE `message_id`
// (identité stable, déjà utilisée partout) → UID IMAP stable, par principal/mailbox, avec un
// compteur `uid_next` STRICTEMENT croissant (un UID libéré n'est JAMAIS réattribué). C'est une
// notion propre au protocole IMAP (RFC 3501), pas une donnée métier zéro-accès du serveur : elle
// vit donc côté Bridge (fichier local sous `bridge_state/`), jamais dans `diamy-maild` — ce qui
// serait polluer le catalogue métier d'un artefact protocolaire (A20-IMAP-1 : le Bridge PRÉSENTE
// les messages comme de l'IMAP standard, c'est lui la couche protocole ; A04 identifie les
// messages par `message_id`, jamais par un UID IMAP).

/// État d'UID stable et persisté pour une (principal, mailbox=INBOX).
#[derive(Serialize, Deserialize, Clone)]
struct MailboxUidState {
    /// Fixée à la création de l'état (timestamp Unix). Bumpée UNIQUEMENT si l'état persisté est
    /// corrompu/absent/incohérent au chargement (secours : force un client à jeter son cache
    /// plutôt qu'à risquer une mauvaise correspondance). Stable sinon (RFC 3501 §2.3.1.1).
    uid_validity: u32,
    /// Prochain UID à attribuer — strictement croissant, JAMAIS décrémenté ni réutilisé.
    uid_next: u32,
    /// `message_id` → UID stable. Une entrée y RESTE même après purge (tombstone) : `uid_next`
    /// garantit déjà la non-réutilisation, et conserver l'entrée évite toute réattribution si un
    /// catalogue transitoirement incomplet réapparaissait.
    entries: std::collections::HashMap<Uuid, u32>,
}

impl MailboxUidState {
    /// Nouvel état frais : `uid_validity` = timestamp (monotone entre démarrages, donc
    /// strictement supérieur à tout état antérieur → un client jette bien son cache), compteur
    /// à 1, aucune correspondance.
    fn fresh() -> Self {
        Self { uid_validity: UidRegistry::fresh_validity(), uid_next: 1, entries: std::collections::HashMap::new() }
    }
}

/// Gère l'état d'UID persisté, PARTAGÉ entre toutes les connexions IMAP du process (un client
/// tiers peut ouvrir plusieurs connexions). Écrit-au-travers sur disque à chaque nouvel UID
/// attribué : c'est cette persistance CROSS-SESSION qui rend les UID vraiment stables (RFC
/// 3501), pas seulement le temps d'une connexion.
struct UidRegistry {
    dir: PathBuf,
    cache: tokio::sync::Mutex<std::collections::HashMap<Uuid, MailboxUidState>>,
}

impl UidRegistry {
    fn new(dir: PathBuf) -> Self {
        Self { dir, cache: tokio::sync::Mutex::new(std::collections::HashMap::new()) }
    }

    fn state_path(&self, principal_id: Uuid) -> PathBuf {
        self.dir.join(format!("{principal_id}.INBOX.uidmap.json"))
    }

    /// `UIDVALIDITY` de secours : secondes Unix (u32). Monotone d'un démarrage à l'autre — un
    /// état recréé (fichier absent/corrompu) reçoit ainsi une validity STRICTEMENT supérieure à
    /// tout état antérieur, ce qui force un client à invalider son cache (RFC 3501 §2.3.1.1).
    fn fresh_validity() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(1)
            .max(1)
    }

    /// Vérifie la cohérence interne d'un état chargé — un état incohérent est traité comme
    /// corrompu (bump de secours) plutôt que servi tel quel (fail-safe).
    fn is_coherent(state: &MailboxUidState) -> bool {
        if state.uid_validity == 0 || state.uid_next < 1 {
            return false;
        }
        let mut seen = std::collections::HashSet::new();
        for &uid in state.entries.values() {
            // Tout UID attribué doit être dans [1, uid_next) et unique.
            if uid < 1 || uid >= state.uid_next || !seen.insert(uid) {
                return false;
            }
        }
        true
    }

    /// Charge l'état depuis le disque, ou en crée un frais (validity bumpée) si le fichier est
    /// absent, illisible, non parsable, ou incohérent — en cas de doute, on préfère forcer un
    /// cache-drop client à risquer une mauvaise correspondance d'UID.
    fn load_or_fresh(&self, principal_id: Uuid) -> MailboxUidState {
        let path = self.state_path(principal_id);
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<MailboxUidState>(&bytes) {
                Ok(state) if Self::is_coherent(&state) => state,
                Ok(_) => {
                    tracing::warn!(%principal_id, "état d'UID INCOHÉRENT — bump UIDVALIDITY (secours, RFC 3501)");
                    MailboxUidState::fresh()
                }
                Err(e) => {
                    tracing::warn!(%principal_id, error = %e, "état d'UID CORROMPU — bump UIDVALIDITY (secours)");
                    MailboxUidState::fresh()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => MailboxUidState::fresh(),
            Err(e) => {
                tracing::warn!(%principal_id, error = %e, "lecture état d'UID échouée — bump UIDVALIDITY (secours)");
                MailboxUidState::fresh()
            }
        }
    }

    /// Écrit l'état sur disque (best-effort : un échec est loggué mais n'interrompt pas la
    /// session — un UID non persisté redeviendra simplement "nouveau" au prochain démarrage, ce
    /// que le bump d'`UIDVALIDITY` couvre déjà côté client).
    fn persist(&self, principal_id: Uuid, state: &MailboxUidState) {
        let path = self.state_path(principal_id);
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::warn!(%principal_id, error = %e, "création du répertoire d'état d'UID échouée");
                return;
            }
        }
        match serde_json::to_vec_pretty(state) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&path, &bytes) {
                    tracing::warn!(%principal_id, error = %e, "persistance de l'état d'UID échouée");
                }
            }
            Err(e) => tracing::warn!(%principal_id, error = %e, "sérialisation de l'état d'UID échouée"),
        }
    }

    /// Résout les UID stables des `message_ids` reçus DANS L'ORDRE (chronologique ascendant : le
    /// plus ancien nouveau message reçoit le plus petit nouvel UID). Attribue un UID neuf
    /// (`uid_next`, puis incrémenté) à chaque `message_id` inconnu, réutilise l'UID mémorisé
    /// pour les autres — jamais une position recalculée. Persiste si de nouveaux UID sont créés.
    /// Retourne `(uid_validity, uid_next, uids alignés à message_ids)`.
    async fn resolve(&self, principal_id: Uuid, message_ids: &[Uuid]) -> (u32, u32, Vec<u32>) {
        let mut cache = self.cache.lock().await;
        let state = cache
            .entry(principal_id)
            .or_insert_with(|| self.load_or_fresh(principal_id));

        let mut changed = false;
        let mut uids = Vec::with_capacity(message_ids.len());
        for &mid in message_ids {
            let uid = match state.entries.get(&mid) {
                Some(&u) => u,
                None => {
                    let u = state.uid_next;
                    // Strictement croissant, jamais réutilisé — même après purge d'anciens UID.
                    state.uid_next = state.uid_next.saturating_add(1);
                    state.entries.insert(mid, u);
                    changed = true;
                    u
                }
            };
            uids.push(uid);
        }
        if changed {
            self.persist(principal_id, state);
        }
        (state.uid_validity, state.uid_next, uids)
    }
}

async fn handle_connection(
    socket: TcpStream,
    config: Arc<BridgeConfig>,
    http: reqwest::Client,
    uid_registry: Arc<UidRegistry>,
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
                    cmd_select(&mut reader, &config, &http, &uid_registry, &mut session, &tag).await?
                } else {
                    format!("{tag} NO seule INBOX existe (V1 démo)\r\n")
                }
            }
            "FETCH" => cmd_fetch(&mut reader, &config, &http, &session, &tag, args, false).await?,
            "STORE" => cmd_store(&mut reader, &config, &http, &mut session, &tag, args, false).await?,
            "EXPUNGE" => cmd_expunge(&mut reader, &config, &http, &mut session, &tag).await?,
            "UID" => {
                let mut uid_parts = args.splitn(2, char::is_whitespace);
                let sub = uid_parts.next().unwrap_or("").to_ascii_uppercase();
                let sub_args = uid_parts.next().unwrap_or("").trim();
                if sub == "FETCH" {
                    cmd_fetch(&mut reader, &config, &http, &session, &tag, sub_args, true).await?
                } else if sub == "STORE" {
                    cmd_store(&mut reader, &config, &http, &mut session, &tag, sub_args, true).await?
                } else {
                    format!("{tag} BAD sous-commande UID non supportée\r\n")
                }
            }
            "NOOP" => {
                cmd_noop(&mut reader, &config, &http, &uid_registry, &mut session).await?;
                String::new()
            }
            "STATUS" => cmd_status(&mut reader, &config, &http, &uid_registry, &session, &tag, args).await?,
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

/// Authentifie le compte de démo préconfiguré et charge tout ce qu'il faut pour parler à
/// `diamy-maild`/`diamy-submitd` comme un vrai appareil (A20-ARCH-1) — factorisé pour être
/// PARTAGÉ entre `LOGIN` (IMAP) et `AUTH` (SMTP, A20-SMTP-1) : les deux protocoles
/// authentifient le MÊME compte de démo unique (A20-CRED-1 simplifié, voir SIMPLIFICATIONS.md).
fn authenticate_bridge_account(config: &BridgeConfig, user: &str, pass: &str) -> Result<AuthedSession, String> {
    // A20-CRED-1 (simplifié, documenté) : un seul compte préconfiguré, PAS un mot de passe
    // Bridge révocable par client — voir SIMPLIFICATIONS.md.
    if user != config.imap_user || pass != config.imap_password {
        return Err("identifiants invalides".to_string());
    }

    let iam = DevIamClient::seeded();
    let canonical =
        diamy_addr_canon(user, TenantAddressPolicy::default()).map_err(|e| format!("adresse invalide : {e}"))?;
    let principal = iam
        .resolve_principal(canonical.as_str())
        .map_err(|_| "principal introuvable".to_string())?;

    let secret_path = bridge_dev_secret_path(canonical.as_str());
    let (device_id, device_sec) =
        load_device_secret(&secret_path).map_err(|e| format!("clé de l'appareil Bridge introuvable : {e}"))?;

    let mail_plane_token = load_fixture_mail_plane_token(principal.id).map_err(|e| e.to_string())?;

    Ok(AuthedSession { principal, device_id, device_sec, mail_plane_token })
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

    match authenticate_bridge_account(config, user, pass) {
        Ok(authed) => {
            session.authed = Some(authed);
            Ok(format!("{tag} OK LOGIN completed\r\n"))
        }
        Err(e) => Ok(format!("{tag} NO {e}\r\n")),
    }
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

/// Interroge FRAÎCHEMENT diamy-maild et reconstruit la liste des messages avec leurs UID
/// STABLES (Point 2 — plus une position 1..N recalculée) — appelée à CHAQUE SELECT/STATUS/NOOP,
/// JAMAIS mise en cache d'une commande à l'autre. C'est cette re-interrogation systématique qui
/// garantit qu'un mail arrivé pendant que la connexion IMAP reste ouverte est vu à la prochaine
/// commande, sans avoir à fermer/rouvrir la session. `context` identifie l'appelant dans les
/// logs debug (visible avec RUST_LOG=diamy_bridged=debug). Les UID viennent du `UidRegistry`
/// persisté : un message garde son UID toute sa vie, un nouveau message reçoit un UID neuf
/// jamais réutilisé.
async fn fetch_mailbox_catalog(
    config: &BridgeConfig,
    http: &reqwest::Client,
    uid_registry: &UidRegistry,
    authed: &AuthedSession,
    context: &str,
) -> Result<MailboxView, String> {
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

    // Le catalogue serveur est trié DESC par `received_at` (`list_recent_messages`) — on inverse
    // pour obtenir l'ordre chronologique ASCENDANT : c'est cet ordre qui détermine l'attribution
    // des NOUVEAUX UID (le plus ancien nouveau message reçoit le plus petit nouvel UID). Les
    // messages déjà connus, eux, gardent l'UID mémorisé quelle que soit leur position.
    let mut ascending = messages;
    ascending.reverse();

    // Résolution des UID STABLES via le registre persisté (Point 2). Un message déjà vu garde
    // EXACTEMENT son UID ; un nouveau message reçoit `uid_next`, jamais une position recalculée.
    let message_ids: Vec<Uuid> = ascending.iter().map(|m| m.message_id).collect();
    let (uid_validity, uid_next, uids) = uid_registry.resolve(authed.principal.id, &message_ids).await;

    // Trie par UID croissant : le numéro de séquence IMAP (position 1..N dans ce Vec) doit
    // rester cohérent avec l'ordre des UID (RFC 3501 : UID strictement croissants avec la
    // séquence). L'ordre chronologique le garantit déjà en pratique, mais on n'en dépend pas.
    let mut numbered: Vec<(u32, MessageSummaryDto)> = uids.into_iter().zip(ascending).collect();
    numbered.sort_by_key(|(uid, _)| *uid);

    Ok(MailboxView { uid_validity, uid_next, messages: numbered })
}

async fn cmd_select<S>(
    reader: &mut BufReader<S>,
    config: &BridgeConfig,
    http: &reqwest::Client,
    uid_registry: &UidRegistry,
    session: &mut Session,
    tag: &str,
) -> std::io::Result<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Some(authed) = &session.authed else {
        return Ok(format!("{tag} NO not authenticated\r\n"));
    };

    let view = match fetch_mailbox_catalog(config, http, uid_registry, authed, "SELECT").await {
        Ok(v) => v,
        Err(e) => return Ok(format!("{tag} NO {e}\r\n")),
    };
    let count = view.messages.len() as u32;
    let (uid_validity, uid_next) = (view.uid_validity, view.uid_next);
    session.mailbox = Some(SelectedMailbox { messages: view.messages });

    write_logged(reader, &format!("* {count} EXISTS\r\n")).await?;
    write_logged(reader, "* 0 RECENT\r\n").await?;
    // A04 §5.3/§6 réel désormais câblé (STORE/EXPUNGE) : \Seen/\Deleted sont de VRAIS flags
    // persistés côté serveur (mail.messages.state_flags), plus un stand-in en lecture seule.
    write_logged(reader, "* FLAGS (\\Seen \\Deleted)\r\n").await?;
    write_logged(reader, "* OK [PERMANENTFLAGS (\\Seen \\Deleted)] flags reels (A04 §5.3)\r\n").await?;
    // UIDVALIDITY stable (Point 2) et UIDNEXT = prochain UID à attribuer (jamais `count + 1` :
    // un EXPUNGE laisse des trous, `uid_next` reste strictement au-dessus de tout UID déjà vu).
    write_logged(reader, &format!("* OK [UIDVALIDITY {uid_validity}]\r\n")).await?;
    write_logged(reader, &format!("* OK [UIDNEXT {uid_next}]\r\n")).await?;
    Ok(format!("{tag} OK [READ-WRITE] SELECT completed\r\n"))
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
    uid_registry: &UidRegistry,
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

    let view = match fetch_mailbox_catalog(config, http, uid_registry, authed, "STATUS").await {
        Ok(v) => v,
        Err(e) => return Ok(format!("{tag} NO {e}\r\n")),
    };
    let count = view.messages.len() as u32;

    // A04 §3/§5.3 réel : UNSEEN reflète maintenant l'état SERVEUR (mail.messages.state_flags),
    // pas une valeur figée — recalculé à chaque STATUS depuis le catalogue fraîchement tiré.
    let unseen_count = view.messages.iter().filter(|(_, m)| !m.read).count() as u32;

    let requested = items_raw.trim_start_matches('(').trim_end_matches(')');
    let mut parts: Vec<String> = Vec::new();
    for tok in requested.split_whitespace() {
        match tok.to_ascii_uppercase().as_str() {
            "MESSAGES" => parts.push(format!("MESSAGES {count}")),
            "RECENT" => parts.push("RECENT 0".to_string()),
            // UIDNEXT stable (Point 2) : prochain UID à attribuer, jamais `count + 1`.
            "UIDNEXT" => parts.push(format!("UIDNEXT {}", view.uid_next)),
            "UIDVALIDITY" => parts.push(format!("UIDVALIDITY {}", view.uid_validity)),
            "UNSEEN" => parts.push(format!("UNSEEN {unseen_count}")),
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
    uid_registry: &UidRegistry,
    session: &mut Session,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if session.authed.is_none() || session.mailbox.is_none() {
        return Ok(());
    }
    let authed = session.authed.as_ref().expect("vérifié ci-dessus");
    let view = match fetch_mailbox_catalog(config, http, uid_registry, authed, "NOOP").await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "NOOP : échec du rafraîchissement du catalogue");
            return Ok(());
        }
    };
    let new_count = view.messages.len() as u32;
    let old_count = session.mailbox.as_ref().map(|m| m.messages.len() as u32).unwrap_or(0);
    session.mailbox = Some(SelectedMailbox { messages: view.messages });
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
    // UID FETCH : le set porte des UID, PAS des numéros de séquence — depuis le Point 2 les UID
    // sont stables et ne valent plus `1..count` (un EXPUNGE laisse des trous, un nouveau message
    // peut avoir un UID > count). On borne donc à l'UID MAXIMAL présent, pas au nombre de
    // messages ; les UID absents seront de toute façon ignorés par le `find` ci-dessous.
    let max_uid = mailbox.messages.iter().map(|(u, _)| *u).max().unwrap_or(0);
    let selected_numbers = if is_uid {
        parse_number_set(set_spec, max_uid)
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
                FetchItem::Flags => attrs.push(format!("FLAGS ({})", render_flags(summary.read, summary.deleted))),
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

#[derive(Debug, Clone, Copy)]
enum StoreMode {
    Set,
    Add,
    Remove,
}

/// Parse `STORE`/`UID STORE`'s arguments : `<set> <[+/-]FLAGS[.SILENT]> <flag-list>`. Le
/// grammaire RFC 3501 §9 autorise la liste de flags SOIT entre parenthèses SOIT nue
/// (espace-séparée) — les deux formes sont acceptées ici (Postel's law côté serveur, même
/// esprit que `parse_fetch_items`).
fn parse_store_args(args: &str) -> Option<(String, StoreMode, bool, Vec<String>)> {
    let mut top = args.splitn(3, char::is_whitespace);
    let set_spec = top.next()?.to_string();
    let item = top.next()?;
    let rest = top.next().unwrap_or("").trim();

    let item_upper = item.to_ascii_uppercase();
    let (mode, base): (StoreMode, &str) = if let Some(b) = item_upper.strip_prefix('+') {
        (StoreMode::Add, b)
    } else if let Some(b) = item_upper.strip_prefix('-') {
        (StoreMode::Remove, b)
    } else {
        (StoreMode::Set, item_upper.as_str())
    };
    let base = base.strip_suffix(".SILENT").unwrap_or(base);
    let silent = item_upper.ends_with(".SILENT");
    if base != "FLAGS" {
        return None;
    }
    let flags_str = rest.trim_start_matches('(').trim_end_matches(')');
    let flags = flags_str.split_whitespace().map(|s| s.to_string()).collect();
    Some((set_spec, mode, silent, flags))
}

/// `STORE`/`UID STORE` (RFC 3501 §6.4.6) — périmètre EXPLICITE de cette tranche : seuls
/// `\Seen`/`\Deleted` sont reconnus (voir `SIMPLIFICATIONS.md`) ; tout autre flag dans la liste
/// du client est syntaxiquement accepté mais ignoré (Postel's law), jamais une erreur bloquante.
///
/// CHAQUE message affecté déclenche un VRAI appel réseau `POST /state/flags` avec une clé
/// d'idempotence FRAÎCHE (UUIDv7, A04-IDEM-1) — jamais un cache local qui remplacerait cet
/// appel (exigence explicite de cette tranche) : c'est ce qui rend le flag visible depuis une
/// AUTRE session/connexion IMAP sur le même principal (A04 §3, preuve du test multi-connexion).
#[allow(clippy::too_many_arguments)]
async fn cmd_store<S>(
    reader: &mut BufReader<S>,
    config: &BridgeConfig,
    http: &reqwest::Client,
    session: &mut Session,
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
    let Some(mailbox) = &mut session.mailbox else {
        return Ok(format!("{tag} NO aucune boite selectionnee\r\n"));
    };

    let Some((set_spec, mode, silent, flags)) = parse_store_args(args) else {
        return Ok(format!("{tag} BAD STORE : arguments invalides\r\n"));
    };
    let wants_seen = flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen"));
    let wants_deleted = flags.iter().any(|f| f.eq_ignore_ascii_case("\\Deleted"));
    if !wants_seen && !wants_deleted {
        // Aucun flag reconnu dans cette V1 (\Seen/\Deleted uniquement) : rien à envoyer au
        // serveur, mais ce n'est pas une erreur (Postel's law) — juste un STORE sans effet ici.
        return Ok(format!("{tag} OK {} completed\r\n", if is_uid { "UID STORE" } else { "STORE" }));
    }

    let count = mailbox.messages.len() as u32;
    // UID STORE : comme UID FETCH, borner à l'UID maximal présent (Point 2 : UID stables, plus
    // `1..count`) et non au nombre de messages, sinon un STORE sur un UID > count serait ignoré.
    let max_uid = mailbox.messages.iter().map(|(u, _)| *u).max().unwrap_or(0);
    let selected_numbers = parse_number_set(&set_spec, if is_uid { max_uid } else { count });

    let mut fetch_lines: Vec<String> = Vec::new();
    for n in selected_numbers {
        let idx = if is_uid {
            mailbox.messages.iter().position(|(u, _)| *u == n)
        } else if n >= 1 && n <= count {
            Some((n - 1) as usize)
        } else {
            None
        };
        let Some(idx) = idx else { continue };
        let (uid, summary) = mailbox.messages[idx].clone();
        let seq = (idx + 1) as u32;

        let new_read = match mode {
            StoreMode::Set => wants_seen,
            StoreMode::Add => summary.read || wants_seen,
            StoreMode::Remove => {
                if wants_seen {
                    false
                } else {
                    summary.read
                }
            }
        };
        let new_deleted = match mode {
            StoreMode::Set => wants_deleted,
            StoreMode::Add => summary.deleted || wants_deleted,
            StoreMode::Remove => {
                if wants_deleted {
                    false
                } else {
                    summary.deleted
                }
            }
        };

        // A04-IDEM-1 : une clé FRAÎCHE par requête mutante — jamais réutilisée entre messages
        // ni entre commandes, sinon le serveur dédupliquerait à tort des mutations distinctes.
        let idempotency_key = Uuid::now_v7();
        let mut body = serde_json::Map::new();
        body.insert("message_id".to_string(), serde_json::json!(summary.message_id));
        body.insert("idempotency_key".to_string(), serde_json::json!(idempotency_key));
        // Seul le champ EFFECTIVEMENT demandé par le client est envoyé (A04-EP-4bis : delta
        // par champ, jamais un "remise à false" implicite du champ non concerné).
        if wants_seen {
            body.insert("read".to_string(), serde_json::json!(new_read));
        }
        if wants_deleted {
            body.insert("deleted".to_string(), serde_json::json!(new_deleted));
        }

        let url = format!(
            "{}/v1/mailbox/{}/state/flags",
            config.sync_base, authed.principal.id
        );
        let resp = auth_headers(http.post(&url), config, &authed.mail_plane_token)
            .json(&serde_json::Value::Object(body))
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => {
                tracing::debug!(message_id = %summary.message_id, %new_read, %new_deleted, "STORE : /state/flags applique");
            }
            Ok(r) => {
                tracing::warn!(status = %r.status(), message_id = %summary.message_id, "STORE : echec /state/flags, message inchange");
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, message_id = %summary.message_id, "STORE : echec reseau /state/flags, message inchange");
                continue;
            }
        }

        // Le mutation a été acceptée par le serveur : on met à jour le cache de SESSION (pas un
        // remplacement de l'appel réseau, juste la cohérence immédiate pour un EXPUNGE/FETCH
        // FLAGS qui suivrait sans NOOP/SELECT intermédiaire).
        mailbox.messages[idx].1.read = new_read;
        mailbox.messages[idx].1.deleted = new_deleted;

        if !silent {
            let flags_rendered = render_flags(new_read, new_deleted);
            let attrs = if is_uid {
                format!("UID {uid} FLAGS ({flags_rendered})")
            } else {
                format!("FLAGS ({flags_rendered})")
            };
            fetch_lines.push(format!("* {seq} FETCH ({attrs})\r\n"));
        }
    }

    for line in &fetch_lines {
        write_logged(reader, line).await?;
    }
    Ok(format!("{tag} OK {} completed\r\n", if is_uid { "UID STORE" } else { "STORE" }))
}

/// `EXPUNGE` (RFC 3501 §6.4.3) — purge (mode `"hard"`, A04 v1.4 changelog) chaque message
/// `\Deleted` de la boîte SÉLECTIONNÉE via un VRAI appel réseau `POST /state/delete`, puis émet
/// les réponses non taguées `* n EXPUNGE` requises. Numérotation : RFC 3501 exige qu'après
/// chaque EXPUNGE annoncé dans la MÊME commande, les numéros de séquence suivants soient déjà
/// décrémentés comme si ce message avait disparu — on traite donc du plus petit au plus grand
/// numéro ORIGINAL et on décrémente par le compte déjà annoncé (`i` ci-dessous), jamais le
/// numéro brut.
async fn cmd_expunge<S>(
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
    let Some(mailbox) = &mut session.mailbox else {
        return Ok(format!("{tag} NO aucune boite selectionnee\r\n"));
    };

    // Numéros de séquence ORIGINAUX (avant toute décrémentation) des messages \Deleted, dans
    // l'ordre croissant (le Vec est déjà trié chronologiquement ascendant, uid == position ici).
    // La suppression est une opération de métadonnée liée au PRINCIPAL (A21 §2.2), pas à
    // l'appareil — aucun `device_id` n'est nécessaire dans le corps de `/state/delete`.
    let to_expunge: Vec<(usize, Uuid)> = mailbox
        .messages
        .iter()
        .enumerate()
        .filter(|(_, (_, m))| m.deleted)
        .map(|(idx, (_, m))| (idx, m.message_id))
        .collect();

    let mut expunged_indices = Vec::new();
    let mut lines = Vec::new();
    for (i, (idx, message_id)) in to_expunge.iter().enumerate() {
        let idempotency_key = Uuid::now_v7();
        let body = serde_json::json!({
            "message_id": message_id,
            "idempotency_key": idempotency_key,
            "mode": "hard",
        });
        let url = format!(
            "{}/v1/mailbox/{}/state/delete",
            config.sync_base, authed.principal.id
        );
        let resp = auth_headers(http.post(&url), config, &authed.mail_plane_token)
            .json(&body)
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => {
                tracing::debug!(%message_id, "EXPUNGE : /state/delete (hard) applique");
            }
            Ok(r) => {
                tracing::warn!(status = %r.status(), %message_id, "EXPUNGE : echec /state/delete, message conserve");
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, %message_id, "EXPUNGE : echec reseau /state/delete, message conserve");
                continue;
            }
        }
        let original_seq = (*idx + 1) as u32;
        // Décrémenté par le nombre d'EXPUNGE DÉJÀ annoncés dans cette même commande (RFC 3501
        // §7.4.1 : chaque suppression décale immédiatement les numéros de séquence suivants).
        let adjusted_seq = original_seq - i as u32;
        lines.push(format!("* {adjusted_seq} EXPUNGE\r\n"));
        expunged_indices.push(*idx);
    }

    // Retire les entrées purgées du cache de session, du plus grand index au plus petit pour ne
    // pas invalider les index restants pendant la suppression.
    for idx in expunged_indices.iter().rev() {
        mailbox.messages.remove(*idx);
    }

    for line in &lines {
        write_logged(reader, line).await?;
    }
    Ok(format!("{tag} OK EXPUNGE completed\r\n"))
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

// ===========================================================================================
// SMTP (A20-SMTP-1) — le Bridge présente un point de soumission SMTP local, et relaie TOUJOURS
// via `diamy-submitd` (A04 `/submit` → A10) : "The Bridge does not bypass A10" (A20-SMTP-1).
// Jamais de relais SMTP direct vers Internet depuis ce processus — voir la doc de module de
// `diamy-submitd` pour la décision d'architecture précise (pas devinée, lue dans A20/A10/A23).
// ===========================================================================================

/// Extrait l'adresse entre `<` et `>` d'une commande `MAIL FROM:<...>` / `RCPT TO:<...>` —
/// même logique que `diamy-mxd::extract_addr` (fichier différent, mêmes règles SMTP).
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

struct SmtpSession {
    authed: Option<AuthedSession>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
}

/// Sessions non-authentifiées : borne défensive sur `MAIL FROM`/`RCPT TO` avant `AUTH` réussi,
/// pour ne jamais laisser une commande non bornée s'accumuler côté serveur (esprit INV-15).
fn require_auth(session: &SmtpSession) -> Option<&'static str> {
    if session.authed.is_none() {
        Some("530 authentification requise\r\n")
    } else {
        None
    }
}

/// Écrit une réponse SMTP sur le fil ET logue le texte EXACT envoyé, AVANT l'envoi — visible
/// avec `RUST_LOG=diamy_bridged=debug`. Miroir de `write_logged` (IMAP) : permet de tracer le
/// dialogue SMTP complet (chaque code de réponse posé sur le socket), notamment pour diagnostiquer
/// à quel moment précis un rejet intervient. INV-21 : on ne loggue QUE des lignes de protocole
/// (codes/textes de réponse), JAMAIS le corps `DATA` du message.
async fn smtp_write<S>(reader: &mut BufReader<S>, line: &str) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tracing::debug!(smtp_response = %line.trim_end(), "reponse SMTP envoyee au client (brute)");
    reader.get_mut().write_all(line.as_bytes()).await
}

async fn handle_smtp_connection(
    socket: TcpStream,
    config: Arc<BridgeConfig>,
    http: reqwest::Client,
    obs: Arc<diamy_obs::Obs>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(socket);
    smtp_write(&mut reader, "220 diamy-bridged ESMTP pret (A20-SMTP, demo)\r\n").await?;

    let mut session = SmtpSession { authed: None, mail_from: None, rcpt_to: Vec::new() };

    loop {
        let line = match read_line_bounded(&mut reader).await? {
            LineRead::Eof => return Ok(()),
            LineRead::TooLong => {
                smtp_write(&mut reader, "500 ligne trop longue\r\n").await?;
                continue;
            }
            LineRead::Line(l) => l,
        };
        let upper = line.to_ascii_uppercase();
        // Ligne de commande SMTP brute (EHLO/MAIL/RCPT/DATA/QUIT...), visible avec
        // RUST_LOG=diamy_bridged=debug. INV-21 : ce sont des commandes de protocole, JAMAIS le
        // corps `DATA` (lu séparément par `read_smtp_data_bounded`, jamais loggué).
        tracing::debug!(smtp_command = %line, "commande SMTP recue (brute)");

        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            smtp_write(&mut reader, "250-diamy-bridged\r\n250-AUTH LOGIN PLAIN\r\n250 SIZE 10485760\r\n").await?;
        } else if upper.starts_with("AUTH LOGIN") {
            cmd_auth_login(&mut reader, &config, &mut session).await?;
        } else if upper.starts_with("AUTH PLAIN") {
            cmd_auth_plain(&mut reader, &config, &mut session, line.trim_end()).await?;
        } else if upper.starts_with("MAIL FROM:") {
            if let Some(msg) = require_auth(&session) {
                smtp_write(&mut reader, msg).await?;
                continue;
            }
            match extract_addr(&line) {
                Some(addr) => {
                    session.mail_from = Some(addr);
                    session.rcpt_to.clear();
                    smtp_write(&mut reader, "250 OK\r\n").await?;
                }
                None => smtp_write(&mut reader, "501 syntaxe MAIL FROM invalide\r\n").await?,
            }
        } else if upper.starts_with("RCPT TO:") {
            if let Some(msg) = require_auth(&session) {
                smtp_write(&mut reader, msg).await?;
                continue;
            }
            if session.mail_from.is_none() {
                smtp_write(&mut reader, "503 MAIL FROM requis avant RCPT TO\r\n").await?;
                continue;
            }
            if session.rcpt_to.len() >= MAX_SMTP_RECIPIENTS {
                smtp_write(&mut reader, "452 trop de destinataires\r\n").await?;
                continue;
            }
            match extract_addr(&line).and_then(|raw| {
                diamy_addr_canon(&raw, TenantAddressPolicy::default()).ok().map(|c| c.as_str().to_string())
            }) {
                Some(canonical) => {
                    // Rejet DÈS le RCPT TO (RFC 5321 §3.6.1) si le domaine n'est pas local : le
                    // relais externe est désactivé en maquette (fail-closed, décision de Cédric),
                    // donc ce destinataire ne sera JAMAIS accepté — inutile de faire téléverser le
                    // DATA au client pour ne rejeter qu'ensuite (c'est ce qui laissait Thunderbird
                    // bloqué sur "Envoi..."). On choisit `550 5.7.1` (relais refusé/livraison non
                    // autorisée), le code canonique de "relaying denied" — permanent (5xx, pas de
                    // retry) et clairement affiché par les clients ; 551/553 conviendraient aussi
                    // mais 550 5.7.1 est le plus universellement reconnu pour un refus de relais.
                    let domain = canonical.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
                    if !config.is_local_domain(domain) {
                        tracing::info!(
                            %domain,
                            "RCPT TO REJETÉ dès le RCPT (relais externe désactivé en maquette)"
                        );
                        obs.events.with_label_values(&["diamy-bridged", "smtp_rcpt_rejected_external"]).inc();
                        smtp_write(
                            &mut reader,
                            &format!(
                                "550 5.7.1 relais externe desactive en maquette : le domaine \"{domain}\" \
                                 n'est pas local, aucun envoi vers l'exterieur n'est possible\r\n"
                            ),
                        )
                        .await?;
                        continue;
                    }
                    session.rcpt_to.push(canonical);
                    smtp_write(&mut reader, "250 OK\r\n").await?;
                }
                None => smtp_write(&mut reader, "501 adresse destinataire invalide\r\n").await?,
            }
        } else if upper.starts_with("DATA") {
            if let Some(msg) = require_auth(&session) {
                smtp_write(&mut reader, msg).await?;
                continue;
            }
            if session.rcpt_to.is_empty() {
                // Aucun destinataire ACCEPTÉ (p. ex. tous rejetés dès le RCPT TO ci-dessus) —
                // réponse dure immédiate, jamais une attente silencieuse.
                smtp_write(&mut reader, "554 5.5.1 aucun destinataire valide (tous refuses)\r\n").await?;
                continue;
            }
            smtp_write(&mut reader, "354 Terminez par <CRLF>.<CRLF>\r\n").await?;
            let read = read_smtp_data_bounded(&mut reader).await?;
            match read {
                SmtpDataOutcome::TooLarge => {
                    smtp_write(&mut reader, "552 message trop volumineux\r\n").await?;
                }
                SmtpDataOutcome::Body(mut raw_message) => {
                    obs.events.with_label_values(&["diamy-bridged", "smtp_submit_attempt"]).inc();
                    // INV-21 : jamais le contenu dans les logs — seulement des métadonnées.
                    tracing::info!(
                        recipients = session.rcpt_to.len(),
                        size_bytes = raw_message.len(),
                        "soumission SMTP recue, transmission a diamy-submitd (A10, pas de relais direct)"
                    );
                    let authed = session.authed.as_ref().expect("verifie par require_auth ci-dessus");
                    let mail_from = session.mail_from.clone().unwrap_or_default();
                    let outcome =
                        submit_via_diamy_submitd(&config, &http, authed, &mail_from, &session.rcpt_to, &raw_message)
                            .await;
                    raw_message.zeroize(); // A10-EMIT-1 esprit : le clair d'émission ne survit pas au-delà de l'usage
                    // Défense en profondeur : même si tous les destinataires externes sont
                    // désormais rejetés dès le RCPT TO, on garde une réponse SMTP explicite ici
                    // pour tout rejet que `diamy-submitd` prononcerait après coup — jamais une
                    // connexion laissée en attente sans réponse (exigence de la mission, point 4).
                    match outcome {
                        Ok(true) => {
                            obs.events.with_label_values(&["diamy-bridged", "smtp_submit_accepted"]).inc();
                            smtp_write(&mut reader, "250 message accepte pour relais (A10)\r\n").await?;
                        }
                        Ok(false) => {
                            obs.events.with_label_values(&["diamy-bridged", "smtp_submit_rejected"]).inc();
                            smtp_write(
                                &mut reader,
                                "550 5.7.1 relais refuse pour tous les destinataires (relais externe desactive en maquette)\r\n",
                            )
                            .await?;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "echec de la soumission vers diamy-submitd");
                            obs.events.with_label_values(&["diamy-bridged", "smtp_submit_error"]).inc();
                            smtp_write(
                                &mut reader,
                                "451 4.4.1 echec temporaire : diamy-submitd injoignable, reessayez\r\n",
                            )
                            .await?;
                        }
                    }
                }
            }
            session.mail_from = None;
            session.rcpt_to.clear();
        } else if upper.starts_with("RSET") {
            session.mail_from = None;
            session.rcpt_to.clear();
            smtp_write(&mut reader, "250 OK\r\n").await?;
        } else if upper.starts_with("NOOP") {
            smtp_write(&mut reader, "250 OK\r\n").await?;
        } else if upper.starts_with("QUIT") {
            smtp_write(&mut reader, "221 au revoir\r\n").await?;
            return Ok(());
        } else {
            smtp_write(&mut reader, "500 commande non reconnue\r\n").await?;
        }
    }
}

async fn cmd_auth_login<S>(
    reader: &mut BufReader<S>,
    config: &BridgeConfig,
    session: &mut SmtpSession,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    smtp_write(reader, "334 VXNlcm5hbWU6\r\n").await?; // "Username:"
    let user_b64 = match read_line_bounded(reader).await? {
        LineRead::Line(l) => l,
        _ => {
            smtp_write(reader, "501 authentification interrompue\r\n").await?;
            return Ok(());
        }
    };
    smtp_write(reader, "334 UGFzc3dvcmQ6\r\n").await?; // "Password:"
    let pass_b64 = match read_line_bounded(reader).await? {
        LineRead::Line(l) => l,
        _ => {
            smtp_write(reader, "501 authentification interrompue\r\n").await?;
            return Ok(());
        }
    };

    let (Ok(user_bytes), Ok(pass_bytes)) = (STANDARD.decode(user_b64.trim()), STANDARD.decode(pass_b64.trim()))
    else {
        smtp_write(reader, "501 base64 invalide\r\n").await?;
        return Ok(());
    };
    let user = String::from_utf8_lossy(&user_bytes).to_string();
    let pass = String::from_utf8_lossy(&pass_bytes).to_string();

    match authenticate_bridge_account(config, &user, &pass) {
        Ok(authed) => {
            session.authed = Some(authed);
            smtp_write(reader, "235 authentification reussie\r\n").await?;
        }
        Err(_) => smtp_write(reader, "535 identifiants invalides\r\n").await?,
    }
    Ok(())
}

async fn cmd_auth_plain<S>(
    reader: &mut BufReader<S>,
    config: &BridgeConfig,
    session: &mut SmtpSession,
    line: &str,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Deux formes valides (RFC 4954) : `AUTH PLAIN <b64>` en une ligne, ou `AUTH PLAIN` seul
    // suivi d'un défi `334 ` puis du `<b64>` sur la ligne suivante.
    let inline_b64 = line.splitn(3, char::is_whitespace).nth(2);
    let b64 = match inline_b64 {
        Some(b) if !b.is_empty() => b.to_string(),
        _ => {
            smtp_write(reader, "334 \r\n").await?;
            match read_line_bounded(reader).await? {
                LineRead::Line(l) => l,
                _ => {
                    smtp_write(reader, "501 authentification interrompue\r\n").await?;
                    return Ok(());
                }
            }
        }
    };

    let Ok(decoded) = STANDARD.decode(b64.trim()) else {
        smtp_write(reader, "501 base64 invalide\r\n").await?;
        return Ok(());
    };
    // RFC 4954 : `\0authzid\0authcid\0password` — on ignore `authzid`, on utilise `authcid`.
    let parts: Vec<&[u8]> = decoded.split(|b| *b == 0).collect();
    let Some((user_bytes, pass_bytes)) = parts.get(1).zip(parts.get(2)) else {
        smtp_write(reader, "501 format AUTH PLAIN invalide\r\n").await?;
        return Ok(());
    };
    let user = String::from_utf8_lossy(user_bytes).to_string();
    let pass = String::from_utf8_lossy(pass_bytes).to_string();

    match authenticate_bridge_account(config, &user, &pass) {
        Ok(authed) => {
            session.authed = Some(authed);
            smtp_write(reader, "235 authentification reussie\r\n").await?;
        }
        Err(_) => smtp_write(reader, "535 identifiants invalides\r\n").await?,
    }
    Ok(())
}

enum SmtpDataOutcome {
    Body(Vec<u8>),
    TooLarge,
}

/// Lit le corps `DATA` jusqu'au terminateur `<CRLF>.<CRLF>`, dot-unstuffing compris — même
/// discipline de borne que `diamy-mxd::read_data_bounded` (INV-15 : jamais une allocation
/// illimitée, même face à une seule ligne géante sans retour à la ligne).
async fn read_smtp_data_bounded<S>(reader: &mut BufReader<S>) -> std::io::Result<SmtpDataOutcome>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut body = Vec::new();
    let mut too_large = false;
    loop {
        let (content, line_too_long) = match read_line_bounded(reader).await? {
            LineRead::Eof => break,
            LineRead::TooLong => (String::new(), true),
            LineRead::Line(l) => (l, false),
        };
        if !line_too_long && content == "." {
            break;
        }
        too_large |= line_too_long;
        let unstuffed = content.strip_prefix('.').filter(|_| content.starts_with("..")).unwrap_or(&content);
        if !too_large {
            if body.len() + unstuffed.len() + 1 > MAX_SMTP_DATA_BYTES {
                too_large = true;
            } else {
                body.extend_from_slice(unstuffed.as_bytes());
                body.push(b'\n');
            }
        }
    }
    if too_large {
        body.zeroize();
        Ok(SmtpDataOutcome::TooLarge)
    } else {
        Ok(SmtpDataOutcome::Body(body))
    }
}

#[derive(Serialize)]
struct SubmitRequestBody<'a> {
    mail_from: &'a str,
    rcpt_to: &'a [String],
    message_b64: String,
}

#[derive(Deserialize)]
struct SubmitResponseBody {
    accepted: bool,
}

/// A20-SMTP-1 : transmet la soumission à `diamy-submitd` via `POST /submit` — le Bridge ne
/// parle JAMAIS SMTP sortant lui-même vers un destinataire réel (A10 n'est pas contourné).
/// Retourne `Ok(true)` si `diamy-submitd` a accepté (au moins un destinataire relayé),
/// `Ok(false)` s'il a répondu mais rejeté tous les destinataires, `Err` sur échec réseau/HTTP.
async fn submit_via_diamy_submitd(
    config: &BridgeConfig,
    http: &reqwest::Client,
    authed: &AuthedSession,
    mail_from: &str,
    rcpt_to: &[String],
    raw_message: &[u8],
) -> Result<bool, String> {
    let body = SubmitRequestBody { mail_from, rcpt_to, message_b64: STANDARD.encode(raw_message) };
    let resp = auth_headers(http.post(&config.submit_url), config, &authed.mail_plane_token)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("requete /submit echouee : {e}"))?;
    let status = resp.status();
    let parsed: SubmitResponseBody =
        resp.json().await.map_err(|e| format!("reponse /submit invalide (status {status}) : {e}"))?;
    Ok(parsed.accepted)
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

    // --- Point 2 : mécanique du registre d'UID stables (unitaire, sans réseau) ---------------

    fn tmp_registry() -> UidRegistry {
        UidRegistry::new(std::env::temp_dir().join(format!("diamy-uidreg-unit-{}", Uuid::now_v7())))
    }

    /// Cœur de la correction : un message garde son UID, un nouveau reçoit un compteur
    /// strictement croissant, et l'UID d'un message disparu n'est JAMAIS réattribué.
    #[tokio::test]
    async fn uids_are_stable_and_counter_is_monotonic() {
        let reg = tmp_registry();
        let p = Uuid::now_v7();
        let (a, b, c) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());

        let (_v, next, uids) = reg.resolve(p, &[a, b, c]).await;
        assert_eq!(uids, vec![1, 2, 3], "attribution dans l'ordre chronologique reçu");
        assert_eq!(next, 4, "UIDNEXT = prochain UID à attribuer");

        // Re-résolution partielle (B disparu, comme après un EXPUNGE) : A et C gardent leur UID.
        let (_v, next2, uids2) = reg.resolve(p, &[a, c]).await;
        assert_eq!(uids2, vec![1, 3], "A=1 et C=3 conservés, jamais recalculés par position");
        assert_eq!(next2, 4, "aucun nouvel UID attribué → compteur inchangé");

        // Un nouveau message D : reçoit 4 (jamais 2, l'UID libéré par B).
        let d = Uuid::now_v7();
        let (_v, next3, uids3) = reg.resolve(p, &[a, c, d]).await;
        assert_eq!(uids3, vec![1, 3, 4], "D reçoit un UID NEUF (4), jamais l'UID 2 de B");
        assert_eq!(next3, 5);
    }

    #[tokio::test]
    async fn uid_state_persists_across_registry_instances_same_dir() {
        let dir = std::env::temp_dir().join(format!("diamy-uidreg-persist-{}", Uuid::now_v7()));
        let p = Uuid::now_v7();
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());

        let (v1, _n, uids1) = UidRegistry::new(dir.clone()).resolve(p, &[a, b]).await;
        assert_eq!(uids1, vec![1, 2]);

        // Nouvelle instance, MÊME répertoire (simule un redémarrage) : UID ET validity conservés.
        let reg2 = UidRegistry::new(dir.clone());
        let (v2, _n, uids2) = reg2.resolve(p, &[a, b]).await;
        assert_eq!(uids2, vec![1, 2], "les UID survivent au redémarrage (persistance)");
        assert_eq!(v2, v1, "UIDVALIDITY stable entre démarrages tant que l'état est sain");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_or_incoherent_state_triggers_a_fresh_bump() {
        let reg = tmp_registry();
        let p = Uuid::now_v7();
        std::fs::create_dir_all(&reg.dir).unwrap();

        // Fichier illisible (JSON invalide) → état frais, jamais un panic ni une lecture douteuse.
        std::fs::write(reg.state_path(p), b"{ ceci n'est pas du json").unwrap();
        let fresh = reg.load_or_fresh(p);
        assert!(fresh.uid_validity > 0 && fresh.uid_next == 1 && fresh.entries.is_empty());

        // État syntaxiquement valide mais INCOHÉRENT (UID >= uid_next) → traité comme corrompu.
        let bad = MailboxUidState { uid_validity: 1, uid_next: 2, entries: [(Uuid::now_v7(), 5)].into_iter().collect() };
        assert!(!UidRegistry::is_coherent(&bad), "un UID hors [1, uid_next) est incohérent");
        let dup = MailboxUidState {
            uid_validity: 1,
            uid_next: 3,
            entries: [(Uuid::now_v7(), 1), (Uuid::now_v7(), 1)].into_iter().collect(),
        };
        assert!(!UidRegistry::is_coherent(&dup), "deux message_id partageant un UID est incohérent");
    }
}

/// Round-trip complet du chemin SORTANT (A20-SMTP-1 / A10, tranche démo) : un VRAI client SMTP
/// parle au VRAI serveur SMTP du Bridge (`handle_smtp_connection`, ce fichier) ; le Bridge
/// relaie via le VRAI routeur HTTPS de `diamy-submitd` (en-process, `diamy_submitd::router`,
/// dépendance de test sur la librairie du service — voir `Cargo.toml`) ; `diamy-submitd` relaie
/// via un VRAI dialogue SMTP (`relay.rs`) vers un VRAI processus `diamy-mxd` séparé (subprocess
/// du binaire déjà compilé — **AUCUNE modification du code de `diamy-mxd`**, conformément au
/// périmètre demandé) ; la réception est vérifiée en lisant DIRECTEMENT le même Postgres via
/// `diamy-mail-storage` et en déchiffrant avec la clé d'un appareil destinataire enrôlé par ce
/// test — même chemin de vérification (AAD, `unwrap_key`/`open_message`) que le reste du projet.
///
/// Prérequis (comme les autres tests d'intégration du dépôt, voir `SIMPLIFICATIONS.md`) :
/// Postgres de dev actif (`docker compose up`) ET `diamy-mxd` déjà compilé
/// (`cargo build --workspace` ou `cargo build -p diamy-mxd` au préalable — `cargo test
/// --workspace` le fait déjà en tant qu'effet de bord de la construction du workspace).
#[cfg(test)]
mod smtp_roundtrip_tests {
    use super::*;
    use diamy_mail_storage as storage;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;
    use tokio::io::AsyncBufReadExt;
    use tokio::io::BufReader as TokioBufReader;

    fn test_database_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://diamy:devonly_change_me@localhost:5433/diamymail".to_string())
    }

    /// Port libre choisi par l'OS, immédiatement relâché — même technique de test qu'ailleurs
    /// dans le projet (`127.0.0.1:0`), nécessaire ici car un SUBPROCESS ne peut pas nous
    /// renvoyer directement le port qu'il a choisi.
    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind port libre").local_addr().unwrap().port()
    }

    /// Répertoire d'état d'UID (Point 2) UNIQUE et jetable, hors du `bridge_state/` de dev — pour
    /// que chaque test parte d'un registre vierge et observe des UID déterministes.
    fn unique_uid_state_dir() -> PathBuf {
        std::env::temp_dir().join(format!("diamy-bridged-uidstate-{}", Uuid::now_v7()))
    }

    fn find_diamy_mxd_binary() -> PathBuf {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR fourni par cargo");
        let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
        let path = PathBuf::from(manifest_dir).join("../../target").join(profile).join("diamy-mxd");
        assert!(
            path.exists(),
            "binaire diamy-mxd introuvable à {} — lance `cargo build --workspace` (ou `-p diamy-mxd`) \
             avant ce test (ce test ne modifie ni ne recompile diamy-mxd, il l'exécute tel quel)",
            path.display()
        );
        path
    }

    /// Garde un handle sur le subprocess `diamy-mxd` réel — le tue à la fin du test (`Drop`),
    /// pour ne jamais laisser un serveur SMTP orphelin sur la machine de dev.
    struct MxdProcess {
        child: Child,
    }
    impl Drop for MxdProcess {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    async fn spawn_mxd_subprocess(smtp_port: u16, metrics_port: u16, database_url: &str) -> MxdProcess {
        let bin = find_diamy_mxd_binary();
        let child = Command::new(bin)
            .env("DIAMY_ENV", "dev")
            .env("DATABASE_URL", database_url)
            .env("DIAMY_MXD_SMTP_ADDR", format!("127.0.0.1:{smtp_port}"))
            .env("DIAMY_MXD_METRICS_ADDR", format!("127.0.0.1:{metrics_port}"))
            .env("DIAMY_MAILD_BLOB_DIR", "./blob_store")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("échec du lancement du subprocess diamy-mxd (binaire compilé ?)");
        // Enveloppé IMMÉDIATEMENT (avant toute attente) : si le port n'ouvre jamais et qu'on
        // panique ci-dessous, le `Drop` de `MxdProcess` tue quand même le subprocess — jamais
        // de processus zombie orphelin sur la machine de dev.
        let mut guard = MxdProcess { child };

        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", smtp_port)).await.is_ok() {
                return guard;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = guard.child.kill();
        let _ = guard.child.wait();
        panic!("diamy-mxd (subprocess) n'a jamais ouvert son port SMTP {smtp_port} à temps");
    }

    /// Enrôle un appareil BRIDGE pour `hugo@w3.tel` — même mécanisme que l'exemple Cargo
    /// `enroll_bridge_device` (écrase le fichier `*.bridge.devicekey` existant s'il y en a un,
    /// exactement comme relancer l'exemple le ferait), pour que ce test soit AUTONOME (pas de
    /// prérequis manuel avant `cargo test`).
    async fn ensure_bridge_device_enrolled(pool: &storage::PgPool, address: &str) {
        let iam = DevIamClient::seeded();
        let canonical = diamy_addr_canon(address, TenantAddressPolicy::default()).unwrap();
        let principal = iam.resolve_principal(canonical.as_str()).unwrap();

        let (identity_pub, identity_sec) = crypto::generate_identity_keypair().unwrap();
        let (mail_pub, mail_sec) = crypto::generate_device_keypair().unwrap();
        let device_id = Uuid::now_v7();
        let signature = crypto::sign_manifest(&identity_sec, &mail_pub.0).unwrap();
        storage::publish_device_bundle(
            pool,
            principal.id,
            device_id,
            &mail_pub.0,
            &signature.0,
            device_id,
            &identity_pub,
        )
        .await
        .unwrap();

        let secret_path = bridge_dev_secret_path(canonical.as_str());
        if let Some(dir) = secret_path.parent() {
            std::fs::create_dir_all(dir).unwrap();
        }
        let mut file_bytes = Vec::with_capacity(16 + mail_sec.as_bytes().len());
        file_bytes.extend_from_slice(device_id.as_bytes());
        file_bytes.extend_from_slice(mail_sec.as_bytes());
        std::fs::write(&secret_path, &file_bytes).unwrap();
    }

    /// Enrôle un appareil DESTINATAIRE de test — même mécanisme que
    /// `diamy-mxd::tests::enroll_device_for_test` (fichier différent, même logique : générer
    /// les clés localement, ne publier que la clé PUBLIQUE dans `keydir`).
    async fn enroll_recipient_device(
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

    /// Cherche, parmi les messages du destinataire, celui qui déchiffre (avec NOTRE clé
    /// d'appareil) sur un contenu contenant `marker` — jamais "le plus récent" (base partagée
    /// entre plusieurs tests/exemples), même discipline que le reste du projet.
    async fn find_own_message_by_marker(
        pool: &storage::PgPool,
        blob_store: &storage::BlobStore,
        principal_id: Uuid,
        device_id: Uuid,
        device_sec: &crypto::DeviceEncSecretKey,
        marker: &str,
    ) -> Option<String> {
        let messages = storage::list_recent_messages(pool, principal_id, 50).await.ok()?;
        for summary in messages {
            let fetched =
                storage::fetch_message_for_device(pool, blob_store, principal_id, summary.message_id, device_id)
                    .await
                    .ok()?;
            let envelope_aad = crypto::aad_for_envelope(summary.message_id, device_id);
            let Ok(message_key) = crypto::unwrap_key(&fetched.envelope, device_sec, &envelope_aad) else {
                continue;
            };
            let body_aad = crypto::aad_for_blob(summary.message_id, fetched.body_blob_id);
            let Ok(body) = crypto::open_message(&fetched.body_ct, &message_key, &body_aad) else {
                continue;
            };
            let body_str = String::from_utf8_lossy(body.as_bytes()).to_string();
            if body_str.contains(marker) {
                return Some(body_str);
            }
        }
        None
    }

    /// Client SMTP minimal pour driver le VRAI serveur SMTP du Bridge — même esprit que
    /// `diamy-mxd::tests::SmtpTestClient` (fichier différent, même rôle).
    struct SmtpTestClient {
        reader: TokioBufReader<TcpStream>,
    }
    impl SmtpTestClient {
        async fn connect(addr: std::net::SocketAddr) -> Self {
            let stream = TcpStream::connect(addr).await.expect("connexion SMTP de test");
            Self { reader: TokioBufReader::new(stream) }
        }
        async fn read_line(&mut self) -> String {
            let mut line = String::new();
            self.reader.read_line(&mut line).await.expect("lecture ligne SMTP");
            line.trim_end().to_string()
        }
        /// Lit une réponse potentiellement multi-lignes (`250-...` puis `250 ...`).
        async fn read_response(&mut self) -> String {
            let mut last = self.read_line().await;
            while last.len() > 3 && last.as_bytes()[3] == b'-' {
                last = self.read_line().await;
            }
            last
        }
        async fn cmd(&mut self, line: &str) -> String {
            self.reader.get_mut().write_all(format!("{line}\r\n").as_bytes()).await.unwrap();
            self.read_response().await
        }
        async fn send_data(&mut self, body: &str) -> String {
            self.reader.get_mut().write_all(body.as_bytes()).await.unwrap();
            self.reader.get_mut().write_all(b"\r\n.\r\n").await.unwrap();
            self.read_response().await
        }
    }

    /// Sérialise les tests d'intégration qui enrôlent le device Bridge du MÊME compte de fixture
    /// (`hugo@w3.tel`) sur la base de dev PARTAGÉE. `ensure_bridge_device_enrolled` régénère un
    /// `device_id` à CHAQUE appel et écrase le fichier de clé partagé : deux tests hugo en
    /// parallèle se clobbereraient (un message scellé pour l'ancien device deviendrait
    /// indéchiffrable après ré-enrôlement concurrent → "message introuvable" intermittent). Ce
    /// verrou rend le déroulé déterministe sans dépendre de l'ordonnancement des threads de test.
    fn hugo_account_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    #[tokio::test]
    async fn full_round_trip_thunderbird_send_to_local_recipient_arrives_decryptable() {
        let _serialize_hugo = hugo_account_lock().lock().await;
        let database_url = test_database_url();
        let pool = storage::connect(&database_url).await.expect("Postgres de dev doit tourner (`docker compose up`)");
        let blob_store = storage::BlobStore::at("./blob_store").expect("object store local");

        // --- 1. Réception réelle : un VRAI processus diamy-mxd séparé, jamais modifié. ---
        let mxd_smtp_port = free_port();
        let mxd_metrics_port = free_port();
        let _mxd = spawn_mxd_subprocess(mxd_smtp_port, mxd_metrics_port, &database_url).await;

        // --- 2. Destinataire : cedric@w3.tel, appareil frais enrôlé par CE test. ---
        let iam = DevIamClient::seeded();
        let recipient_canonical = diamy_addr_canon("cedric@w3.tel", TenantAddressPolicy::default()).unwrap();
        let recipient_principal = iam.resolve_principal(recipient_canonical.as_str()).unwrap();
        let (recipient_device_id, recipient_device_sec) =
            enroll_recipient_device(&pool, recipient_principal.id).await;

        // --- 3. Expéditeur : le compte Bridge de démo (hugo@w3.tel), appareil auto-enrôlé. ---
        ensure_bridge_device_enrolled(&pool, "hugo@w3.tel").await;

        // --- 4. diamy-submitd : VRAI routeur, en-process, pointé vers le subprocess mxd. ---
        let submitd_port = free_port();
        let submitd_config = std::sync::Arc::new(diamy_submitd::SubmitdConfig {
            local_domains: vec!["w3.tel".to_string()],
            mxd_relay_host: "127.0.0.1".to_string(),
            mxd_relay_port: mxd_smtp_port,
            external_relay_port: 25,
            helo_domain: "submit-test.w3.tel".to_string(),
            // Ce round-trip n'émet que vers un destinataire LOCAL (cedric@w3.tel) : le relais
            // externe reste désactivé (fail-closed), exactement comme en maquette.
            allow_external_relay: false,
        });
        let submitd_auth = diamy_submitd::auth::AuthState {
            app_keys: diamy_submitd::auth::AppKeyStore::seeded_from_env(),
            mail_jwt_secret: b"devonly_change_me_mail_jwt_secret".to_vec(),
        };
        let submitd_tls = diamy_submitd::generate_dev_tls_config("submit-test.w3.tel").await.unwrap();
        let submitd_addr: std::net::SocketAddr = format!("127.0.0.1:{submitd_port}").parse().unwrap();
        let submitd_state = diamy_submitd::SubmitState { config: submitd_config };
        tokio::spawn(async move {
            let _ = axum_server::bind_rustls(submitd_addr, submitd_tls)
                .serve(diamy_submitd::router(submitd_state, submitd_auth).into_make_service())
                .await;
        });

        // --- 5. Le Bridge : VRAI serveur SMTP, en-process, pointé vers diamy-submitd ci-dessus. ---
        let bridge_config = Arc::new(BridgeConfig {
            imap_bind_addr: "127.0.0.1:0".parse().unwrap(),
            smtp_bind_addr: "127.0.0.1:0".parse().unwrap(),
            imap_user: "hugo@w3.tel".to_string(),
            imap_password: "devonly_change_me_bridge_password".to_string(),
            sync_base: "https://127.0.0.1:0".to_string(),
            app_key: "devonly_change_me_appkey_bridge_dev_client".to_string(),
            submit_url: format!("https://127.0.0.1:{submitd_port}/submit"),
            local_domains: vec!["w3.tel".to_string()],
        });
        let http = reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap();
        let obs = Arc::new(diamy_obs::Obs::new("diamy-bridged-test"));
        let smtp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bridge_smtp_addr = smtp_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _peer)) = smtp_listener.accept().await else { break };
                let cfg = bridge_config.clone();
                let http = http.clone();
                let obs = obs.clone();
                tokio::spawn(async move {
                    let _ = handle_smtp_connection(socket, cfg, http, obs).await;
                });
            }
        });

        // Laisse le temps aux deux serveurs en-process de commencer à accepter (spawn est
        // asynchrone) — court, pas une dépendance temporelle fragile : la connexion SMTP
        // ci-dessous retentera de toute façon si besoin via le comportement normal de connect().
        tokio::time::sleep(Duration::from_millis(50)).await;

        // --- 6. Le "Thunderbird" de test : un VRAI client SMTP, dialogue complet avec AUTH. ---
        let marker = format!("marker-bridge-outbound-roundtrip-{}", Uuid::now_v7());
        let mut client = SmtpTestClient::connect(bridge_smtp_addr).await;
        let banner = client.read_line().await;
        assert!(banner.starts_with("220"), "bannière SMTP inattendue : {banner}");

        assert!(client.cmd("EHLO thunderbird-test").await.starts_with("250"));

        assert_eq!(client.cmd("AUTH LOGIN").await, "334 VXNlcm5hbWU6");
        assert_eq!(client.cmd(&STANDARD.encode("hugo@w3.tel")).await, "334 UGFzc3dvcmQ6");
        let auth_resp = client.cmd(&STANDARD.encode("devonly_change_me_bridge_password")).await;
        assert!(auth_resp.starts_with("235"), "AUTH LOGIN a échoué : {auth_resp}");

        assert!(client.cmd("MAIL FROM:<hugo@w3.tel>").await.starts_with("250"));
        assert!(client.cmd("RCPT TO:<cedric@w3.tel>").await.starts_with("250"));
        assert!(client.cmd("DATA").await.starts_with("354"));

        let message = format!(
            "From: hugo@w3.tel\r\nTo: cedric@w3.tel\r\nSubject: Round-trip demo\r\n\r\nCorps du message {marker}"
        );
        let data_resp = client.send_data(&message).await;
        assert!(data_resp.starts_with("250"), "le Bridge doit accepter le relais : {data_resp}");

        assert!(client.cmd("QUIT").await.starts_with("221"));

        // --- 7. Vérification côté RÉCEPTION : le message existe et déchiffre correctement dans
        //        le VRAI processus diamy-mxd séparé, via le MÊME Postgres. ---
        let mut found = None;
        for _ in 0..20 {
            found = find_own_message_by_marker(
                &pool,
                &blob_store,
                recipient_principal.id,
                recipient_device_id,
                &recipient_device_sec,
                &marker,
            )
            .await;
            if found.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        let body = found.expect("le message n'est jamais arrivé côté diamy-mxd (round-trip incomplet)");
        assert!(body.contains(&marker), "le corps déchiffré doit contenir le marqueur exact");
    }

    // --- Tests IMAP réels STORE/EXPUNGE/SELECT (A04 §3/§5.3, mission "sync réelle") ---------
    //
    // Ces tests pilotent le VRAI protocole texte IMAP (`handle_connection`, ce fichier) contre
    // un VRAI subprocess `diamy-maild` séparé (même technique que `spawn_mxd_subprocess`
    // ci-dessus) — pas d'appel direct aux fonctions `cmd_store`/`cmd_expunge`. La preuve de
    // persistance passe par le réseau (HTTP réel vers `diamy-maild`, VRAI Postgres), jamais un
    // raccourci en mémoire.

    fn find_diamy_maild_binary() -> PathBuf {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR fourni par cargo");
        let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
        let path = PathBuf::from(manifest_dir).join("../../target").join(profile).join("diamy-maild");
        assert!(
            path.exists(),
            "binaire diamy-maild introuvable à {} — lance `cargo build --workspace` (ou `-p diamy-maild`) \
             avant ce test (ce test ne modifie ni ne recompile diamy-maild, il l'exécute tel quel)",
            path.display()
        );
        path
    }

    struct MaildProcess {
        child: Child,
    }
    impl Drop for MaildProcess {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Lance un VRAI subprocess `diamy-maild` (HTTPS, certificat auto-signé de dev — comme en
    /// prod de dev) sur un port libre. Les valeurs par défaut des AppKeys/secret JWT du service
    /// correspondent DÉJÀ à celles attendues par la fixture de jetons pré-signés
    /// (`tests/fixtures/dev_mail_plane_tokens.json`, secret `devonly_change_me_mail_jwt_secret`)
    /// et par `BridgeConfig::from_env` (AppKey Bridge par défaut) : aucune variable d'env
    /// supplémentaire à aligner.
    async fn spawn_maild_subprocess(sync_port: u16, metrics_port: u16, database_url: &str) -> MaildProcess {
        let bin = find_diamy_maild_binary();
        let child = Command::new(bin)
            .env("DIAMY_ENV", "dev")
            .env("DATABASE_URL", database_url)
            .env("DIAMY_MAILD_SYNC_ADDR", format!("127.0.0.1:{sync_port}"))
            .env("DIAMY_MAILD_METRICS_ADDR", format!("127.0.0.1:{metrics_port}"))
            .env("DIAMY_MAILD_BLOB_DIR", "./blob_store")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("échec du lancement du subprocess diamy-maild (binaire compilé ?)");
        let mut guard = MaildProcess { child };

        // Le port HTTPS n'accepte qu'une fois le certificat de dev généré ET le routeur monté —
        // même stratégie de polling que `spawn_mxd_subprocess` (le port SMTP, lui, ouvre plus tôt).
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", sync_port)).await.is_ok() {
                return guard;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = guard.child.kill();
        let _ = guard.child.wait();
        panic!("diamy-maild (subprocess) n'a jamais ouvert son port de sync {sync_port} à temps");
    }

    /// Scelle et catalogue directement un message pour le compte Bridge de démo (contourne
    /// SMTP/diamy-mxd, hors périmètre de ce test) — sous l'enveloppe du device BRIDGE déjà
    /// enrôlé (`ensure_bridge_device_enrolled`), exactement le device que `diamy-bridged`
    /// utilisera pour déchiffrer via IMAP.
    async fn store_message_for_bridge(
        pool: &storage::PgPool,
        blob_store: &storage::BlobStore,
        principal_id: Uuid,
        domain_alabel: &str,
        bridge_device_id: Uuid,
        marker: &str,
    ) -> Uuid {
        let plaintext = format!("Subject: test\r\n\r\nCorps {marker}");
        let message_id = Uuid::now_v7();
        let body_blob_id = Uuid::now_v7();
        let (body_ct, message_key) =
            crypto::seal_message(plaintext.as_bytes(), &crypto::aad_for_blob(message_id, body_blob_id)).unwrap();
        // A20-IMAP-2 : le Sujet est scellé sous le MÊME `message_key` que le corps (AAD
        // distincte) — c'est ce que `fetch_and_decrypt` du Bridge attend réellement pour
        // déchiffrer `summary_ct` (contrairement au `store_test_message` de `sync_api.rs`, qui
        // ne vérifie jamais le résumé et peut se permettre une clé indépendante aussitôt jetée).
        let summary_ct = crypto::seal_message_with_key(b"[resume]", &message_key, &crypto::aad_for_summary(message_id)).unwrap();

        let devices = storage::active_device_keys(pool, principal_id).await.unwrap();
        let (_, mlkem_pub) = devices.into_iter().find(|(id, _)| *id == bridge_device_id).unwrap();
        let envelope = crypto::wrap_key_for_device(
            &message_key,
            &crypto::DeviceEncPublicKey(mlkem_pub),
            &crypto::aad_for_envelope(message_id, bridge_device_id),
        )
        .unwrap();
        drop(message_key);

        let (folder_name_ct, folder_key) =
            crypto::seal_message(b"Inbox", b"mailfolder-placeholder:not-a02-modeled").unwrap();
        drop(folder_key);
        let tenant_id = diamy_mail_iam::derive_dev_tenant_id(domain_alabel);
        let folder_id =
            storage::ensure_inbox_folder(pool, principal_id, tenant_id, &folder_name_ct.bytes).await.unwrap();

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
                recipient_canonical: "hugo@w3.tel",
                body_ct: &body_ct,
                summary_ct: &summary_ct,
                size_bytes: plaintext.len() as i64,
                envelopes: &[(bridge_device_id, &envelope)],
                trust_metadata: None,
            },
        )
        .await
        .unwrap()
    }

    /// Client IMAP texte minimal pour driver le VRAI serveur du Bridge — même esprit que
    /// `SmtpTestClient` ci-dessus. Ne connaît RIEN du protocole au-delà de lire/écrire des
    /// lignes CRLF : le test lui-même assert sur le contenu exact des réponses.
    struct ImapTestClient {
        reader: TokioBufReader<TcpStream>,
    }
    impl ImapTestClient {
        async fn connect(addr: std::net::SocketAddr) -> Self {
            let stream = TcpStream::connect(addr).await.expect("connexion IMAP de test");
            Self { reader: TokioBufReader::new(stream) }
        }
        async fn read_line(&mut self) -> String {
            let mut line = String::new();
            self.reader.read_line(&mut line).await.expect("lecture ligne IMAP");
            line.trim_end().to_string()
        }
        /// Envoie une commande taguée et collecte toutes les lignes (untagged incluses)
        /// jusqu'à la ligne taguée `OK`/`NO`/`BAD` correspondante.
        async fn cmd(&mut self, tag: &str, line: &str) -> Vec<String> {
            self.reader.get_mut().write_all(format!("{tag} {line}\r\n").as_bytes()).await.unwrap();
            let mut lines = Vec::new();
            loop {
                let l = self.read_line().await;
                let is_tagged = l.starts_with(&format!("{tag} "));
                lines.push(l);
                if is_tagged {
                    break;
                }
            }
            lines
        }
    }

    /// Preuve n°3 de la mission (bridge IMAP réel) : `STORE` marque `\Seen`/`\Deleted` via de
    /// VRAIS appels réseau à `diamy-maild` (pas un cache local), `FETCH FLAGS` depuis la MÊME
    /// session le confirme, `EXPUNGE` purge réellement le message (réponse non taguée
    /// `* n EXPUNGE`), et un second `SELECT` — donc une nouvelle interrogation réseau du
    /// catalogue — montre `0 EXISTS` : la suppression est persistée côté serveur, pas locale à
    /// la session Bridge.
    #[tokio::test]
    async fn imap_store_and_expunge_round_trip_against_real_maild() {
        // Sérialisé avec les autres tests hugo (voir `hugo_account_lock`) : évite qu'un
        // ré-enrôlement concurrent du device Bridge de hugo n'invalide notre message scellé.
        let _serialize_hugo = hugo_account_lock().lock().await;

        let database_url = test_database_url();
        let pool = storage::connect(&database_url).await.expect("Postgres de dev doit tourner (`docker compose up`)");
        let blob_store = storage::BlobStore::at("./blob_store").expect("object store local");

        // --- 1. VRAI subprocess diamy-maild, sur des ports LIBRES (jamais le port fixe par
        //        défaut, au cas où une instance de dev tournerait déjà dessus). ---
        let maild_port = free_port();
        let maild_metrics_port = free_port();
        let _maild = spawn_maild_subprocess(maild_port, maild_metrics_port, &database_url).await;

        // --- 2. Compte Bridge de démo (hugo@w3.tel), appareil BRIDGE enrôlé par ce test. ---
        ensure_bridge_device_enrolled(&pool, "hugo@w3.tel").await;
        let iam = DevIamClient::seeded();
        let principal = iam.resolve_principal("hugo@w3.tel").unwrap();
        let (bridge_device_id, _bridge_device_sec) =
            load_device_secret(&bridge_dev_secret_path("hugo@w3.tel")).expect("clé Bridge chargeable après enrôlement");

        // --- 3. Un message frais, catalogué directement (SMTP hors périmètre de ce test). ---
        let marker = format!("marker-imap-store-expunge-{}", Uuid::now_v7());
        let message_id = store_message_for_bridge(
            &pool, &blob_store, principal.id, principal.address.domain_alabel(), bridge_device_id, &marker,
        )
        .await;

        // --- 4. Le Bridge : VRAI serveur IMAP, en-process, pointé vers le subprocess maild. ---
        let bridge_config = Arc::new(BridgeConfig {
            imap_bind_addr: "127.0.0.1:0".parse().unwrap(),
            smtp_bind_addr: "127.0.0.1:0".parse().unwrap(),
            imap_user: "hugo@w3.tel".to_string(),
            imap_password: "devonly_change_me_bridge_password".to_string(),
            sync_base: format!("https://127.0.0.1:{maild_port}"),
            app_key: "devonly_change_me_appkey_bridge_dev_client".to_string(),
            submit_url: "https://127.0.0.1:0/submit".to_string(), // non utilisé par ce test (pas d'envoi)
            local_domains: vec!["w3.tel".to_string()],
        });
        let http = reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap();
        let obs = Arc::new(diamy_obs::Obs::new("diamy-bridged-imap-test"));
        // Répertoire d'état d'UID ISOLÉ pour ce test (Point 2) — jamais partagé avec le state de
        // dev ni avec un autre test, pour que les UID observés soient déterministes.
        let uid_registry = Arc::new(UidRegistry::new(unique_uid_state_dir()));
        let imap_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let imap_addr = imap_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _peer)) = imap_listener.accept().await else { break };
                let cfg = bridge_config.clone();
                let http = http.clone();
                let uid_registry = uid_registry.clone();
                let obs = obs.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(socket, cfg, http, uid_registry, obs).await;
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // --- 5. Le dialogue IMAP réel. ---
        let mut client = ImapTestClient::connect(imap_addr).await;
        let greeting = client.read_line().await;
        assert!(greeting.starts_with("* OK"), "bannière IMAP inattendue : {greeting}");

        let login = client.cmd("a1", "LOGIN hugo@w3.tel devonly_change_me_bridge_password").await;
        assert!(login.last().unwrap().starts_with("a1 OK"), "LOGIN a échoué : {login:?}");

        let select1 = client.cmd("a2", "SELECT INBOX").await;
        assert!(
            select1.iter().any(|l| l.contains("EXISTS")),
            "SELECT doit annoncer EXISTS : {select1:?}"
        );
        assert!(
            select1.iter().any(|l| l.contains("PERMANENTFLAGS") && l.contains("\\Seen") && l.contains("\\Deleted")),
            "PERMANENTFLAGS doit annoncer \\Seen et \\Deleted (A04 §5.3 réel) : {select1:?}"
        );
        let tagged1 = select1.last().unwrap();
        assert!(tagged1.contains("[READ-WRITE]"), "SELECT ne doit plus renvoyer [READ-ONLY] : {tagged1}");

        // Retrouve le numéro de séquence (1..N) de NOTRE message via son UID — le seul autre
        // message potentiellement présent serait celui d'un AUTRE test partageant la même base
        // (discipline d'isolation du projet : jamais de TRUNCATE) ; UID FETCH ... RFC822.SIZE
        // ne suffit pas à identifier le nôtre, donc on énumère 1..count et on repère celui dont
        // le FETCH BODY contient notre marqueur.
        let count: u32 = {
            let line = select1.iter().find(|l| l.contains("EXISTS")).unwrap();
            line.split_whitespace().nth(1).unwrap().parse().unwrap()
        };
        let mut our_seq = None;
        for seq in 1..=count {
            let fetch = client.cmd("a3", &format!("FETCH {seq} (BODY[])")).await;
            if fetch.iter().any(|l| l.contains(&marker)) {
                our_seq = Some(seq);
                break;
            }
        }
        let our_seq = our_seq.expect("notre message doit apparaître dans la boîte fraîchement sélectionnée");

        // --- 6. STORE +FLAGS (\Seen) : VRAI appel réseau à /state/flags, pas un cache local. ---
        let store_seen = client.cmd("a4", &format!("STORE {our_seq} +FLAGS (\\Seen)")).await;
        assert!(
            store_seen.iter().any(|l| l.contains("FETCH") && l.contains("\\Seen")),
            "STORE non-SILENT doit renvoyer la réponse FETCH avec le nouveau flag : {store_seen:?}"
        );
        assert!(store_seen.last().unwrap().starts_with("a4 OK"));

        // FETCH FLAGS depuis la MÊME session confirme \Seen (déjà mis à jour en cache session,
        // mais provient bien de la réponse serveur du STORE ci-dessus, pas d'une valeur inventée).
        let fetch_flags = client.cmd("a5", &format!("FETCH {our_seq} (FLAGS)")).await;
        assert!(fetch_flags.iter().any(|l| l.contains("\\Seen")), "FETCH FLAGS doit refléter \\Seen : {fetch_flags:?}");

        // --- 7. STORE +FLAGS (\Deleted) puis EXPUNGE : purge réelle. ---
        let store_deleted = client.cmd("a6", &format!("STORE {our_seq} +FLAGS (\\Deleted)")).await;
        assert!(store_deleted.iter().any(|l| l.contains("\\Deleted")), "STORE \\Deleted : {store_deleted:?}");

        // `cmd_expunge` purge à raison TOUS les messages `\Deleted` de la boîte, pas seulement
        // le nôtre — sur la base de dev PARTAGÉE (jamais de TRUNCATE, discipline du projet),
        // d'anciens messages `\Deleted` non purgés d'exécutions antérieures de ce même test
        // PEUVENT coexister avec le nôtre. On n'assert donc PAS un numéro de séquence exact
        // (qui dépend du nombre total purgé dans CE passage) : au moins une réponse EXPUNGE non
        // taguée doit sortir, et la preuve que NOTRE message a bien disparu vient du SELECT frais
        // + de la vérification directe en base ci-dessous, jamais d'un décompte de séquence.
        let expunge = client.cmd("a7", "EXPUNGE").await;
        assert!(
            expunge.iter().any(|l| l.trim().ends_with(" EXPUNGE")),
            "EXPUNGE doit émettre au moins une réponse non taguée \"* n EXPUNGE\" : {expunge:?}"
        );
        assert!(expunge.last().unwrap().starts_with("a7 OK"));

        // --- 8. Nouveau SELECT (nouvelle requête réseau, pas un état de session) : le message
        //        ne doit plus apparaître — preuve de persistance côté serveur. ---
        let select2 = client.cmd("a8", "SELECT INBOX").await;
        let count2: u32 = {
            let line = select2.iter().find(|l| l.contains("EXISTS")).unwrap();
            line.split_whitespace().nth(1).unwrap().parse().unwrap()
        };
        assert!(
            count2 < count,
            "au moins un message (dont le nôtre) doit avoir disparu d'un SELECT frais après EXPUNGE (avant={count}, après={count2})"
        );

        // --- 9. Preuve indépendante, directement en base (pas seulement via le protocole
        //        IMAP) : la ligne catalogue a bien disparu de Postgres. ---
        let remaining = storage::list_recent_messages(&pool, principal.id, 50).await.unwrap();
        assert!(
            !remaining.iter().any(|m| m.message_id == message_id),
            "le message purgé ne doit plus exister dans mail.messages (A02-DEL-1)"
        );

        let _ = client.cmd("a9", "LOGOUT").await;
    }

    /// Extrait l'UID d'une réponse `FETCH ... (UID n ...)` et joint le corps pour recherche du
    /// marqueur — helper du test de stabilité d'UID ci-dessous.
    fn uid_from_fetch_lines(lines: &[String]) -> Option<u32> {
        for l in lines {
            if let Some(p) = l.find("FETCH (UID ") {
                let rest = &l[p + "FETCH (UID ".len()..];
                let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(u) = num.parse::<u32>() {
                    return Some(u);
                }
            }
        }
        None
    }

    /// Parcourt les séquences 1..=count et retourne l'UID du message dont le corps contient
    /// `marker` (via un vrai `FETCH seq (UID BODY[])`) — jamais une position devinée.
    async fn find_uid_by_marker(client: &mut ImapTestClient, count: u32, marker: &str) -> Option<u32> {
        for seq in 1..=count {
            let lines = client.cmd("uf", &format!("FETCH {seq} (UID BODY[])")).await;
            if lines.iter().any(|l| l.contains(marker)) {
                return uid_from_fetch_lines(&lines);
            }
        }
        None
    }

    fn exists_count(select_lines: &[String]) -> u32 {
        let line = select_lines.iter().find(|l| l.contains("EXISTS")).expect("SELECT doit annoncer EXISTS");
        line.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    /// **Preuve du Point 2 — reproduction EXACTE du scénario de bug de l'audit.** Boîte avec 3
    /// messages A/B/C ; on note leurs UID ; on supprime B (`UID STORE \Deleted` + `EXPUNGE`) ;
    /// un nouveau message D arrive ; puis on vérifie que :
    ///   1. l'UID qui désignait B n'est JAMAIS réattribué à D (le bug d'origine : D héritait de
    ///      l'UID caché par un client pour B) ;
    ///   2. A et C gardent EXACTEMENT leurs UID d'origine tout du long ;
    ///   3. `UIDVALIDITY` ne change pas (les UID sont stables, plus besoin de bump).
    /// Tout passe par le VRAI protocole IMAP contre un VRAI subprocess `diamy-maild` + Postgres,
    /// avec un registre d'UID persisté ISOLÉ pour ce test.
    #[tokio::test]
    async fn uid_of_expunged_message_is_never_reassigned_to_a_new_message() {
        let database_url = test_database_url();
        let pool = storage::connect(&database_url).await.expect("Postgres de dev doit tourner (`docker compose up`)");
        let blob_store = storage::BlobStore::at("./blob_store").expect("object store local");

        let maild_port = free_port();
        let maild_metrics_port = free_port();
        let _maild = spawn_maild_subprocess(maild_port, maild_metrics_port, &database_url).await;

        // Compte DÉDIÉ à ce test (aubin@w3.tel) — les autres tests d'intégration ré-enrôlent le
        // device Bridge de hugo/cedric en parallèle ; utiliser un compte distinct évite qu'une
        // ré-enrôlement concurrente n'invalide le device sous lequel nos messages sont scellés.
        ensure_bridge_device_enrolled(&pool, "aubin@w3.tel").await;
        let iam = DevIamClient::seeded();
        let principal = iam.resolve_principal("aubin@w3.tel").unwrap();
        let domain = principal.address.domain_alabel().to_string();
        let (bridge_device_id, _sec) =
            load_device_secret(&bridge_dev_secret_path("aubin@w3.tel")).expect("clé Bridge chargeable");

        // --- 3 messages A, B, C dans cet ordre chronologique. Marqueurs uniques par run. ---
        let run = Uuid::now_v7();
        let (marker_a, marker_b, marker_c, marker_d) = (
            format!("uidstab-A-{run}"),
            format!("uidstab-B-{run}"),
            format!("uidstab-C-{run}"),
            format!("uidstab-D-{run}"),
        );
        for m in [&marker_a, &marker_b, &marker_c] {
            store_message_for_bridge(&pool, &blob_store, principal.id, &domain, bridge_device_id, m).await;
            // Espace les `received_at` pour un ordre chronologique A<B<C non ambigu.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // --- Bridge IMAP en-process, registre d'UID PERSISTÉ mais ISOLÉ (fichier jetable). ---
        let bridge_config = Arc::new(BridgeConfig {
            imap_bind_addr: "127.0.0.1:0".parse().unwrap(),
            smtp_bind_addr: "127.0.0.1:0".parse().unwrap(),
            imap_user: "aubin@w3.tel".to_string(),
            imap_password: "devonly_change_me_bridge_password".to_string(),
            sync_base: format!("https://127.0.0.1:{maild_port}"),
            app_key: "devonly_change_me_appkey_bridge_dev_client".to_string(),
            submit_url: "https://127.0.0.1:0/submit".to_string(),
            local_domains: vec!["w3.tel".to_string()],
        });
        let http = reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap();
        let obs = Arc::new(diamy_obs::Obs::new("diamy-bridged-uidstab-test"));
        let uid_registry = Arc::new(UidRegistry::new(unique_uid_state_dir()));
        let imap_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let imap_addr = imap_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _peer)) = imap_listener.accept().await else { break };
                let cfg = bridge_config.clone();
                let http = http.clone();
                let uid_registry = uid_registry.clone();
                let obs = obs.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(socket, cfg, http, uid_registry, obs).await;
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = ImapTestClient::connect(imap_addr).await;
        let _greeting = client.read_line().await;
        let login = client.cmd("a1", "LOGIN aubin@w3.tel devonly_change_me_bridge_password").await;
        assert!(login.last().unwrap().starts_with("a1 OK"), "LOGIN : {login:?}");

        // --- SELECT initial : note UIDVALIDITY + les UID de A, B, C. ---
        let select1 = client.cmd("a2", "SELECT INBOX").await;
        let count1 = exists_count(&select1);
        let uidvalidity1: u32 = {
            let l = select1.iter().find(|l| l.contains("UIDVALIDITY")).expect("UIDVALIDITY annoncée");
            let p = l.find("UIDVALIDITY ").unwrap() + "UIDVALIDITY ".len();
            l[p..].chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap()
        };

        let uid_a = find_uid_by_marker(&mut client, count1, &marker_a).await.expect("A doit être présent");
        let uid_b = find_uid_by_marker(&mut client, count1, &marker_b).await.expect("B doit être présent");
        let uid_c = find_uid_by_marker(&mut client, count1, &marker_c).await.expect("C doit être présent");
        assert!(uid_a != uid_b && uid_b != uid_c && uid_a != uid_c, "A/B/C doivent avoir des UID distincts");

        // --- Supprime B : UID STORE \Deleted (exerce aussi la borne max_uid) puis EXPUNGE. ---
        let store = client.cmd("a3", &format!("UID STORE {uid_b} +FLAGS (\\Deleted)")).await;
        assert!(store.last().unwrap().starts_with("a3 OK"), "UID STORE \\Deleted : {store:?}");
        let expunge = client.cmd("a4", "EXPUNGE").await;
        assert!(expunge.last().unwrap().starts_with("a4 OK"), "EXPUNGE : {expunge:?}");

        // --- Un nouveau message D arrive APRÈS la suppression de B. ---
        store_message_for_bridge(&pool, &blob_store, principal.id, &domain, bridge_device_id, &marker_d).await;

        // --- Nouveau SELECT (nouvelle interrogation réseau + re-résolution des UID). ---
        let select2 = client.cmd("a5", "SELECT INBOX").await;
        let count2 = exists_count(&select2);
        let uidvalidity2: u32 = {
            let l = select2.iter().find(|l| l.contains("UIDVALIDITY")).unwrap();
            let p = l.find("UIDVALIDITY ").unwrap() + "UIDVALIDITY ".len();
            l[p..].chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap()
        };

        let uid_a2 = find_uid_by_marker(&mut client, count2, &marker_a).await.expect("A toujours présent");
        let uid_c2 = find_uid_by_marker(&mut client, count2, &marker_c).await.expect("C toujours présent");
        let uid_d = find_uid_by_marker(&mut client, count2, &marker_d).await.expect("D doit être présent");
        let b_still_there = find_uid_by_marker(&mut client, count2, &marker_b).await;

        // === Les 4 preuves du scénario de bug de l'audit. ===
        assert!(b_still_there.is_none(), "B doit avoir disparu de la boîte après EXPUNGE");
        assert_eq!(uid_a2, uid_a, "A doit garder EXACTEMENT son UID d'origine ({uid_a}) tout du long");
        assert_eq!(uid_c2, uid_c, "C doit garder EXACTEMENT son UID d'origine ({uid_c}) tout du long");
        assert_ne!(
            uid_d, uid_b,
            "l'UID de B ({uid_b}) ne doit JAMAIS être réattribué au nouveau message D ({uid_d}) — c'est LE bug"
        );
        assert!(uid_d != uid_a && uid_d != uid_c, "D doit avoir un UID neuf, distinct de A et C");
        assert!(
            uid_d > uid_b && uid_d > uid_a && uid_d > uid_c,
            "un nouveau message doit recevoir un UID strictement croissant (jamais réutilisé) : D={uid_d}"
        );
        assert_eq!(
            uidvalidity2, uidvalidity1,
            "UIDVALIDITY doit rester stable (les UID sont désormais réellement stables, pas de bump)"
        );

        let _ = client.cmd("a6", "LOGOUT").await;
    }

    /// Écrit UNIQUEMENT le fichier de clé d'appareil Bridge en local (16 o `device_id` + clé
    /// secrète brute), sans rien publier en base — suffisant pour `authenticate_bridge_account`,
    /// qui ne consulte que ce fichier + la fixture de jetons. Rend le test de rejet RCPT
    /// hermétique (ni Postgres, ni sous-processus).
    fn write_local_bridge_device(canonical: &str) {
        let (_pub, sec) = crypto::generate_device_keypair().unwrap();
        let device_id = Uuid::now_v7();
        let path = bridge_dev_secret_path(canonical);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).unwrap();
        }
        let mut bytes = Vec::with_capacity(16 + sec.as_bytes().len());
        bytes.extend_from_slice(device_id.as_bytes());
        bytes.extend_from_slice(sec.as_bytes());
        std::fs::write(&path, &bytes).unwrap();
    }

    /// **Preuve de la correction UX (mission SMTP)** : un `RCPT TO` vers une adresse EXTERNE est
    /// rejeté DÈS le RCPT TO (code `550` permanent, RFC 5321 §3.6.1), AVANT tout `DATA` — le
    /// client (Thunderbird) reçoit une erreur claire immédiate au lieu de rester bloqué sur
    /// "Envoi du message...". Hermétique : ni Postgres ni sous-processus (le rejet intervient
    /// avant toute interaction réseau avec diamy-maild/submitd). Compte `cedric@w3.tel` : son
    /// fichier de clé Bridge n'est utilisé par aucun autre test (pas de course concurrente).
    #[tokio::test]
    async fn external_rcpt_is_rejected_at_rcpt_to_before_data() {
        let address = "cedric@w3.tel";
        let canonical = diamy_addr_canon(address, TenantAddressPolicy::default()).unwrap();
        write_local_bridge_device(canonical.as_str());

        let bridge_config = Arc::new(BridgeConfig {
            imap_bind_addr: "127.0.0.1:0".parse().unwrap(),
            smtp_bind_addr: "127.0.0.1:0".parse().unwrap(),
            imap_user: address.to_string(),
            imap_password: "devonly_change_me_bridge_password".to_string(),
            sync_base: "https://127.0.0.1:0".to_string(),
            app_key: "devonly_change_me_appkey_bridge_dev_client".to_string(),
            submit_url: "https://127.0.0.1:0/submit".to_string(),
            local_domains: vec!["w3.tel".to_string()],
        });
        let http = reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap();
        let obs = Arc::new(diamy_obs::Obs::new("diamy-bridged-rcpt-test"));
        let smtp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smtp_addr = smtp_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _peer)) = smtp_listener.accept().await else { break };
                let cfg = bridge_config.clone();
                let http = http.clone();
                let obs = obs.clone();
                tokio::spawn(async move {
                    let _ = handle_smtp_connection(socket, cfg, http, obs).await;
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client = SmtpTestClient::connect(smtp_addr).await;
        assert!(client.read_line().await.starts_with("220"), "bannière SMTP");
        assert!(client.cmd("EHLO thunderbird-test").await.starts_with("250"));
        assert_eq!(client.cmd("AUTH LOGIN").await, "334 VXNlcm5hbWU6");
        assert_eq!(client.cmd(&STANDARD.encode(address)).await, "334 UGFzc3dvcmQ6");
        assert!(client.cmd(&STANDARD.encode("devonly_change_me_bridge_password")).await.starts_with("235"));

        assert!(client.cmd("MAIL FROM:<cedric@w3.tel>").await.starts_with("250"));

        // Cœur du test : RCPT TO externe → 550 IMMÉDIAT (jamais 250), donc AUCUN DATA n'est
        // téléversé — plus de "chargement infini" côté client.
        let rcpt = client.cmd("RCPT TO:<test@gmail.com>").await;
        assert!(
            rcpt.starts_with("550"),
            "un destinataire externe doit être rejeté DÈS le RCPT TO (550 permanent), obtenu : {rcpt}"
        );
        assert!(
            rcpt.contains("5.7.1") || rcpt.to_lowercase().contains("relais externe"),
            "le rejet doit porter un message clair (relais externe désactivé) : {rcpt}"
        );

        // Contraste : un destinataire LOCAL est bien accepté (250 OK) au RCPT TO.
        assert!(
            client.cmd("RCPT TO:<hugo@w3.tel>").await.starts_with("250"),
            "un destinataire local doit rester accepté au RCPT TO"
        );

        assert!(client.cmd("QUIT").await.starts_with("221"));
    }
}
