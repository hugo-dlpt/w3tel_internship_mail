//! Relais SMTP sortant — A10 §2 étape 7 (« EMIT : SMTP to the Internet from the chosen
//! sending server/IP »), réduit à sa forme la plus simple pour cette tranche démo : un VRAI
//! dialogue SMTP (EHLO/MAIL FROM/RCPT TO/DATA/QUIT) contre un serveur distant, mais SANS
//! signature DKIM, SANS vérification SPF/DKIM/DMARC de sortie, SANS allocation de pool
//! d'envoi (A23), SANS rate limiting (A10-RL) — toutes ces obligations normatives sont
//! documentées comme ABSENTES dans `SIMPLIFICATIONS.md`, pas silencieusement contournées.
//!
//! **Boucle fermée de démo** (`submit_api.rs` en décide) : un destinataire dont le domaine
//! figure dans `local_domains` est relayé vers `diamy-mxd` (même port que `DIAMY_MXD_SMTP_ADDR`)
//! plutôt que vers Internet — ça permet "envoi depuis Thunderbird → réception visible dans
//! Thunderbird" sans sortir sur le vrai réseau.
//!
//! **Simplification assumée** : pas de résolution MX (A10 ne l'exige pas explicitement pour
//! cette tranche, mais un vrai `diamy-submitd` le ferait) — la relance externe se connecte
//! directement à `<domaine>:<port>`, un stand-in honnête, pas une implémentation complète.
//!
//! **Relais externe DÉSACTIVÉ en maquette (décision de Cédric, fail-closed)** : ce module reste
//! le moteur du dialogue SMTP, mais `submit_api.rs` ne l'appelle plus JAMAIS avec un hôte
//! externe par défaut — un destinataire hors des domaines locaux est rejeté AVANT toute
//! connexion (`RelayRoute::RejectedExternalDisabled`). `relay_via_smtp` n'est donc plus utilisé
//! que pour la réinjection LOCALE dans `diamy-mxd` (boucle fermée de démo), sauf réactivation
//! explicite et jamais-par-défaut du relais externe (`DIAMY_SUBMITD_ALLOW_EXTERNAL_RELAY=1`).

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayOutcome {
    /// Le serveur distant a répondu `2xx` à la commande finale de `DATA` — accepté.
    Delivered,
    /// Réponse `4xx` (ou échec réseau) — transitoire, un vrai A10 retenterait avec backoff
    /// (A10-RETRY-1) ; cette V1 ne retente PAS (voir `SIMPLIFICATIONS.md`).
    TransientFailure(String),
    /// Réponse `5xx` — permanent, un vrai A10 générerait un DSN (A10-RETRY-2) ; cette V1 ne
    /// génère AUCUN DSN (voir `SIMPLIFICATIONS.md`).
    PermanentFailure(String),
}

/// Dialogue SMTP réel et minimal contre `host:port` : EHLO/MAIL FROM/RCPT TO/DATA/QUIT.
/// Pas de STARTTLS (connexion locale de démo ou relais direct non authentifié — voir
/// `SIMPLIFICATIONS.md`), pas de pipelining, une seule tentative (pas de retry/backoff).
pub async fn relay_via_smtp(
    host: &str,
    port: u16,
    helo_domain: &str,
    mail_from: &str,
    rcpt_to: &str,
    raw_message: &[u8],
) -> RelayOutcome {
    let stream = match TcpStream::connect((host, port)).await {
        Ok(s) => s,
        Err(e) => return RelayOutcome::TransientFailure(format!("connexion à {host}:{port} échouée : {e}")),
    };
    let mut reader = BufReader::new(stream);

    macro_rules! read_or_fail {
        () => {
            match read_smtp_response(&mut reader).await {
                Ok(r) => r,
                Err(e) => return RelayOutcome::TransientFailure(format!("lecture réponse SMTP échouée : {e}")),
            }
        };
    }
    macro_rules! write_or_fail {
        ($line:expr) => {
            if let Err(e) = reader.get_mut().write_all($line.as_bytes()).await {
                return RelayOutcome::TransientFailure(format!("écriture SMTP échouée : {e}"));
            }
        };
    }

    // Bannière serveur (220).
    let banner = read_or_fail!();
    if !banner.code_is_2xx() {
        return classify(&banner);
    }

    write_or_fail!(format!("EHLO {helo_domain}\r\n"));
    let ehlo = read_or_fail!();
    if !ehlo.code_is_2xx() {
        return classify(&ehlo);
    }

    write_or_fail!(format!("MAIL FROM:<{mail_from}>\r\n"));
    let mf = read_or_fail!();
    if !mf.code_is_2xx() {
        return classify(&mf);
    }

    write_or_fail!(format!("RCPT TO:<{rcpt_to}>\r\n"));
    let rcpt = read_or_fail!();
    if !rcpt.code_is_2xx() {
        return classify(&rcpt);
    }

    write_or_fail!("DATA\r\n");
    let data_go = read_or_fail!();
    if data_go.code != 354 {
        return classify(&data_go);
    }

    write_or_fail!(dot_stuff_for_wire(raw_message));
    let final_resp = read_or_fail!();

    write_or_fail!("QUIT\r\n");
    let _ = read_smtp_response(&mut reader).await; // best-effort, l'issue est déjà connue

    if final_resp.code_is_2xx() {
        RelayOutcome::Delivered
    } else {
        classify(&final_resp)
    }
}

fn classify(resp: &SmtpResponse) -> RelayOutcome {
    if resp.code >= 500 {
        RelayOutcome::PermanentFailure(format!("{} {}", resp.code, resp.text))
    } else {
        RelayOutcome::TransientFailure(format!("{} {}", resp.code, resp.text))
    }
}

struct SmtpResponse {
    code: u16,
    text: String,
}

impl SmtpResponse {
    fn code_is_2xx(&self) -> bool {
        (200..300).contains(&self.code)
    }
}

/// Lit une réponse SMTP, gérant les lignes de continuation `250-...` (RFC 5321 §4.2.1) —
/// s'arrête à la première ligne dont le 4e caractère est un espace plutôt qu'un tiret.
async fn read_smtp_response<S>(reader: &mut BufReader<S>) -> std::io::Result<SmtpResponse>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let last_line;
    loop {
        let line = read_line(reader).await?;
        let is_continuation = line.len() > 3 && line.as_bytes()[3] == b'-';
        if !is_continuation {
            last_line = line;
            break;
        }
    }
    let code: u16 = last_line.get(..3).and_then(|s| s.parse().ok()).unwrap_or(0);
    let text = last_line.get(4..).unwrap_or("").to_string();
    Ok(SmtpResponse { code, text })
}

async fn read_line<S>(reader: &mut BufReader<S>) -> std::io::Result<String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&buf).trim_end_matches('\r').to_string())
}

/// Normalise les fins de ligne en CRLF, applique le dot-stuffing (RFC 5321 §4.5.2 : une ligne
/// commençant par `.` est doublée) et ajoute le terminateur `<CRLF>.<CRLF>`.
fn dot_stuff_for_wire(raw_message: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw_message);
    let mut out = String::with_capacity(text.len() + 16);
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str(".\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// "Faux MTA" local minimal : accepte une connexion, joue le dialogue SMTP standard
    /// (220/250/250/250/354/250), et renvoie au test le corps DATA reçu (dé-dot-stuffé) pour
    /// vérifier qu'il correspond exactement à ce qui a été envoyé — preuve d'un VRAI dialogue
    /// sur le fil, pas une simulation en mémoire.
    async fn spawn_fake_mta(final_code: &'static str) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(socket);
            reader.get_mut().write_all(b"220 fake-mta ready\r\n").await.unwrap();
            let _ehlo = read_line(&mut reader).await.unwrap();
            reader.get_mut().write_all(b"250 fake-mta\r\n").await.unwrap();
            let _mail_from = read_line(&mut reader).await.unwrap();
            reader.get_mut().write_all(b"250 OK\r\n").await.unwrap();
            let _rcpt_to = read_line(&mut reader).await.unwrap();
            reader.get_mut().write_all(b"250 OK\r\n").await.unwrap();
            let _data_cmd = read_line(&mut reader).await.unwrap();
            reader.get_mut().write_all(b"354 go ahead\r\n").await.unwrap();

            let mut body = String::new();
            loop {
                let line = read_line(&mut reader).await.unwrap();
                if line == "." {
                    break;
                }
                let unstuffed = line.strip_prefix('.').filter(|_| line.starts_with("..")).unwrap_or(&line);
                body.push_str(unstuffed);
                body.push('\n');
            }
            let final_line = format!("{final_code}\r\n");
            reader.get_mut().write_all(final_line.as_bytes()).await.unwrap();
            let _quit = read_line(&mut reader).await;
            let _ = tx.send(body);
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn real_smtp_dialogue_delivers_and_preserves_body() {
        let (addr, rx) = spawn_fake_mta("250 accepted").await;
        let marker = "marker-relay-happy-path-12345";
        let message = format!("From: a@example.fr\r\nTo: b@example.fr\r\n\r\nCorps {marker}\r\n");

        let outcome = relay_via_smtp(
            &addr.ip().to_string(),
            addr.port(),
            "submit.w3.tel",
            "a@example.fr",
            "b@example.fr",
            message.as_bytes(),
        )
        .await;

        assert_eq!(outcome, RelayOutcome::Delivered);
        let received_body = rx.await.unwrap();
        assert!(received_body.contains(marker), "le corps reçu par le faux MTA doit contenir le marqueur");
    }

    #[tokio::test]
    async fn permanent_failure_is_classified_as_5xx() {
        let (addr, _rx) = spawn_fake_mta("550 no such user").await;
        let outcome = relay_via_smtp(&addr.ip().to_string(), addr.port(), "submit.w3.tel", "a@example.fr", "b@example.fr", b"x\r\n").await;
        assert!(matches!(outcome, RelayOutcome::PermanentFailure(_)));
    }

    #[tokio::test]
    async fn transient_failure_is_classified_as_4xx() {
        let (addr, _rx) = spawn_fake_mta("451 try again later").await;
        let outcome = relay_via_smtp(&addr.ip().to_string(), addr.port(), "submit.w3.tel", "a@example.fr", "b@example.fr", b"x\r\n").await;
        assert!(matches!(outcome, RelayOutcome::TransientFailure(_)));
    }

    #[tokio::test]
    async fn connection_refused_is_transient() {
        // Port fermé sur loopback (aucun listener) — l'échec réseau doit être classé
        // transitoire, jamais paniquer.
        let outcome = relay_via_smtp("127.0.0.1", 1, "submit.w3.tel", "a@example.fr", "b@example.fr", b"x\r\n").await;
        assert!(matches!(outcome, RelayOutcome::TransientFailure(_)));
    }

    #[test]
    fn dot_stuffing_doubles_leading_dots() {
        let raw = b"line one\r\n.leading dot\r\nnormal\r\n";
        let stuffed = dot_stuff_for_wire(raw);
        assert!(stuffed.contains("\r\n..leading dot\r\n"));
        assert!(stuffed.ends_with(".\r\n"));
    }
}
