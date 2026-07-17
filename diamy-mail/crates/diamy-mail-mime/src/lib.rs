#![forbid(unsafe_code)]
//! Parsing MIME/RFC 5322 côté **frontière** (A01-PARSE, pipeline step 2, A01 §4) :
//! `RECEIVE (1) -> PARSE (2, ici) -> AUTH (3) -> AV/CDR (4) -> ...`.
//!
//! Périmètre normatif couvert par ce module :
//! - **Parse MIME/RFC 5322** et **récupération de charset** (A01-STAB-2) — via
//!   [`mail-parser`](https://docs.rs/mail-parser), une bibliothèque Rust sans
//!   `unsafe`, fuzzée/testée MIRI, conçue précisément pour du courrier hostile
//!   (mêmes raisons qu'on réutilise `idna`/`aes-gcm` ailleurs plutôt que de
//!   réécrire un parseur MIME à la main : A18-TOP-2 esprit appliqué à un
//!   parseur, pas seulement à la crypto).
//! - **Décodage d'en-têtes RFC 2047/2231** : assuré par `mail-parser` en
//!   interne pendant le parsing (c'est ce qui permet par ex. de distinguer
//!   correctement les parties du message) ; ce module ne RESSORT toutefois
//!   aucun en-tête décodé (Subject, From display-name...) — rien dans cette
//!   maquette n'a besoin d'un en-tête en clair côté serveur, et ne pas l'exposer
//!   évite tout risque qu'un en-tête finisse traité comme métadonnée serveur-
//!   visible (le sujet d'un mail EST du contenu, jamais un champ public).
//! - **Bornes anti-abus (A01-STAB-1/3)** : la taille totale du message est déjà
//!   bornée EN AMONT par `diamy-mxd` (`max_data_bytes`, avant même d'arriver
//!   ici) ; `mail-parser` borne en interne la récursion message-dans-message
//!   (`MAX_NESTED_ENCODED = 3`) ; ce module ajoute une borne défensive
//!   supplémentaire sur le nombre total de parties MIME ([`MAX_PARTS`]).
//!
//! Périmètre volontairement PAS couvert ici (voir `SIMPLIFICATIONS.md`) :
//! - Steps 3–4 (AUTH SPF/DKIM/DMARC/ARC, AV/CDR) : hors de ce module, pas
//!   implémentés dans cette maquette.
//! - Séparation des pièces jointes en blobs distincts (A02-CRY step 7) :
//!   nécessite l'AV (A01-AV-1 : toute pièce jointe DOIT être scannée avant
//!   d'être conservée) — tant que l'AV n'existe pas, une pièce jointe détectée
//!   ici n'est PAS conservée séparément (ni chiffrée, ni délivrée) ; le seul
//!   corps textuel sélectionné devient le contenu chiffré. C'est un choix
//!   sûr-par-construction (rien de non scanné n'est jamais stocké), pas un
//!   oubli — voir [`ParsedMessage::attachments_seen`].
//! - Conversion HTML -> Tiptap (A08) : reste strictement client-side (A01
//!   §1.1) ; ce module ne convertit ni ne nettoie jamais le HTML, il le
//!   préserve tel quel comme source pour la conversion future.

use mail_parser::{Message, MessageParser, PartType};

/// Borne défensive sur le nombre total de parties MIME (A01-STAB-1), en plus de
/// la borne de taille déjà appliquée en amont et de la borne interne de
/// `mail-parser` sur la récursion message-dans-message.
const MAX_PARTS: usize = 10_000;

/// D'où vient `ParsedMessage::body` — purement informatif (trust_metadata),
/// jamais utilisé pour une décision de sécurité.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodySource {
    /// Une partie `text/plain` authentique a été trouvée (A08-TXT-1 côté client
    /// n'a alors rien à deviner).
    PlainText,
    /// Aucune partie texte, mais une partie `text/html` authentique existe —
    /// préservée TELLE QUELLE (markup non converti, non nettoyé : A08 reste le
    /// seul endroit qui convertit du HTML, et seulement côté client).
    HtmlSource,
    /// Ni texte ni HTML exploitable (message vide, pièces jointes seules, ou
    /// parsing en échec/hors bornes) : repli sur les octets bruts d'origine —
    /// jamais de perte silencieuse de contenu.
    RawFallback,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedMessage {
    /// Le contenu qui deviendra LE corps chiffré (A02-CRY-1, step 7 du
    /// pipeline). Voir [`BodySource`] pour l'ordre de préférence.
    pub body: Vec<u8>,
    pub body_source: BodySource,
    /// Sujet décodé (RFC 2047 assuré par `mail-parser`), destiné à devenir LUI AUSSI du
    /// CIPHERTEXT (jamais stocké en clair côté serveur, comme le corps — voir
    /// `diamy-mxd::deliver_to_recipients`/`hold_recipient`, qui le scellent sous le même
    /// `k_msg` que le corps). `None` si le parsing a échoué entièrement (repli brut,
    /// [`BodySource::RawFallback`] sans message analysable) — aucun en-tête n'est alors
    /// disponible, pas seulement le sujet.
    pub subject: Option<String>,
    /// A01 §9 : le parsing MIME/RFC 5322 a échoué ou a dépassé une borne —
    /// jamais un rejet du message pour ce seul motif (A01-STAB-2/A08-TXT-2
    /// esprit : on dégrade, on ne perd jamais silencieusement).
    pub malformed: bool,
    /// A01-STAB-2 : la partie sélectionnée avait un problème d'encodage
    /// détecté par le parseur (charset douteux/absent, récupéré au mieux).
    pub charset_recovered: bool,
    /// Nombre de pièces jointes détectées mais NON conservées séparément dans
    /// cette maquette (voir le commentaire de module — A01-AV non implémenté).
    pub attachments_seen: usize,
}

/// PARSE (step 2 du pipeline A01 §4). Ne panique jamais, quelle que soit
/// l'entrée (Postel's law côté parseur sous-jacent + bornes défensives ici) —
/// c'est un service exposé à Internet, l'entrée est par définition hostile.
pub fn parse_inbound_message(raw: &[u8]) -> ParsedMessage {
    let Some(message) = MessageParser::default().parse(raw) else {
        return raw_fallback(raw, true, 0, None);
    };

    if message.parts.len() > MAX_PARTS {
        return raw_fallback(raw, true, message.attachments.len(), None);
    }

    let attachments_seen = message.attachments.len();
    let subject = message.subject().map(str::to_string);

    if let Some((body, charset_recovered)) = first_genuine_text(&message, &message.text_body) {
        return ParsedMessage {
            body,
            body_source: BodySource::PlainText,
            subject,
            malformed: false,
            charset_recovered,
            attachments_seen,
        };
    }
    if let Some((body, charset_recovered)) = first_genuine_html(&message, &message.html_body) {
        return ParsedMessage {
            body,
            body_source: BodySource::HtmlSource,
            subject,
            malformed: false,
            charset_recovered,
            attachments_seen,
        };
    }

    raw_fallback(raw, false, attachments_seen, subject)
}

fn raw_fallback(raw: &[u8], malformed: bool, attachments_seen: usize, subject: Option<String>) -> ParsedMessage {
    ParsedMessage {
        body: raw.to_vec(),
        body_source: BodySource::RawFallback,
        subject,
        malformed,
        charset_recovered: false,
        attachments_seen,
    }
}

fn first_genuine_text(message: &Message, ids: &[u32]) -> Option<(Vec<u8>, bool)> {
    ids.iter().find_map(|&idx| {
        let part = message.parts.get(idx as usize)?;
        match &part.body {
            PartType::Text(t) => Some((t.as_bytes().to_vec(), part.is_encoding_problem)),
            _ => None,
        }
    })
}

fn first_genuine_html(message: &Message, ids: &[u32]) -> Option<(Vec<u8>, bool)> {
    ids.iter().find_map(|&idx| {
        let part = message.parts.get(idx as usize)?;
        match &part.body {
            PartType::Html(h) => Some((h.as_bytes().to_vec(), part.is_encoding_problem)),
            _ => None,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_message_without_mime_headers_extracts_body_only() {
        let raw = b"From: sender@example.org\r\nTo: hugo@w3.tel\r\nSubject: Test\r\n\r\nBonjour,\r\n\r\nCorps du message.\r\n";
        let parsed = parse_inbound_message(raw);
        assert_eq!(parsed.body_source, BodySource::PlainText);
        assert!(!parsed.malformed);
        let body = String::from_utf8(parsed.body).unwrap();
        assert!(body.contains("Corps du message."));
        assert!(!body.contains("Subject:"), "les en-têtes ne doivent pas fuiter dans le corps sélectionné");
    }

    #[test]
    fn subject_is_extracted_and_rfc2047_decoded() {
        let raw = b"From: sender@example.org\r\nTo: hugo@w3.tel\r\nSubject: Bonjour\r\n\r\nCorps.\r\n";
        let parsed = parse_inbound_message(raw);
        assert_eq!(parsed.subject.as_deref(), Some("Bonjour"));

        // RFC 2047 encoded-word (ex. accents) doit être décodé par mail-parser.
        let raw_encoded =
            b"From: sender@example.org\r\nTo: hugo@w3.tel\r\nSubject: =?UTF-8?B?UsOpdW5pb24gw6AgMTRo?=\r\n\r\nCorps.\r\n";
        let parsed_encoded = parse_inbound_message(raw_encoded);
        assert_eq!(parsed_encoded.subject.as_deref(), Some("Réunion à 14h"));
    }

    #[test]
    fn missing_subject_header_yields_none() {
        let raw = b"From: sender@example.org\r\nTo: hugo@w3.tel\r\n\r\nCorps sans sujet.\r\n";
        let parsed = parse_inbound_message(raw);
        assert_eq!(parsed.subject, None);
    }

    #[test]
    fn multipart_alternative_prefers_genuine_text_plain_over_html() {
        let raw = b"From: a@example.org\r\nTo: hugo@w3.tel\r\nSubject: Test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"BOUND\"\r\n\r\n--BOUND\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nVersion texte brut.\r\n--BOUND\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><b>Version HTML</b></body></html>\r\n--BOUND--\r\n";
        let parsed = parse_inbound_message(raw);
        assert_eq!(parsed.body_source, BodySource::PlainText);
        let body = String::from_utf8(parsed.body).unwrap();
        assert!(body.contains("Version texte brut."));
        assert!(!body.contains("<html>"));
    }

    #[test]
    fn html_only_message_preserves_raw_markup_unconverted() {
        let raw = b"From: a@example.org\r\nTo: hugo@w3.tel\r\nSubject: Test\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><b>Seulement du HTML</b></body></html>\r\n";
        let parsed = parse_inbound_message(raw);
        assert_eq!(parsed.body_source, BodySource::HtmlSource);
        let body = String::from_utf8(parsed.body).unwrap();
        assert!(body.contains("<b>Seulement du HTML</b>"), "le HTML doit rester non converti (A08 est client-side)");
    }

    #[test]
    fn attachment_only_message_falls_back_to_raw_bytes_without_losing_data() {
        let raw: &[u8] = b"From: a@example.org\r\nTo: hugo@w3.tel\r\nSubject: Piece jointe\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n--BOUND\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n--BOUND--\r\n";
        let parsed = parse_inbound_message(raw);
        assert_eq!(parsed.body_source, BodySource::RawFallback);
        assert_eq!(parsed.attachments_seen, 1);
        assert_eq!(parsed.body, raw.to_vec(), "rien ne doit disparaitre silencieusement");
    }

    #[test]
    fn adversarial_garbage_never_panics() {
        let inputs: [&[u8]; 4] = [
            b"",
            b"\x00\x01\x02\xff\xfe not even close to a message",
            b"Content-Type: multipart/mixed; boundary=\"x\"\r\n\r\n--x\r\n--x\r\n--x--",
            &[b'a'; 200_000],
        ];
        for input in inputs {
            let parsed = parse_inbound_message(input);
            assert!(!parsed.body.is_empty() || input.is_empty());
        }
    }

    #[test]
    fn deeply_nested_multipart_is_bounded_not_hanging() {
        // Un multipart profondément imbriqué (pas des messages imbriqués, donc hors
        // MAX_NESTED_ENCODED de mail-parser) doit rester borné par MAX_PARTS ou par la
        // taille déjà bornée en amont — la mesure ici est juste "ça retourne", pas un
        // contenu précis.
        let mut raw = String::from("Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n");
        for _ in 0..2000 {
            raw.push_str("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n");
        }
        raw.push_str("--b--\r\n");
        let parsed = parse_inbound_message(raw.as_bytes());
        // Ne doit pas paniquer/boucler ; le résultat précis importe peu ici.
        let _ = parsed;
    }
}
