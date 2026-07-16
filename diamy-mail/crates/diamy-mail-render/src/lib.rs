#![forbid(unsafe_code)]
//! Conversion du contenu déchiffré d'un message vers un document **Tiptap JSON à
//! schéma fermé** (A08), la représentation par défaut pour le rendu (INV-17,
//! A00 SEC-RENDER-1) : jamais de HTML brut passé tel quel au rendu (A08-SCH-1).
//!
//! **Périmètre de cette maquette : uniquement le chemin `text/plain` (A08-TXT-1).**
//! `diamy-mxd` fait DÉSORMAIS un vrai parsing MIME/RFC 5322 (`diamy-mail-mime`,
//! A01-PARSE) et sélectionne un corps : texte brut authentique, ou source HTML
//! préservée TELLE QUELLE (jamais convertie côté serveur). Mais AUCUN pipeline
//! HTML→Tiptap n'existe encore ici : un corps HTML sélectionné à la frontière
//! traverse la chaîne comme du markup brut inerte (affiché non converti), et le
//! pipeline HTML complet d'A08 (pré-nettoyage §3 étape 2, construction DOM bornée
//! §10, élagage du contenu caché §5, classification/aplatissement des tables §7,
//! résolution CID §8, passerelle image distante A09) n'est **pas** implémenté.
//! Ne pas l'étendre au jugé sans un vrai parseur DOM borné : conformément au guide
//! §5.1, un trou de spec se signale, il ne se comble pas en silence.
//!
//! Cette fonction est **pure et déterministe** (A08-PIPE-2) : mêmes octets
//! d'entrée -> même document Tiptap. Le nommage des nœuds/marks suit le
//! whitelist V1 d'A08 §2 (`doc`/`paragraph`/`hardBreak`/`text`/mark `link`).

use serde::Serialize;
use unicode_normalization::UnicodeNormalization;

/// Version du schéma Tiptap fermé (A08-SCH-2). À incrémenter si le node/mark
/// whitelist change, pour qu'un renderer sache quel jeu attendre.
pub const SCHEMA_VERSION: u32 = 1;

/// Schémas de lien whitelistés (A08-URL-1). Un jeton qui ne commence PAS par
/// l'un de ces préfixes reste du texte simple par construction — il n'y a pas
/// de détection générique d'URL suivie d'une validation de schéma a posteriori :
/// la détection EST restreinte à la whitelist, donc un `javascript:...` ou
/// `data:text/html...` littéral dans un corps text/plain ne devient jamais un
/// lien (§14 erreur IA #7 évitée par construction, pas par un filtre séparé).
const ALLOWED_LINK_PREFIXES: [&str; 4] = ["https://", "http://", "mailto:", "tel:"];

/// Ponctuation finale usuelle à ne pas inclure dans un lien auto-détecté
/// (ex. "voir https://ex.fr." -> lien "https://ex.fr", puis le "." en texte).
/// Simplification de maquette : pas la grammaire URI complète de la RFC 3986,
/// même esprit que le sous-ensemble RFC 5322 documenté pour `diamy-addr` (A24).
const TRAILING_PUNCT: [char; 9] = ['.', ',', ';', ':', '!', '?', ')', ']', '\''];

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LinkAttrs {
    pub href: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Mark {
    Link { attrs: LinkAttrs },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Inline {
    Text {
        text: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        marks: Vec<Mark>,
    },
    HardBreak,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Node {
    Paragraph { content: Vec<Inline> },
}

#[derive(Debug, Clone, Serialize)]
pub struct TiptapDoc {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub schema_version: u32,
    pub content: Vec<Node>,
}

/// Élément écarté avec sa raison (A08-EXH-1, règle d'exhaustivité : rien ne
/// disparaît sans laisser de trace). Toujours vide sur le chemin text/plain de
/// cette maquette — rien n'y est aujourd'hui écarté — mais le mécanisme existe
/// pour ne pas devoir changer le contrat de sortie le jour où le pipeline HTML
/// (qui, lui, écarte des `<script>`, iframes, images distantes...) est branché.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DroppedItem {
    pub raw: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ConversionLog {
    pub dropped: Vec<DroppedItem>,
}

/// Sortie de conversion (A08-OUT-1) : le document Tiptap (rendu), la
/// projection texte visible (recherche/IA locale, A05), et le journal de
/// conversion (transparence, A08-EXH-1).
#[derive(Debug, Clone)]
pub struct Conversion {
    pub doc: TiptapDoc,
    pub plain_text_projection: String,
    pub log: ConversionLog,
}

/// Convertit un message `text/plain` en document Tiptap (A08-TXT-1) : découpage
/// en paragraphes sur les lignes vides ; à l'intérieur d'un paragraphe, un
/// retour à la ligne simple devient un nœud `hardBreak` (jamais fusionné en une
/// seule ligne, jamais un nouveau paragraphe) ; un jeton délimité par des
/// espaces dont le préfixe est whitelisté (§`ALLOWED_LINK_PREFIXES`) devient un
/// mark `link`. Aucun parsing HTML n'intervient sur ce chemin (A08-TXT-1: "No
/// HTML parsing path is involved").
pub fn convert_plain_text(input: &str) -> Conversion {
    let normalized: String = input.nfc().collect();

    let content = split_paragraphs(&normalized)
        .into_iter()
        .map(|paragraph| {
            let mut inlines = Vec::new();
            for (i, line) in paragraph.split('\n').enumerate() {
                if i > 0 {
                    inlines.push(Inline::HardBreak);
                }
                push_line_inlines(line, &mut inlines);
            }
            Node::Paragraph { content: inlines }
        })
        .collect();

    Conversion {
        doc: TiptapDoc {
            kind: "doc",
            schema_version: SCHEMA_VERSION,
            content,
        },
        // Rien n'est masqué sur le chemin text/plain : la projection visible
        // EST le texte normalisé (A08-OUT-2 — pertinent surtout côté HTML, où
        // le contenu caché §5 est retiré avant projection).
        plain_text_projection: normalized,
        log: ConversionLog::default(),
    }
}

/// Découpe sur les lignes vides (une ou plusieurs) — A08-TXT-1 "splitting on
/// blank lines". Un texte entièrement vide produit zéro paragraphe (doc vide,
/// valide dans le schéma).
fn split_paragraphs(text: &str) -> Vec<String> {
    let mut paragraphs = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    for line in text.split('\n') {
        if line.trim().is_empty() {
            if !current.is_empty() {
                paragraphs.push(current.join("\n"));
                current.clear();
            }
        } else {
            current.push(line);
        }
    }
    if !current.is_empty() {
        paragraphs.push(current.join("\n"));
    }
    paragraphs
}

enum Chunk<'a> {
    Word(&'a str),
    Space(&'a str),
}

/// Découpe une ligne en jetons mot/espace (préserve les octets, aucune perte).
fn chunk_line(line: &str) -> Vec<Chunk<'_>> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut current_is_space: Option<bool> = None;
    for (i, c) in line.char_indices() {
        let is_space = c.is_whitespace();
        match current_is_space {
            None => current_is_space = Some(is_space),
            Some(prev) if prev != is_space => {
                out.push(if prev { Chunk::Space(&line[start..i]) } else { Chunk::Word(&line[start..i]) });
                start = i;
                current_is_space = Some(is_space);
            }
            _ => {}
        }
    }
    if let Some(prev) = current_is_space {
        out.push(if prev { Chunk::Space(&line[start..]) } else { Chunk::Word(&line[start..]) });
    }
    out
}

fn push_line_inlines(line: &str, out: &mut Vec<Inline>) {
    for chunk in chunk_line(line) {
        match chunk {
            Chunk::Space(s) => push_text(out, s, Vec::new()),
            Chunk::Word(word) => {
                if ALLOWED_LINK_PREFIXES.iter().any(|p| word.starts_with(p)) {
                    let trim_len = word.len() - word.trim_end_matches(TRAILING_PUNCT).len();
                    let href_len = word.len() - trim_len;
                    let (href_part, trailing) = word.split_at(href_len);
                    push_text(
                        out,
                        href_part,
                        vec![Mark::Link { attrs: LinkAttrs { href: href_part.to_string() } }],
                    );
                    if !trailing.is_empty() {
                        push_text(out, trailing, Vec::new());
                    }
                } else {
                    push_text(out, word, Vec::new());
                }
            }
        }
    }
}

/// Fusionne avec le dernier nœud `Text` si les marks sont identiques, sinon en
/// pousse un nouveau — évite une explosion de nœuds `text` d'un seul
/// caractère et garde la sortie déterministe et stable pour un diff.
fn push_text(out: &mut Vec<Inline>, text: &str, marks: Vec<Mark>) {
    if text.is_empty() {
        return;
    }
    if let Some(Inline::Text { text: last_text, marks: last_marks }) = out.last_mut() {
        if *last_marks == marks {
            last_text.push_str(text);
            return;
        }
    }
    out.push(Inline::Text { text: text.to_string(), marks });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc_json(input: &str) -> serde_json::Value {
        serde_json::to_value(convert_plain_text(input).doc).unwrap()
    }

    #[test]
    fn blank_line_splits_into_paragraphs() {
        let conv = convert_plain_text("Premier paragraphe.\n\nSecond paragraphe.");
        assert_eq!(conv.doc.content.len(), 2);
    }

    #[test]
    fn single_newline_is_hard_break_not_new_paragraph() {
        let conv = convert_plain_text("ligne 1\nligne 2");
        assert_eq!(conv.doc.content.len(), 1);
        let Node::Paragraph { content } = &conv.doc.content[0];
        assert!(content.iter().any(|i| matches!(i, Inline::HardBreak)));
    }

    #[test]
    fn whitelisted_scheme_becomes_link_trailing_punct_excluded() {
        let conv = convert_plain_text("Voir https://w3.tel/doc.");
        let json = serde_json::to_value(&conv.doc).unwrap();
        let text = json["content"][0]["content"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["marks"][0]["type"] == "link")
            .expect("un nœud texte avec mark link");
        assert_eq!(text["text"], "https://w3.tel/doc");
        assert_eq!(text["marks"][0]["attrs"]["href"], "https://w3.tel/doc");
    }

    #[test]
    fn non_whitelisted_scheme_stays_plain_text() {
        let conv = convert_plain_text("javascript:alert(1)");
        let Node::Paragraph { content } = &conv.doc.content[0];
        assert!(content.iter().all(|i| match i {
            Inline::Text { marks, .. } => marks.is_empty(),
            Inline::HardBreak => true,
        }));
    }

    #[test]
    fn conversion_is_deterministic() {
        let input = "Bonjour,\n\nCeci est un test avec https://w3.tel et des accents éàî.";
        assert_eq!(doc_json(input), doc_json(input));
    }

    #[test]
    fn schema_version_is_recorded() {
        let conv = convert_plain_text("x");
        assert_eq!(conv.doc.schema_version, SCHEMA_VERSION);
        assert_eq!(conv.doc.kind, "doc");
    }

    #[test]
    fn empty_input_produces_empty_doc() {
        let conv = convert_plain_text("");
        assert!(conv.doc.content.is_empty());
    }
}
