//! # diamy-addr
//!
//! LA fonction de normalisation canonique d'adresse (A24 / CDM-ADDR-3), partagée
//! octet-pour-octet entre serveur et client (INV-10). Toute comparaison, tout hash,
//! tout Blind-Index passe par ici — une 2e implémentation casserait recherche et routage.
//!
//! Implémente le pipeline normatif A24 §3.2 (Steps 0-6) et doit faire passer les
//! 13 vecteurs de test normatifs d'A24 §9 (voir les tests de ce module).
//!
//! Limitations assumées de cette maquette (voir `SIMPLIFICATIONS.md`) :
//! - le parseur RFC 5322 addr-spec / display-name est un sous-ensemble minimal, pas une
//!   implémentation complète de la grammaire ;
//! - le décodage RFC 2047 ne supporte que les encodages `B` (base64) et `Q`
//!   (quoted-printable), charset traité comme UTF-8 ;
//! - le case-folding "insensitive" utilise `str::to_lowercase()` (Rust), une
//!   approximation du "Unicode full case folding" normatif (diverge sur des cas rares,
//!   ex. `ß` allemand) ;
//! - la détection de script mixte (`MIXED_SCRIPT_*`) est une heuristique par plages
//!   Unicode, pas l'algorithme UTS #39 complet ;
//! - `CONFUSABLE_DOMAIN` et `PUNYCODE_LOOKALIKE` (A24 §7.1) ne sont PAS implémentés :
//!   ils dépendent respectivement de l'historique de correspondants on-device et d'une
//!   liste de marques versionnée, absents de la maquette. Ces bits restent toujours à 0.
#![forbid(unsafe_code)]

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

/// Erreurs normatives A24 §3.4.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddrError {
    #[error("ERR_ADDR_SYNTAX: adresse non conforme à RFC 5322 addr-spec")]
    Syntax,
    #[error("ERR_ADDR_DOMAIN: domaine invalide (échec IDNA2008)")]
    Domain,
    #[error("ERR_ADDR_TOO_LONG: dépasse la borne de longueur (raw 320o / local-part 64o)")]
    TooLong,
    #[error("ERR_ADDR_CONTROL_CHARS: caractère de contrôle présent")]
    ControlChars,
}

/// Politique de casse de la partie locale (A24 §3.2 Step 4), paramètre tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalCasePolicy {
    /// DEFAULT : casefold Unicode de la partie locale non-quotée.
    Insensitive,
    /// Préserve la casse de la partie locale non-quotée.
    Sensitive,
}

/// Politique de sub-adressing (A24 §3.2 Step 5), paramètre tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubaddressPolicy {
    /// DEFAULT : conserve le `+tag` intact.
    Preserve,
    /// Retire le premier `+` et tout ce qui suit, dans la partie locale non-quotée uniquement.
    Strip,
}

/// `TenantAddressPolicy` (A24 §3.1) : paramètre EXPLICITE de [`diamy_addr_canon`], jamais
/// un état ambiant (Common AI Error #8, A24 §10) — chaque appelant doit le fournir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantAddressPolicy {
    pub local_case: LocalCasePolicy,
    pub subaddress: SubaddressPolicy,
}

impl Default for TenantAddressPolicy {
    /// Politique par défaut de la plateforme (A24-POL-1) : `insensitive` / `preserve`.
    fn default() -> Self {
        Self {
            local_case: LocalCasePolicy::Insensitive,
            subaddress: SubaddressPolicy::Preserve,
        }
    }
}

/// Bits du champ `confusable_flags` (A24 §7.1).
pub mod confusable_flags {
    pub const MIXED_SCRIPT_LOCAL: u32 = 1 << 0;
    pub const MIXED_SCRIPT_DOMAIN: u32 = 1 << 1;
    /// Non implémenté dans cette maquette (nécessite l'historique de correspondants on-device).
    pub const CONFUSABLE_DOMAIN: u32 = 1 << 2;
    /// Non implémenté dans cette maquette (nécessite une liste de marques versionnée).
    pub const PUNYCODE_LOOKALIKE: u32 = 1 << 3;
    pub const INVISIBLE_CHARS: u32 = 1 << 4;
}

/// Adresse canonique — produite UNIQUEMENT par [`diamy_addr_canon`] (type-state, A18-TYPE).
/// Aucune autre voie de construction : impossible de comparer/hacher une adresse non canonique.
///
/// Porte les champs du modèle de données A24 §2.1. L'égalité/hash ne portent que sur
/// `canonical` (A24-BI-1 : c'est l'UNIQUE forme utilisée pour égalité, jointures et
/// dérivation d'index).
#[derive(Clone, Debug)]
pub struct CanonicalAddress {
    raw: String,
    canonical: String,
    display: Option<String>,
    local_part: String,
    domain_alabel: String,
    domain_ulabel: Option<String>,
    is_eai: bool,
    confusable_flags: u32,
}

impl CanonicalAddress {
    /// Forme canonique complète (`local_part@domain_alabel`) — la clé de recherche/jointure.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
    pub fn canonical(&self) -> &str {
        &self.canonical
    }
    /// L'adresse telle que reçue, préservée octet pour octet (CDM-I18N-4).
    pub fn raw(&self) -> &str {
        &self.raw
    }
    /// Display-name RFC 5322 décodé (RFC 2047) et NFC-normalisé, si présent.
    pub fn display(&self) -> Option<&str> {
        self.display.as_deref()
    }
    pub fn local_part(&self) -> &str {
        &self.local_part
    }
    /// Toujours en A-label (ASCII/punycode) — routage, SPF/DKIM/DMARC, SNI TLS.
    pub fn domain_alabel(&self) -> &str {
        &self.domain_alabel
    }
    /// U-label (Unicode), pour affichage uniquement ; présent seulement si le domaine est un IDN.
    pub fn domain_ulabel(&self) -> Option<&str> {
        self.domain_ulabel.as_deref()
    }
    pub fn is_eai(&self) -> bool {
        self.is_eai
    }
    pub fn confusable_flags(&self) -> u32 {
        self.confusable_flags
    }
}

impl std::fmt::Display for CanonicalAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.canonical)
    }
}

// A24-BI-1 : le canonical est l'UNIQUE forme comparée/hachée.
impl PartialEq for CanonicalAddress {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}
impl Eq for CanonicalAddress {}
impl std::hash::Hash for CanonicalAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.canonical.hash(state);
    }
}

/// Normalise une adresse en sa forme canonique unique (A24 §3), en suivant l'ordre normatif
/// des étapes (A24 §3.2) : réordonner les étapes change les sorties.
pub fn diamy_addr_canon(
    raw_address: &str,
    policy: TenantAddressPolicy,
) -> Result<CanonicalAddress, AddrError> {
    // --- Step 0: INPUT GUARD ---
    let raw = raw_address.trim();
    if raw.len() > 320 {
        return Err(AddrError::TooLong);
    }
    if raw.chars().any(is_control_char) {
        return Err(AddrError::ControlChars);
    }

    // --- Step 1: PARSE ---
    let (display_raw, addr_spec) = split_display_and_addr_spec(raw)?;
    let display = display_raw
        .map(decode_rfc2047)
        .map(|d| d.nfc().collect::<String>())
        .filter(|d| !d.is_empty());

    let (local_raw, domain_raw, is_quoted) = split_local_and_domain(addr_spec)?;

    if local_raw.is_empty() {
        return Err(AddrError::Syntax);
    }
    if local_raw.len() > 64 {
        return Err(AddrError::TooLong);
    }
    if domain_raw.is_empty() {
        return Err(AddrError::Syntax);
    }
    // Un domaine non-quoté ne peut pas contenir d'espace ni de '@' supplémentaire :
    // rejeté ici (ERR_ADDR_SYNTAX), pas à l'étape IDNA (ERR_ADDR_DOMAIN) — A24 §9 vecteur 11.
    if domain_raw.chars().any(|c| c.is_whitespace()) {
        return Err(AddrError::Syntax);
    }

    // --- Step 2: DOMAIN NORMALIZATION (IDNA2008 / UTS #46, transitional=false) ---
    let domain_alabel = idna::domain_to_ascii(domain_raw)
        .map_err(|_| AddrError::Domain)?
        .to_ascii_lowercase();
    if domain_alabel.is_empty() || domain_alabel.split('.').any(|label| label.is_empty()) {
        return Err(AddrError::Domain);
    }
    let (domain_unicode, uni_result) = idna::domain_to_unicode(domain_raw);
    let domain_ulabel = if uni_result.is_ok() && domain_unicode != domain_alabel {
        Some(domain_unicode)
    } else {
        None
    };

    // --- Step 3: LOCAL PART UNICODE NORMALIZATION ---
    // 3a. NFC (toujours, même sur de l'ASCII pur).
    let nfc_local: String = local_raw.nfc().collect();
    // 3b. strip des codepoints de catégorie Cf (format-class) ; flag si présents.
    let (stripped_local, had_invisible) = strip_format_chars(&nfc_local);
    // 3c. is_eai
    let is_eai = !stripped_local.is_ascii();

    // --- Step 4: LOCAL PART CASE POLICY (partie non-quotée uniquement) ---
    let cased_local = if is_quoted {
        // Une partie locale quotée est TOUJOURS préservée verbatim (RFC 5321 : le
        // guillemetage est une demande explicite d'interprétation littérale).
        stripped_local
    } else {
        match policy.local_case {
            LocalCasePolicy::Insensitive => stripped_local.to_lowercase(),
            LocalCasePolicy::Sensitive => stripped_local,
        }
    };

    // --- Step 5: SUB-ADDRESSING POLICY (partie non-quotée uniquement) ---
    let final_local = if !is_quoted && policy.subaddress == SubaddressPolicy::Strip {
        match cased_local.find('+') {
            Some(idx) => cased_local[..idx].to_string(),
            None => cased_local,
        }
    } else {
        cased_local
    };

    // --- Step 6: ASSEMBLE + confusable flags ---
    let canonical = format!("{final_local}@{domain_alabel}");

    let mut flags = 0u32;
    if had_invisible {
        flags |= confusable_flags::INVISIBLE_CHARS;
    }
    let local_for_script_check = if is_quoted {
        final_local.trim_matches('"')
    } else {
        &final_local
    };
    if is_mixed_script(local_for_script_check) {
        flags |= confusable_flags::MIXED_SCRIPT_LOCAL;
    }
    if is_mixed_script(domain_ulabel.as_deref().unwrap_or(&domain_alabel)) {
        flags |= confusable_flags::MIXED_SCRIPT_DOMAIN;
    }

    Ok(CanonicalAddress {
        raw: raw.to_string(),
        canonical,
        display,
        local_part: final_local,
        domain_alabel,
        domain_ulabel,
        is_eai,
        confusable_flags: flags,
    })
}

fn is_control_char(c: char) -> bool {
    matches!(c, '\u{0000}'..='\u{001F}' | '\u{007F}')
}

/// Codepoints de catégorie Unicode Cf (format) les plus courants dans un contexte
/// d'adresse mail : zero-width space/joiners, marques de direction, contrôles bidi,
/// word joiner, BOM. Ce n'est pas la table Cf complète (voir limitations en tête de fichier).
fn is_format_control(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}' // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | '\u{202A}'..='\u{202E}' // bidi embedding/override
        | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
        | '\u{FEFF}' // BOM / zero-width no-break space
    )
}

fn strip_format_chars(s: &str) -> (String, bool) {
    let mut had_any = false;
    let out: String = s
        .chars()
        .filter(|c| {
            if is_format_control(*c) {
                had_any = true;
                false
            } else {
                true
            }
        })
        .collect();
    (out, had_any)
}

/// Classification de script minimale (heuristique, pas UTS #39 complet) : suffit à
/// distinguer Latin / Cyrillic / Greek / Han pour la détection de script mixte.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Script {
    Common,
    Latin,
    Cyrillic,
    Greek,
    Han,
    Other,
}

fn classify_script(c: char) -> Script {
    let cp = c as u32;
    match cp {
        0x0041..=0x024F | 0x1E00..=0x1EFF => Script::Latin,
        0x0400..=0x04FF => Script::Cyrillic,
        0x0370..=0x03FF => Script::Greek,
        0x4E00..=0x9FFF | 0x3400..=0x4DBF => Script::Han,
        _ if c.is_alphabetic() => Script::Other,
        _ => Script::Common, // digits, ponctuation, symboles : script "Common", ignoré
    }
}

fn is_mixed_script(s: &str) -> bool {
    let mut seen: Option<Script> = None;
    for c in s.chars() {
        let script = classify_script(c);
        if script == Script::Common {
            continue;
        }
        match seen {
            None => seen = Some(script),
            Some(prev) if prev != script => return true,
            _ => {}
        }
    }
    false
}

/// Sépare un éventuel display-name (RFC 5322) de l'addr-spec. Reconnaît la forme
/// `display-name <addr-spec>` ; sinon l'entrée entière est l'addr-spec.
fn split_display_and_addr_spec(raw: &str) -> Result<(Option<&str>, &str), AddrError> {
    if let Some(lt) = raw.find('<') {
        if raw.ends_with('>') && lt < raw.len() - 1 {
            let display = raw[..lt].trim();
            let addr_spec = &raw[lt + 1..raw.len() - 1];
            let display = if display.is_empty() {
                None
            } else {
                Some(display)
            };
            return Ok((display, addr_spec));
        }
        return Err(AddrError::Syntax);
    }
    Ok((None, raw))
}

/// Décode les encoded-words RFC 2047 (`=?charset?B|Q?texte?=`) présents dans une chaîne.
/// Charset traité comme UTF-8 (limitation assumée). Encodages `B` (base64) et `Q`
/// (quoted-printable) supportés ; toute autre séquence est laissée telle quelle.
fn decode_rfc2047(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("=?") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(q1) = after.find('?') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let _charset = &after[..q1];
        let after_charset = &after[q1 + 1..];
        let Some(q2) = after_charset.find('?') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let encoding = &after_charset[..q2];
        let after_encoding = &after_charset[q2 + 1..];
        let Some(end) = after_encoding.find("?=") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let encoded_text = &after_encoding[..end];

        let decoded = match encoding.to_ascii_uppercase().as_str() {
            "B" => base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded_text)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok()),
            "Q" => Some(decode_quoted_printable_word(encoded_text)),
            _ => None,
        };
        out.push_str(&decoded.unwrap_or_else(|| encoded_text.to_string()));

        rest = &after_encoding[end + 2..];
    }
    out.push_str(rest);
    out
}

fn decode_quoted_printable_word(s: &str) -> String {
    let mut out = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut raw_bytes = Vec::new();
    while i < bytes.len() {
        match bytes[i] {
            b'_' => {
                raw_bytes.push(b' ');
                i += 1;
            }
            b'=' if i + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    raw_bytes.push(byte);
                    i += 3;
                } else {
                    raw_bytes.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                raw_bytes.push(b);
                i += 1;
            }
        }
    }
    out.push_str(&String::from_utf8_lossy(&raw_bytes));
    out
}

/// Sépare la partie locale du domaine sur le SEUL `@` de premier niveau (hors guillemets).
/// Retourne aussi si la partie locale est quotée (préservée verbatim, A24 §3.2 Step 1/4/5).
fn split_local_and_domain(addr_spec: &str) -> Result<(&str, &str, bool), AddrError> {
    let bytes: Vec<(usize, char)> = addr_spec.char_indices().collect();
    let mut in_quotes = false;
    let mut at_idx: Option<usize> = None;
    let mut i = 0;
    while i < bytes.len() {
        let (byte_idx, c) = bytes[i];
        if c == '\\' && in_quotes {
            i += 2;
            continue;
        }
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c == '@' && !in_quotes {
            at_idx = Some(byte_idx);
        }
        i += 1;
    }
    if in_quotes {
        return Err(AddrError::Syntax);
    }
    let at_idx = at_idx.ok_or(AddrError::Syntax)?;
    let local = &addr_spec[..at_idx];
    let domain = &addr_spec[at_idx + 1..];
    let is_quoted = local.starts_with('"') && local.ends_with('"') && local.len() >= 2;
    Ok((local, domain, is_quoted))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(s: &str) -> String {
        diamy_addr_canon(s, TenantAddressPolicy::default())
            .unwrap()
            .as_str()
            .to_string()
    }

    fn canon_with(s: &str, policy: TenantAddressPolicy) -> String {
        diamy_addr_canon(s, policy).unwrap().as_str().to_string()
    }

    // --- Vecteurs normatifs A24 §9 (les 13 doivent passer, release-blocking A24 §10.1) ---

    #[test]
    fn vector_01_case_folding_both_sides() {
        assert_eq!(canon("Jean.Dupont@Example.FR"), "jean.dupont@example.fr");
    }

    #[test]
    fn vector_02_default_preserves_subaddress() {
        assert_eq!(canon("user+tag@example.fr"), "user+tag@example.fr");
    }

    #[test]
    fn vector_03_strip_subaddress_policy() {
        let policy = TenantAddressPolicy {
            local_case: LocalCasePolicy::Insensitive,
            subaddress: SubaddressPolicy::Strip,
        };
        assert_eq!(canon_with("user+tag@example.fr", policy), "user@example.fr");
    }

    #[test]
    fn vector_04_eai_local_and_idn_domain_nfc_preserved() {
        assert_eq!(canon("café@société.fr"), "café@xn--socit-esab.fr");
    }

    #[test]
    fn vector_05_nfc_folds_combining_acute_identical_to_vector_04() {
        // "cafe" + combining acute (U+0301) doit NFC-folder en "café" (U+00E9).
        let input = "cafe\u{0301}@société.fr";
        assert_eq!(canon(input), canon("café@société.fr"));
    }

    #[test]
    fn vector_06_quoted_local_part_preserved_with_quotes() {
        assert_eq!(canon(r#""jean dupont"@example.fr"#), r#""jean dupont"@example.fr"#);
    }

    #[test]
    fn vector_07_sensitive_policy_preserves_local_domain_still_folds() {
        let policy = TenantAddressPolicy {
            local_case: LocalCasePolicy::Sensitive,
            subaddress: SubaddressPolicy::Preserve,
        };
        assert_eq!(canon_with("USER@EXAMPLE.FR", policy), "USER@example.fr");
    }

    #[test]
    fn vector_08_display_name_decoded_canonical_from_addr_spec_only() {
        let result =
            diamy_addr_canon("=?utf-8?B?SsOpcsO0bWU=?= <j@example.fr>", TenantAddressPolicy::default())
                .unwrap();
        assert_eq!(result.as_str(), "j@example.fr");
        assert_eq!(result.display(), Some("Jérôme"));
    }

    #[test]
    fn vector_09_alabel_input_accepted_as_is_ulabel_present() {
        let result =
            diamy_addr_canon("user@xn--socit-esab.fr", TenantAddressPolicy::default()).unwrap();
        assert_eq!(result.as_str(), "user@xn--socit-esab.fr");
        assert_eq!(result.domain_ulabel(), Some("société.fr"));
    }

    #[test]
    fn vector_10_cyrillic_lookalike_keeps_codepoint_and_flags_mixed_script() {
        let input = "p\u{0430}ypal@example.fr"; // 'а' cyrillique (U+0430)
        let result = diamy_addr_canon(input, TenantAddressPolicy::default()).unwrap();
        assert_eq!(result.as_str(), input);
        assert_ne!(
            result.confusable_flags() & confusable_flags::MIXED_SCRIPT_LOCAL,
            0
        );
    }

    #[test]
    fn vector_11_space_in_domain_is_syntax_error() {
        assert_eq!(
            diamy_addr_canon("user@exam ple.fr", TenantAddressPolicy::default()),
            Err(AddrError::Syntax)
        );
    }

    #[test]
    fn vector_12_zero_width_space_stripped_and_flagged() {
        let input = "us\u{200B}er@example.fr";
        let result = diamy_addr_canon(input, TenantAddressPolicy::default()).unwrap();
        assert_eq!(result.as_str(), "user@example.fr");
        assert_ne!(
            result.confusable_flags() & confusable_flags::INVISIBLE_CHARS,
            0
        );
    }

    #[test]
    fn vector_13_quoted_local_part_casefold_does_not_apply() {
        // Politique insensitive, mais quoté => casefold ignoré (Step 4).
        assert_eq!(
            canon(r#""Jean Dupont"@example.fr"#),
            r#""Jean Dupont"@example.fr"#
        );
    }

    // --- Tests structurels complémentaires (bornes, erreurs, idempotence) ---

    #[test]
    fn surrounding_whitespace_trimmed() {
        assert_eq!(canon("  hugo@w3.tel  "), "hugo@w3.tel");
    }

    #[test]
    fn idempotent() {
        let once = canon("Hugo@CAFÉ.FR");
        let twice = canon(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn missing_at_is_syntax_error() {
        assert_eq!(
            diamy_addr_canon("hugo.w3.tel", TenantAddressPolicy::default()),
            Err(AddrError::Syntax)
        );
    }

    #[test]
    fn control_char_is_rejected() {
        assert_eq!(
            diamy_addr_canon("hu\u{0007}go@w3.tel", TenantAddressPolicy::default()),
            Err(AddrError::ControlChars)
        );
    }

    #[test]
    fn local_part_over_64_octets_is_too_long() {
        let long_local = "a".repeat(65);
        let input = format!("{long_local}@w3.tel");
        assert_eq!(
            diamy_addr_canon(&input, TenantAddressPolicy::default()),
            Err(AddrError::TooLong)
        );
    }

    #[test]
    fn raw_over_320_bytes_is_too_long() {
        let input = format!("{}@w3.tel", "a".repeat(320));
        assert_eq!(
            diamy_addr_canon(&input, TenantAddressPolicy::default()),
            Err(AddrError::TooLong)
        );
    }

    #[test]
    fn canonical_address_equality_ignores_raw_case_after_normalization() {
        let a = diamy_addr_canon("Hugo@W3.TEL", TenantAddressPolicy::default()).unwrap();
        let b = diamy_addr_canon("hugo@w3.tel", TenantAddressPolicy::default()).unwrap();
        assert_eq!(a, b);
    }
}
