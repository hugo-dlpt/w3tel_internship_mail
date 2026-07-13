//! # diamy-addr
//!
//! LA fonction de normalisation canonique d'adresse (A24 / CDM-ADDR-3), partagée
//! octet-pour-octet entre serveur et client (INV-10). Toute comparaison, tout hash,
//! tout Blind-Index passe par ici — une 2e implémentation casserait recherche et routage.
//!
//! Forme canonique : domaine en minuscules + IDN→A-label (punycode) ; partie locale
//! NFC-normalisée ; espaces de bordure supprimés. (La casse de la partie locale est
//! PRÉSERVÉE par défaut — CDM-ADDR-5 : politique tenant, non traitée ici.)
#![forbid(unsafe_code)]

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddrError {
    #[error("adresse sans '@'")]
    MissingAt,
    #[error("partie locale vide")]
    EmptyLocal,
    #[error("domaine vide")]
    EmptyDomain,
    #[error("domaine invalide (IDN/punycode)")]
    InvalidDomain,
}

/// Adresse canonique — produite UNIQUEMENT par [`diamy_addr_canon`] (type-state, A18-TYPE).
/// Aucune autre voie de construction : impossible de comparer/hacher une adresse non canonique.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalAddress(String);

impl CanonicalAddress {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CanonicalAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Normalise une adresse en sa forme canonique unique (A24 §3).
pub fn diamy_addr_canon(input: &str) -> Result<CanonicalAddress, AddrError> {
    let trimmed = input.trim();
    let at = trimmed.rfind('@').ok_or(AddrError::MissingAt)?;
    let (local_raw, domain_raw) = trimmed.split_at(at);
    let domain_raw = &domain_raw[1..]; // enlève le '@'

    if local_raw.is_empty() {
        return Err(AddrError::EmptyLocal);
    }
    if domain_raw.is_empty() {
        return Err(AddrError::EmptyDomain);
    }

    // Partie locale : NFC (visuellement identiques -> mêmes octets, A24 / CDM-I18N-9).
    let local: String = local_raw.nfc().collect();

    // Domaine : IDN → A-label (punycode) + minuscules (idna gère les deux).
    let domain = idna::domain_to_ascii(domain_raw).map_err(|_| AddrError::InvalidDomain)?;
    if domain.is_empty() {
        return Err(AddrError::EmptyDomain);
    }

    Ok(CanonicalAddress(format!("{local}@{domain}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(s: &str) -> String {
        diamy_addr_canon(s).unwrap().as_str().to_string()
    }

    #[test]
    fn domain_is_lowercased() {
        assert_eq!(canon("Hugo@W3.TEL"), "Hugo@w3.tel");
    }

    #[test]
    fn surrounding_whitespace_trimmed() {
        assert_eq!(canon("  hugo@w3.tel  "), "hugo@w3.tel");
    }

    #[test]
    fn local_case_preserved_by_default() {
        // CDM-ADDR-5 : casse locale préservée (politique tenant non appliquée ici).
        assert_eq!(canon("Hugo.B@w3.tel"), "Hugo.B@w3.tel");
    }

    #[test]
    fn idn_domain_to_punycode() {
        // café.fr -> xn--caf-dma.fr (A-label)
        assert_eq!(canon("test@café.fr"), "test@xn--caf-dma.fr");
    }

    #[test]
    fn idempotent() {
        let once = canon("Hugo@CAFÉ.FR");
        let twice = canon(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn missing_at_is_error() {
        assert_eq!(diamy_addr_canon("hugo.w3.tel"), Err(AddrError::MissingAt));
    }

    // TODO(A24) : câbler ici les 13 vecteurs normatifs officiels d'A24 (dont cas punycode)
    // comme gate CI (A18-TEST-1). Les cas ci-dessus ne sont qu'un point de départ.
}
