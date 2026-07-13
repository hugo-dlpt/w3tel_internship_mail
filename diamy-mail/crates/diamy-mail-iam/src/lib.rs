//! # diamy-mail-iam
//!
//! Client de **consommation** de Diamy IAM (A17). Diamy Mail ne réimplémente jamais
//! l'identité, la session ni les clés (INV-9 / A17-P-2) : il RÉSOUT les principaux via IAM.
//!
//! `DevIamClient` est un **doublure de test** pointant, à terme, vers l'environnement de dev
//! IAM (avec son jeu de clés). Ce n'est PAS un registre d'utilisateurs parallèle : c'est un
//! adaptateur local en attendant le branchement de l'API IAM de dev. Toute résolution passe
//! par l'adresse canonique (A24 / INV-10).
#![forbid(unsafe_code)]

use diamy_addr::{diamy_addr_canon, CanonicalAddress};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum IamError {
    #[error("principal introuvable pour cette adresse")]
    NotFound,
    #[error("adresse invalide : {0}")]
    Addr(#[from] diamy_addr::AddrError),
}

/// Un principal IAM (identifié par son UUID interne ; l'adresse est la clé de jointure, CDM-ADDR-2).
#[derive(Clone, Debug)]
pub struct Principal {
    pub id: Uuid,
    pub address: CanonicalAddress,
    /// Entitlement `diamy_mail` (A17-ENT-1).
    pub mail_enabled: bool,
}

/// Contrat de consommation IAM. Le vrai backend (env de dev IAM) implémentera ce trait ;
/// aucun appelant ne dépend de l'implémentation concrète.
pub trait IamClient {
    fn resolve_principal(&self, address: &str) -> Result<Principal, IamError>;
}

/// Doublure de dev : map en mémoire, amorcée avec des principaux de test `@w3.tel`.
/// À remplacer par l'adaptateur vers l'API de l'environnement de dev IAM.
pub struct DevIamClient {
    principals: std::collections::HashMap<String, Principal>,
}

impl DevIamClient {
    /// Amorce quelques principaux de test sous le domaine `w3.tel`.
    pub fn seeded() -> Self {
        let mut principals = std::collections::HashMap::new();
        for local in ["hugo", "cedric", "aubin"] {
            let addr =
                diamy_addr_canon(&format!("{local}@w3.tel")).expect("adresse de test valide");
            principals.insert(
                addr.as_str().to_string(),
                Principal {
                    id: Uuid::now_v7(),
                    address: addr,
                    mail_enabled: true,
                },
            );
        }
        Self { principals }
    }
}

impl IamClient for DevIamClient {
    fn resolve_principal(&self, address: &str) -> Result<Principal, IamError> {
        let canon = diamy_addr_canon(address)?; // canonicalisation AVANT lookup (A17-RES-1)
        self.principals
            .get(canon.as_str())
            .cloned()
            .ok_or(IamError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_seeded_principal_case_insensitive_domain() {
        let iam = DevIamClient::seeded();
        let p = iam.resolve_principal("hugo@W3.TEL").unwrap();
        assert!(p.mail_enabled);
        assert_eq!(p.address.as_str(), "hugo@w3.tel");
    }

    #[test]
    fn unknown_is_not_found() {
        let iam = DevIamClient::seeded();
        assert!(iam.resolve_principal("inconnu@w3.tel").is_err());
    }
}
