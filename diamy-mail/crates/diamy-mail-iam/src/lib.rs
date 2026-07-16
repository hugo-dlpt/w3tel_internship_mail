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

use diamy_addr::{diamy_addr_canon, CanonicalAddress, TenantAddressPolicy};
use thiserror::Error;
use uuid::Uuid;

mod mail_plane_token;
// Seule la VÉRIFICATION est exposée. Aucune fonction d'émission de jeton n'existe (INV-9 /
// A17-P-1 : seul IAM émet des jetons) — voir la note dans `mail_plane_token.rs`.
pub use mail_plane_token::{verify_mail_plane_token, MailPlaneTokenError};

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

/// Dérivation de DEV UNIQUEMENT du `tenant_id` depuis le domaine (A17-P-3 : "A Diamy Mail
/// tenant IS a Diamy IAM tenant") — UUIDv5 déterministe, EXACTEMENT le même pattern que
/// `DevIamClient::seeded()` pour `principal_id` (voir sa doc : plusieurs process doivent
/// résoudre le MÊME id pour un même domaine à chaque démarrage, pas un id frais qui rendrait
/// une donnée déjà écrite sous l'ancien id introuvable).
///
/// Ceci reste un **holder INERTE** tant qu'A11 (vrai mapping domaine→tenant, onboarding)
/// n'existe pas : c'est un id stable et déterministe pour un domaine donné, PAS un vrai
/// tenant IAM résolu. Voir `SIMPLIFICATIONS.md`.
pub fn derive_dev_tenant_id(domain_alabel: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_DNS, domain_alabel.as_bytes())
}

/// Doublure de dev : map en mémoire, amorcée avec des principaux de test `@w3.tel`.
/// À remplacer par l'adaptateur vers l'API de l'environnement de dev IAM.
pub struct DevIamClient {
    principals: std::collections::HashMap<String, Principal>,
}

impl DevIamClient {
    /// Amorce quelques principaux de test sous le domaine `w3.tel`.
    ///
    /// L'`id` de chaque principal est un UUIDv5 **dérivé de façon déterministe** de son
    /// adresse canonique (pas un `Uuid::now_v7()` généré à l'exécution) : plusieurs
    /// processus (`diamy-mxd`, `diamy-maild`, l'exemple `enroll_test_device`) doivent
    /// résoudre le MÊME `principal_id` pour "hugo@w3.tel" à chaque démarrage — sans quoi
    /// une clé d'appareil publiée par l'un ne serait jamais retrouvée par l'autre (un vrai
    /// IAM donnerait un id stable, persisté une fois pour toutes ; cette doublure de dev
    /// doit imiter cette stabilité, pas la recréer aléatoirement à chaque run).
    pub fn seeded() -> Self {
        let mut principals = std::collections::HashMap::new();
        for local in ["hugo", "cedric", "aubin"] {
            let addr = diamy_addr_canon(&format!("{local}@w3.tel"), TenantAddressPolicy::default())
                .expect("adresse de test valide");
            let id = Uuid::new_v5(&Uuid::NAMESPACE_DNS, addr.as_str().as_bytes());
            principals.insert(
                addr.as_str().to_string(),
                Principal {
                    id,
                    address: addr,
                    mail_enabled: true,
                },
            );
        }
        Self { principals }
    }

    /// Résolution INVERSE (id -> principal) : un vrai IAM la supporte trivialement ; cette
    /// doublure de dev l'ajoute pour que `diamy-mxd` puisse retrouver l'adresse d'un
    /// principal qui a de la file de hold en attente (A01-HOLD-4, le job de release ne
    /// connait que des `principal_id`, jamais des adresses) sans avoir à stocker
    /// l'adresse une seconde fois côté stockage (voir SIMPLIFICATIONS.md).
    pub fn find_by_id(&self, id: Uuid) -> Option<&Principal> {
        self.principals.values().find(|p| p.id == id)
    }
}

impl IamClient for DevIamClient {
    fn resolve_principal(&self, address: &str) -> Result<Principal, IamError> {
        // Politique plateforme par défaut (A24-POL-3 passe 1) : le tenant n'est pas encore
        // connu à ce stade de la résolution ; cette maquette ne fait pas la 2e passe avec la
        // politique du tenant résolu (simplification, voir SIMPLIFICATIONS.md).
        let canon = diamy_addr_canon(address, TenantAddressPolicy::default())?;
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

    #[test]
    fn dev_tenant_id_is_deterministic_per_domain() {
        // Même exigence que pour principal_id (voir DevIamClient::seeded) : plusieurs
        // process/redémarrages doivent retrouver le MÊME tenant_id pour "w3.tel", pas un
        // id frais qui rendrait une ligne déjà écrite orpheline.
        assert_eq!(derive_dev_tenant_id("w3.tel"), derive_dev_tenant_id("w3.tel"));
    }

    #[test]
    fn dev_tenant_id_differs_across_domains() {
        assert_ne!(derive_dev_tenant_id("w3.tel"), derive_dev_tenant_id("example.fr"));
    }
}
