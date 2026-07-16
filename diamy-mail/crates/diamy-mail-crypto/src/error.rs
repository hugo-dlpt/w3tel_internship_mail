use thiserror::Error;

/// Erreurs crypto. Toutes les opérations échouent *fail-closed* (INV-16) :
/// aucune ne renvoie de clair non vérifié.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("échec du chiffrement AEAD")]
    Encrypt,
    #[error("échec du déchiffrement / vérification du tag (fail-closed)")]
    DecryptVerify,
    #[error("clé ou matériel cryptographique invalide")]
    InvalidKeyMaterial,
    #[error("encapsulation/décapsulation KEM échouée")]
    Kem,
    #[error(
        "le backend `dev-crypto` ne peut pas tourner hors d'un environnement de dev (fail-closed)"
    )]
    DevBackendInProd,
    #[error("backend `messaging-crypto` pas encore branché : {0}")]
    MessagingBackendNotWired(&'static str),
    #[error("version d'algorithme inconnue au déchiffrement : {0} (fail-closed, A02-CRY-7 / INV-7)")]
    UnknownAlgVersion(i32),
}
