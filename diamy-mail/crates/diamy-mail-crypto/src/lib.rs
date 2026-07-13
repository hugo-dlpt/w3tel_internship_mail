//! # diamy-mail-crypto
//!
//! LA seule maison de la crypto de Diamy Mail (INV-5, A18-TOP-1). Le reste du
//! workspace n'appelle QUE cette API — jamais une primitive directement.
//!
//! Deux backends interchangeables derrière un *feature flag* Cargo :
//!   - `dev-crypto`       : primitives auditées RustCrypto — débloque la maquette. NON EXPÉDIABLE.
//!   - `messaging-crypto` : la cible (primitives du messaging Diamy) — à brancher quand il est stable.
//!
//! La bascule d'un backend à l'autre ne change RIEN chez les appelants.
#![forbid(unsafe_code)]

mod error;
mod newtypes;

pub use error::CryptoError;
pub use newtypes::{
    Ciphertext, DerivedKey, DeviceEncPublicKey, DeviceEncSecretKey, Envelope, IdentityPublicKey,
    IdentitySecretKey, MessageKey, Signature, VerifiedPlaintext,
};

#[cfg(all(feature = "dev-crypto", feature = "messaging-crypto"))]
compile_error!("Active EXACTEMENT un backend crypto : `dev-crypto` OU `messaging-crypto`.");

#[cfg(not(any(feature = "dev-crypto", feature = "messaging-crypto")))]
compile_error!("Active un backend crypto : `dev-crypto` (dev) ou `messaging-crypto` (cible).");

#[cfg(feature = "dev-crypto")]
mod dev_backend;
#[cfg(feature = "dev-crypto")]
use dev_backend as backend;

#[cfg(feature = "messaging-crypto")]
mod messaging_backend;
#[cfg(feature = "messaging-crypto")]
use messaging_backend as backend;

/// Nom lisible du backend actif (pour les logs / la bannière de démarrage).
pub const fn backend_name() -> &'static str {
    backend::NAME
}

/// `true` si le backend actif est le backend de développement (non expédiable).
pub const fn is_dev_backend() -> bool {
    backend::IS_DEV
}

/// Garde-fou *fail-closed* : le backend `dev-crypto` ne doit JAMAIS tourner en prod.
/// À appeler au démarrage de chaque service (esprit A18 SEC-FC-1). `env` vient p.ex.
/// de la variable `DIAMY_ENV` (`dev` | `staging` | `prod`).
pub fn assert_backend_allowed_for_env(env: &str) -> Result<(), CryptoError> {
    if is_dev_backend() && env != "dev" {
        return Err(CryptoError::DevBackendInProd);
    }
    Ok(())
}

// --- Façade publique : délègue au backend actif ---

/// Chiffre un contenu et renvoie (chiffré, clé de message fraîche).
pub fn seal_message(plaintext: &[u8]) -> Result<(Ciphertext, MessageKey), CryptoError> {
    backend::seal_message(plaintext)
}

/// Déchiffre et VÉRIFIE le tag ; ne renvoie un `VerifiedPlaintext` qu'en cas de succès (INV-8).
pub fn open_message(ct: &Ciphertext, key: &MessageKey) -> Result<VerifiedPlaintext, CryptoError> {
    backend::open_message(ct, key)
}

/// Génère une paire de clés de chiffrement d'appareil (ML-KEM-768).
pub fn generate_device_keypair() -> Result<(DeviceEncPublicKey, DeviceEncSecretKey), CryptoError> {
    backend::generate_device_keypair()
}

/// Emballe la clé de message pour UN appareil (une enveloppe par appareil, STO-1).
pub fn wrap_key_for_device(
    key: &MessageKey,
    device_pub: &DeviceEncPublicKey,
) -> Result<Envelope, CryptoError> {
    backend::wrap_key_for_device(key, device_pub)
}

/// Désemballe la clé de message avec la clé privée de l'appareil.
pub fn unwrap_key(
    env: &Envelope,
    device_sec: &DeviceEncSecretKey,
) -> Result<MessageKey, CryptoError> {
    backend::unwrap_key(env, device_sec)
}

/// Dérive une clé via HKDF avec un label `info` explicite (jamais un secret brut, A18-CRY-2).
pub fn derive_key(secret: &[u8], info: &[u8]) -> Result<DerivedKey, CryptoError> {
    backend::derive_key(secret, info)
}

/// Génère une paire de clés d'identité (signature). Cible ML-DSA-65 ; dev Ed25519.
pub fn generate_identity_keypair() -> Result<(IdentityPublicKey, IdentitySecretKey), CryptoError> {
    backend::generate_identity_keypair()
}

/// Signe un manifest (Diamy↔Diamy, A02 §5.2).
pub fn sign_manifest(sk: &IdentitySecretKey, msg: &[u8]) -> Result<Signature, CryptoError> {
    backend::sign_manifest(sk, msg)
}

/// Vérifie la signature d'un manifest avant tout rendu (A19-CRY-4).
pub fn verify_manifest(
    pk: &IdentityPublicKey,
    msg: &[u8],
    sig: &Signature,
) -> Result<bool, CryptoError> {
    backend::verify_manifest(pk, msg, sig)
}

#[cfg(all(test, feature = "dev-crypto"))]
mod tests {
    use super::*;

    // Round-trip enveloppe : sceller -> emballer par appareil -> désemballer -> ouvrir.
    #[test]
    fn envelope_round_trip() {
        let plaintext = b"Bonjour Hugo, ceci est un message de test Diamy Mail.";
        let (ct, mk) = seal_message(plaintext).unwrap();

        let (pk, sk) = generate_device_keypair().unwrap();
        let env = wrap_key_for_device(&mk, &pk).unwrap();

        let mk2 = unwrap_key(&env, &sk).unwrap();
        let opened = open_message(&ct, &mk2).unwrap();
        assert_eq!(opened.as_bytes(), plaintext);
    }

    // Fail-closed : un tag GCM altéré NE doit PAS produire de clair (INV-8/16).
    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut ct, mk) = seal_message(b"payload").unwrap();
        let last = ct.bytes.len() - 1;
        ct.bytes[last] ^= 0x01; // corruption d'un octet
        assert!(open_message(&ct, &mk).is_err());
    }

    // Une mauvaise clé d'appareil ne désemballe pas.
    #[test]
    fn wrong_device_cannot_unwrap() {
        let (_ct, mk) = seal_message(b"payload").unwrap();
        let (pk, _sk) = generate_device_keypair().unwrap();
        let (_pk2, sk2) = generate_device_keypair().unwrap();
        let env = wrap_key_for_device(&mk, &pk).unwrap();
        assert!(unwrap_key(&env, &sk2).is_err());
    }

    // Signature d'identité (stand-in Ed25519).
    #[test]
    fn identity_sign_verify() {
        let (pk, sk) = generate_identity_keypair().unwrap();
        let msg = b"manifest";
        let sig = sign_manifest(&sk, msg).unwrap();
        assert!(verify_manifest(&pk, msg, &sig).unwrap());
        assert!(!verify_manifest(&pk, b"autre", &sig).unwrap());
    }

    #[test]
    fn dev_backend_refused_in_prod() {
        assert!(assert_backend_allowed_for_env("dev").is_ok());
        assert!(assert_backend_allowed_for_env("prod").is_err());
    }
}
