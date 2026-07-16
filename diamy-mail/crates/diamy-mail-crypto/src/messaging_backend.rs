//! Backend `messaging-crypto` — la CIBLE : primitives auditées du messaging Diamy
//! (ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF via la crate crypto partagée du messaging).
//!
//! PAS ENCORE BRANCHÉ : le messaging vient d'être mis en ligne et n'est pas stable.
//! Quand il le sera, on implémente ces fonctions ici — et RIEN d'autre dans le workspace
//! ne change (INV-5 : une seule maison pour la crypto). Points à récupérer côté messaging :
//! labels HKDF `info` exacts et format d'enveloppe (interop, A02-CRY / A19-PAR).

use crate::error::CryptoError;
use crate::newtypes::*;

pub const NAME: &str = "messaging-crypto (Diamy messaging shared crate) — NON BRANCHÉ";
pub const IS_DEV: bool = false;

fn not_wired<T>() -> Result<T, CryptoError> {
    Err(CryptoError::MessagingBackendNotWired(
        "brancher les primitives du messaging Diamy",
    ))
}

pub fn seal_message(_plaintext: &[u8], _aad: &[u8]) -> Result<(Ciphertext, MessageKey), CryptoError> {
    not_wired()
}
pub fn open_message(
    _ct: &Ciphertext,
    _key: &MessageKey,
    _aad: &[u8],
) -> Result<VerifiedPlaintext, CryptoError> {
    not_wired()
}
pub fn generate_device_keypair() -> Result<(DeviceEncPublicKey, DeviceEncSecretKey), CryptoError> {
    not_wired()
}
pub fn wrap_key_for_device(
    _mk: &MessageKey,
    _pk: &DeviceEncPublicKey,
    _aad: &[u8],
) -> Result<Envelope, CryptoError> {
    not_wired()
}
pub fn unwrap_key(_env: &Envelope, _sk: &DeviceEncSecretKey, _aad: &[u8]) -> Result<MessageKey, CryptoError> {
    not_wired()
}
pub fn derive_key(_secret: &[u8], _info: &[u8]) -> Result<DerivedKey, CryptoError> {
    not_wired()
}
pub fn seal_with_key(_plaintext: &[u8], _key: &DerivedKey, _aad: &[u8]) -> Result<Ciphertext, CryptoError> {
    not_wired()
}
pub fn open_with_key(_ct: &Ciphertext, _key: &DerivedKey, _aad: &[u8]) -> Result<VerifiedPlaintext, CryptoError> {
    not_wired()
}
pub fn wrap_message_key_under_hold(
    _mk: &MessageKey,
    _k_hold: &DerivedKey,
    _aad: &[u8],
) -> Result<Ciphertext, CryptoError> {
    not_wired()
}
pub fn unwrap_message_key_from_hold(
    _ct: &Ciphertext,
    _k_hold: &DerivedKey,
    _aad: &[u8],
) -> Result<MessageKey, CryptoError> {
    not_wired()
}
pub fn generate_identity_keypair() -> Result<(IdentityPublicKey, IdentitySecretKey), CryptoError> {
    not_wired()
}
pub fn sign_manifest(_sk: &IdentitySecretKey, _msg: &[u8]) -> Result<Signature, CryptoError> {
    not_wired()
}
pub fn verify_manifest(
    _pk: &IdentityPublicKey,
    _msg: &[u8],
    _sig: &Signature,
) -> Result<bool, CryptoError> {
    not_wired()
}
