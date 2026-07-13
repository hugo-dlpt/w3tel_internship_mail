//! Types du contrat crypto. Les types « clair » et « clé » sont zeroized au drop
//! et n'impriment jamais leur contenu (A18-ZERO-1/3). Ils sont volontairement
//! opaques : le reste du workspace ne manipule que ces types, jamais une primitive.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Clé AES-256 d'un message (secret). Zeroized au drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MessageKey(pub(crate) [u8; 32]);

impl MessageKey {
    pub(crate) fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Clé dérivée par HKDF-avec-label (jamais un secret brut, A18-CRY-2). Zeroized au drop.
#[derive(ZeroizeOnDrop)]
pub struct DerivedKey(pub(crate) [u8; 32]);

impl DerivedKey {
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Chiffré AEAD : nonce (96 bits) + octets (contenu + tag GCM).
#[derive(Clone)]
pub struct Ciphertext {
    pub nonce: [u8; 12],
    pub bytes: Vec<u8>,
}

/// Clair dont l'authenticité a été vérifiée (tag GCM OK). Ne peut être obtenu
/// QUE via `open_message` — impossible de rendre/indexer du clair non vérifié (INV-8).
pub struct VerifiedPlaintext(pub(crate) Vec<u8>);

impl VerifiedPlaintext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Consomme le type pour récupérer les octets vérifiés.
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for VerifiedPlaintext {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Clé publique de chiffrement d'un appareil (ML-KEM-768, publiée à l'annuaire).
#[derive(Clone)]
pub struct DeviceEncPublicKey(pub Vec<u8>);

/// Clé privée de chiffrement d'un appareil (ML-KEM-768). Ne quitte jamais l'appareil (INV-4).
#[derive(Clone, ZeroizeOnDrop)]
pub struct DeviceEncSecretKey(pub(crate) Vec<u8>);

impl DeviceEncSecretKey {
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self(b)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Enveloppe : la clé de message emballée pour UN appareil (une par appareil, STO-1).
#[derive(Clone)]
pub struct Envelope {
    /// Ciphertext KEM (encapsulation vers la clé publique de l'appareil).
    pub kem_ct: Vec<u8>,
    /// Clé de message emballée sous la KEK dérivée du secret KEM.
    pub wrapped: Ciphertext,
}

/// Clé publique d'identité (signature). Cible : ML-DSA-65 ; dev : Ed25519.
#[derive(Clone)]
pub struct IdentityPublicKey(pub Vec<u8>);

/// Clé privée d'identité (signature). Zeroized au drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct IdentitySecretKey(pub(crate) Vec<u8>);

/// Signature d'un manifest (Diamy↔Diamy, A02 §5.2).
#[derive(Clone)]
pub struct Signature(pub Vec<u8>);
