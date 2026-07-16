//! Types du contrat crypto. Les types « clair » et « clé » sont zeroized au drop
//! et n'impriment jamais leur contenu (A18-ZERO-1/3). Ils sont volontairement
//! opaques : le reste du workspace ne manipule que ces types, jamais une primitive.

use crate::error::CryptoError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Version du schéma cryptographique d'un chiffré/enveloppe (A02-CRY-7 ; colonnes
/// `mail.blobs.blob_alg_version` et `mail.envelopes.alg_version` d'A21). Représentée
/// comme un **enum** (INV-7, A18-CRY-4) : le `match` de dispatch au déchiffrement (dans le
/// backend) et [`AlgVersion::as_i32`] ci-dessous n'ont PAS de bras `_` — ajouter une
/// variante ici sans traiter tous ces `match` est une **erreur de compilation**, jamais
/// une version silencieusement « devinée ».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgVersion {
    /// Suite courante : AES-256-GCM + ML-KEM-768 + HKDF-SHA256 (A02 / A17-KEY-2).
    V1,
}

impl AlgVersion {
    /// Version que le scellement écrit aujourd'hui (A02-CRY-7).
    pub const CURRENT: AlgVersion = AlgVersion::V1;

    /// Entier stocké en base (colonnes A21). `match` exhaustif SANS catch-all : une
    /// nouvelle variante non traitée casse la compilation ici (A18-CRY-4).
    pub const fn as_i32(self) -> i32 {
        match self {
            AlgVersion::V1 => 1,
        }
    }

    /// Analyse une version lue en base / sur le fil **AU DÉCHIFFREMENT** (INV-7). Une
    /// version inconnue est rejetée *fail-closed* (INV-16), jamais devinée (A18-CRY-4).
    /// Le `match` porte sur un `i32` externe non fiable : son dernier bras rejette tout
    /// inconnu — ce n'est pas le « catch-all sur l'enum » proscrit, mais le rejet explicite
    /// exigé d'une entrée hors du type.
    pub fn from_i32(v: i32) -> Result<AlgVersion, CryptoError> {
        match v {
            1 => Ok(AlgVersion::V1),
            other => Err(CryptoError::UnknownAlgVersion(other)),
        }
    }
}

/// Clé AES-256 d'un message (secret). Zeroized au drop. PAS `Clone` (A18-ZERO-3,
/// forbidden pattern #4) : dupliquer du matériel de clé doit être une erreur de
/// compilation, pas une simple observation — aucun appelant n'en a besoin.
#[derive(ZeroizeOnDrop)]
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

/// Chiffré AEAD : version de suite + nonce (96 bits) + octets (contenu + tag GCM).
/// `alg_version` (A02-CRY-7) est vérifiée à CHAQUE déchiffrement (INV-7) : voir le
/// dispatch sans catch-all dans le backend (`open_message`/`open_with_key`/`unwrap_key`/
/// `unwrap_message_key_from_hold`).
#[derive(Clone)]
pub struct Ciphertext {
    pub alg_version: AlgVersion,
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
/// PAS `Clone` (A18-ZERO-3, forbidden pattern #4) : voir [`MessageKey`].
#[derive(ZeroizeOnDrop)]
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

/// Clé privée d'identité (signature). Zeroized au drop. PAS `Clone` (A18-ZERO-3,
/// forbidden pattern #4) : voir [`MessageKey`].
#[derive(ZeroizeOnDrop)]
pub struct IdentitySecretKey(pub(crate) Vec<u8>);

/// Signature d'un manifest (Diamy↔Diamy, A02 §5.2).
#[derive(Clone)]
pub struct Signature(pub Vec<u8>);
