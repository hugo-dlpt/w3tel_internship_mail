//! # diamy-mail-model
//!
//! Types de données du serveur, miroir de la DDL A21 (source de vérité : la DDL, CDM-NULL-2).
//! Chaque champ stocké porte sa **classification de chiffrement** (CDM-ENC-1) : le serveur
//! ne détient QUE du `PlaintextMetadata`, du `BlindIndex` (webmail) ou du `Ciphertext`.
#![forbid(unsafe_code)]

use uuid::Uuid;

/// Classification de chiffrement d'un champ stocké (CDM-ENC-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldClass {
    /// Routage/technique, visible du serveur.
    PlaintextMetadata,
    /// Index aveugle (uniquement si webmail activé).
    BlindIndex,
    /// Jamais lisible par le serveur.
    Ciphertext,
}

/// Enveloppe stockée pour UN appareil (le serveur ne peut pas l'ouvrir, INV-1).
pub struct StoredEnvelope {
    pub device_id: Uuid,
    /// Ciphertext KEM + clé de message emballée (octets opaques côté serveur).
    pub kem_ct: Vec<u8>,
    pub wrap_nonce: [u8; 12],
    pub wrapped_key: Vec<u8>,
}

/// Message tel que le serveur le stocke : chiffré + enveloppes + métadonnées. Aucun clair.
pub struct StoredMessage {
    /// Identifiant interne (UUIDv7, time-ordered — CDM-ID-1).
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub recipient_id: Uuid,
    // --- CIPHERTEXT (jamais lisible côté serveur) ---
    pub body_nonce: [u8; 12],
    pub body_ciphertext: Vec<u8>,
    pub envelopes: Vec<StoredEnvelope>,
    // --- PLAINTEXT_METADATA (routage) ---
    pub size_bytes: u64,
    pub received_at_ms: i64,
}

impl StoredMessage {
    /// Génère un identifiant de message conforme (UUIDv7).
    pub fn new_id() -> Uuid {
        Uuid::now_v7()
    }

    /// Classification déclarée de chaque champ (doc vivante + base d'un futur linter INV-2).
    pub fn field_class(field: &str) -> Option<FieldClass> {
        Some(match field {
            "body_ciphertext" | "wrapped_key" | "kem_ct" => FieldClass::Ciphertext,
            "size_bytes" | "received_at_ms" | "recipient_id" | "tenant_id" => {
                FieldClass::PlaintextMetadata
            }
            _ => return None,
        })
    }
}
