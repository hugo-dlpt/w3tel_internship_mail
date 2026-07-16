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
    ///
    /// Source de vérité : la DDL A21 (CDM-NULL-2) et A02 §4 (CDM-ENC-1). En particulier,
    /// A02 §4.3 (footnote¹) classe `kem_ct` et `wrapped_key` comme **PLAINTEXT_METADATA**,
    /// PAS CIPHERTEXT : ils sont « cryptographically opaque to the server (it holds no
    /// ML-KEM private keys) but are classified metadata, not CIPHERTEXT, because the server
    /// must serve them per device without decryption semantics ». Seul le contenu réel du
    /// message est CIPHERTEXT : `body_ciphertext`, `summary_ct` (A02 §4.1) et le nom de
    /// dossier `name_ct` (A02-DM-1).
    pub fn field_class(field: &str) -> Option<FieldClass> {
        Some(match field {
            // CIPHERTEXT — contenu du message, jamais lisible côté serveur (INV-1).
            "body_ciphertext" | "summary_ct" | "name_ct" => FieldClass::Ciphertext,
            // PLAINTEXT_METADATA — routage/technique. kem_ct/wrapped_key : A02 §4.3 footnote¹
            // (opaques au serveur mais métadonnées, pas ciphertext).
            "kem_ct" | "wrapped_key" | "size_bytes" | "received_at_ms" | "recipient_id"
            | "tenant_id" => FieldClass::PlaintextMetadata,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verrou anti-désynchronisation avec A02 §4 (CDM-ENC-1) / DDL A21.
    /// Toute future re-divergence de `field_class` avec la classification normative
    /// casse ce test plutôt que de dormir silencieusement.
    #[test]
    fn field_class_matches_a02_classification() {
        // A02 §4.3 footnote¹ : kem_ct et wrapped_key sont PLAINTEXT_METADATA, PAS CIPHERTEXT
        // (opaques au serveur, mais servis par appareil sans sémantique de déchiffrement).
        assert_eq!(
            StoredMessage::field_class("kem_ct"),
            Some(FieldClass::PlaintextMetadata),
            "A02 §4.3 footnote¹ : kem_ct est PLAINTEXT_METADATA, pas CIPHERTEXT"
        );
        assert_eq!(
            StoredMessage::field_class("wrapped_key"),
            Some(FieldClass::PlaintextMetadata),
            "A02 §4.3 footnote¹ : wrapped_key est PLAINTEXT_METADATA, pas CIPHERTEXT"
        );

        // Contenu réel du message = CIPHERTEXT (A02 §4.1 pour summary_ct, A02-DM-1 pour name_ct).
        for f in ["body_ciphertext", "summary_ct", "name_ct"] {
            assert_eq!(
                StoredMessage::field_class(f),
                Some(FieldClass::Ciphertext),
                "{f} porte du contenu : CIPHERTEXT"
            );
        }

        // Métadonnées de routage/technique = PLAINTEXT_METADATA.
        for f in ["size_bytes", "received_at_ms", "recipient_id", "tenant_id"] {
            assert_eq!(
                StoredMessage::field_class(f),
                Some(FieldClass::PlaintextMetadata),
                "{f} est une métadonnée de routage : PLAINTEXT_METADATA"
            );
        }

        // Champ inconnu → None : aucune classification n'est devinée.
        assert_eq!(StoredMessage::field_class("champ_inconnu"), None);
    }
}
