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
    AlgVersion, Ciphertext, DerivedKey, DeviceEncPublicKey, DeviceEncSecretKey, Envelope,
    IdentityPublicKey, IdentitySecretKey, MessageKey, Signature, VerifiedPlaintext,
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

/// Chiffre un contenu et renvoie (chiffré, clé de message fraîche). `aad` est
/// OBLIGATOIRE (A02-CRY-2/CRY-3) : elle lie ce chiffré à l'emplacement de stockage exact
/// pour lequel il a été produit, pour qu'un attaquant honest-but-curious avec accès au
/// stockage ne puisse pas permuter deux chiffrés (ex. `body_ct` d'un message pour le
/// `summary_ct` d'un autre) sans que le tag GCM le détecte au déchiffrement. Utiliser
/// [`aad_for_blob`] ou [`aad_for_summary`] pour construire l'AAD normative — jamais une
/// AAD vide "par défaut" pour ce chemin.
pub fn seal_message(plaintext: &[u8], aad: &[u8]) -> Result<(Ciphertext, MessageKey), CryptoError> {
    backend::seal_message(plaintext, aad)
}

/// Déchiffre et VÉRIFIE le tag ; ne renvoie un `VerifiedPlaintext` qu'en cas de succès
/// (INV-8). `aad` DOIT être exactement celle passée à `seal_message` au chiffrement,
/// sans quoi la vérification échoue par construction (fail-closed, INV-16).
pub fn open_message(
    ct: &Ciphertext,
    key: &MessageKey,
    aad: &[u8],
) -> Result<VerifiedPlaintext, CryptoError> {
    backend::open_message(ct, key, aad)
}

/// AAD normative d'un blob de corps/pièce jointe (A02-CRY-2) : `"mailblob:" + message_id + ":" + blob_id`.
///
/// UUIDs en forme BINAIRE (16 octets chacun), jamais la représentation texte à tirets
/// (CDM-ID-2, common AI error #2 de A02) : une AAD construite à partir de chaînes UUID
/// rendrait les enveloppes non-interopérables entre Rust et TS.
pub fn aad_for_blob(message_id: uuid::Uuid, blob_id: uuid::Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(9 + 16 + 1 + 16);
    aad.extend_from_slice(b"mailblob:");
    aad.extend_from_slice(message_id.as_bytes());
    aad.extend_from_slice(b":");
    aad.extend_from_slice(blob_id.as_bytes());
    aad
}

/// AAD normative du résumé chiffré (A02-CRY-3) : `"mailsum:" + message_id`, UUID binaire.
pub fn aad_for_summary(message_id: uuid::Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 16);
    aad.extend_from_slice(b"mailsum:");
    aad.extend_from_slice(message_id.as_bytes());
    aad
}

/// AAD de la file de hold (A01-HOLD) : `"mailhold:" + hold_id`, UUID binaire. Convention
/// propre à cette maquette (ni A01 ni A21 ne fixent ce libellé) — même discipline
/// binaire-UUID que [`aad_for_blob`]/[`aad_for_summary`] (CDM-ID-2).
pub fn aad_for_hold(hold_id: uuid::Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(9 + 16);
    aad.extend_from_slice(b"mailhold:");
    aad.extend_from_slice(hold_id.as_bytes());
    aad
}

/// Dérive `k_hold` (A01-HOLD-2 : "server-side key... scoped per (tenant, principal)").
/// `master_secret` vient du coffre de secrets — voir `SIMPLIFICATIONS.md` pour la
/// doublure de dev utilisée en l'absence d'un vrai `diamy-secretd` (Level A pattern,
/// A17-ENC-1). Jamais un secret brut utilisé directement comme clé (A18-CRY-2) : toujours
/// via HKDF avec un label explicite, scopé par tenant+principal pour qu'une fuite de
/// `k_hold` d'un principal ne compromette pas celui d'un autre.
pub fn derive_k_hold(
    master_secret: &[u8],
    tenant_id: uuid::Uuid,
    principal_id: uuid::Uuid,
) -> Result<DerivedKey, CryptoError> {
    let mut info = Vec::with_capacity(10 + 16 + 16);
    info.extend_from_slice(b"mail/hold/"); // label distinct de INFO_ENVELOPE du backend
    info.extend_from_slice(tenant_id.as_bytes());
    info.extend_from_slice(principal_id.as_bytes());
    derive_key(master_secret, &info)
}

/// Scelle un contenu (arbitraire) sous une clé DÉJÀ dérivée (contrairement à
/// [`seal_message`], qui tire une clé fraîche à chaque appel). AAD obligatoire, même
/// discipline que `seal_message`. NOTE : la file de hold n'emballe QUE `k_msg` (design clé
/// seule A01-HOLD-1/5) — utiliser pour ça [`wrap_message_key_under_hold`], pas cette
/// fonction générique (qui, elle, scellerait un CORPS et n'a plus d'appelant en production).
pub fn seal_with_key(
    plaintext: &[u8],
    key: &DerivedKey,
    aad: &[u8],
) -> Result<Ciphertext, CryptoError> {
    backend::seal_with_key(plaintext, key, aad)
}

/// Déchiffre et VÉRIFIE le tag sous une clé déjà dérivée (INV-8) — pendant du couple
/// [`seal_with_key`]. Déchiffre un CORPS : NE PAS l'utiliser pour la release de hold, qui
/// ne fait transiter que `k_msg` via [`unwrap_message_key_from_hold`] (A01-HOLD-5).
pub fn open_with_key(
    ct: &Ciphertext,
    key: &DerivedKey,
    aad: &[u8],
) -> Result<VerifiedPlaintext, CryptoError> {
    backend::open_with_key(ct, key, aad)
}

/// Emballe la PETITE clé de message `k_msg` sous `k_hold` pour la file de hold
/// (A01-HOLD-1, design **clé seule**) : SEULE `k_msg` (32 octets) est scellée, JAMAIS le
/// corps du message — celui-ci est déjà persisté sous `k_msg` dans `mail.blobs` (comme une
/// livraison ordinaire, sans enveloppe d'appareil) et n'est plus jamais re-manipulé.
/// Pendant de [`unwrap_message_key_from_hold`]. `aad` OBLIGATOIRE (utiliser [`aad_for_hold`]).
///
/// Distincte de [`open_message`]/[`open_with_key`] (qui déchiffrent un CORPS) : la release
/// de hold ne doit JAMAIS reconstruire le clair du corps (A01-HOLD-5, A01 §13 err.#8) —
/// elle ne fait transiter que la clé, comme le re-wrap délégué (A02-RW-1).
pub fn wrap_message_key_under_hold(
    key: &MessageKey,
    k_hold: &DerivedKey,
    aad: &[u8],
) -> Result<Ciphertext, CryptoError> {
    backend::wrap_message_key_under_hold(key, k_hold, aad)
}

/// Désemballe `k_msg` depuis la file de hold — reconstruit un [`MessageKey`] à partir du
/// chiffré produit par [`wrap_message_key_under_hold`] (A01-HOLD-4). NE déchiffre JAMAIS le
/// corps (A01-HOLD-5) : c'est le pendant "clé seule" du re-wrap délégué (A02-RW-1). `aad`
/// DOIT être exactement celle du scellement (fail-closed, INV-8/16).
pub fn unwrap_message_key_from_hold(
    ct: &Ciphertext,
    k_hold: &DerivedKey,
    aad: &[u8],
) -> Result<MessageKey, CryptoError> {
    backend::unwrap_message_key_from_hold(ct, k_hold, aad)
}

/// Génère une paire de clés de chiffrement d'appareil (ML-KEM-768).
pub fn generate_device_keypair() -> Result<(DeviceEncPublicKey, DeviceEncSecretKey), CryptoError> {
    backend::generate_device_keypair()
}

/// AAD normative de l'enveloppe (A02-CRY-4) : `"mailenv:" + message_id + ":" + device_id`.
/// UUIDs en forme BINAIRE (16 octets chacun), même discipline que [`aad_for_blob`]/
/// [`aad_for_summary`] (CDM-ID-2) — lie l'enveloppe scellée à CE message et CET appareil :
/// un attaquant honest-but-curious avec accès au stockage ne peut pas rejouer l'enveloppe
/// d'un appareil sur un autre message, ni celle d'un autre appareil sur ce message, sans
/// que le tag GCM le détecte au désemballage.
pub fn aad_for_envelope(message_id: uuid::Uuid, device_id: uuid::Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 16 + 1 + 16);
    aad.extend_from_slice(b"mailenv:");
    aad.extend_from_slice(message_id.as_bytes());
    aad.extend_from_slice(b":");
    aad.extend_from_slice(device_id.as_bytes());
    aad
}

/// Emballe la clé de message pour UN appareil (une enveloppe par appareil, STO-1). `aad`
/// OBLIGATOIRE (A02-CRY-4) : utiliser [`aad_for_envelope`] — jamais une AAD vide.
pub fn wrap_key_for_device(
    key: &MessageKey,
    device_pub: &DeviceEncPublicKey,
    aad: &[u8],
) -> Result<Envelope, CryptoError> {
    backend::wrap_key_for_device(key, device_pub, aad)
}

/// Désemballe la clé de message avec la clé privée de l'appareil. `aad` DOIT être
/// exactement celle passée à [`wrap_key_for_device`] (A02-CRY-4) — sans quoi la
/// vérification échoue par construction (fail-closed, INV-16).
pub fn unwrap_key(
    env: &Envelope,
    device_sec: &DeviceEncSecretKey,
    aad: &[u8],
) -> Result<MessageKey, CryptoError> {
    backend::unwrap_key(env, device_sec, aad)
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
        let message_id = uuid::Uuid::now_v7();
        let blob_id = uuid::Uuid::now_v7();
        let device_id = uuid::Uuid::now_v7();
        let aad = aad_for_blob(message_id, blob_id);
        let (ct, mk) = seal_message(plaintext, &aad).unwrap();

        let (pk, sk) = generate_device_keypair().unwrap();
        let env_aad = aad_for_envelope(message_id, device_id);
        let env = wrap_key_for_device(&mk, &pk, &env_aad).unwrap();

        let mk2 = unwrap_key(&env, &sk, &env_aad).unwrap();
        let opened = open_message(&ct, &mk2, &aad).unwrap();
        assert_eq!(opened.as_bytes(), plaintext);
    }

    // Fail-closed : un tag GCM altéré NE doit PAS produire de clair (INV-8/16).
    #[test]
    fn tampered_ciphertext_is_rejected() {
        let aad = aad_for_summary(uuid::Uuid::now_v7());
        let (mut ct, mk) = seal_message(b"payload", &aad).unwrap();
        let last = ct.bytes.len() - 1;
        ct.bytes[last] ^= 0x01; // corruption d'un octet
        assert!(open_message(&ct, &mk, &aad).is_err());
    }

    // AAD obligatoire (A02-CRY-2/3) : un chiffré scellé avec l'AAD d'UN message ne doit
    // JAMAIS s'ouvrir avec l'AAD d'un AUTRE — sinon un attaquant avec accès au stockage
    // pourrait permuter deux chiffrés sans que le tag GCM le détecte (le point corrigé
    // par cet audit).
    #[test]
    fn mismatched_aad_is_rejected() {
        let (message_id_a, message_id_b) = (uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
        let blob_id = uuid::Uuid::now_v7();
        let (ct, mk) = seal_message(b"payload", &aad_for_blob(message_id_a, blob_id)).unwrap();
        assert!(open_message(&ct, &mk, &aad_for_blob(message_id_b, blob_id)).is_err());
    }

    // Une mauvaise clé d'appareil ne désemballe pas.
    #[test]
    fn wrong_device_cannot_unwrap() {
        let (_ct, mk) = seal_message(b"payload", b"test-aad").unwrap();
        let (pk, _sk) = generate_device_keypair().unwrap();
        let (_pk2, sk2) = generate_device_keypair().unwrap();
        let env_aad = aad_for_envelope(uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
        let env = wrap_key_for_device(&mk, &pk, &env_aad).unwrap();
        assert!(unwrap_key(&env, &sk2, &env_aad).is_err());
    }

    // A02-CRY-4 : une enveloppe scellée pour UN (message, appareil) ne doit PAS s'ouvrir
    // avec l'AAD d'un AUTRE couple — sinon un attaquant avec accès au stockage pourrait
    // permuter des enveloppes sans que le tag GCM le détecte.
    #[test]
    fn envelope_mismatched_aad_is_rejected() {
        let (pk, sk) = generate_device_keypair().unwrap();
        let (_ct, mk) = seal_message(b"payload", b"test-aad").unwrap();
        let (message_id_a, message_id_b) = (uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
        let device_id = uuid::Uuid::now_v7();
        let env = wrap_key_for_device(&mk, &pk, &aad_for_envelope(message_id_a, device_id)).unwrap();
        assert!(unwrap_key(&env, &sk, &aad_for_envelope(message_id_b, device_id)).is_err());
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

    // A01-HOLD : round-trip sous k_hold — dérivé, jamais tiré au hasard comme seal_message.
    #[test]
    fn hold_key_round_trip() {
        let tenant_id = uuid::Uuid::now_v7();
        let principal_id = uuid::Uuid::now_v7();
        let hold_id = uuid::Uuid::now_v7();
        let k_hold = derive_k_hold(b"dev-master-secret-not-real", tenant_id, principal_id).unwrap();
        let aad = aad_for_hold(hold_id);
        let ct = seal_with_key(b"message tenu en attente", &k_hold, &aad).unwrap();
        let opened = open_with_key(&ct, &k_hold, &aad).unwrap();
        assert_eq!(opened.as_bytes(), b"message tenu en attente");
    }

    // A01-HOLD-2 : scopé par (tenant, principal) — deux principaux du même tenant ne
    // doivent PAS partager k_hold (sinon un principal pourrait lire la file de l'autre).
    #[test]
    fn hold_key_is_scoped_per_principal() {
        let tenant_id = uuid::Uuid::now_v7();
        let (principal_a, principal_b) = (uuid::Uuid::now_v7(), uuid::Uuid::now_v7());
        let hold_id = uuid::Uuid::now_v7();
        let k_a = derive_k_hold(b"dev-master-secret-not-real", tenant_id, principal_a).unwrap();
        let k_b = derive_k_hold(b"dev-master-secret-not-real", tenant_id, principal_b).unwrap();
        let aad = aad_for_hold(hold_id);
        let ct = seal_with_key(b"secret de A", &k_a, &aad).unwrap();
        assert!(open_with_key(&ct, &k_b, &aad).is_err());
    }

    // INV-7 / A18-CRY-4 : une version d'algorithme inconnue est rejetée fail-closed AU
    // déchiffrement (jamais devinée). `from_i32` est le point de contrôle appelé par le
    // serveur en lisant `mail.blobs.blob_alg_version`/`mail.envelopes.alg_version` (A21) et
    // par le client sur le fil, avant tout `open_*`.
    #[test]
    fn unknown_alg_version_is_rejected_fail_closed() {
        assert_eq!(AlgVersion::from_i32(1).unwrap(), AlgVersion::V1);
        assert_eq!(AlgVersion::V1.as_i32(), 1);
        assert!(matches!(AlgVersion::from_i32(2), Err(CryptoError::UnknownAlgVersion(2))));
        assert!(matches!(AlgVersion::from_i32(0), Err(CryptoError::UnknownAlgVersion(0))));
        assert!(AlgVersion::from_i32(-1).is_err());
    }

    // Le round-trip normal porte bien la version courante (écrite au scellement, INV-7).
    #[test]
    fn sealed_ciphertext_carries_current_alg_version() {
        let (ct, _mk) = seal_message(b"payload", b"aad").unwrap();
        assert_eq!(ct.alg_version, AlgVersion::CURRENT);
    }

    // Fail-closed : une AAD différente (mauvais hold_id) ne doit pas ouvrir (INV-8/16).
    #[test]
    fn hold_mismatched_aad_is_rejected() {
        let k_hold = derive_k_hold(b"seed", uuid::Uuid::now_v7(), uuid::Uuid::now_v7()).unwrap();
        let ct = seal_with_key(b"payload", &k_hold, &aad_for_hold(uuid::Uuid::now_v7())).unwrap();
        assert!(open_with_key(&ct, &k_hold, &aad_for_hold(uuid::Uuid::now_v7())).is_err());
    }

    // A01-HOLD-1/5 (design clé seule) : emballer k_msg sous k_hold puis le désemballer
    // reconstruit un MessageKey qui déchiffre le corps INCHANGÉ scellé sous ce k_msg —
    // et à AUCUN moment le corps n'est re-manipulé (seule la clé transite, A02-RW-1).
    #[test]
    fn hold_wraps_only_the_message_key_body_untouched() {
        let message_id = uuid::Uuid::now_v7();
        let blob_id = uuid::Uuid::now_v7();
        let hold_id = uuid::Uuid::now_v7();
        let body_aad = aad_for_blob(message_id, blob_id);

        // Corps scellé une seule fois sous un k_msg frais (comme à la réception).
        let (body_ct, k_msg) = seal_message(b"corps du message tenu", &body_aad).unwrap();
        let body_ct_snapshot = body_ct.bytes.clone(); // le chiffré du corps ne doit PAS bouger

        // Hold : on emballe SEULEMENT k_msg sous k_hold.
        let k_hold = derive_k_hold(b"dev-master", uuid::Uuid::now_v7(), uuid::Uuid::now_v7()).unwrap();
        let hold_aad = aad_for_hold(hold_id);
        let wrapped = wrap_message_key_under_hold(&k_msg, &k_hold, &hold_aad).unwrap();
        drop(k_msg);

        // Release : on désemballe k_msg (jamais le corps) et on ouvre le corps INCHANGÉ.
        let k_msg2 = unwrap_message_key_from_hold(&wrapped, &k_hold, &hold_aad).unwrap();
        assert_eq!(body_ct.bytes, body_ct_snapshot, "le chiffré du corps est resté identique");
        let opened = open_message(&body_ct, &k_msg2, &body_aad).unwrap();
        assert_eq!(opened.as_bytes(), b"corps du message tenu");
    }

    // Fail-closed : un mauvais k_hold ou une mauvaise AAD ne désemballe pas k_msg (INV-8/16).
    #[test]
    fn hold_key_unwrap_is_fail_closed() {
        let (_ct, k_msg) = seal_message(b"x", b"aad").unwrap();
        let k_hold = derive_k_hold(b"seed", uuid::Uuid::now_v7(), uuid::Uuid::now_v7()).unwrap();
        let k_hold_other = derive_k_hold(b"autre", uuid::Uuid::now_v7(), uuid::Uuid::now_v7()).unwrap();
        let aad = aad_for_hold(uuid::Uuid::now_v7());
        let wrapped = wrap_message_key_under_hold(&k_msg, &k_hold, &aad).unwrap();
        assert!(unwrap_message_key_from_hold(&wrapped, &k_hold_other, &aad).is_err());
        assert!(unwrap_message_key_from_hold(&wrapped, &k_hold, &aad_for_hold(uuid::Uuid::now_v7())).is_err());
    }
}
