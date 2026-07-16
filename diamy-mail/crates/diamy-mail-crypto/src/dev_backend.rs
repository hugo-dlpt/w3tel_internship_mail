//! Backend `dev-crypto` — primitives AUDITÉES RustCrypto, pour débloquer la maquette
//! sans dépendre du messaging Diamy (tout juste mis en ligne).
//!
//! ⚠️ NON EXPÉDIABLE. Le format d'enveloppe et les labels HKDF sont provisoires et
//! NE sont PAS interopérables avec le backend `messaging-crypto`. À la bascule, on
//! re-provisionne (pas de migration). Voir SIMPLIFICATIONS.md.
//!
//! Algorithmes (alignés sur la cible du corpus, A02/A17-KEY-2) :
//!   - contenu           : AES-256-GCM, nonce 96 bits CSPRNG unique par message
//!   - enveloppe/appareil : ML-KEM-768 (FIPS 203) -> HKDF-SHA256 -> AES-256-GCM
//!   - dérivation        : HKDF-SHA256 avec label `info` explicite
//!   - signature identité : Ed25519 (STAND-IN dev de ML-DSA-65 — À REMPLACER)

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

use crate::error::CryptoError;
use crate::newtypes::*;

pub const NAME: &str =
    "dev-crypto (RustCrypto: AES-256-GCM, ML-KEM-768, HKDF-SHA256, Ed25519 stand-in for ML-DSA-65)";
pub const IS_DEV: bool = true;

const INFO_ENVELOPE: &[u8] = b"diamy-mail/dev-crypto/envelope-kek/v0";

type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;

fn aes_encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; 12], Vec<u8>), CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce); // nonce indépendant par chiffrement (A18-CRY-3)
    let bytes = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Encrypt)?;
    Ok((nonce, bytes))
}

fn aes_decrypt(key: &[u8; 32], nonce: &[u8; 12], bytes: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    // .decrypt vérifie le tag GCM (lié à cette AAD précise) ; en cas d'échec -> Err
    // (fail-closed, INV-8/16) — y compris si l'AAD ne correspond pas à celle du scellement.
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: bytes, aad })
        .map_err(|_| CryptoError::DecryptVerify)
}

fn hkdf32(secret: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("HKDF expand 32 octets");
    okm
}

pub fn seal_message(plaintext: &[u8], aad: &[u8]) -> Result<(Ciphertext, MessageKey), CryptoError> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let (nonce, bytes) = aes_encrypt(&key, plaintext, aad)?;
    // A02-CRY-7 : la version de suite est écrite au scellement (INV-7).
    Ok((
        Ciphertext { alg_version: AlgVersion::CURRENT, nonce, bytes },
        MessageKey::from_bytes(key),
    ))
}

pub fn open_message(
    ct: &Ciphertext,
    key: &MessageKey,
    aad: &[u8],
) -> Result<VerifiedPlaintext, CryptoError> {
    // INV-7 / A18-CRY-4 : dispatch sur la version AU DÉCHIFFREMENT, `match` SANS catch-all.
    // Ajouter une variante à `AlgVersion` casse la compilation ici tant qu'elle n'est pas
    // traitée — jamais un `_ => devine`. Une version inconnue a déjà été rejetée en amont
    // par `AlgVersion::from_i32` (fail-closed, INV-16).
    match ct.alg_version {
        AlgVersion::V1 => {
            let pt = aes_decrypt(key.as_bytes(), &ct.nonce, &ct.bytes, aad)?;
            Ok(VerifiedPlaintext(pt))
        }
    }
}

pub fn generate_device_keypair() -> Result<(DeviceEncPublicKey, DeviceEncSecretKey), CryptoError> {
    let mut rng = OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    Ok((
        DeviceEncPublicKey(ek.as_bytes().to_vec()),
        DeviceEncSecretKey::from_bytes(dk.as_bytes().to_vec()),
    ))
}

pub fn wrap_key_for_device(
    mk: &MessageKey,
    pk: &DeviceEncPublicKey,
    aad: &[u8],
) -> Result<Envelope, CryptoError> {
    let ek_arr =
        ml_kem::Encoded::<Ek>::try_from(&pk.0[..]).map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let ek = Ek::from_bytes(&ek_arr);
    let mut rng = OsRng;
    let (kem_ct, ss) = ek.encapsulate(&mut rng).map_err(|_| CryptoError::Kem)?;
    let kek = hkdf32(ss.as_slice(), INFO_ENVELOPE);
    // AAD normative de l'enveloppe ("mailenv:"+message_id+":"+device_id, A02-CRY-4) —
    // câblée (gap comblé, voir SIMPLIFICATIONS.md pour l'historique : c'était un gap
    // DISTINCT de celui déjà corrigé sur body_ct/summary_ct sous seal_message).
    let (nonce, bytes) = aes_encrypt(&kek, mk.as_bytes(), aad)?;
    Ok(Envelope {
        kem_ct: kem_ct.to_vec(),
        // A02-CRY-7 : version écrite au scellement de l'enveloppe (INV-7).
        wrapped: Ciphertext { alg_version: AlgVersion::CURRENT, nonce, bytes },
    })
}

pub fn unwrap_key(env: &Envelope, sk: &DeviceEncSecretKey, aad: &[u8]) -> Result<MessageKey, CryptoError> {
    // INV-7 / A18-CRY-4 : la version de l'enveloppe (portée par son chiffré emballé) est
    // dispatchée AU DÉCHIFFREMENT, `match` SANS catch-all.
    match env.wrapped.alg_version {
        AlgVersion::V1 => {
            let dk_arr = ml_kem::Encoded::<Dk>::try_from(sk.as_bytes())
                .map_err(|_| CryptoError::InvalidKeyMaterial)?;
            let dk = Dk::from_bytes(&dk_arr);
            let ct_arr = ml_kem::Ciphertext::<MlKem768>::try_from(&env.kem_ct[..])
                .map_err(|_| CryptoError::InvalidKeyMaterial)?;
            let ss = dk.decapsulate(&ct_arr).map_err(|_| CryptoError::Kem)?;
            let kek = hkdf32(ss.as_slice(), INFO_ENVELOPE);
            let raw = aes_decrypt(&kek, &env.wrapped.nonce, &env.wrapped.bytes, aad)?; // AAD A02-CRY-4
            let arr: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::DecryptVerify)?;
            Ok(MessageKey::from_bytes(arr))
        }
    }
}

pub fn derive_key(secret: &[u8], info: &[u8]) -> Result<DerivedKey, CryptoError> {
    Ok(DerivedKey(hkdf32(secret, info)))
}

pub fn seal_with_key(plaintext: &[u8], key: &DerivedKey, aad: &[u8]) -> Result<Ciphertext, CryptoError> {
    let (nonce, bytes) = aes_encrypt(key.expose(), plaintext, aad)?;
    Ok(Ciphertext { alg_version: AlgVersion::CURRENT, nonce, bytes })
}

pub fn open_with_key(ct: &Ciphertext, key: &DerivedKey, aad: &[u8]) -> Result<VerifiedPlaintext, CryptoError> {
    // INV-7 / A18-CRY-4 : dispatch sur la version AU DÉCHIFFREMENT, `match` SANS catch-all.
    match ct.alg_version {
        AlgVersion::V1 => {
            let pt = aes_decrypt(key.expose(), &ct.nonce, &ct.bytes, aad)?;
            Ok(VerifiedPlaintext(pt))
        }
    }
}

pub fn wrap_message_key_under_hold(
    mk: &MessageKey,
    k_hold: &DerivedKey,
    aad: &[u8],
) -> Result<Ciphertext, CryptoError> {
    // A01-HOLD-1 (clé seule) : on scelle les 32 octets de k_msg sous k_hold — jamais le
    // corps. Symétrique (k_hold EST la clé), pas de KEM ici, contrairement à
    // `wrap_key_for_device`.
    let (nonce, bytes) = aes_encrypt(k_hold.expose(), mk.as_bytes(), aad)?;
    Ok(Ciphertext { alg_version: AlgVersion::CURRENT, nonce, bytes })
}

pub fn unwrap_message_key_from_hold(
    ct: &Ciphertext,
    k_hold: &DerivedKey,
    aad: &[u8],
) -> Result<MessageKey, CryptoError> {
    // INV-7 / A18-CRY-4 : dispatch sur la version AU DÉCHIFFREMENT, `match` SANS catch-all
    // (5e site de dispatch, comme `open_message`/`unwrap_key`/`open_with_key`) — ajouter une
    // variante à `AlgVersion` casse la compilation ici tant qu'elle n'est pas traitée.
    match ct.alg_version {
        AlgVersion::V1 => {
            let raw = aes_decrypt(k_hold.expose(), &ct.nonce, &ct.bytes, aad)?;
            let arr: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::DecryptVerify)?;
            Ok(MessageKey::from_bytes(arr))
        }
    }
}

pub fn generate_identity_keypair() -> Result<(IdentityPublicKey, IdentitySecretKey), CryptoError> {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    Ok((
        IdentityPublicKey(vk.to_bytes().to_vec()),
        IdentitySecretKey(sk.to_bytes().to_vec()),
    ))
}

pub fn sign_manifest(sk: &IdentitySecretKey, msg: &[u8]) -> Result<Signature, CryptoError> {
    let arr: [u8; 32] =
        sk.0.as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let signing = SigningKey::from_bytes(&arr);
    Ok(Signature(signing.sign(msg).to_bytes().to_vec()))
}

pub fn verify_manifest(
    pk: &IdentityPublicKey,
    msg: &[u8],
    sig: &Signature,
) -> Result<bool, CryptoError> {
    let pk_arr: [u8; 32] =
        pk.0.as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let sig_arr: [u8; 64] = sig
        .0
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let ed_sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    Ok(vk.verify(msg, &ed_sig).is_ok())
}
