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

use aes_gcm::aead::{Aead, KeyInit};
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

fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>), CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce); // nonce indépendant par chiffrement (A18-CRY-3)
    let bytes = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| CryptoError::Encrypt)?;
    Ok((nonce, bytes))
}

fn aes_decrypt(key: &[u8; 32], nonce: &[u8; 12], bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    // .decrypt vérifie le tag GCM ; en cas d'échec -> Err (fail-closed, INV-8/16).
    cipher
        .decrypt(Nonce::from_slice(nonce), bytes)
        .map_err(|_| CryptoError::DecryptVerify)
}

fn hkdf32(secret: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("HKDF expand 32 octets");
    okm
}

pub fn seal_message(plaintext: &[u8]) -> Result<(Ciphertext, MessageKey), CryptoError> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let (nonce, bytes) = aes_encrypt(&key, plaintext)?;
    Ok((Ciphertext { nonce, bytes }, MessageKey::from_bytes(key)))
}

pub fn open_message(ct: &Ciphertext, key: &MessageKey) -> Result<VerifiedPlaintext, CryptoError> {
    let pt = aes_decrypt(key.as_bytes(), &ct.nonce, &ct.bytes)?;
    Ok(VerifiedPlaintext(pt))
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
) -> Result<Envelope, CryptoError> {
    let ek_arr =
        ml_kem::Encoded::<Ek>::try_from(&pk.0[..]).map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let ek = Ek::from_bytes(&ek_arr);
    let mut rng = OsRng;
    let (kem_ct, ss) = ek.encapsulate(&mut rng).map_err(|_| CryptoError::Kem)?;
    let kek = hkdf32(ss.as_slice(), INFO_ENVELOPE);
    let (nonce, bytes) = aes_encrypt(&kek, mk.as_bytes())?;
    Ok(Envelope {
        kem_ct: kem_ct.to_vec(),
        wrapped: Ciphertext { nonce, bytes },
    })
}

pub fn unwrap_key(env: &Envelope, sk: &DeviceEncSecretKey) -> Result<MessageKey, CryptoError> {
    let dk_arr = ml_kem::Encoded::<Dk>::try_from(sk.as_bytes())
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let dk = Dk::from_bytes(&dk_arr);
    let ct_arr = ml_kem::Ciphertext::<MlKem768>::try_from(&env.kem_ct[..])
        .map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let ss = dk.decapsulate(&ct_arr).map_err(|_| CryptoError::Kem)?;
    let kek = hkdf32(ss.as_slice(), INFO_ENVELOPE);
    let raw = aes_decrypt(&kek, &env.wrapped.nonce, &env.wrapped.bytes)?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::DecryptVerify)?;
    Ok(MessageKey::from_bytes(arr))
}

pub fn derive_key(secret: &[u8], info: &[u8]) -> Result<DerivedKey, CryptoError> {
    Ok(DerivedKey(hkdf32(secret, info)))
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
