//! Pair-wise consistency check for private key and certificate

use log::error;
use ml_kem::TryKeyInit;
use sha2::Digest;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use zerocopy::IntoBytes;

use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use ml_kem::{
    KeyInit, MlKem512, MlKem768, MlKem1024,
    kem::{Decapsulate, Encapsulate},
};
use signature::{Signer, Verifier};
use slh_dsa::*;

use const_oid::db::{
    fips203::{ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768, ID_ALG_ML_KEM_1024},
    fips204::*,
    fips205::*,
};
use der::{Decode, Encode};
use spki::{DecodePublicKey, SubjectPublicKeyInfoOwned};

use pqckeys::oak::OneAsymmetricKey;
use pqckeys::pqc_oids::{
    ID_MLDSA44_ECDSA_P256_SHA256, ID_MLDSA44_RSA2048_PKCS15_SHA256, ID_MLDSA44_RSA2048_PSS_SHA256,
    ID_MLDSA65_ECDSA_P256_SHA512, ID_MLDSA65_ECDSA_P384_SHA512, ID_MLDSA65_RSA3072_PSS_SHA512,
    ID_MLDSA65_RSA4096_PKCS15_SHA512, ID_MLDSA65_RSA4096_PSS_SHA512, ID_MLDSA87_ECDSA_P384_SHA512,
    ID_MLDSA87_ECDSA_P521_SHA512, ID_MLDSA87_RSA3072_PSS_SHA512, ID_MLDSA87_RSA4096_PSS_SHA512,
};

use crate::error::{Error, Result};
use crate::misc::gen_certs::buffer_to_hex;
use crate::misc::utils::extract_private_key;

macro_rules! check_ml_kem_key {
    ($ct_ty:ty, $oak:expr, $spki:expr, $filename:expr) => {{
        let private_key =
            extract_private_key($oak.private_key_alg.oid, $oak.private_key.as_bytes())?;
        let dk = <$ct_ty as ml_kem::Kem>::DecapsulationKey::new_from_slice(private_key.as_bytes())
            .map_err(|e| crate::Error::Builder(format!("{e:?}")))?;
        let spki_bytes = $spki.subject_public_key.raw_bytes();
        println!("spki_bytes len = {:?}", spki_bytes.len());
        println!("spki_bytes = {:?}", buffer_to_hex(spki_bytes));
        let ek = <$ct_ty as ml_kem::Kem>::EncapsulationKey::new_from_slice(spki_bytes)
            .map_err(|e| crate::Error::Builder(format!("{e:?}")))?;
        let (ct, ss) = ek.encapsulate();
        let k = dk.decapsulate(&ct);
        if k == ss {
            println!("Consistency check passed for {}", $filename);
            return Ok(true);
        } else {
            println!("Consistency check failed for {}", $filename);
            return Ok(false);
        }
    }};
}

macro_rules! check_ml_dsa_key {
    ($dsa:ty, $oak:expr, $spki:expr, $filename:expr) => {{
        let private_key =
            extract_private_key($oak.private_key_alg.oid, $oak.private_key.as_bytes())?;
        let sk_bytes = ml_dsa::ExpandedSigningKey::<$dsa>::try_from(private_key.as_slice())
            .map_err(|e| Error::MlDsa(format!("{e:?}")))?;
        #[allow(deprecated)]
        let sk = ml_dsa::SigningKey::<$dsa>::from_expanded(&sk_bytes);
        let sig = sk.sign("abc".as_bytes());
        let vk = ml_dsa::VerifyingKey::<$dsa>::from_public_key_der(&$spki.to_der()?)
            .map_err(|e| crate::Error::Builder(format!("{e:?}")))?;
        match vk.verify("abc".as_bytes(), &sig) {
            Ok(()) => {
                println!("Consistency check passed for {}", $filename);
                return Ok(true);
            }
            Err(e) => {
                error!("Consistency check failed for {}: {e:?}", $filename);
                return Ok(false);
            }
        }
    }};
}

macro_rules! check_slh_dsa_key {
    ($dsa:ty, $oak:expr, $spki:expr, $filename:expr) => {{
        let private_key =
            extract_private_key($oak.private_key_alg.oid, $oak.private_key.as_bytes())?;
        let sk = SigningKey::<$dsa>::try_from(private_key.as_slice())
            .map_err(|e| Error::SlhDsa(format!("{e:?}")))?;
        let vk = VerifyingKey::<$dsa>::try_from($spki.subject_public_key.raw_bytes())
            .map_err(|e| Error::SlhDsa(format!("{e:?}")))?;
        let sig = sk.sign("abc".as_bytes());
        match vk.verify("abc".as_bytes(), &sig) {
            Ok(()) => {
                println!("Consistency check passed for {}", $filename);
                return Ok(true);
            }
            Err(e) => {
                error!("Consistency check failed for {}: {e:?}", $filename);
                return Ok(false);
            }
        }
    }};
}

macro_rules! check_hash_ml_dsa_key {
    ($dsa:ty, $oak:expr, $spki:expr, $filename:expr, $hash_oid_bytes:expr) => {{
        let private_key =
            extract_private_key($oak.private_key_alg.oid, $oak.private_key.as_bytes())?;
        let sk_bytes = ml_dsa::ExpandedSigningKey::<$dsa>::try_from(private_key.as_slice())
            .map_err(|e| Error::MlDsa(format!("{e:?}")))?;
        #[allow(deprecated)]
        let sk = ml_dsa::SigningKey::<$dsa>::from_expanded(&sk_bytes);

        let test_msg = b"abc";
        let hash = sha2::Sha512::digest(test_msg);
        let mut message_rep = vec![0x01, 0x00];
        message_rep.extend_from_slice(&$hash_oid_bytes);
        message_rep.extend_from_slice(&hash);

        let mut rng = rand::rng();
        let rnd: ml_dsa::B32 = crate::misc::gen_certs::rand(&mut rng);
        let sig = sk.sign_internal(&[&message_rep], &rnd);

        let vk_bytes =
            ml_dsa::EncodedVerifyingKey::<$dsa>::try_from($spki.subject_public_key.raw_bytes())
                .map_err(|_| crate::Error::Builder("Invalid verifying key length".to_string()))?;
        let vk = ml_dsa::VerifyingKey::<$dsa>::decode(&vk_bytes);
        if vk.verify_internal(&message_rep, &sig) {
            println!("Consistency check passed for {}", $filename);
            return Ok(true);
        } else {
            error!("Consistency check failed for {}", $filename);
            return Ok(false);
        }
    }};
}

macro_rules! check_hash_slh_dsa_sha2_key {
    ($dsa:ty, $oak:expr, $spki:expr, $filename:expr, $hash_oid_bytes:expr, $hash:expr) => {{
        let private_key =
            extract_private_key($oak.private_key_alg.oid, $oak.private_key.as_bytes())?;
        let sk = SigningKey::<$dsa>::try_from(private_key.as_slice())
            .map_err(|e| Error::SlhDsa(format!("{e:?}")))?;
        let vk = VerifyingKey::<$dsa>::try_from($spki.subject_public_key.raw_bytes())
            .map_err(|e| Error::SlhDsa(format!("{e:?}")))?;

        let test_msg = b"abc";
        let hash = $hash(test_msg);
        let mut message_rep = vec![0x01, 0x00];
        message_rep.extend_from_slice(&$hash_oid_bytes);
        message_rep.extend_from_slice(&hash);

        let sig = sk.slh_sign_internal(&[&message_rep], None);
        match vk.slh_verify_internal(&[&message_rep], &sig) {
            Ok(()) => {
                println!("Consistency check passed for {}", $filename);
                return Ok(true);
            }
            Err(e) => {
                error!("Consistency check failed for {}: {e:?}", $filename);
                return Ok(false);
            }
        }
    }};
}

/// SHA-256 OID bytes (DER-encoded)
const SHA256_OID_BYTES: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];
/// SHA-512 OID bytes (DER-encoded)
const SHA512_OID_BYTES: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
];
/// SHAKE-128 OID bytes (DER-encoded)
const SHAKE128_OID_BYTES: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B,
];
/// SHAKE-256 OID bytes (DER-encoded)
const SHAKE256_OID_BYTES: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C,
];

fn sha256_hash(msg: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(msg).to_vec()
}

fn sha512_hash(msg: &[u8]) -> Vec<u8> {
    sha2::Sha512::digest(msg).to_vec()
}

fn shake128_hash(msg: &[u8]) -> Vec<u8> {
    let mut hasher = sha3::Shake128::default();
    hasher.update(msg);
    let mut output = vec![0u8; 32];
    hasher.finalize_xof().read(&mut output);
    output
}

fn shake256_hash(msg: &[u8]) -> Vec<u8> {
    let mut hasher = sha3::Shake256::default();
    hasher.update(msg);
    let mut output = vec![0u8; 64];
    hasher.finalize_xof().read(&mut output);
    output
}

/// ML-DSA expanded signing key sizes (FIPS 204)
const MLDSA44_SK_SIZE: usize = 2560;
const MLDSA65_SK_SIZE: usize = 4032;
const MLDSA87_SK_SIZE: usize = 4896;

/// ML-DSA verifying key sizes
const MLDSA44_VK_SIZE: usize = 1312;
const MLDSA65_VK_SIZE: usize = 1952;
const MLDSA87_VK_SIZE: usize = 2592;

/// Check the ML-DSA component of a composite key pair
macro_rules! check_composite_mldsa {
    ($dsa:ty, $sk_size:expr, $vk_size:expr, $sk_bytes:expr, $pk_bytes:expr, $filename:expr) => {{
        if $sk_bytes.len() < $sk_size || $pk_bytes.len() < $vk_size {
            error!(
                "Composite key too short for {}: sk={} (need {}), pk={} (need {})",
                $filename,
                $sk_bytes.len(),
                $sk_size,
                $pk_bytes.len(),
                $vk_size
            );
            return Ok(false);
        }
        let mldsa_sk_bytes = &$sk_bytes[..$sk_size];
        let mldsa_vk_bytes = &$pk_bytes[..$vk_size];

        let sk_expanded = ml_dsa::ExpandedSigningKey::<$dsa>::try_from(mldsa_sk_bytes)
            .map_err(|e| Error::MlDsa(format!("{e:?}")))?;
        #[allow(deprecated)]
        let sk = ml_dsa::SigningKey::<$dsa>::from_expanded(&sk_expanded);
        let sig = sk.sign("abc".as_bytes());

        let vk_encoded = ml_dsa::EncodedVerifyingKey::<$dsa>::try_from(mldsa_vk_bytes)
            .map_err(|_| Error::Builder("Invalid ML-DSA verifying key length".to_string()))?;
        let vk = ml_dsa::VerifyingKey::<$dsa>::decode(&vk_encoded);
        if vk.verify("abc".as_bytes(), &sig).is_err() {
            error!(
                "ML-DSA component consistency check failed for {}",
                $filename
            );
            return Ok(false);
        }
    }};
}

/// Check the RSA component of a composite key pair by sign/verify
fn check_composite_rsa(rsa_sk_bytes: &[u8], rsa_pk_bytes: &[u8], filename: &str) -> Result<bool> {
    use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
    use rsa::pkcs1v15::{SigningKey as Pkcs15SigningKey, VerifyingKey as Pkcs15VerifyingKey};

    let rsa_sk = rsa::RsaPrivateKey::from_pkcs1_der(rsa_sk_bytes)
        .map_err(|e| Error::Misc(format!("Failed to parse RSA private key: {e:?}")))?;
    let rsa_pk = rsa_sk.to_public_key();

    // Just verify the public key from the private key matches what's in the cert
    let rsa_pk_from_cert = rsa::RsaPublicKey::from_pkcs1_der(rsa_pk_bytes)
        .map_err(|e| Error::Misc(format!("Failed to parse RSA public key: {e:?}")))?;

    if rsa_pk != rsa_pk_from_cert {
        error!("RSA component consistency check failed for {}", filename);
        return Ok(false);
    }

    // Also do a sign/verify to be thorough
    let signing_key = Pkcs15SigningKey::<sha2::Sha256>::new(rsa_sk);
    let sig = signing_key.sign("abc".as_bytes());
    let verifying_key = Pkcs15VerifyingKey::<sha2::Sha256>::new(rsa_pk);
    match verifying_key.verify("abc".as_bytes(), &sig) {
        Ok(()) => Ok(true),
        Err(e) => {
            error!(
                "RSA sign/verify consistency check failed for {}: {e:?}",
                filename
            );
            Ok(false)
        }
    }
}

/// Check the ECDSA component of a composite key pair
fn check_composite_ecdsa_p256(
    ecdsa_sk_bytes: &[u8],
    ecdsa_pk_bytes: &[u8],
    filename: &str,
) -> Result<bool> {
    use p256::ecdsa::{SigningKey, VerifyingKey};

    let sk = SigningKey::from_slice(ecdsa_sk_bytes)
        .map_err(|e| Error::Misc(format!("Failed to parse P256 private key: {e:?}")))?;
    let vk_from_sk = sk.verifying_key().to_sec1_point(true);
    if vk_from_sk.as_bytes() != ecdsa_pk_bytes {
        error!(
            "ECDSA P256 component consistency check failed for {}",
            filename
        );
        return Ok(false);
    }
    let sig: p256::ecdsa::Signature = sk.sign("abc".as_bytes());
    let vk = VerifyingKey::from_sec1_bytes(ecdsa_pk_bytes)
        .map_err(|e| Error::Misc(format!("Failed to parse P256 public key: {e:?}")))?;
    match vk.verify("abc".as_bytes(), &sig) {
        Ok(()) => Ok(true),
        Err(e) => {
            error!("ECDSA P256 sign/verify failed for {}: {e:?}", filename);
            Ok(false)
        }
    }
}

fn check_composite_ecdsa_p384(
    ecdsa_sk_bytes: &[u8],
    ecdsa_pk_bytes: &[u8],
    filename: &str,
) -> Result<bool> {
    use p384::ecdsa::{SigningKey, VerifyingKey};

    let sk = SigningKey::from_slice(ecdsa_sk_bytes)
        .map_err(|e| Error::Misc(format!("Failed to parse P384 private key: {e:?}")))?;
    let vk_from_sk = sk.verifying_key().to_sec1_point(true);
    if vk_from_sk.as_bytes() != ecdsa_pk_bytes {
        error!(
            "ECDSA P384 component consistency check failed for {}",
            filename
        );
        return Ok(false);
    }
    let sig: p384::ecdsa::Signature = sk.sign("abc".as_bytes());
    let vk = VerifyingKey::from_sec1_bytes(ecdsa_pk_bytes)
        .map_err(|e| Error::Misc(format!("Failed to parse P384 public key: {e:?}")))?;
    match vk.verify("abc".as_bytes(), &sig) {
        Ok(()) => Ok(true),
        Err(e) => {
            error!("ECDSA P384 sign/verify failed for {}: {e:?}", filename);
            Ok(false)
        }
    }
}

fn check_composite_ecdsa_p521(
    ecdsa_sk_bytes: &[u8],
    ecdsa_pk_bytes: &[u8],
    filename: &str,
) -> Result<bool> {
    use p521::ecdsa::{SigningKey, VerifyingKey};

    let sk = SigningKey::from_slice(ecdsa_sk_bytes)
        .map_err(|e| Error::Misc(format!("Failed to parse P521 private key: {e:?}")))?;
    let vk_from_sk = sk.verifying_key().to_sec1_point(true);
    if vk_from_sk.as_bytes() != ecdsa_pk_bytes {
        error!(
            "ECDSA P521 component consistency check failed for {}",
            filename
        );
        return Ok(false);
    }
    let sig: p521::ecdsa::Signature = sk.sign("abc".as_bytes());
    let vk = VerifyingKey::from_sec1_bytes(ecdsa_pk_bytes)
        .map_err(|e| Error::Misc(format!("Failed to parse P521 public key: {e:?}")))?;
    match vk.verify("abc".as_bytes(), &sig) {
        Ok(()) => Ok(true),
        Err(e) => {
            error!("ECDSA P521 sign/verify failed for {}: {e:?}", filename);
            Ok(false)
        }
    }
}

/// Takes a buffer containing a OneAsymmetricKey and a SubjectPublicKeyInfo and performs a consistency
/// check to affirm the two correspond, i.e., encap/decap or sign/verify.
pub(crate) fn check_private_key(
    oak_bytes: &[u8],
    spki: &SubjectPublicKeyInfoOwned,
    filename: &str,
) -> Result<bool> {
    let oak = OneAsymmetricKey::from_der(oak_bytes)?;
    if oak.private_key_alg.oid == ID_ML_DSA_44 {
        check_ml_dsa_key!(MlDsa44, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_ML_DSA_65 {
        check_ml_dsa_key!(MlDsa65, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_ML_DSA_87 {
        check_ml_dsa_key!(MlDsa87, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_SLH_DSA_SHA_2_128_F {
        check_slh_dsa_key!(Sha2_128f, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_SLH_DSA_SHA_2_128_S {
        check_slh_dsa_key!(Sha2_128s, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_SLH_DSA_SHA_2_192_F {
        check_slh_dsa_key!(Sha2_192f, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_SLH_DSA_SHA_2_192_S {
        check_slh_dsa_key!(Sha2_192s, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_SLH_DSA_SHA_2_256_F {
        check_slh_dsa_key!(Sha2_256f, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_SLH_DSA_SHA_2_256_S {
        check_slh_dsa_key!(Sha2_256s, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_SLH_DSA_SHAKE_128_F {
        check_slh_dsa_key!(Shake128f, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_SLH_DSA_SHAKE_128_S {
        check_slh_dsa_key!(Shake128s, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_SLH_DSA_SHAKE_192_F {
        check_slh_dsa_key!(Shake192f, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_SLH_DSA_SHAKE_192_S {
        check_slh_dsa_key!(Shake192s, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_SLH_DSA_SHAKE_256_F {
        check_slh_dsa_key!(Shake256f, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_SLH_DSA_SHAKE_256_S {
        check_slh_dsa_key!(Shake256s, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_HASH_ML_DSA_44_WITH_SHA_512 {
        check_hash_ml_dsa_key!(MlDsa44, oak, spki, filename, SHA512_OID_BYTES);
    } else if oak.private_key_alg.oid == ID_HASH_ML_DSA_65_WITH_SHA_512 {
        check_hash_ml_dsa_key!(MlDsa65, oak, spki, filename, SHA512_OID_BYTES);
    } else if oak.private_key_alg.oid == ID_HASH_ML_DSA_87_WITH_SHA_512 {
        check_hash_ml_dsa_key!(MlDsa87, oak, spki, filename, SHA512_OID_BYTES);
    } else if oak.private_key_alg.oid == ID_HASH_SLH_DSA_SHA_2_128_S_WITH_SHA_256 {
        check_hash_slh_dsa_sha2_key!(
            Sha2_128s,
            oak,
            spki,
            filename,
            SHA256_OID_BYTES,
            sha256_hash
        );
    } else if oak.private_key_alg.oid == ID_HASH_SLH_DSA_SHA_2_128_F_WITH_SHA_256 {
        check_hash_slh_dsa_sha2_key!(
            Sha2_128f,
            oak,
            spki,
            filename,
            SHA256_OID_BYTES,
            sha256_hash
        );
    } else if oak.private_key_alg.oid == ID_HASH_SLH_DSA_SHA_2_192_S_WITH_SHA_512 {
        check_hash_slh_dsa_sha2_key!(
            Sha2_192s,
            oak,
            spki,
            filename,
            SHA512_OID_BYTES,
            sha512_hash
        );
    } else if oak.private_key_alg.oid == ID_HASH_SLH_DSA_SHA_2_192_F_WITH_SHA_512 {
        check_hash_slh_dsa_sha2_key!(
            Sha2_192f,
            oak,
            spki,
            filename,
            SHA512_OID_BYTES,
            sha512_hash
        );
    } else if oak.private_key_alg.oid == ID_HASH_SLH_DSA_SHA_2_256_S_WITH_SHA_512 {
        check_hash_slh_dsa_sha2_key!(
            Sha2_256s,
            oak,
            spki,
            filename,
            SHA512_OID_BYTES,
            sha512_hash
        );
    } else if oak.private_key_alg.oid == ID_HASH_SLH_DSA_SHA_2_256_F_WITH_SHA_512 {
        check_hash_slh_dsa_sha2_key!(
            Sha2_256f,
            oak,
            spki,
            filename,
            SHA512_OID_BYTES,
            sha512_hash
        );
    } else if oak.private_key_alg.oid == ID_HASH_SLH_DSA_SHAKE_128_S_WITH_SHAKE_128 {
        check_hash_slh_dsa_sha2_key!(
            Shake128s,
            oak,
            spki,
            filename,
            SHAKE128_OID_BYTES,
            shake128_hash
        );
    } else if oak.private_key_alg.oid == ID_HASH_SLH_DSA_SHAKE_128_F_WITH_SHAKE_128 {
        check_hash_slh_dsa_sha2_key!(
            Shake128f,
            oak,
            spki,
            filename,
            SHAKE128_OID_BYTES,
            shake128_hash
        );
    } else if oak.private_key_alg.oid == ID_HASH_SLH_DSA_SHAKE_192_S_WITH_SHAKE_256 {
        check_hash_slh_dsa_sha2_key!(
            Shake192s,
            oak,
            spki,
            filename,
            SHAKE256_OID_BYTES,
            shake256_hash
        );
    } else if oak.private_key_alg.oid == ID_HASH_SLH_DSA_SHAKE_192_F_WITH_SHAKE_256 {
        check_hash_slh_dsa_sha2_key!(
            Shake192f,
            oak,
            spki,
            filename,
            SHAKE256_OID_BYTES,
            shake256_hash
        );
    } else if oak.private_key_alg.oid == ID_HASH_SLH_DSA_SHAKE_256_S_WITH_SHAKE_256 {
        check_hash_slh_dsa_sha2_key!(
            Shake256s,
            oak,
            spki,
            filename,
            SHAKE256_OID_BYTES,
            shake256_hash
        );
    } else if oak.private_key_alg.oid == ID_HASH_SLH_DSA_SHAKE_256_F_WITH_SHAKE_256 {
        check_hash_slh_dsa_sha2_key!(
            Shake256f,
            oak,
            spki,
            filename,
            SHAKE256_OID_BYTES,
            shake256_hash
        );
    } else if oak.private_key_alg.oid == ID_ALG_ML_KEM_512 {
        println!("512");
        check_ml_kem_key!(MlKem512, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_ALG_ML_KEM_768 {
        println!("768");
        check_ml_kem_key!(MlKem768, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_ALG_ML_KEM_1024 {
        println!("1024");
        check_ml_kem_key!(MlKem1024, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_MLDSA44_RSA2048_PSS_SHA256
        || oak.private_key_alg.oid == ID_MLDSA44_RSA2048_PKCS15_SHA256
    {
        let sk_bytes = oak.private_key.as_bytes();
        let pk_bytes = spki.subject_public_key.raw_bytes();
        check_composite_mldsa!(
            MlDsa44,
            MLDSA44_SK_SIZE,
            MLDSA44_VK_SIZE,
            sk_bytes,
            pk_bytes,
            filename
        );
        if !check_composite_rsa(
            &sk_bytes[MLDSA44_SK_SIZE..],
            &pk_bytes[MLDSA44_VK_SIZE..],
            filename,
        )? {
            return Ok(false);
        }
        println!("Consistency check passed for {}", filename);
        Ok(true)
    } else if oak.private_key_alg.oid == ID_MLDSA44_ECDSA_P256_SHA256 {
        let sk_bytes = oak.private_key.as_bytes();
        let pk_bytes = spki.subject_public_key.raw_bytes();
        check_composite_mldsa!(
            MlDsa44,
            MLDSA44_SK_SIZE,
            MLDSA44_VK_SIZE,
            sk_bytes,
            pk_bytes,
            filename
        );
        if !check_composite_ecdsa_p256(
            &sk_bytes[MLDSA44_SK_SIZE..],
            &pk_bytes[MLDSA44_VK_SIZE..],
            filename,
        )? {
            return Ok(false);
        }
        println!("Consistency check passed for {}", filename);
        Ok(true)
    } else if oak.private_key_alg.oid == ID_MLDSA65_RSA3072_PSS_SHA512 {
        let sk_bytes = oak.private_key.as_bytes();
        let pk_bytes = spki.subject_public_key.raw_bytes();
        check_composite_mldsa!(
            MlDsa65,
            MLDSA65_SK_SIZE,
            MLDSA65_VK_SIZE,
            sk_bytes,
            pk_bytes,
            filename
        );
        if !check_composite_rsa(
            &sk_bytes[MLDSA65_SK_SIZE..],
            &pk_bytes[MLDSA65_VK_SIZE..],
            filename,
        )? {
            return Ok(false);
        }
        println!("Consistency check passed for {}", filename);
        Ok(true)
    } else if oak.private_key_alg.oid == ID_MLDSA65_RSA4096_PSS_SHA512
        || oak.private_key_alg.oid == ID_MLDSA65_RSA4096_PKCS15_SHA512
    {
        let sk_bytes = oak.private_key.as_bytes();
        let pk_bytes = spki.subject_public_key.raw_bytes();
        check_composite_mldsa!(
            MlDsa65,
            MLDSA65_SK_SIZE,
            MLDSA65_VK_SIZE,
            sk_bytes,
            pk_bytes,
            filename
        );
        if !check_composite_rsa(
            &sk_bytes[MLDSA65_SK_SIZE..],
            &pk_bytes[MLDSA65_VK_SIZE..],
            filename,
        )? {
            return Ok(false);
        }
        println!("Consistency check passed for {}", filename);
        Ok(true)
    } else if oak.private_key_alg.oid == ID_MLDSA65_ECDSA_P256_SHA512 {
        let sk_bytes = oak.private_key.as_bytes();
        let pk_bytes = spki.subject_public_key.raw_bytes();
        check_composite_mldsa!(
            MlDsa65,
            MLDSA65_SK_SIZE,
            MLDSA65_VK_SIZE,
            sk_bytes,
            pk_bytes,
            filename
        );
        if !check_composite_ecdsa_p256(
            &sk_bytes[MLDSA65_SK_SIZE..],
            &pk_bytes[MLDSA65_VK_SIZE..],
            filename,
        )? {
            return Ok(false);
        }
        println!("Consistency check passed for {}", filename);
        Ok(true)
    } else if oak.private_key_alg.oid == ID_MLDSA65_ECDSA_P384_SHA512 {
        let sk_bytes = oak.private_key.as_bytes();
        let pk_bytes = spki.subject_public_key.raw_bytes();
        check_composite_mldsa!(
            MlDsa65,
            MLDSA65_SK_SIZE,
            MLDSA65_VK_SIZE,
            sk_bytes,
            pk_bytes,
            filename
        );
        if !check_composite_ecdsa_p384(
            &sk_bytes[MLDSA65_SK_SIZE..],
            &pk_bytes[MLDSA65_VK_SIZE..],
            filename,
        )? {
            return Ok(false);
        }
        println!("Consistency check passed for {}", filename);
        Ok(true)
    } else if oak.private_key_alg.oid == ID_MLDSA87_ECDSA_P384_SHA512 {
        let sk_bytes = oak.private_key.as_bytes();
        let pk_bytes = spki.subject_public_key.raw_bytes();
        check_composite_mldsa!(
            MlDsa87,
            MLDSA87_SK_SIZE,
            MLDSA87_VK_SIZE,
            sk_bytes,
            pk_bytes,
            filename
        );
        if !check_composite_ecdsa_p384(
            &sk_bytes[MLDSA87_SK_SIZE..],
            &pk_bytes[MLDSA87_VK_SIZE..],
            filename,
        )? {
            return Ok(false);
        }
        println!("Consistency check passed for {}", filename);
        Ok(true)
    } else if oak.private_key_alg.oid == ID_MLDSA87_RSA3072_PSS_SHA512 {
        let sk_bytes = oak.private_key.as_bytes();
        let pk_bytes = spki.subject_public_key.raw_bytes();
        check_composite_mldsa!(
            MlDsa87,
            MLDSA87_SK_SIZE,
            MLDSA87_VK_SIZE,
            sk_bytes,
            pk_bytes,
            filename
        );
        if !check_composite_rsa(
            &sk_bytes[MLDSA87_SK_SIZE..],
            &pk_bytes[MLDSA87_VK_SIZE..],
            filename,
        )? {
            return Ok(false);
        }
        println!("Consistency check passed for {}", filename);
        Ok(true)
    } else if oak.private_key_alg.oid == ID_MLDSA87_RSA4096_PSS_SHA512 {
        let sk_bytes = oak.private_key.as_bytes();
        let pk_bytes = spki.subject_public_key.raw_bytes();
        check_composite_mldsa!(
            MlDsa87,
            MLDSA87_SK_SIZE,
            MLDSA87_VK_SIZE,
            sk_bytes,
            pk_bytes,
            filename
        );
        if !check_composite_rsa(
            &sk_bytes[MLDSA87_SK_SIZE..],
            &pk_bytes[MLDSA87_VK_SIZE..],
            filename,
        )? {
            return Ok(false);
        }
        println!("Consistency check passed for {}", filename);
        Ok(true)
    } else if oak.private_key_alg.oid == ID_MLDSA87_ECDSA_P521_SHA512 {
        let sk_bytes = oak.private_key.as_bytes();
        let pk_bytes = spki.subject_public_key.raw_bytes();
        check_composite_mldsa!(
            MlDsa87,
            MLDSA87_SK_SIZE,
            MLDSA87_VK_SIZE,
            sk_bytes,
            pk_bytes,
            filename
        );
        if !check_composite_ecdsa_p521(
            &sk_bytes[MLDSA87_SK_SIZE..],
            &pk_bytes[MLDSA87_VK_SIZE..],
            filename,
        )? {
            return Ok(false);
        }
        println!("Consistency check passed for {}", filename);
        Ok(true)
    } else {
        println!("Unrecognized algorithm");
        Err(Error::Unrecognized)
    }
}
