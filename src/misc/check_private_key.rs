//! Pair-wise consistency check for private key and certificate

use log::error;
use rand::rngs::OsRng;
use rand_core::TryRngCore;
use zerocopy::IntoBytes;

use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use ml_kem::{
    Encoded, EncodedSizeUser, MlKem512, MlKem512Params, MlKem768, MlKem768Params, MlKem1024,
    MlKem1024Params,
    kem::{Decapsulate, Encapsulate},
};
use signature::{Signer, Verifier};
use slh_dsa::*;

use const_oid::db::{
    fips203::{ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768, ID_ALG_ML_KEM_1024},
    fips204::*,
    fips205::*,
};
use der::Decode;
use spki::SubjectPublicKeyInfoOwned;

use pqckeys::oak::OneAsymmetricKey;

use crate::error::{Error, Result};
use crate::misc::gen_certs::buffer_to_hex;
use crate::misc::utils::extract_private_key;

macro_rules! check_ml_kem_key {
    ($params_ty:ty, $ct_ty:ty, $oak:expr, $spki:expr, $filename:expr) => {{
        let private_key = extract_private_key($oak.private_key_alg.oid, $oak.private_key.as_bytes())?;
        let dk_bytes = Encoded::<<ml_kem::kem::Kem<$params_ty> as ml_kem::KemCore>::DecapsulationKey>::try_from(private_key.as_bytes()).map_err(|e| Error::MlKem(format!("{e:?}")))?;
        let dk = <ml_kem::kem::Kem<$params_ty> as ml_kem::KemCore>::DecapsulationKey::from_bytes(&dk_bytes);
        let spki_bytes = $spki.subject_public_key.raw_bytes();
        println!("spki_bytes len = {:?}", spki_bytes.len());
        println!("spki_bytes = {:?}", buffer_to_hex(spki_bytes));
        let ek_bytes = Encoded::<<ml_kem::kem::Kem<$params_ty> as ml_kem::KemCore>::EncapsulationKey>::try_from(spki_bytes).map_err(|e| Error::MlKem(format!("{e:?}")))?;
        let ek = <ml_kem::kem::Kem<$params_ty> as ml_kem::KemCore>::EncapsulationKey::from_bytes(&ek_bytes);
        let (ct, ss) = ek.encapsulate(&mut OsRng.unwrap_err()).map_err(|e| Error::MlKem(format!("{e:?}")))?;
        let c = ml_kem::Ciphertext::<$ct_ty>::try_from(ct).map_err(|e| Error::MlKem(format!("{e:?}")))?;
        let k = dk.decapsulate(&c).map_err(|e| Error::MlKem(format!("{e:?}")))?;
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
        let sk_bytes = ml_dsa::EncodedSigningKey::<$dsa>::try_from(private_key.as_slice())
            .map_err(|e| Error::MlDsa(format!("{e:?}")))?;
        let sk = ml_dsa::SigningKey::<$dsa>::decode(&sk_bytes);
        let sig = sk.sign("abc".as_bytes());
        let vk_bytes =
            ml_dsa::EncodedVerifyingKey::<$dsa>::try_from($spki.subject_public_key.raw_bytes())
                .map_err(|e| Error::MlDsa(format!("{e:?}")))?;
        let vk = ml_dsa::VerifyingKey::<$dsa>::decode(&vk_bytes);
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
    } else if oak.private_key_alg.oid == ID_ALG_ML_KEM_512 {
        println!("512");
        check_ml_kem_key!(MlKem512Params, MlKem512, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_ALG_ML_KEM_768 {
        println!("768");
        check_ml_kem_key!(MlKem768Params, MlKem768, oak, spki, filename);
    } else if oak.private_key_alg.oid == ID_ALG_ML_KEM_1024 {
        println!("1024");
        check_ml_kem_key!(MlKem1024Params, MlKem1024, oak, spki, filename);
    } else {
        println!("Unrecognized algorithm");
        Err(Error::Unrecognized)
    }
}
