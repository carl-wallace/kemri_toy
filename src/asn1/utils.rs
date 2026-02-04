//! Utility functions in support of AuthEnvelopedData processing and KemRecipientInfo processing.

use const_oid::{
    ObjectIdentifier,
    db::rfc5911::{ID_AES_128_WRAP, ID_AES_192_WRAP, ID_AES_256_WRAP},
};
use hmac::digest::Digest;
use log::{debug, error};
use sha3::Sha3_256;

use pqckeys::pqc_oids::*;

use crate::{Result, buffer_to_hex};

/// Gets the domain separator for a given OID.
pub fn get_domain(oid: ObjectIdentifier) -> Result<Vec<u8>> {
    if oid == ID_MLKEM768_RSA2048_SHA3_256 {
        Ok(DS_MLKEM768_RSA2048_SHA3_256.to_vec())
    } else if oid == ID_MLKEM768_RSA3072_SHA3_256 {
        Ok(DS_MLKEM768_RSA3072_SHA3_256.to_vec())
    } else if oid == ID_MLKEM768_RSA4096_SHA3_256 {
        Ok(DS_MLKEM768_RSA4096_SHA3_256.to_vec())
    } else if oid == ID_MLKEM768_X25519_SHA3_256 {
        Ok(DS_MLKEM768_X25519_SHA3_256.to_vec())
    } else if oid == ID_MLKEM768_ECDH_P256_SHA3_256 {
        Ok(DS_MLKEM768_ECDH_P256_SHA3_256.to_vec())
    } else if oid == ID_MLKEM768_ECDH_P384_SHA3_256 {
        Ok(DS_MLKEM768_ECDH_P384_SHA3_256.to_vec())
    } else if oid == ID_MLKEM768_ECDH_BRAINPOOL_P256R1_SHA3_256 {
        Ok(DS_MLKEM768_ECDH_BRAINPOOL_P256R1_SHA3_256.to_vec())
    } else if oid == ID_MLKEM1024_RSA3072_SHA3_256 {
        Ok(DS_MLKEM1024_RSA3072_SHA3_256.to_vec())
    } else if oid == ID_MLKEM1024_ECDH_P384_SHA3_256 {
        Ok(DS_MLKEM1024_ECDH_P384_SHA3_256.to_vec())
    } else if oid == ID_MLKEM1024_ECDH_BRAINPOOL_P384R1_SHA3_256 {
        Ok(DS_MLKEM1024_ECDH_BRAINPOOL_P384R1_SHA3_256.to_vec())
    } else if oid == ID_MLKEM1024_X448_SHA3_256 {
        Ok(DS_MLKEM1024_X448_SHA3_256.to_vec())
    } else if oid == ID_MLKEM1024_ECDH_P521_SHA3_256 {
        Ok(DS_MLKEM1024_ECDH_P521_SHA3_256.to_vec())
    } else if oid == ID_MLDSA44_RSA2048_PSS_SHA256 {
        Ok(DS_MLDSA44_RSA2048_PSS_SHA256.to_vec())
    } else if oid == ID_MLDSA44_RSA2048_PKCS15_SHA256 {
        Ok(DS_MLDSA44_RSA2048_PKCS15_SHA256.to_vec())
    } else if oid == ID_MLDSA44_ED25519_SHA512 {
        Ok(DS_MLDSA44_ED25519_SHA512.to_vec())
    } else if oid == ID_MLDSA44_ECDSA_P256_SHA256 {
        Ok(DS_MLDSA44_ECDSA_P256_SHA256.to_vec())
    } else if oid == ID_MLDSA65_RSA3072_PSS_SHA512 {
        Ok(DS_MLDSA65_RSA3072_PSS_SHA512.to_vec())
    } else if oid == ID_MLDSA65_RSA3072_PKCS15_SHA512 {
        Ok(DS_MLDSA65_RSA3072_PKCS15_SHA512.to_vec())
    } else if oid == ID_MLDSA65_RSA4096_PSS_SHA512 {
        Ok(DS_MLDSA65_RSA4096_PSS_SHA512.to_vec())
    } else if oid == ID_MLDSA65_RSA4096_PKCS15_SHA512 {
        Ok(DS_MLDSA65_RSA4096_PKCS15_SHA512.to_vec())
    } else if oid == ID_MLDSA65_ECDSA_P256_SHA512 {
        Ok(DS_MLDSA65_ECDSA_P256_SHA512.to_vec())
    } else if oid == ID_MLDSA65_ECDSA_P384_SHA512 {
        Ok(DS_MLDSA65_ECDSA_P384_SHA512.to_vec())
    } else if oid == ID_MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512 {
        Ok(DS_MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512.to_vec())
    } else if oid == ID_MLDSA65_ED25519_SHA512 {
        Ok(DS_MLDSA65_ED25519_SHA512.to_vec())
    } else if oid == ID_MLDSA87_ECDSA_P384_SHA512 {
        Ok(DS_MLDSA87_ECDSA_P384_SHA512.to_vec())
    } else if oid == ID_MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512 {
        Ok(DS_MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512.to_vec())
    } else if oid == ID_MLDSA87_ED448_SHAKE256 {
        Ok(DS_MLDSA87_ED448_SHAKE256.to_vec())
    } else if oid == ID_MLDSA87_RSA3072_PSS_SHA512 {
        Ok(DS_MLDSA87_RSA3072_PSS_SHA512.to_vec())
    } else if oid == ID_MLDSA87_RSA4096_PSS_SHA512 {
        Ok(DS_MLDSA87_RSA4096_PSS_SHA512.to_vec())
    } else if oid == ID_MLDSA87_ECDSA_P521_SHA512 {
        Ok(DS_MLDSA87_ECDSA_P521_SHA512.to_vec())
    } else {
        Err(crate::Error::Unrecognized)
    }
}

/// Get the block size of the given algorithm
pub(crate) fn get_block_size(oid: &ObjectIdentifier) -> Result<usize> {
    match *oid {
        ID_AES_128_WRAP
        | const_oid::db::rfc5911::ID_AES_128_CBC
        | const_oid::db::rfc5911::ID_AES_128_GCM => Ok(16),
        ID_AES_192_WRAP | const_oid::db::rfc5911::ID_AES_192_CBC => Ok(24),
        ID_AES_256_WRAP
        | const_oid::db::rfc5911::ID_AES_256_CBC
        | const_oid::db::rfc5911::ID_AES_256_GCM => Ok(32),
        _ => {
            error!("Failed to get block size for {oid}");
            Err(crate::Error::Unrecognized)
        }
    }
}

/// Prepares a composite shared secret per [draft-ietf-lamps-pq-composite-kem-12 section 3.4].
///
/// [draft-ietf-lamps-pq-composite-kem-12 section 3.4](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-12#section-3.4)
pub fn kem_combiner(
    pqc_ss: &[u8],
    trad_ss: &[u8],
    trad_ct: &[u8],
    trad_pk: &[u8],
    composite_oid: ObjectIdentifier,
) -> Result<Vec<u8>> {
    // SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)
    let mut hasher = Sha3_256::default();
    let label = get_domain(composite_oid)?;
    debug!("pqc_ss: {}", buffer_to_hex(pqc_ss));
    hasher.update(pqc_ss);
    debug!("trad_ss: {}", buffer_to_hex(trad_ss));
    hasher.update(trad_ss);
    debug!("trad_ct: {}", buffer_to_hex(trad_ct));
    hasher.update(trad_ct);
    debug!("trad_pk: {}", buffer_to_hex(trad_pk));
    hasher.update(trad_pk);
    debug!("enc_domain: {}", buffer_to_hex(&label));
    hasher.update(&label);
    Ok(hasher.finalize().to_vec())
}
