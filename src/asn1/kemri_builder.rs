//! Builder for `KemRecipientInfo` based on `RecipientInfoBuilder` trait from the cms crate

use crate::misc::ecdh::EcdhKem;
use log::debug;
use std::marker::PhantomData;

use aes::{Aes128, Aes192, Aes256};
use aes_kw::AesKw;
use cipher::{KeyInit, KeySizeUser, rand_core::CryptoRng};
use hkdf::Hkdf;
use ml_kem::{
    Encoded, EncodedSizeUser, KemCore, MlKem512Params, MlKem768Params, MlKem1024Params,
    kem::Encapsulate,
};
use sha2::{Sha256, Sha384, Sha512};
use tari_tiny_keccak::{Hasher, Kmac};

use cms::{
    builder::{Error, RecipientInfoBuilder, RecipientInfoType},
    content_info::CmsVersion,
    enveloped_data::{OtherRecipientInfo, RecipientIdentifier, RecipientInfo, UserKeyingMaterial},
    kemri::{CmsOriForKemOtherInfo, KemRecipientInfo},
};
use const_oid::db::fips203::{ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768, ID_ALG_ML_KEM_1024};
use const_oid::{
    ObjectIdentifier,
    db::rfc5911::{ID_AES_128_WRAP, ID_AES_192_WRAP, ID_AES_256_WRAP},
};
use der::{Any, Decode, Encode, asn1::OctetString};
use hmac::Hmac;
use pqckeys::pqc_oids::{
    ID_MLKEM768_ECDH_P256_HMAC_SHA256, ID_MLKEM768_ECDH_P384_HMAC_SHA256,
    ID_MLKEM768_RSA2048_HMAC_SHA256, ID_MLKEM768_RSA4096_HMAC_SHA256,
    ID_MLKEM1024_ECDH_P384_HMAC_SHA512, ID_MLKEM1024_ECDH_P521_HMAC_SHA512,
    ID_MLKEM1024_RSA3072_HMAC_SHA512,
};
use spki::AlgorithmIdentifier;

use crate::misc::rsa::RsaKem;
use crate::misc::utils::composite_ss;
use crate::{
    ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384, ID_ALG_HKDF_WITH_SHA512, ID_KMAC128,
    ID_KMAC256, ID_ORI_KEM,
    misc::{gen_certs::buffer_to_hex, utils::get_block_size},
};

/// Contains information required to encrypt the content encryption key with a specific KEM
#[derive(Clone, PartialEq)]
#[allow(dead_code)]
pub enum KeyEncryptionInfoKem {
    MlKem512(Box<Encoded<<ml_kem::kem::Kem<MlKem512Params> as KemCore>::EncapsulationKey>>),
    MlKem768(Box<Encoded<<ml_kem::kem::Kem<MlKem768Params> as KemCore>::EncapsulationKey>>),
    MlKem1024(Box<Encoded<<ml_kem::kem::Kem<MlKem1024Params> as KemCore>::EncapsulationKey>>),
    MlKem768Rsa2048HmacSha256(Vec<u8>),
    MlKem768Rsa3072HmacSha256(Vec<u8>),
    MlKem768Rsa4096HmacSha256(Vec<u8>),
    MlKem1024Rsa3072HmacSha512(Vec<u8>),
    MlKem768X25519SHA3_256(Vec<u8>),
    MlKem768EcdhP256HmacSha256(Vec<u8>),
    MlKem768EcdhP384HmacSha256(Vec<u8>),
    MlKem1024EcdhP384HmacSha512(Vec<u8>),
    MlKem1024X448Sha3_256(Vec<u8>),
    MlKem1024EcdhP521HmacSha512(Vec<u8>),
}

/// Builds a `KemRecipientInfo` according to draft-ietf-lamps-cms-kemri-07 § 3.
/// This type uses the recipient's public key to encrypt the content-encryption key.
pub struct KemRecipientInfoBuilder<R: ?Sized> {
    pub rid: RecipientIdentifier,
    pub key_encryption_info: KeyEncryptionInfoKem,
    pub kdf: ObjectIdentifier,
    pub ukm: Option<Vec<u8>>,
    pub wrap: ObjectIdentifier,
    _rng: PhantomData<R>,
}

impl<R> KemRecipientInfoBuilder<R> {
    pub fn new(
        rid: RecipientIdentifier,
        key_encryption_info: KeyEncryptionInfoKem,
        kdf: ObjectIdentifier,
        ukm: Option<Vec<u8>>,
        wrap: ObjectIdentifier,
    ) -> crate::Result<Self> {
        Ok(KemRecipientInfoBuilder {
            rid,
            key_encryption_info,
            kdf,
            ukm,
            wrap,
            _rng: PhantomData,
        })
    }
}

/// Macro for encrypting data using Aes128Wrap, Aes192Wrap or Aes256Wrap
macro_rules! encrypt_wrap {
    ($cek:expr, $alg:ty, $key:ident) => {{
        let kek: AesKw<$alg> = AesKw::new_from_slice($key.as_slice())
            .map_err(|e| cms::builder::Error::Builder(format!("Wrap failed: {e:?}")))?;
        let mut wrapped_key = vec![0u8; <$alg>::key_size() + 8];
        kek.wrap_key($cek, &mut wrapped_key)
            .map_err(|e| cms::builder::Error::Builder(format!("Wrap failed: {e:?}")))?;
        wrapped_key.to_vec()
    }};
}

pub fn is_sha512(oid: ObjectIdentifier) -> bool {
    ID_MLKEM1024_RSA3072_HMAC_SHA512 == oid
        || ID_MLKEM1024_ECDH_P384_HMAC_SHA512 == oid
        || ID_MLKEM1024_ECDH_P521_HMAC_SHA512 == oid
}

/// Prepare and return composite shared secret, composite ciphertext and OID.
#[macro_export]
macro_rules! comp_encap_rsa {
    ($pk:expr, $pqc_size:expr, $domain:expr, $rng:expr, $params:ty) => {{
        let (pqc_pk, trad_pk) = $pk.split_at($pqc_size);
        let pk = match Encoded::<<ml_kem::kem::Kem<$params> as KemCore>::EncapsulationKey,>::try_from(pqc_pk,) {
            Ok(pk) => pk,
            Err(e) => {
                return Err(Error::Builder(format!("Encapsulate failed: {e:?}")))
            }
        };
        let ek = <ml_kem::kem::Kem<$params> as KemCore>::EncapsulationKey::from_bytes(&pk);
        let (mut pqc_ct, pqc_ss) = match ek.encapsulate($rng) {
            Ok((ct, ss)) => (ct.to_vec(), ss.to_vec()),
            Err(e) => return Err(Error::Builder(format!("Encapsulate failed: {e:?}"))),
        };
        let (trad_ss, mut trad_ct) = match RsaKem::encap(trad_pk) {
            Ok((trad_ss, trad_ct)) => (trad_ss, trad_ct.to_vec()),
            Err(e) => {
                return Err(Error::Builder(format!("RSA encapsulate failed: {e:?}")))
            }
        };

        let ss = if is_sha512($domain) {
            match composite_ss::<Hmac<Sha512>>(&pqc_ss, &trad_ss, &trad_ct, &trad_pk, $domain) {
                Ok(ss) => ss,
                Err(e) => {
                    return Err(Error::Builder(format!("RSA encapsulate failed: {e:?}")))
                }
            }
        } else {
            match composite_ss::<Hmac<Sha256>>(&pqc_ss, &trad_ss, &trad_ct, &trad_pk, $domain) {
                Ok(ss) => ss,
                Err(e) => {
                    return Err(Error::Builder(format!("RSA encapsulate failed: {e:?}")))
                }
            }
        };
        let mut ct = vec![];
        ct.append(&mut pqc_ct);
        ct.append(&mut trad_ct);
        (ss, ct, $domain)
    }};
}

/// comp_encap_ecdh
#[macro_export]
macro_rules! comp_encap_ecdh {
    ($pk:expr, $pqc_size:expr, $domain:expr, $rng:expr, $params:ty, $ec:ty) => {{
        let (pqc_pk, trad_pk) = $pk.split_at($pqc_size);
        let pk = match Encoded::<<ml_kem::kem::Kem<$params> as KemCore>::EncapsulationKey,>::try_from(pqc_pk,) {
            Ok(pk) => pk,
            Err(e) => {
                return Err(Error::Builder(format!("Encapsulate failed: {e:?}")))
            }
        };
        let ek = <ml_kem::kem::Kem<$params> as KemCore>::EncapsulationKey::from_bytes(&pk);
        let (mut pqc_ct, pqc_ss) = match ek.encapsulate($rng) {
            Ok((ct, ss)) => (ct.to_vec(), ss.to_vec()),
            Err(e) => return Err(Error::Builder(format!("Encapsulate failed: {e:?}"))),
        };
        let (trad_ss, trad_ct) = match EcdhKem::<$ec>::encap(trad_pk) {
            Ok((trad_ss, trad_ct)) => (trad_ss, trad_ct.to_vec()),
            Err(e) => {
                return Err(Error::Builder(format!("RSA encapsulate failed: {e:?}")))
            }
        };

        let ss = if is_sha512($domain) {
            match composite_ss::<Hmac<Sha512>>(&pqc_ss, &trad_ss, &trad_ct, &trad_pk, $domain) {
                Ok(ss) => ss,
                Err(e) => {
                    return Err(Error::Builder(format!("RSA encapsulate failed: {e:?}")))
                }
            }
        } else {
            match composite_ss::<Hmac<Sha256>>(&pqc_ss, &trad_ss, &trad_ct, &trad_pk, $domain) {
                Ok(ss) => ss,
                Err(e) => {
                    return Err(Error::Builder(format!("RSA encapsulate failed: {e:?}")))
                }
            }
        };
        let mut ct = vec![];
        ct.append(&mut pqc_ct);
        ct.append(&mut trad_ct.to_vec());
        (ss, ct, $domain)
    }};
}
impl<R: ?Sized> RecipientInfoBuilder for KemRecipientInfoBuilder<R>
where
    R: CryptoRng,
{
    type Rng = R;
    /// Returns the RecipientInfoType
    fn recipient_info_type(&self) -> RecipientInfoType {
        RecipientInfoType::Ori
    }

    /// Returns the `CMSVersion` for this `RecipientInfo`
    fn recipient_info_version(&self) -> CmsVersion {
        CmsVersion::V3
    }

    /// Build a `KemRecipientInfoBuilder`. See draft-ietf-lamps-cms-kemri-07 § 5.
    ///
    /// Supports the following KEM public keys: ML_KEM_512, ML_KEM_768 and ML_KEM_1024
    /// Supports the following KDFs: ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384 and ID_ALG_HKDF_WITH_SHA512
    /// Supports the following key wrap algorithms: ID_AES_128_WRAP, ID_AES_192_WRAP, ID_AES_256_WRAP
    fn build_with_rng(
        &mut self,
        content_encryption_key: &[u8],
        rng: &mut R,
    ) -> Result<RecipientInfo, Error> {
        // The recipient's public key is used with the KEM Encapsulate() function to obtain a pairwise shared secret (ss) and the ciphertext for the recipient.
        let (ss, ct, oid) = match &self.key_encryption_info {
            KeyEncryptionInfoKem::MlKem512(pk) => {
                let ek =
                    <ml_kem::kem::Kem<MlKem512Params> as KemCore>::EncapsulationKey::from_bytes(pk);
                let (ct, ss) = match ek.encapsulate(rng) {
                    Ok((ct, ss)) => (ct, ss),
                    Err(e) => return Err(Error::Builder(format!("Encapsulate failed: {e:?}"))),
                };
                (ss.to_vec(), ct.to_vec(), ID_ALG_ML_KEM_512)
            }
            KeyEncryptionInfoKem::MlKem768(pk) => {
                let ek =
                    <ml_kem::kem::Kem<MlKem768Params> as KemCore>::EncapsulationKey::from_bytes(pk);
                let (ct, ss) = match ek.encapsulate(rng) {
                    Ok((ct, ss)) => (ct, ss),
                    Err(e) => return Err(Error::Builder(format!("Encapsulate failed: {e:?}"))),
                };
                (ss.to_vec(), ct.to_vec(), ID_ALG_ML_KEM_768)
            }
            KeyEncryptionInfoKem::MlKem1024(pk) => {
                let ek =
                    <ml_kem::kem::Kem<MlKem1024Params> as KemCore>::EncapsulationKey::from_bytes(
                        pk,
                    );
                let (ct, ss) = match ek.encapsulate(rng) {
                    Ok((ct, ss)) => (ct, ss),
                    Err(e) => return Err(Error::Builder(format!("Encapsulate failed: {e:?}"))),
                };
                (ss.to_vec(), ct.to_vec(), ID_ALG_ML_KEM_1024)
            }
            KeyEncryptionInfoKem::MlKem768Rsa2048HmacSha256(pk) => {
                comp_encap_rsa!(
                    pk,
                    1184,
                    ID_MLKEM768_RSA2048_HMAC_SHA256,
                    rng,
                    MlKem768Params
                )
            }
            KeyEncryptionInfoKem::MlKem768Rsa3072HmacSha256(pk) => {
                comp_encap_rsa!(
                    pk,
                    1184,
                    ID_MLKEM768_RSA2048_HMAC_SHA256,
                    rng,
                    MlKem768Params
                )
            }
            KeyEncryptionInfoKem::MlKem768Rsa4096HmacSha256(pk) => {
                comp_encap_rsa!(
                    pk,
                    1184,
                    ID_MLKEM768_RSA4096_HMAC_SHA256,
                    rng,
                    MlKem768Params
                )
            }
            KeyEncryptionInfoKem::MlKem1024Rsa3072HmacSha512(pk) => {
                comp_encap_rsa!(
                    pk,
                    1568,
                    ID_MLKEM1024_RSA3072_HMAC_SHA512,
                    rng,
                    MlKem1024Params
                )
            }
            KeyEncryptionInfoKem::MlKem768X25519SHA3_256(_) => {
                todo!("Support encap for EC variants")
            }
            KeyEncryptionInfoKem::MlKem768EcdhP256HmacSha256(pk) => {
                comp_encap_ecdh!(
                    pk,
                    1184,
                    ID_MLKEM768_ECDH_P256_HMAC_SHA256,
                    rng,
                    MlKem768Params,
                    p256::NistP256
                )
            }
            KeyEncryptionInfoKem::MlKem768EcdhP384HmacSha256(pk) => {
                comp_encap_ecdh!(
                    pk,
                    1184,
                    ID_MLKEM768_ECDH_P384_HMAC_SHA256,
                    rng,
                    MlKem768Params,
                    p384::NistP384
                )
            }
            KeyEncryptionInfoKem::MlKem1024EcdhP384HmacSha512(pk) => {
                comp_encap_ecdh!(
                    pk,
                    1568,
                    ID_MLKEM1024_ECDH_P384_HMAC_SHA512,
                    rng,
                    MlKem1024Params,
                    p384::NistP384
                )
            }
            KeyEncryptionInfoKem::MlKem1024X448Sha3_256(_) => {
                todo!("Support encap for EC variants")
            }
            KeyEncryptionInfoKem::MlKem1024EcdhP521HmacSha512(pk) => {
                comp_encap_ecdh!(
                    pk,
                    1568,
                    ID_MLKEM1024_ECDH_P521_HMAC_SHA512,
                    rng,
                    MlKem1024Params,
                    p521::NistP521
                )
            }
        };

        debug!("Shared Secret: {}", buffer_to_hex(&ss));

        // The DER-encoded CMSORIforKEMOtherInfo structure is created from elements of the KEMRecipientInfo structure.
        let wrap = AlgorithmIdentifier {
            oid: self.wrap,
            parameters: None, // Params are absent for AES key wrap algorithms per RFC 5911 section 4
        };

        let kek_length = match get_block_size(&wrap.oid) {
            Ok(l) => l as u16,
            Err(e) => return Err(Error::Builder(format!("Unexpected block size: {e:?}"))),
        };

        let ukm = match &self.ukm {
            Some(ukm) => Some(UserKeyingMaterial::new(ukm.clone())?),
            None => None,
        };

        let kdf_input = CmsOriForKemOtherInfo {
            wrap: wrap.clone(),
            kek_length,
            ukm: ukm.clone(),
        };
        let der_kdf_input = kdf_input.to_der()?;
        debug!("CMSORIforKEMOtherInfo: {}", buffer_to_hex(&der_kdf_input));

        let mut okm = vec![0; kek_length as usize];
        match self.kdf {
            ID_ALG_HKDF_WITH_SHA256 => {
                Hkdf::<Sha256>::new(None, &ss)
                    .expand(&der_kdf_input, &mut okm)
                    .map_err(|e| Error::Builder(format!("{e:?}")))?;
            }
            ID_ALG_HKDF_WITH_SHA384 => {
                Hkdf::<Sha384>::new(None, &ss)
                    .expand(&der_kdf_input, &mut okm)
                    .map_err(|e| Error::Builder(format!("{e:?}")))?;
            }
            ID_ALG_HKDF_WITH_SHA512 => {
                Hkdf::<Sha512>::new(None, &ss)
                    .expand(&der_kdf_input, &mut okm)
                    .map_err(|e| Error::Builder(format!("{e:?}")))?;
            }
            ID_KMAC128 => {
                let custom = b"";
                let mut kmac = Kmac::v128(&ss, custom);
                kmac.update(&der_kdf_input);
                kmac.finalize(&mut okm);
            }
            ID_KMAC256 => {
                let custom = b"";
                let mut kmac = Kmac::v256(&ss, custom);
                kmac.update(&der_kdf_input);
                kmac.finalize(&mut okm);
            }
            _ => {
                return Err(Error::Builder(format!(
                    "Unrecognized KDF algorithm: {}",
                    self.kdf
                )));
            }
        };

        debug!("KEK: {}", buffer_to_hex(&okm));
        let wrapped_key = match self.wrap {
            ID_AES_128_WRAP => {
                encrypt_wrap!(content_encryption_key, Aes128, okm)
            }
            ID_AES_192_WRAP => {
                encrypt_wrap!(content_encryption_key, Aes192, okm)
            }
            ID_AES_256_WRAP => {
                encrypt_wrap!(content_encryption_key, Aes256, okm)
            }
            _ => {
                return Err(Error::Builder(format!(
                    "Unrecognized wrap algorithm: {}",
                    self.wrap
                )));
            }
        };

        debug!("Wrapped CEK: {}", buffer_to_hex(&wrapped_key));
        let kemri = KemRecipientInfo {
            version: CmsVersion::V0,
            rid: self.rid.clone(),
            kem: AlgorithmIdentifier {
                oid,
                parameters: None, // Params are absent for ML-KEM algorithms per draft-ietf-lamps-cms-mlkem-01 section 10.2.1
            },
            kem_ct: OctetString::new(ct)?,
            kdf: AlgorithmIdentifier {
                oid: self.kdf,
                parameters: None, // Params are absent for AES key wrap algorithms per RFC 8619 section 3
            },
            kek_length,
            ukm,
            wrap,
            encrypted_key: OctetString::new(wrapped_key)?,
        };
        let der = kemri.to_der()?;
        let ori_value = Any::from_der(&der)?;
        let ori = OtherRecipientInfo {
            ori_type: ID_ORI_KEM,
            ori_value,
        };

        Ok(RecipientInfo::Ori(ori))
    }
}
