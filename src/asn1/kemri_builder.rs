//! Builder for `KemRecipientInfo` based on `RecipientInfoBuilder` trait from the cms crate

use crate::asn1::utils::kem_combiner;
use core::marker::PhantomData;
use ml_kem::TryKeyInit;

use log::debug;

use aes::{Aes128, Aes192, Aes256};
use aes_kw::AesKw;
use cipher::{KeyInit, KeySizeUser};
use hkdf::Hkdf;
use ml_kem::{MlKem512, MlKem768, MlKem1024, kem::Encapsulate};
use sha2::{Sha256, Sha384, Sha512};

use cms::{
    builder::{RecipientInfoBuilder, RecipientInfoType},
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
use spki::AlgorithmIdentifier;
use x509_cert::Certificate;

use pqckeys::pqc_oids::*;

use crate::asn1::utils;
use crate::{
    asn1::oids::{
        ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384, ID_ALG_HKDF_WITH_SHA512, ID_ORI_KEM,
    },
    misc::{ecdh::EcdhKem, rsa::RsaKem},
};
use crate::{buffer_to_hex, recipient_identifier_from_cert};
use cms::builder::Error;
use kem::Kem;

/// Contains information required to encrypt the content encryption key with a specific KEM
#[derive(Clone, PartialEq)]
#[allow(dead_code, missing_docs)]
pub enum KeyEncryptionInfoKem {
    MlKem512(Box<<MlKem512 as Kem>::EncapsulationKey>),
    MlKem768(Box<<MlKem768 as Kem>::EncapsulationKey>),
    MlKem1024(Box<<MlKem1024 as Kem>::EncapsulationKey>),
    MlKem768Rsa2048Sha3_256(Vec<u8>),
    MlKem768Rsa3072Sha3_256(Vec<u8>),
    MlKem768Rsa4096Sha3_256(Vec<u8>),
    MlKem1024Rsa3072Sha3_256(Vec<u8>),
    MlKem768EcdhP256Sha3_256(Vec<u8>),
    MlKem768EcdhP384Sha3_256(Vec<u8>),
    MlKem1024EcdhP384Sha3_256(Vec<u8>),
    MlKem1024EcdhP521Sha3_256(Vec<u8>),
}

/// Builds a `KemRecipientInfo` per to [RFC 9629 Section 3]. This type uses the recipient's public
/// key to encrypt the content-encryption key.
///
/// [RFC 9629 Section 3]: https://datatracker.ietf.org/doc/html/rfc9629#section-3
#[allow(missing_docs)]
pub struct KemRecipientInfoBuilder<R: ?Sized> {
    pub rid: RecipientIdentifier,
    pub key_encryption_info: KeyEncryptionInfoKem,
    pub kdf: ObjectIdentifier,
    pub ukm: Option<Vec<u8>>,
    pub wrap: ObjectIdentifier,
    _rng: PhantomData<R>,
}

impl<R> KemRecipientInfoBuilder<R> {
    /// Instantiates a new [KemRecipientInfoBuilder] instance.
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

impl<R: ?Sized> RecipientInfoBuilder for KemRecipientInfoBuilder<R>
where
    R: rand_core::CryptoRng,
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
        _rng: &mut R,
    ) -> Result<RecipientInfo, Error> {
        // The recipient's public key is used with the KEM Encapsulate() function to obtain a pairwise shared secret (ss) and the ciphertext for the recipient.
        let (ss, ct, oid) = match &self.key_encryption_info {
            KeyEncryptionInfoKem::MlKem512(pk) => {
                let ek = <MlKem512 as Kem>::EncapsulationKey::from(pk.as_ref().clone());
                let (ct, ss) = ek.encapsulate();
                (ss.to_vec(), ct.to_vec(), ID_ALG_ML_KEM_512)
            }
            KeyEncryptionInfoKem::MlKem768(pk) => {
                let ek = <MlKem768 as Kem>::EncapsulationKey::from(pk.as_ref().clone());
                let (ct, ss) = ek.encapsulate();
                (ss.to_vec(), ct.to_vec(), ID_ALG_ML_KEM_768)
            }
            KeyEncryptionInfoKem::MlKem1024(pk) => {
                let ek = <MlKem1024 as Kem>::EncapsulationKey::from(pk.as_ref().clone());
                let (ct, ss) = ek.encapsulate();
                (ss.to_vec(), ct.to_vec(), ID_ALG_ML_KEM_1024)
            }
            KeyEncryptionInfoKem::MlKem768Rsa2048Sha3_256(pk) => {
                comp_encap_rsa!(pk, 1184, ID_MLKEM768_RSA2048_SHA3_256, MlKem768)
            }
            KeyEncryptionInfoKem::MlKem768Rsa3072Sha3_256(pk) => {
                comp_encap_rsa!(pk, 1184, ID_MLKEM768_RSA2048_SHA3_256, MlKem768)
            }
            KeyEncryptionInfoKem::MlKem768Rsa4096Sha3_256(pk) => {
                comp_encap_rsa!(pk, 1184, ID_MLKEM768_RSA4096_SHA3_256, MlKem768)
            }
            KeyEncryptionInfoKem::MlKem1024Rsa3072Sha3_256(pk) => {
                comp_encap_rsa!(pk, 1568, ID_MLKEM1024_RSA3072_SHA3_256, MlKem1024)
            }
            KeyEncryptionInfoKem::MlKem768EcdhP256Sha3_256(pk) => {
                comp_encap_ecdh!(
                    pk,
                    1184,
                    ID_MLKEM768_ECDH_P256_SHA3_256,
                    MlKem768,
                    p256::NistP256
                )
            }
            KeyEncryptionInfoKem::MlKem768EcdhP384Sha3_256(pk) => {
                comp_encap_ecdh!(
                    pk,
                    1184,
                    ID_MLKEM768_ECDH_P384_SHA3_256,
                    MlKem768,
                    p384::NistP384
                )
            }
            KeyEncryptionInfoKem::MlKem1024EcdhP384Sha3_256(pk) => {
                comp_encap_ecdh!(
                    pk,
                    1568,
                    ID_MLKEM1024_ECDH_P384_SHA3_256,
                    MlKem1024,
                    p384::NistP384
                )
            }
            KeyEncryptionInfoKem::MlKem1024EcdhP521Sha3_256(pk) => {
                comp_encap_ecdh!(
                    pk,
                    1568,
                    ID_MLKEM1024_ECDH_P521_SHA3_256,
                    MlKem1024,
                    p521::NistP521
                )
            }
        };

        debug!("Shared Secret: {}", buffer_to_hex(&ss));

        // The DER-encoded CMSORIforKEMOtherInfo structure is created from elements of the
        // KEMRecipientInfo structure.
        let wrap = AlgorithmIdentifier {
            oid: self.wrap,
            parameters: None, // Params are absent for AES key wrap per RFC 5911 section 4
        };

        let kek_length = match utils::get_block_size(&wrap.oid) {
            Ok(l) => l as u16,
            Err(e) => {
                return Err(Error::Builder(format!("Unexpected block size: {e:?}")));
            }
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

/// Create a KemRecipientInfoBuilder instance for a given certificate, KDF algorithm, UKM and wrap
/// algorithm
pub(crate) fn kemri_builder_from_cert<R>(
    ee_cert: &Certificate,
    kdf: ObjectIdentifier,
    ukm: Option<Vec<u8>>,
    wrap: ObjectIdentifier,
) -> crate::Result<KemRecipientInfoBuilder<R>> {
    let recipient_identifier = recipient_identifier_from_cert(ee_cert)?;
    let recipient_info_builder = match ee_cert
        .tbs_certificate()
        .subject_public_key_info()
        .algorithm
        .oid
    {
        ID_ALG_ML_KEM_512 => {
            let pk = <MlKem512 as Kem>::EncapsulationKey::new_from_slice(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes(),
            )
            .map_err(|e| crate::Error::Builder(format!("{e:?}")))?;
            KemRecipientInfoBuilder::new(
                recipient_identifier,
                KeyEncryptionInfoKem::MlKem512(Box::new(pk)),
                kdf,
                ukm,
                wrap,
            )?
        }
        ID_ALG_ML_KEM_768 => {
            let pk = <MlKem768 as Kem>::EncapsulationKey::new_from_slice(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes(),
            )
            .map_err(|e| crate::Error::Builder(format!("{e:?}")))?;
            KemRecipientInfoBuilder::new(
                recipient_identifier,
                KeyEncryptionInfoKem::MlKem768(Box::new(pk)),
                kdf,
                ukm,
                wrap,
            )?
        }
        ID_ALG_ML_KEM_1024 => {
            let pk = <MlKem1024 as Kem>::EncapsulationKey::new_from_slice(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes(),
            )
            .map_err(|e| crate::Error::Builder(format!("{e:?}")))?;
            KemRecipientInfoBuilder::new(
                recipient_identifier,
                KeyEncryptionInfoKem::MlKem1024(Box::new(pk)),
                kdf,
                ukm,
                wrap,
            )?
        }
        ID_MLKEM768_RSA2048_SHA3_256 => KemRecipientInfoBuilder::new(
            recipient_identifier,
            KeyEncryptionInfoKem::MlKem768Rsa2048Sha3_256(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes()
                    .to_vec(),
            ),
            kdf,
            ukm,
            wrap,
        )?,
        ID_MLKEM768_RSA3072_SHA3_256 => KemRecipientInfoBuilder::new(
            recipient_identifier,
            KeyEncryptionInfoKem::MlKem768Rsa3072Sha3_256(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes()
                    .to_vec(),
            ),
            kdf,
            ukm,
            wrap,
        )?,
        ID_MLKEM768_RSA4096_SHA3_256 => KemRecipientInfoBuilder::new(
            recipient_identifier,
            KeyEncryptionInfoKem::MlKem768Rsa4096Sha3_256(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes()
                    .to_vec(),
            ),
            kdf,
            ukm,
            wrap,
        )?,
        ID_MLKEM1024_RSA3072_SHA3_256 => KemRecipientInfoBuilder::new(
            recipient_identifier,
            KeyEncryptionInfoKem::MlKem1024Rsa3072Sha3_256(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes()
                    .to_vec(),
            ),
            kdf,
            ukm,
            wrap,
        )?,
        ID_MLKEM768_X25519_SHA3_256 => {
            todo!("Support recip info builder prep for EC variants")
        }
        ID_MLKEM768_ECDH_P256_SHA3_256 => KemRecipientInfoBuilder::new(
            recipient_identifier,
            KeyEncryptionInfoKem::MlKem768EcdhP256Sha3_256(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes()
                    .to_vec(),
            ),
            kdf,
            ukm,
            wrap,
        )?,
        ID_MLKEM768_ECDH_P384_SHA3_256 => KemRecipientInfoBuilder::new(
            recipient_identifier,
            KeyEncryptionInfoKem::MlKem768EcdhP384Sha3_256(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes()
                    .to_vec(),
            ),
            kdf,
            ukm,
            wrap,
        )?,
        ID_MLKEM1024_ECDH_P384_SHA3_256 => KemRecipientInfoBuilder::new(
            recipient_identifier,
            KeyEncryptionInfoKem::MlKem1024EcdhP384Sha3_256(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes()
                    .to_vec(),
            ),
            kdf,
            ukm,
            wrap,
        )?,
        ID_MLKEM1024_X448_SHA3_256 => {
            todo!("Support recip info builder prep for EC variants")
        }
        ID_MLKEM1024_ECDH_P521_SHA3_256 => KemRecipientInfoBuilder::new(
            recipient_identifier,
            KeyEncryptionInfoKem::MlKem1024EcdhP521Sha3_256(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes()
                    .to_vec(),
            ),
            kdf,
            ukm,
            wrap,
        )?,
        _ => return Err(crate::Error::Unrecognized),
    };
    Ok(recipient_info_builder)
}
