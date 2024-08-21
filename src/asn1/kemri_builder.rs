//! Builder for `KemRecipientInfo` based on `RecipientInfoBuilder` trait from the cms crate

use log::debug;

use aes::{Aes128, Aes192, Aes256};
use aes_kw::Kek;
use cipher::generic_array::GenericArray;
use cipher::KeySizeUser;
use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};

use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::kem::{Ciphertext, SharedSecret};

use cms::{
    builder::{Error, RecipientInfoBuilder, RecipientInfoType},
    content_info::CmsVersion,
    enveloped_data::{OtherRecipientInfo, RecipientIdentifier, RecipientInfo, UserKeyingMaterial},
    kemri::{CmsOriForKemOtherInfo, KemRecipientInfo},
};
use const_oid::{
    db::rfc5911::{ID_AES_128_WRAP, ID_AES_192_WRAP, ID_AES_256_WRAP},
    ObjectIdentifier,
};
use der::{asn1::OctetString, Any, Decode, Encode};
use spki::AlgorithmIdentifier;
use tari_tiny_keccak::{Hasher, Kmac};

use crate::{
    misc::{gen_certs::buffer_to_hex, utils::get_block_size},
    ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384, ID_ALG_HKDF_WITH_SHA512, ID_KMAC128,
    ID_KMAC256, ID_ORI_KEM, ML_KEM_1024_IPD, ML_KEM_512_IPD, ML_KEM_768_IPD,
};

/// Contains information required to encrypt the content encryption key with a specific KEM
#[derive(Clone, PartialEq)]
pub enum KeyEncryptionInfoKem {
    MlKem512(Box<kyber512::PublicKey>),
    MlKem768(Box<kyber768::PublicKey>),
    MlKem1024(Box<kyber1024::PublicKey>),
}

/// Builds a `KemRecipientInfo` according to draft-ietf-lamps-cms-kemri-07 § 3.
/// This type uses the recipient's public key to encrypt the content-encryption key.
pub struct KemRecipientInfoBuilder {
    pub rid: RecipientIdentifier,
    pub key_encryption_info: KeyEncryptionInfoKem,
    pub kdf: ObjectIdentifier,
    pub ukm: Option<Vec<u8>>,
    pub wrap: ObjectIdentifier,
}

impl KemRecipientInfoBuilder {
    pub fn new(
        rid: RecipientIdentifier,
        key_encryption_info: KeyEncryptionInfoKem,
        kdf: ObjectIdentifier,
        ukm: Option<Vec<u8>>,
        wrap: ObjectIdentifier,
    ) -> crate::Result<KemRecipientInfoBuilder> {
        Ok(KemRecipientInfoBuilder {
            rid,
            key_encryption_info,
            kdf,
            ukm,
            wrap,
        })
    }
}

/// Macro for encrypting data using Aes128Wrap, Aes192Wrap or Aes256Wrap
macro_rules! encrypt_wrap {
    ($cek:expr, $alg:ty, $key:ident) => {{
        let kek_buf = GenericArray::from_slice($key.as_slice());
        let kek = Kek::<$alg>::from(*kek_buf);
        let mut wrapped_key = vec![0u8; <$alg>::key_size() + 8];
        kek.wrap($cek, &mut wrapped_key)
            .map_err(|e| cms::builder::Error::Builder(format!("Wrap failed: {e:?}")))?;
        wrapped_key.to_vec()
    }};
}

impl RecipientInfoBuilder for KemRecipientInfoBuilder {
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
    /// Supports the following KEM public keys: ML_KEM_512_IPD, ML_KEM_768_IPD and ML_KEM_1024_IPD
    /// Supports the following KDFs: ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384 and ID_ALG_HKDF_WITH_SHA512
    /// Supports the following key wrap algorithms: ID_AES_128_WRAP, ID_AES_192_WRAP, ID_AES_256_WRAP
    fn build(&mut self, content_encryption_key: &[u8]) -> Result<RecipientInfo, Error> {
        // The recipient's public key is used with the KEM Encapsulate() function to obtain a pairwise shared secret (ss) and the ciphertext for the recipient.
        let (ss, ct, oid) = match &self.key_encryption_info {
            KeyEncryptionInfoKem::MlKem512(pk) => {
                let (ss, ct) = kyber512::encapsulate(pk);
                (
                    ss.as_bytes().to_vec(),
                    ct.as_bytes().to_vec(),
                    ML_KEM_512_IPD,
                )
            }
            KeyEncryptionInfoKem::MlKem768(pk) => {
                let (ss, ct) = kyber768::encapsulate(pk);
                (
                    ss.as_bytes().to_vec(),
                    ct.as_bytes().to_vec(),
                    ML_KEM_768_IPD,
                )
            }
            KeyEncryptionInfoKem::MlKem1024(pk) => {
                let (ss, ct) = kyber1024::encapsulate(pk);
                (
                    ss.as_bytes().to_vec(),
                    ct.as_bytes().to_vec(),
                    ML_KEM_1024_IPD,
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
                parameters: None, // Params are absent for ML-KEM algorithms per draft-ietf-lamps-cms-kyber-01 section 10.2.1
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
