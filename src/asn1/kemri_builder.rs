//! Builder for `KemRecipientInfo` based on `RecipientInfoBuilder` trait from the cms crate

use std::marker::PhantomData;
use log::debug;

use aes::{Aes128, Aes192, Aes256};
use aes_kw::Kek;
use cipher::KeySizeUser;
use cipher::generic_array::GenericArray;
use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};

// use pqcrypto_mlkem::{mlkem512, mlkem768, mlkem1024};
// use pqcrypto_traits::kem::{Ciphertext, SharedSecret};

use crate::{
    ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384, ID_ALG_HKDF_WITH_SHA512, ID_KMAC128,
    ID_KMAC256, ID_ORI_KEM, ML_KEM_512, ML_KEM_768, ML_KEM_1024,
    misc::{gen_certs::buffer_to_hex, utils::get_block_size},
};
use cms::{
    builder::{Error, RecipientInfoBuilder, RecipientInfoType},
    content_info::CmsVersion,
    enveloped_data::{OtherRecipientInfo, RecipientIdentifier, RecipientInfo, UserKeyingMaterial},
    kemri::{CmsOriForKemOtherInfo, KemRecipientInfo},
};
use const_oid::{
    ObjectIdentifier,
    db::rfc5911::{ID_AES_128_WRAP, ID_AES_192_WRAP, ID_AES_256_WRAP},
};
use der::{Any, Decode, Encode, asn1::OctetString};
use ml_kem::EncodedSizeUser;
use ml_kem::kem::Encapsulate;
use ml_kem::{Encoded, MlKem512Params, MlKem768Params, MlKem1024Params};
use rand::rngs::OsRng;
use cipher::rand_core::CryptoRng;
use spki::AlgorithmIdentifier;
use tari_tiny_keccak::{Hasher, Kmac};

/// Contains information required to encrypt the content encryption key with a specific KEM
#[derive(Clone, PartialEq)]
pub enum KeyEncryptionInfoKem {
    MlKem512(Box<Encoded<<ml_kem::kem::Kem<MlKem512Params> as ml_kem::KemCore>::EncapsulationKey>>),
    MlKem768(Box<Encoded<<ml_kem::kem::Kem<MlKem768Params> as ml_kem::KemCore>::EncapsulationKey>>),
    MlKem1024(
        Box<Encoded<<ml_kem::kem::Kem<MlKem1024Params> as ml_kem::KemCore>::EncapsulationKey>>,
    ),
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
        let kek_buf = GenericArray::from_slice($key.as_slice());
        let kek = Kek::<$alg>::from(*kek_buf);
        let mut wrapped_key = vec![0u8; <$alg>::key_size() + 8];
        kek.wrap($cek, &mut wrapped_key)
            .map_err(|e| cms::builder::Error::Builder(format!("Wrap failed: {e:?}")))?;
        wrapped_key.to_vec()
    }};
}

impl<R: ?Sized> RecipientInfoBuilder for KemRecipientInfoBuilder<R> where
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
    fn build_with_rng(&mut self, content_encryption_key: &[u8], rng: &mut R) -> Result<RecipientInfo, Error>
    {
        // The recipient's public key is used with the KEM Encapsulate() function to obtain a pairwise shared secret (ss) and the ciphertext for the recipient.
        let (ss, ct, oid) = match &self.key_encryption_info {
            KeyEncryptionInfoKem::MlKem512(pk) => {
                let ek = <ml_kem::kem::Kem<MlKem512Params> as ml_kem::KemCore>::EncapsulationKey::from_bytes(pk);
                let (ct, ss) = match ek.encapsulate(rng) {
                    Ok((ct, ss)) => (ct, ss),
                    Err(e) => return Err(Error::Builder(format!("Encapsulate failed: {e:?}"))),
                };
                (ss.to_vec(), ct.to_vec(), ML_KEM_512)
            }
            KeyEncryptionInfoKem::MlKem768(pk) => {
                let ek = <ml_kem::kem::Kem<MlKem768Params> as ml_kem::KemCore>::EncapsulationKey::from_bytes(pk);
                let (ct, ss) = match ek.encapsulate(rng) {
                    Ok((ct, ss)) => (ct, ss),
                    Err(e) => return Err(Error::Builder(format!("Encapsulate failed: {e:?}"))),
                };
                (ss.to_vec(), ct.to_vec(), ML_KEM_768)
            }
            KeyEncryptionInfoKem::MlKem1024(pk) => {
                let ek = <ml_kem::kem::Kem<MlKem1024Params> as ml_kem::KemCore>::EncapsulationKey::from_bytes(pk);
                let (ct, ss) = match ek.encapsulate(&mut OsRng) {
                    Ok((ct, ss)) => (ct, ss),
                    Err(e) => return Err(Error::Builder(format!("Encapsulate failed: {e:?}"))),
                };
                (ss.to_vec(), ct.to_vec(), ML_KEM_1024)
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
