//! Builder for `KemRecipientInfo` based on `RecipientInfoBuilder` trait from the cms crate

use crate::misc::oaep_kem::oaep_encapsulate;
use log::debug;

use aes::{Aes128, Aes192, Aes256};
use aes_kw::Kek;
use cipher::generic_array::GenericArray;
use cipher::KeySizeUser;
use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};

use pqcrypto_mlkem::{mlkem512, mlkem768, mlkem1024};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};

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
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::RsaPublicKey;
use sha3::{Digest, Sha3_256, Sha3_384, Sha3_512};
use spki::AlgorithmIdentifier;
use tari_tiny_keccak::{Hasher, Kmac};

use crate::asn1::composite::{
    CompositeCiphertextValue, CompositeKemPublicKey, ML_KEM_512_RSA2048, ML_KEM_512_RSA3072,
};
use crate::{
    misc::{gen_certs::buffer_to_hex, utils::get_block_size},
    ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384, ID_ALG_HKDF_WITH_SHA3_256,
    ID_ALG_HKDF_WITH_SHA3_384, ID_ALG_HKDF_WITH_SHA3_512, ID_ALG_HKDF_WITH_SHA512, ID_KMAC128,
    ID_KMAC256, ID_ORI_KEM, ID_SHA3_256, ID_SHA3_384, ID_SHA3_512, ML_KEM_1024, ML_KEM_512, ML_KEM_768,
};

/// Contains information required to encrypt the content encryption key with a specific KEM
#[derive(Clone, PartialEq)]
pub enum KeyEncryptionInfoKem {
    MlKem512(Box<mlkem512::PublicKey>),
    MlKem768(Box<mlkem768::PublicKey>),
    MlKem1024(Box<mlkem1024::PublicKey>),
    MlKem512Rsa2048(Box<CompositeKemPublicKey>),
    MlKem512Rsa3072(Box<CompositeKemPublicKey>),
}

impl KeyEncryptionInfoKem {
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            KeyEncryptionInfoKem::MlKem512(_) => ML_KEM_512,
            KeyEncryptionInfoKem::MlKem768(_) => ML_KEM_768,
            KeyEncryptionInfoKem::MlKem1024(_) => ML_KEM_1024,
            KeyEncryptionInfoKem::MlKem512Rsa2048(_) => ML_KEM_512_RSA2048,
            KeyEncryptionInfoKem::MlKem512Rsa3072(_) => ML_KEM_512_RSA3072,
        }
    }
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
    /// Supports the following KEM public keys: ML_KEM_512, ML_KEM_768 and ML_KEM_1024
    /// Supports the following KDFs: ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384 and ID_ALG_HKDF_WITH_SHA512
    /// Supports the following key wrap algorithms: ID_AES_128_WRAP, ID_AES_192_WRAP, ID_AES_256_WRAP
    fn build(&mut self, content_encryption_key: &[u8]) -> Result<RecipientInfo, Error> {
        // The recipient's public key is used with the KEM Encapsulate() function to obtain a pairwise shared secret (ss) and the ciphertext for the recipient.
        let (ss, ct, oid) = match &self.key_encryption_info {
            KeyEncryptionInfoKem::MlKem512(pk) => {
                let (ss, ct) = mlkem512::encapsulate(pk);
                (
                    ss.as_bytes().to_vec(),
                    ct.as_bytes().to_vec(),
                    ML_KEM_512,
                )
            }
            KeyEncryptionInfoKem::MlKem768(pk) => {
                let (ss, ct) = mlkem768::encapsulate(pk);
                (
                    ss.as_bytes().to_vec(),
                    ct.as_bytes().to_vec(),
                    ML_KEM_768,
                )
            }
            KeyEncryptionInfoKem::MlKem1024(pk) => {
                let (ss, ct) = mlkem1024::encapsulate(pk);
                (
                    ss.as_bytes().to_vec(),
                    ct.as_bytes().to_vec(),
                    ML_KEM_1024,
                )
            }
            KeyEncryptionInfoKem::MlKem512Rsa2048(pk) => {
                let rsa = match pk.as_ref() {
                    CompositeKemPublicKey::Rsa(rsa) => rsa,
                    _ => {
                        return Err(Error::Builder(
                            "Unrecognized composite public key type".to_string(),
                        ))
                    }
                };

                let rsa_pk = RsaPublicKey::from_pkcs1_der(
                    rsa.second_public_key.as_bytes().unwrap_or_default(),
                )
                .map_err(|_| Error::Builder("Failed to parse RSA public key".to_string()))?;
                let ml_kem_pk = mlkem512::PublicKey::from_bytes(
                    rsa.first_public_key.as_bytes().unwrap_or_default(),
                )
                .map_err(|_| Error::Builder("Failed to parse ML-KEM public key".to_string()))?;

                let (ss_ml_kem, ct_ml_kem) = mlkem512::encapsulate(&ml_kem_pk);
                let (mut ss_rsa, ct_rsa) = oaep_encapsulate(&rsa_pk)
                    .map_err(|_| Error::Builder("OAEP encapsulation failed".to_string()))?;

                let mut ct_rsa_clone = ct_rsa.clone();

                // KEK <- Combiner(tradSS, mlkemSS, tradCT, tradPK, domSep) =
                //   KDF(counter || tradSS || mlkemSS || tradCT || tradPK ||
                //        domSep, outputBits)
                let mut composite_ss: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01];
                let mut dom_sep = self.key_encryption_info.oid().to_der()?;
                composite_ss.append(&mut ss_rsa);
                composite_ss.append(&mut ss_ml_kem.as_bytes().to_vec());
                composite_ss.append(&mut ct_rsa_clone);
                composite_ss.append(&mut ct_ml_kem.as_bytes().to_vec());
                composite_ss.append(&mut dom_sep);
                let composite_ct: CompositeCiphertextValue = [
                    OctetString::new(ct_ml_kem.as_bytes().to_vec())?,
                    OctetString::new(ct_rsa)?,
                ];
                (composite_ss, composite_ct.to_der()?, ML_KEM_512_RSA2048)
            }
            KeyEncryptionInfoKem::MlKem512Rsa3072(pk) => {
                let rsa = match pk.as_ref() {
                    CompositeKemPublicKey::Rsa(rsa) => rsa,
                    _ => {
                        return Err(Error::Builder(
                            "Unrecognized composite public key type".to_string(),
                        ))
                    }
                };

                let rsa_pk = RsaPublicKey::from_pkcs1_der(
                    rsa.second_public_key.as_bytes().unwrap_or_default(),
                )
                .map_err(|_| Error::Builder("Failed to parse RSA public key".to_string()))?;
                let ml_kem_pk = mlkem512::PublicKey::from_bytes(
                    rsa.first_public_key.as_bytes().unwrap_or_default(),
                )
                .map_err(|_| Error::Builder("Failed to parse ML-KEM public key".to_string()))?;

                let (ss_ml_kem, ct_ml_kem) = mlkem512::encapsulate(&ml_kem_pk);
                let (mut ss_rsa, ct_rsa) = oaep_encapsulate(&rsa_pk)
                    .map_err(|_| Error::Builder("OAEP encapsulation failed".to_string()))?;

                let mut ct_rsa_clone = ct_rsa.clone();

                // KEK <- Combiner(tradSS, mlkemSS, tradCT, tradPK, domSep) =
                //   KDF(counter || tradSS || mlkemSS || tradCT || tradPK ||
                //        domSep, outputBits)
                let mut composite_ss: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01];
                let mut dom_sep = self.key_encryption_info.oid().to_der()?;
                composite_ss.append(&mut ss_rsa);
                composite_ss.append(&mut ss_ml_kem.as_bytes().to_vec());
                composite_ss.append(&mut ct_rsa_clone);
                composite_ss.append(&mut ct_ml_kem.as_bytes().to_vec());
                composite_ss.append(&mut dom_sep);
                let composite_ct: CompositeCiphertextValue = [
                    OctetString::new(ct_ml_kem.as_bytes().to_vec())?,
                    OctetString::new(ct_rsa)?,
                ];
                (composite_ss, composite_ct.to_der()?, ML_KEM_512_RSA3072)
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
            ID_ALG_HKDF_WITH_SHA3_256 => {
                Hkdf::<Sha3_256>::new(None, &ss)
                    .expand(&der_kdf_input, &mut okm)
                    .map_err(|e| Error::Builder(format!("{e:?}")))?;
            }
            ID_ALG_HKDF_WITH_SHA3_384 => {
                Hkdf::<Sha3_384>::new(None, &ss)
                    .expand(&der_kdf_input, &mut okm)
                    .map_err(|e| Error::Builder(format!("{e:?}")))?;
            }
            ID_ALG_HKDF_WITH_SHA3_512 => {
                Hkdf::<Sha3_512>::new(None, &ss)
                    .expand(&der_kdf_input, &mut okm)
                    .map_err(|e| Error::Builder(format!("{e:?}")))?;
            }
            ID_SHA3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(ss);
                let result = hasher.finalize();
                okm = result.to_vec();
                okm.truncate(kek_length as usize);
            }
            ID_SHA3_384 => {
                let mut hasher = Sha3_384::new();
                hasher.update(ss);
                let result = hasher.finalize();
                okm = result.to_vec();
                okm.truncate(kek_length as usize);
            }
            ID_SHA3_512 => {
                let mut hasher = Sha3_512::new();
                hasher.update(ss);
                let result = hasher.finalize();
                okm = result.to_vec();
                okm.truncate(kek_length as usize);
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
