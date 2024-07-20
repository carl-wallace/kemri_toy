//! Utility functions for `kemri_toy`

use const_oid::db::rfc5911::{ID_CT_AUTH_ENVELOPED_DATA, ID_ENVELOPED_DATA};
use log::{debug, error};
use rand_core::OsRng;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm};
use aes_kw::Kek;
use cipher::{BlockDecryptMut, KeyInit, KeyIvInit};
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::digest::generic_array::GenericArray;

use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

use cms::cert::IssuerAndSerialNumber;
use cms::enveloped_data::KeyTransRecipientInfo;
use cms::{
    builder::{ContentEncryptionAlgorithm, EnvelopedDataBuilder},
    content_info::ContentInfo,
    enveloped_data::{EnvelopedData, OtherRecipientInfo, RecipientIdentifier, RecipientInfo},
};
use const_oid::{
    db::{
        rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
        rfc5911::{
            ID_AES_128_CBC, ID_AES_128_GCM, ID_AES_128_WRAP, ID_AES_192_CBC, ID_AES_192_WRAP,
            ID_AES_256_CBC, ID_AES_256_GCM, ID_AES_256_WRAP,
        },
    },
    ObjectIdentifier,
};
use der::{asn1::OctetString, Any, AnyRef, Decode, Encode};
use pqckeys::oak::OneAsymmetricKey;
use tari_tiny_keccak::Hasher;
use tari_tiny_keccak::Kmac;
use x509_cert::{ext::pkix::SubjectKeyIdentifier, Certificate};

use crate::{
    asn1::{
        auth_env_data::{AuthEnvelopedData, GcmParameters},
        auth_env_data_builder::AuthEnvelopedDataBuilder,
        composite::{ML_KEM_512_RSA2048, ML_KEM_512_RSA3072},
        kemri::CmsOriForKemOtherInfo,
        kemri_builder::{KemRecipientInfoBuilder, KeyEncryptionInfoKem},
    },
    misc::gen_certs::buffer_to_hex,
    Error, ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384, ID_ALG_HKDF_WITH_SHA512, ID_KMAC128,
    ID_KMAC256, ML_KEM_1024_IPD, ML_KEM_512_IPD, ML_KEM_768_IPD,
};

/// Macro to decrypt data using Aes128Gcm or Aes256Gcn
macro_rules! decrypt_gcm_mode {
    ($data:expr, $aead:ty, $key:expr, $aad:ident, $nonce:ident, $mac:ident) => {{
        let key = GenericArray::from_slice($key);
        let cipher = <$aead>::new(key);
        $data.extend_from_slice($mac);
        cipher.decrypt_in_place($nonce.into(), $aad.as_slice(), $data)
    }};
}

/// Macro to decrypt data using Aes128, Aes192 or Aes256
macro_rules! decrypt_block_mode {
    ($ct:expr, $alg:ty, $key:expr, $iv:ident) => {{
        let key = GenericArray::from_slice(&$key);
        let cipher = <$alg>::new(key, $iv.into());
        cipher.decrypt_padded_vec_mut::<cipher::block_padding::Pkcs7>($ct)
    }};
}

/// Macro to decrypt data using ML-KEM512, ML-KEM768 or ML-KEM1024
macro_rules! decrypt_kem {
    ($kem_ct:expr, $ct_ty:ty, $sk_ty:ty, $decap:expr, $ee_sk:expr) => {{
        let ct = <$ct_ty>::from_bytes($kem_ct)?;
        let private_key = <$sk_ty>::from_bytes($ee_sk)?;
        let ss = $decap(&ct, &private_key);
        ss.as_bytes().to_vec()
    }};
}

/// Extract subject key identifier value from a certificate
pub(crate) fn skid_from_cert(cert: &Certificate) -> crate::Result<Vec<u8>> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER {
                match OctetString::from_der(ext.extn_value.as_bytes()) {
                    Ok(b) => return Ok(b.as_bytes().to_vec()),
                    Err(e) => {
                        error!("Failed to parse SKID extension: {e:?}. Ignoring error and will use calculated value.");
                    }
                }
            }
        }
    }

    let working_spki = &cert.tbs_certificate.subject_public_key_info;
    match working_spki.subject_public_key.as_bytes() {
        Some(spki) => Ok(Sha256::digest(spki).to_vec()),
        None => {
            error!("Failed to render SPKI as bytes");
            Err(Error::Unrecognized)
        }
    }
}

/// Create a RecipientIdentifier corresponding to certificate
pub(crate) fn recipient_identifier_from_cert(
    cert: &Certificate,
) -> crate::Result<RecipientIdentifier> {
    match skid_from_cert(cert) {
        Ok(skid_bytes) => {
            let os = match OctetString::new(skid_bytes) {
                Ok(os) => os,
                Err(e) => return Err(Error::Asn1(e)),
            };
            let skid = SubjectKeyIdentifier::from(os);

            Ok(RecipientIdentifier::SubjectKeyIdentifier(skid))
        }
        Err(_) => Ok(RecipientIdentifier::IssuerAndSerialNumber(
            IssuerAndSerialNumber {
                issuer: cert.tbs_certificate.issuer.clone(),
                serial_number: cert.tbs_certificate.serial_number.clone(),
            },
        )),
    }
}

/// Create a KemRecipientInfoBuilder for a given certificate, KDF algorithm, UKM and wrap algorithm
pub(crate) fn kemri_builder_from_cert(
    ee_cert: &Certificate,
    kdf: ObjectIdentifier,
    ukm: Option<Vec<u8>>,
    wrap: ObjectIdentifier,
) -> crate::Result<KemRecipientInfoBuilder> {
    let recipient_identifier = recipient_identifier_from_cert(ee_cert)?;
    let recipient_info_builder = match ee_cert
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .oid
    {
        ML_KEM_512_IPD => {
            let pk = kyber512::PublicKey::from_bytes(
                ee_cert
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes(),
            )?;
            KemRecipientInfoBuilder::new(
                recipient_identifier,
                KeyEncryptionInfoKem::MlKem512(Box::new(pk)),
                kdf,
                ukm,
                wrap,
            )?
        }
        ML_KEM_768_IPD => {
            let pk = kyber768::PublicKey::from_bytes(
                ee_cert
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes(),
            )?;
            KemRecipientInfoBuilder::new(
                recipient_identifier,
                KeyEncryptionInfoKem::MlKem768(Box::new(pk)),
                kdf,
                ukm,
                wrap,
            )?
        }
        ML_KEM_1024_IPD => {
            let pk = kyber1024::PublicKey::from_bytes(
                ee_cert
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes(),
            )?;
            KemRecipientInfoBuilder::new(
                recipient_identifier,
                KeyEncryptionInfoKem::MlKem1024(Box::new(pk)),
                kdf,
                ukm,
                wrap,
            )?
        }
        ML_KEM_512_RSA2048 => {
            todo!()
        },
        ML_KEM_512_RSA3072 => {
            todo!()
        },
        _ => return Err(Error::Unrecognized),
    };
    Ok(recipient_info_builder)
}

/// Generate an EnvelopedData object
pub fn generate_enveloped_data(
    plaintext: &[u8],
    ee_cert: &Certificate,
    kdf: ObjectIdentifier,
    ukm: Option<Vec<u8>>,
    wrap: ObjectIdentifier,
    enc: ObjectIdentifier,
) -> crate::Result<Vec<u8>> {
    let recipient_info_builder = kemri_builder_from_cert(ee_cert, kdf, ukm, wrap)?;

    let cea = match enc {
        ID_AES_128_CBC => ContentEncryptionAlgorithm::Aes128Cbc,
        ID_AES_192_CBC => ContentEncryptionAlgorithm::Aes192Cbc,
        ID_AES_256_CBC => ContentEncryptionAlgorithm::Aes256Cbc,
        _ => return Err(Error::Unrecognized),
    };

    let mut enveloped_data_builder = EnvelopedDataBuilder::new(
        None, plaintext, // data to be encrypted...
        cea,       // ... with this algorithm
        None,
    )
    .map_err(|_| Error::Unrecognized)?;

    let mut rng = OsRng;
    let enveloped_data = enveloped_data_builder
        .add_recipient_info(recipient_info_builder)
        .map_err(|_| Error::Unrecognized)?
        .build_with_rng(&mut rng)
        .map_err(|_| Error::Unrecognized)?;

    let enveloped_data_der = enveloped_data.to_der()?;
    let content = AnyRef::try_from(enveloped_data_der.as_slice())?;
    let content_info = ContentInfo {
        content_type: ID_ENVELOPED_DATA,
        content: Any::from(content),
    };
    Ok(content_info.to_der()?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentEncryptionAlgorithmAead {
    /// AES-128 GCM
    Aes128Gcm,
    /// AES-256 GCM
    Aes256Gcm,
}

impl ContentEncryptionAlgorithmAead {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            ContentEncryptionAlgorithmAead::Aes128Gcm => ID_AES_128_GCM,
            ContentEncryptionAlgorithmAead::Aes256Gcm => ID_AES_256_GCM,
        }
    }
}

/// Generate an AuthEnvelopedData object
pub fn generate_auth_enveloped_data(
    plaintext: &[u8],
    ee_cert: &Certificate,
    kdf: ObjectIdentifier,
    ukm: Option<Vec<u8>>,
    wrap: ObjectIdentifier,
    enc: ObjectIdentifier,
) -> crate::Result<Vec<u8>> {
    let recipient_info_builder = kemri_builder_from_cert(ee_cert, kdf, ukm, wrap)?;

    let cea = match enc {
        ID_AES_128_GCM => ContentEncryptionAlgorithmAead::Aes128Gcm,
        ID_AES_256_GCM => ContentEncryptionAlgorithmAead::Aes256Gcm,
        _ => return Err(Error::Unrecognized),
    };

    let mut enveloped_data_builder = AuthEnvelopedDataBuilder::new(
        None, plaintext, // data to be encrypted...
        cea,       // ... with this algorithm
        None, None,
    )
    .map_err(|_| Error::Unrecognized)?;

    let mut rng = OsRng;
    let enveloped_data = enveloped_data_builder
        .add_recipient_info(recipient_info_builder)
        .map_err(|_| Error::Unrecognized)?
        .build_with_rng(&mut rng)
        .map_err(|_| Error::Unrecognized)?;

    let enveloped_data_der = enveloped_data.to_der()?;
    let content = AnyRef::try_from(enveloped_data_der.as_slice())?;
    let content_info = ContentInfo {
        content_type: ID_CT_AUTH_ENVELOPED_DATA,
        content: Any::from(content),
    };
    Ok(content_info.to_der()?)
}

pub fn process_ktri(ktri: &KeyTransRecipientInfo, ee_sk: &[u8]) -> crate::Result<Vec<u8>> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

    let recipient_private_key = match RsaPrivateKey::from_pkcs1_der(ee_sk) {
        Ok(pk) => pk,
        Err(e) => {
            return Err(Error::Builder(format!(
                "Failed to parse RSA private key: {e:?}"
            )));
        }
    };
    let content_encryption_key =
        match recipient_private_key.decrypt(Pkcs1v15Encrypt, ktri.enc_key.as_bytes()) {
            Ok(cek) => cek,
            Err(e) => {
                return Err(Error::Builder(format!(
                    "Failed to decrypt CEK using RSA private key: {e:?}"
                )));
            }
        };

    Ok(content_encryption_key)
}

/// Process KemRecipientInfo using the provided private key
pub fn process_kemri(ori: &OtherRecipientInfo, ee_sk: &[u8]) -> crate::Result<Vec<u8>> {
    let ori_value = ori.ori_value.to_der()?;
    let kemri = crate::asn1::kemri::KemRecipientInfo::from_der(&ori_value)?;
    let kem_ct = kemri.kem_ct.as_bytes();
    let ss = match kemri.kem.oid {
        ML_KEM_512_IPD => {
            decrypt_kem!(
                kem_ct,
                kyber512::Ciphertext,
                kyber512::SecretKey,
                kyber512::decapsulate,
                ee_sk
            )
        }
        ML_KEM_768_IPD => {
            decrypt_kem!(
                kem_ct,
                kyber768::Ciphertext,
                kyber768::SecretKey,
                kyber768::decapsulate,
                ee_sk
            )
        }
        ML_KEM_1024_IPD => {
            decrypt_kem!(
                kem_ct,
                kyber1024::Ciphertext,
                kyber1024::SecretKey,
                kyber1024::decapsulate,
                ee_sk
            )
        }
        _ => {
            error!("Unrecognized KEM algorithm: {}", kemri.kem.oid);
            return Err(Error::Unrecognized);
        }
    };

    let kdf_input = CmsOriForKemOtherInfo {
        wrap: kemri.wrap.clone(),
        kek_length: kemri.kek_length,
        ukm: kemri.ukm,
    };
    let der_kdf_input = kdf_input.to_der()?;

    debug!("Shared Secret: {}", buffer_to_hex(&ss));
    debug!("CMSORIforKEMOtherInfo: {}", buffer_to_hex(&der_kdf_input));
    let mut okm = vec![0; get_block_size(&kemri.wrap.oid)?];
    match kemri.kdf.oid {
        ID_ALG_HKDF_WITH_SHA256 => {
            let hk = Hkdf::<Sha256>::new(None, &ss);
            hk.expand(&der_kdf_input, &mut okm)
                .map_err(|_e| Error::Unrecognized)?;
        }
        ID_ALG_HKDF_WITH_SHA384 => {
            let hk = Hkdf::<Sha384>::new(None, &ss);
            hk.expand(&der_kdf_input, &mut okm)
                .map_err(|_e| Error::Unrecognized)?;
        }
        ID_ALG_HKDF_WITH_SHA512 => {
            let hk = Hkdf::<Sha512>::new(None, &ss);
            hk.expand(&der_kdf_input, &mut okm)
                .map_err(|_e| Error::Unrecognized)?;
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
            error!("Unrecognized KDF algorithm: {}", kemri.kdf.oid);
            return Err(Error::Unrecognized);
        }
    };

    debug!("KEK: {}", buffer_to_hex(&okm));
    debug!(
        "Wrapped CEK: {}",
        buffer_to_hex(kemri.encrypted_key.as_bytes())
    );

    let mut wrapped_key = vec![0; kemri.kek_length as usize];
    match kemri.wrap.oid {
        ID_AES_128_WRAP => {
            let kek_buf = GenericArray::from_slice(okm.as_slice());
            let kek = Kek::<Aes128>::from(*kek_buf);
            if let Err(e) = kek.unwrap(kemri.encrypted_key.as_bytes(), &mut wrapped_key) {
                error!("Unwrap failed: {e:?}");
            }
            wrapped_key.to_vec()
        }
        ID_AES_192_WRAP => {
            let kek_buf = GenericArray::from_slice(okm.as_slice());
            let kek = Kek::<Aes192>::from(*kek_buf);
            if let Err(e) = kek.unwrap(kemri.encrypted_key.as_bytes(), &mut wrapped_key) {
                error!("Unwrap failed: {e:?}");
            }
            wrapped_key.to_vec()
        }
        ID_AES_256_WRAP => {
            let kek_buf = GenericArray::from_slice(okm.as_slice());
            let kek = Kek::<Aes256>::from(*kek_buf);
            if let Err(e) = kek.unwrap(kemri.encrypted_key.as_bytes(), &mut wrapped_key) {
                error!("Unwrap failed: {e:?}");
            }
            wrapped_key.to_vec()
        }
        _ => panic!(),
    };
    Ok(wrapped_key.to_vec())
}

/// Process a ContentInfo as an EnvelopedData or AuthEnvelopedData using the provided private key
pub fn process_content_info(enveloped_data: &[u8], ee_oak: &[u8]) -> crate::Result<Vec<u8>> {
    let oak = OneAsymmetricKey::from_der(ee_oak)?;
    let ci = ContentInfo::from_der(enveloped_data)?;
    if ci.content_type == ID_ENVELOPED_DATA {
        process_enveloped_data(&ci.content.to_der()?, oak.private_key.as_bytes())
    } else if ci.content_type == ID_CT_AUTH_ENVELOPED_DATA {
        process_auth_enveloped_data(&ci.content.to_der()?, oak.private_key.as_bytes())
    } else {
        Err(Error::Unrecognized)
    }
}

/// Process AuthEnvelopedData using the provided private key
pub fn process_auth_enveloped_data(
    enveloped_data_bytes: &[u8],
    ee_sk: &[u8],
) -> crate::Result<Vec<u8>> {
    let ed = AuthEnvelopedData::from_der(enveloped_data_bytes)?;
    let params = match ed.auth_encrypted_content.content_enc_alg.parameters {
        Some(p) => p,
        None => {
            error!("Failed to read encrypted content algorithm parameters field");
            return Err(Error::Unrecognized);
        }
    };
    let enc_params = params.to_der()?;

    let gcm_params = GcmParameters::from_der(&enc_params)?;

    let mut ct = match ed.auth_encrypted_content.encrypted_content {
        Some(ct) => ct.as_bytes().to_vec(),
        None => {
            error!("Failed to read encrypted content field");
            return Err(Error::Unrecognized);
        }
    };

    let aad = match &ed.auth_attrs {
        Some(attrs) => attrs.to_der()?,
        None => "".as_bytes().to_vec(),
    };

    for ri in ed.recip_infos.0.iter() {
        let key = match ri {
            RecipientInfo::Ori(ori) => process_kemri(ori, ee_sk)?,
            RecipientInfo::Ktri(ktri) => process_ktri(ktri, ee_sk)?,
            _ => {
                // todo implement support for recipient info types other than KEMRecipientInfo
                continue;
            }
        };

        debug!("CEK: {}", buffer_to_hex(&key));
        debug!("Nonce: {}", buffer_to_hex(gcm_params.nonce.as_bytes()));
        let nonce = gcm_params.nonce.as_bytes();
        let mac = ed.mac.as_bytes();
        match ed.auth_encrypted_content.content_enc_alg.oid {
            ID_AES_128_GCM => {
                if decrypt_gcm_mode!(&mut ct, Aes128Gcm, &key, aad, nonce, mac).is_ok() {
                    return Ok(ct);
                }
            }
            ID_AES_256_GCM => {
                if decrypt_gcm_mode!(&mut ct, Aes256Gcm, &key, aad, nonce, mac).is_ok() {
                    return Ok(ct);
                }
            }
            _ => {
                error!(
                    "Unrecognized content encryption algorithm: {}",
                    ed.auth_encrypted_content.content_enc_alg.oid
                );
                return Err(Error::Unrecognized);
            }
        }
    }

    error!("Failed to process AuthEnvelopedData");
    Err(Error::Unrecognized)
}

/// Process EnvelopedData using the provided private key
pub fn process_enveloped_data(enveloped_data_bytes: &[u8], ee_sk: &[u8]) -> crate::Result<Vec<u8>> {
    let ed = EnvelopedData::from_der(enveloped_data_bytes)?;

    let params = match ed.encrypted_content.content_enc_alg.parameters {
        Some(p) => p,
        None => {
            error!("Failed to read encrypted content algorithm parameters field");
            return Err(Error::Unrecognized);
        }
    };
    let enc_params = params.to_der()?;

    let os_iv = OctetString::from_der(&enc_params)?;
    let iv = os_iv.as_bytes();

    let ct = match ed.encrypted_content.encrypted_content {
        Some(ct) => ct.as_bytes().to_vec(),
        None => {
            error!("Failed to read encrypted content field");
            return Err(Error::Unrecognized);
        }
    };

    for ri in ed.recip_infos.0.iter() {
        let key = match ri {
            RecipientInfo::Ori(ori) => process_kemri(ori, ee_sk)?,
            RecipientInfo::Ktri(ktri) => process_ktri(ktri, ee_sk)?,
            _ => continue,
        };

        match ed.encrypted_content.content_enc_alg.oid {
            ID_AES_128_CBC => {
                type Aes128CbcDec = cbc::Decryptor<Aes128>;
                return decrypt_block_mode!(&ct, Aes128CbcDec, &key, iv)
                    .map_err(|_e| Error::Unrecognized);
            }
            ID_AES_192_CBC => {
                type Aes192CbcDec = cbc::Decryptor<Aes192>;
                return decrypt_block_mode!(&ct, Aes192CbcDec, &key, iv)
                    .map_err(|_e| Error::Unrecognized);
            }
            ID_AES_256_CBC => {
                type Aes256CbcDec = cbc::Decryptor<Aes256>;
                return decrypt_block_mode!(&ct, Aes256CbcDec, &key, iv)
                    .map_err(|_e| Error::Unrecognized);
            }
            _ => {
                error!(
                    "Unrecognized content encryption algorithm: {}",
                    ed.encrypted_content.content_enc_alg.oid
                );
                continue;
            }
        }
    }

    error!("Failed to process EnvelopedData");
    Err(Error::Unrecognized)
}

/// Get the block size of the given algorithm
pub(crate) fn get_block_size(oid: &ObjectIdentifier) -> crate::Result<usize> {
    match *oid {
        ID_AES_128_WRAP | ID_AES_128_CBC | ID_AES_128_GCM => Ok(16),
        ID_AES_192_WRAP | ID_AES_192_CBC => Ok(24),
        ID_AES_256_WRAP | ID_AES_256_CBC | ID_AES_256_GCM => Ok(32),
        _ => {
            error!("Failed to get block size for {oid}");
            Err(Error::Unrecognized)
        }
    }
}

/// Get contents of given file as a vector of bytes
pub fn get_file_as_byte_vec(filename: &Path) -> crate::Result<Vec<u8>> {
    match File::open(filename) {
        Ok(mut f) => match std::fs::metadata(filename) {
            Ok(metadata) => {
                let mut buffer = vec![0; metadata.len() as usize];
                match f.read_exact(&mut buffer) {
                    Ok(_) => Ok(buffer),
                    Err(_e) => Err(Error::Unrecognized),
                }
            }
            Err(_e) => Err(Error::Unrecognized),
        },
        Err(e) => {
            error!("Failed to open file {filename:?}: {e:?}");
            Err(Error::Unrecognized)
        }
    }
}

/// Read buffer from file identified in file_name param, if present
pub fn get_buffer_from_file_arg(file_name: &Option<PathBuf>) -> crate::Result<Vec<u8>> {
    match file_name {
        Some(file_name) => {
            if !file_name.exists() {
                error!("{} does not exist", file_name.to_str().unwrap_or_default());
                Err(Error::Unrecognized)
            } else {
                get_file_as_byte_vec(file_name)
            }
        }
        None => Err(Error::Unrecognized),
    }
}

/// Read certificate from file identified in file_name param, if present
pub fn get_cert_from_file_arg(file_name: &Option<PathBuf>) -> crate::Result<Certificate> {
    let der = get_buffer_from_file_arg(file_name)?;
    Ok(Certificate::from_der(&der)?)
}

pub fn get_filename_from_oid(oid: ObjectIdentifier) -> String {
    match oid {
        ML_KEM_512_IPD => "ML-KEM-512-ipd".to_string(),
        ML_KEM_768_IPD => "ML-KEM-768-ipd".to_string(),
        ML_KEM_1024_IPD => "ML-KEM-1024-ipd".to_string(),
        ML_KEM_512_RSA2048 => "ML-KEM-512-RSA2048".to_string(),
        ML_KEM_512_RSA3072 => "ML-KEM-512-RSA3072".to_string(),
        _ => "Unrecognized".to_string(),
    }
}

#[cfg(test)]
fn test_decrypt(key_folder: &str, artifact_folder: &str) -> Result<(), Error> {
    use crate::KemAlgorithms;
    use std::collections::BTreeMap;

    let expected_plaintext = get_file_as_byte_vec(Path::new(&format!(
        "{}/expected_plaintext.txt",
        artifact_folder
    )))
    .unwrap();

    // read in three private keys (not using include bytes so that when OID changes, files will be read)
    let mut key_map = BTreeMap::new();
    key_map.insert(
        ML_KEM_512_IPD.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_priv.der",
            key_folder,
            KemAlgorithms::MlKem512.filename()
        )))?,
    );
    key_map.insert(
        ML_KEM_768_IPD.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_priv.der",
            key_folder,
            KemAlgorithms::MlKem768.filename()
        )))?,
    );
    key_map.insert(
        ML_KEM_1024_IPD.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_priv.der",
            key_folder,
            KemAlgorithms::MlKem1024.filename()
        )))?,
    );
    let paths = std::fs::read_dir(artifact_folder).unwrap();
    for path in paths {
        match path {
            Ok(path) => {
                if let Some(file_name) = path.file_name().to_str() {
                    if file_name.contains("_priv")
                        || file_name.contains("_ee")
                        || file_name.contains(".txt")
                    {
                        continue;
                    } else {
                        let parts = file_name.split('_').collect::<Vec<&str>>();
                        if let Some(oid) = parts.first() {
                            if let Some(key) = key_map.get(&oid.to_string()) {
                                if let Ok(ci) = get_file_as_byte_vec(&path.path()) {
                                    println!("Processing {:?}", path.path());
                                    match process_content_info(&ci, key) {
                                        Ok(pt) => assert_eq!(pt, expected_plaintext),
                                        Err(e) => {
                                            println!("ERROR processing {:?}: {e:?}", path.path());
                                            return Err(e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }
    Ok(())
}

#[test]
fn decrypt_cryptonext() {
    assert!(test_decrypt("tests/artifacts/cryptonext", "tests/artifacts/cryptonext").is_ok());
}

#[test]
fn decrypt_kemri_toy() {
    assert!(test_decrypt("tests/artifacts/kemri_toy", "tests/artifacts/kemri_toy").is_ok());
}

#[test]
fn decrypt_wrong_keys() {
    assert!(test_decrypt("tests/artifacts/daniel", "tests/artifacts/kemri_toy").is_err());
}

#[cfg(test)]
fn test_encrypt(key_folder: &str) -> Result<(), Error> {
    use crate::args::{AeadAlgorithms, EncAlgorithms, KdfAlgorithms, KemAlgorithms};
    use std::collections::BTreeMap;

    // read in three private keys (not using include bytes so that when OID changes, files will be read)
    let mut key_map = BTreeMap::new();
    key_map.insert(
        ML_KEM_512_IPD.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_priv.der",
            key_folder,
            KemAlgorithms::MlKem512.filename()
        )))?,
    );
    key_map.insert(
        ML_KEM_768_IPD.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_priv.der",
            key_folder,
            KemAlgorithms::MlKem768.filename()
        )))?,
    );
    key_map.insert(
        ML_KEM_1024_IPD.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_priv.der",
            key_folder,
            KemAlgorithms::MlKem1024.filename()
        )))?,
    );

    let mut cert_map = BTreeMap::new();
    cert_map.insert(
        ML_KEM_512_IPD.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_ee.der",
            key_folder,
            KemAlgorithms::MlKem512.filename()
        )))?,
    );
    cert_map.insert(
        ML_KEM_768_IPD.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_ee.der",
            key_folder,
            KemAlgorithms::MlKem768.filename()
        )))?,
    );
    cert_map.insert(
        ML_KEM_1024_IPD.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_ee.der",
            key_folder,
            KemAlgorithms::MlKem1024.filename()
        )))?,
    );

    let kem_algs = [
        KemAlgorithms::MlKem512,
        KemAlgorithms::MlKem768,
        KemAlgorithms::MlKem1024,
        KemAlgorithms::MlKem512Rsa2048,
        KemAlgorithms::MlKem512Rsa3072,
    ];
    let kdf_algs = [
        KdfAlgorithms::HkdfSha256,
        KdfAlgorithms::HkdfSha384,
        KdfAlgorithms::HkdfSha512,
    ];
    let enc_algs = [
        EncAlgorithms::Aes128,
        EncAlgorithms::Aes192,
        EncAlgorithms::Aes256,
    ];
    let aead_algs = [AeadAlgorithms::Aes128Gcm, AeadAlgorithms::Aes256Gcm];

    for kem_alg in &kem_algs {
        let key = key_map.get(&kem_alg.oid().to_string()).unwrap();
        let cert_bytes = cert_map.get(&kem_alg.oid().to_string()).unwrap();
        let cert = Certificate::from_der(cert_bytes)?;
        for kdf_alg in &kdf_algs {
            for enc_alg in &enc_algs {
                println!("EnvelopedData - {kem_alg} - {kdf_alg} - {enc_alg}");
                let ci = generate_enveloped_data(
                    "abc".as_bytes(),
                    &cert,
                    kdf_alg.oid(),
                    None,
                    enc_alg.wrap(),
                    enc_alg.oid(),
                )?;
                let pt = process_content_info(&ci, key)?;
                assert_eq!("abc".as_bytes(), pt);
                let ci = generate_enveloped_data(
                    "abc".as_bytes(),
                    &cert,
                    kdf_alg.oid(),
                    Some("UKM".as_bytes().to_vec()),
                    enc_alg.wrap(),
                    enc_alg.oid(),
                )?;
                let pt = process_content_info(&ci, key)?;
                assert_eq!("abc".as_bytes(), pt);
            }
        }
    }
    for kem_alg in &kem_algs {
        let key = key_map.get(&kem_alg.oid().to_string()).unwrap();
        let cert_bytes = cert_map.get(&kem_alg.oid().to_string()).unwrap();
        let cert = Certificate::from_der(cert_bytes)?;
        for kdf_alg in &kdf_algs {
            for aead_alg in &aead_algs {
                println!("AuthEnvelopedData - {kem_alg} - {kdf_alg} - {aead_alg}");
                let ci = generate_auth_enveloped_data(
                    "abc".as_bytes(),
                    &cert,
                    kdf_alg.oid(),
                    None,
                    aead_alg.wrap(),
                    aead_alg.oid(),
                )?;
                let pt = process_content_info(&ci, key)?;
                assert_eq!("abc".as_bytes(), pt);
                let ci = generate_auth_enveloped_data(
                    "abc".as_bytes(),
                    &cert,
                    kdf_alg.oid(),
                    Some("UKM".as_bytes().to_vec()),
                    aead_alg.wrap(),
                    aead_alg.oid(),
                )?;
                let pt = process_content_info(&ci, key)?;
                assert_eq!("abc".as_bytes(), pt);
            }
        }
    }
    Ok(())
}
#[test]
fn generate_test() {
    assert!(test_encrypt("tests/artifacts/kemri_toy").is_ok());
}

#[test]
fn rsa_auth_env_data_tests() {
    // openssl cms -encrypt -in data.txt -recip cert.der -originator cert.der -out auth_enveloped_data_256.bin -aes-256-gcm -outform DER
    // openssl cms -encrypt -in data.txt -recip cert.der -originator cert.der -out auth_enveloped_data_128.bin -aes-128-gcm -outform DER
    let rsa_priv = include_bytes!("../../tests/artifacts/openssl/rsa.key");
    let _rsa_cert = include_bytes!("../../tests/artifacts/openssl/rsa.der");
    let expected_plaintext = include_bytes!("../../tests/artifacts/openssl/data.txt");

    let rsa_ad = include_bytes!("../../tests/artifacts/openssl/auth_enveloped_data_256.bin");
    let pt = process_content_info(rsa_ad, rsa_priv).unwrap();
    assert_eq!(pt, expected_plaintext);

    let rsa_ad = include_bytes!("../../tests/artifacts/openssl/auth_enveloped_data_128.bin");
    let pt = process_content_info(rsa_ad, rsa_priv).unwrap();
    assert_eq!(pt, expected_plaintext);
}

#[test]
fn break_things() {
    use crate::asn1::kemri::KemRecipientInfo;
    use cms::enveloped_data::RecipientInfos;
    let expected_plaintext =
        include_bytes!("../../tests/artifacts/cryptonext/expected_plaintext.txt");
    let ml_kem_512_key = include_bytes!(
        "../../tests/artifacts/cryptonext/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_priv.der"
    );
    let auth_data_bytes = include_bytes!(
        "../../tests/artifacts/cryptonext/1.3.6.1.4.1.22554.5.6.1_ML-KEM-512-ipd_kemri_auth.der"
    );

    let pt = process_content_info(auth_data_bytes, ml_kem_512_key).unwrap();
    assert_eq!(pt, expected_plaintext);

    let ci = ContentInfo::from_der(auth_data_bytes).unwrap();
    {
        let mut ad_bad_mac = AuthEnvelopedData::from_der(&ci.content.to_der().unwrap()).unwrap();
        let mut mac = ad_bad_mac.mac.as_bytes().to_vec();
        if mac[0] != 0xff {
            mac[0] = 0xff;
        } else {
            mac[0] = 0xfe;
        }
        ad_bad_mac.mac = OctetString::new(mac.as_slice()).unwrap();
        let ad_bad_mac_der = ad_bad_mac.to_der().unwrap();
        assert!(process_auth_enveloped_data(&ad_bad_mac_der, ml_kem_512_key).is_err());
    }

    {
        let mut ad_bad_enc_content =
            AuthEnvelopedData::from_der(&ci.content.to_der().unwrap()).unwrap();
        let mut enc_content_alg = ad_bad_enc_content.auth_encrypted_content.content_enc_alg;
        if enc_content_alg.oid != ID_AES_256_GCM {
            enc_content_alg.oid = ID_AES_256_GCM;
        } else {
            enc_content_alg.oid = ID_AES_128_GCM;
        }
        ad_bad_enc_content.auth_encrypted_content.content_enc_alg = enc_content_alg;
        let ad_bad_mac_der = ad_bad_enc_content.to_der().unwrap();
        assert!(process_auth_enveloped_data(&ad_bad_mac_der, ml_kem_512_key).is_err());
    }

    {
        let mut ad_bad_wrap = AuthEnvelopedData::from_der(&ci.content.to_der().unwrap()).unwrap();
        let mut replacement_ris = vec![];
        for ri in ad_bad_wrap.recip_infos.0.iter() {
            match ri {
                RecipientInfo::Ori(ori) => {
                    let mut kemri =
                        KemRecipientInfo::from_der(&ori.ori_value.to_der().unwrap()).unwrap();
                    if kemri.wrap.oid != ID_AES_256_WRAP {
                        kemri.wrap.oid = ID_AES_256_WRAP;
                    } else {
                        kemri.wrap.oid = ID_AES_128_WRAP;
                    }
                    let kemri_der = kemri.to_der().unwrap();
                    let new_ori = OtherRecipientInfo {
                        ori_type: ori.ori_type,
                        ori_value: Any::from_der(&kemri_der).unwrap(),
                    };
                    replacement_ris.push(RecipientInfo::Ori(new_ori));
                }
                _ => {
                    // todo implement support for recipient info types other than KEMRecipientInfo
                    continue;
                }
            }
        }
        ad_bad_wrap.recip_infos = RecipientInfos::try_from(replacement_ris).unwrap();
        let ad_bad_mac_der = ad_bad_wrap.to_der().unwrap();
        assert!(process_auth_enveloped_data(&ad_bad_mac_der, ml_kem_512_key).is_err());
    }
}
