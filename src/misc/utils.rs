//! Utility functions for `kemri_toy`

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use elliptic_curve::sec1::FromEncodedPoint;
use log::{debug, error};
use rand::rngs::OsRng;
use zerocopy::IntoBytes;

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Key,
    aead::{AeadInOut, Nonce},
};
use aes_kw::AesKw;
use cipher::{BlockModeDecrypt, Iv, KeyInit, KeyIvInit};
use hkdf::Hkdf;
use ml_dsa::{KeyGen, MlDsa44, MlDsa65, MlDsa87};
use ml_kem::{
    B32, Encoded, EncodedSizeUser, KemCore, MlKem512, MlKem512Params, MlKem768, MlKem768Params,
    MlKem1024, MlKem1024Params, kem::Decapsulate,
};
use rsa::{pkcs1::EncodeRsaPublicKey, rand_core::TryRngCore};
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::Sha3_256;
use tari_tiny_keccak::{Hasher, Kmac};

use cms::{
    builder::{ContentEncryptionAlgorithm, EnvelopedDataBuilder},
    cert::IssuerAndSerialNumber,
    content_info::ContentInfo,
    enveloped_data::{
        EnvelopedData, KeyTransRecipientInfo, OtherRecipientInfo, RecipientIdentifier,
        RecipientInfo,
    },
    kemri::CmsOriForKemOtherInfo,
};
use const_oid::{
    AssociatedOid, ObjectIdentifier,
    db::{
        fips203::{ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768, ID_ALG_ML_KEM_1024},
        fips204::*,
        fips205::*,
        rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
        rfc5911::{
            ID_AES_128_CBC, ID_AES_128_GCM, ID_AES_128_WRAP, ID_AES_192_CBC, ID_AES_192_WRAP,
            ID_AES_256_CBC, ID_AES_256_GCM, ID_AES_256_WRAP, ID_CT_AUTH_ENVELOPED_DATA,
            ID_ENVELOPED_DATA,
        },
    },
};
use der::{Any, AnyRef, Decode, DecodePem, Encode, asn1::OctetString};
use elliptic_curve::{
    CurveArithmetic, FieldBytesSize,
    sec1::{ModulusSize, ToEncodedPoint, ValidatePublicKey},
};
use x509_cert::{Certificate, ext::pkix::SubjectKeyIdentifier};

use pqckeys::{oak::OneAsymmetricKey, pqc_oids::*};

use crate::{
    Error, ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384, ID_ALG_HKDF_WITH_SHA512, ID_KMAC128,
    ID_KMAC256,
    asn1::{
        EcPrivateKey,
        auth_env_data::{AuthEnvelopedData, GcmParameters},
        auth_env_data_builder::AuthEnvelopedDataBuilder,
        kemri_builder::{KemRecipientInfoBuilder, KeyEncryptionInfoKem},
        private_key::{
            MlDsa44PrivateKey, MlDsa65PrivateKey, MlDsa87PrivateKey, MlKem512PrivateKey,
            MlKem768PrivateKey, MlKem1024PrivateKey,
        },
    },
    misc::{ecdh::EcdhKem, gen_certs::buffer_to_hex, rsa::RsaKem},
};

/// Macro to decrypt data using Aes128Gcm or Aes256Gcn
macro_rules! decrypt_gcm_mode {
    ($data:expr, $aead:ty, $key:expr, $aad:ident, $nonce:ident, $mac:ident) => {{
        #[allow(deprecated)]
        let aes_key = Key::<$aead>::from_slice($key.as_slice());
        let cipher = <$aead>::new(aes_key);
        $data.extend_from_slice($mac);
        #[allow(deprecated)]
        let aes_nonce = Nonce::<$aead>::from_slice($nonce);
        cipher.decrypt_in_place(aes_nonce, $aad.as_slice(), $data)
    }};
}

/// Macro to decrypt data using Aes128, Aes192 or Aes256
macro_rules! decrypt_block_mode {
    ($ct:expr, $alg:ty, $key:expr, $iv:ident) => {{
        type AesType = cbc::Decryptor<$alg>;
        #[allow(deprecated)]
        let aes_key: &Key<AesType> = Key::<AesType>::from_slice($key);
        #[allow(deprecated)]
        let aes_nonce: &Iv<AesType> = Iv::<AesType>::from_slice($iv);
        let cipher = <AesType>::new(aes_key, aes_nonce);
        cipher.decrypt_padded_vec::<cipher::block_padding::Pkcs7>($ct)
    }};
}

/// Macro to decrypt data using ML-KEM512, ML-KEM768 or ML-KEM1024
macro_rules! decrypt_kem_rust_crypto {
    ($kem_ct:expr, $ct_ty:ty, $params_ty:ty, $ee_sk:expr) => {{
        let dk_bytes = Encoded::<<ml_kem::kem::Kem<$params_ty> as ml_kem::KemCore>::DecapsulationKey>::try_from($ee_sk.as_slice()).map_err(|e| Error::MlKem(format!("{e:?}")))?;
        let dk = <ml_kem::kem::Kem<$params_ty> as ml_kem::KemCore>::DecapsulationKey::from_bytes(&dk_bytes);
        let c = ml_kem::Ciphertext::<$ct_ty>::try_from($kem_ct).map_err(|e| Error::MlKem(format!("{e:?}")))?;
        let k = dk.decapsulate(&c).map_err(|e| Error::MlKem(format!("{e:?}")))?;
        k.to_vec()
    }};
}

macro_rules! private_key_from_seed {
    ($seed:expr, $ct_ty:ty) => {{
        let (d, z) = $seed.as_bytes().split_at(32);
        let (dk, _) = <$ct_ty>::generate_deterministic(<&B32>::try_from(d)?, <&B32>::try_from(z)?);
        let dk_bytes = dk.as_bytes().to_vec();
        dk_bytes
    }};
}

/// Extract subject key identifier value from a certificate
pub(crate) fn skid_from_cert(cert: &Certificate) -> crate::Result<Vec<u8>> {
    if let Some(exts) = cert.tbs_certificate().extensions() {
        for ext in exts {
            if ext.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER {
                match OctetString::from_der(ext.extn_value.as_bytes()) {
                    Ok(b) => return Ok(b.as_bytes().to_vec()),
                    Err(e) => {
                        error!(
                            "Failed to parse SKID extension: {e:?}. Ignoring error and will use calculated value."
                        );
                    }
                }
            }
        }
    }

    let working_spki = &cert.tbs_certificate().subject_public_key_info();
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
                issuer: cert.tbs_certificate().issuer().clone(),
                serial_number: cert.tbs_certificate().serial_number().clone(),
            },
        )),
    }
}

/// Create a KemRecipientInfoBuilder for a given certificate, KDF algorithm, UKM and wrap algorithm
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
            let pk = Encoded::<
                <ml_kem::kem::Kem<MlKem512Params> as KemCore>::EncapsulationKey,
            >::try_from(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
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
        ID_ALG_ML_KEM_768 => {
            let pk = Encoded::<
                <ml_kem::kem::Kem<MlKem768Params> as KemCore>::EncapsulationKey,
            >::try_from(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
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
        ID_ALG_ML_KEM_1024 => {
            let pk = Encoded::<
                <ml_kem::kem::Kem<MlKem1024Params> as KemCore>::EncapsulationKey,
            >::try_from(
                ee_cert
                    .tbs_certificate()
                    .subject_public_key_info()
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

    let enveloped_data = enveloped_data_builder
        .add_recipient_info(recipient_info_builder)
        .map_err(|_| Error::Unrecognized)?
        .build_with_rng(&mut OsRng.unwrap_err())
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

    let mut rng = OsRng.unwrap_err();
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

pub(crate) fn extract_private_key(
    oid: ObjectIdentifier,
    private_key_bytes: &[u8],
) -> crate::Result<Vec<u8>> {
    match oid {
        ID_ALG_ML_KEM_512 => {
            let key = MlKem512PrivateKey::from_der(private_key_bytes)?;
            match key {
                MlKem512PrivateKey::Seed(seed) => {
                    let (d, z) = seed.as_bytes().split_at(32);
                    let (dk, _) = MlKem512::generate_deterministic(
                        <&B32>::try_from(d)?,
                        <&B32>::try_from(z)?,
                    );
                    Ok(dk.as_bytes().to_vec())
                }
                MlKem512PrivateKey::ExpandedKey(exp_key) => Ok(exp_key.as_bytes().to_vec()),
                MlKem512PrivateKey::Both(both) => {
                    let (d, z) = both.seed.as_bytes().split_at(32);
                    let (dk, _) = MlKem512::generate_deterministic(
                        <&B32>::try_from(d)?,
                        <&B32>::try_from(z)?,
                    );
                    if dk.as_bytes().to_vec() != both.expanded_key.as_bytes().to_vec() {
                        return Err(Error::MlKem(
                            "Inconsistent values in both option".to_string(),
                        ));
                    }
                    Ok(both.expanded_key.as_bytes().to_vec())
                }
            }
        }
        ID_ALG_ML_KEM_768 => {
            let key = MlKem768PrivateKey::from_der(private_key_bytes)?;
            match key {
                MlKem768PrivateKey::Seed(seed) => {
                    let (d, z) = seed.as_bytes().split_at(32);
                    let (dk, _) = MlKem768::generate_deterministic(
                        <&B32>::try_from(d)?,
                        <&B32>::try_from(z)?,
                    );
                    Ok(dk.as_bytes().to_vec())
                }
                MlKem768PrivateKey::ExpandedKey(exp_key) => Ok(exp_key.as_bytes().to_vec()),
                MlKem768PrivateKey::Both(both) => {
                    let (d, z) = both.seed.as_bytes().split_at(32);
                    let (dk, _) = MlKem768::generate_deterministic(
                        <&B32>::try_from(d)?,
                        <&B32>::try_from(z)?,
                    );
                    if dk.as_bytes().to_vec() != both.expanded_key.as_bytes().to_vec() {
                        return Err(Error::MlKem(
                            "Inconsistent values in both option".to_string(),
                        ));
                    }
                    Ok(both.expanded_key.as_bytes().to_vec())
                }
            }
        }
        ID_ALG_ML_KEM_1024 => {
            let key = MlKem1024PrivateKey::from_der(private_key_bytes)?;
            match key {
                MlKem1024PrivateKey::Seed(seed) => {
                    let (d, z) = seed.as_bytes().split_at(32);
                    let (dk, _) = MlKem1024::generate_deterministic(
                        <&B32>::try_from(d)?,
                        <&B32>::try_from(z)?,
                    );
                    Ok(dk.as_bytes().to_vec())
                }
                MlKem1024PrivateKey::ExpandedKey(exp_key) => Ok(exp_key.as_bytes().to_vec()),
                MlKem1024PrivateKey::Both(both) => {
                    let (d, z) = both.seed.as_bytes().split_at(32);
                    let (dk, _) = MlKem1024::generate_deterministic(
                        <&B32>::try_from(d)?,
                        <&B32>::try_from(z)?,
                    );
                    if dk.as_bytes().to_vec() != both.expanded_key.as_bytes().to_vec() {
                        return Err(Error::MlKem(
                            "Inconsistent values in both option".to_string(),
                        ));
                    }
                    Ok(both.expanded_key.as_bytes().to_vec())
                }
            }
        }
        ID_ML_DSA_44 => {
            let key = MlDsa44PrivateKey::from_der(private_key_bytes)?;
            match key {
                MlDsa44PrivateKey::Seed(seed) => {
                    let b32 = B32::try_from(seed.as_bytes())?;
                    Ok(MlDsa44::key_gen_internal(&b32)
                        .signing_key()
                        .encode()
                        .as_bytes()
                        .to_vec())
                }
                MlDsa44PrivateKey::ExpandedKey(exp_key) => Ok(exp_key.as_bytes().to_vec()),
                MlDsa44PrivateKey::Both(both) => {
                    let b32 = B32::try_from(both.seed.as_bytes())?;
                    let ek = MlDsa44::key_gen_internal(&b32)
                        .signing_key()
                        .encode()
                        .as_bytes()
                        .to_vec();
                    if ek.as_bytes().to_vec() != both.expanded_key.as_bytes().to_vec() {
                        return Err(Error::MlKem(
                            "Inconsistent values in both option".to_string(),
                        ));
                    }
                    Ok(both.expanded_key.as_bytes().to_vec())
                }
            }
        }
        ID_ML_DSA_65 => {
            let key = MlDsa65PrivateKey::from_der(private_key_bytes)?;
            match key {
                MlDsa65PrivateKey::Seed(seed) => {
                    let b32 = B32::try_from(seed.as_bytes())?;
                    Ok(MlDsa65::key_gen_internal(&b32)
                        .signing_key()
                        .encode()
                        .as_bytes()
                        .to_vec())
                }
                MlDsa65PrivateKey::ExpandedKey(exp_key) => Ok(exp_key.as_bytes().to_vec()),
                MlDsa65PrivateKey::Both(both) => {
                    let b32 = B32::try_from(both.seed.as_bytes())?;
                    let ek = MlDsa65::key_gen_internal(&b32)
                        .signing_key()
                        .encode()
                        .as_bytes()
                        .to_vec();
                    if ek.as_bytes().to_vec() != both.expanded_key.as_bytes().to_vec() {
                        return Err(Error::MlKem(
                            "Inconsistent values in both option".to_string(),
                        ));
                    }
                    Ok(both.expanded_key.as_bytes().to_vec())
                }
            }
        }
        ID_ML_DSA_87 => {
            let key = MlDsa87PrivateKey::from_der(private_key_bytes)?;
            match key {
                MlDsa87PrivateKey::Seed(seed) => {
                    let b32 = B32::try_from(seed.as_bytes())?;
                    Ok(MlDsa87::key_gen_internal(&b32)
                        .signing_key()
                        .encode()
                        .as_bytes()
                        .to_vec())
                }
                MlDsa87PrivateKey::ExpandedKey(exp_key) => Ok(exp_key.as_bytes().to_vec()),
                MlDsa87PrivateKey::Both(both) => {
                    let b32 = B32::try_from(both.seed.as_bytes())?;
                    let ek = MlDsa87::key_gen_internal(&b32)
                        .signing_key()
                        .encode()
                        .as_bytes()
                        .to_vec();
                    if ek.as_bytes().to_vec() != both.expanded_key.as_bytes().to_vec() {
                        return Err(Error::MlKem(
                            "Inconsistent values in both option".to_string(),
                        ));
                    }
                    Ok(both.expanded_key.as_bytes().to_vec())
                }
            }
        }
        _ => Ok(private_key_bytes.to_vec()),
    }
}

fn get_domain(oid: ObjectIdentifier) -> crate::Result<Vec<u8>> {
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
    } else {
        Err(Error::Unrecognized)
    }
}

pub fn composite_ss(
    pqc_ss: &[u8],
    trad_ss: &[u8],
    trad_ct: &[u8],
    trad_pk: &[u8],
    domain: ObjectIdentifier,
) -> crate::Result<Vec<u8>> {
    // mlkemSS || tradSS || tradCT || tradPK || Domain
    let mut hasher = Sha3_256::default();
    let enc_domain = get_domain(domain)?;
    debug!("pqc_ss: {}", buffer_to_hex(pqc_ss));
    hasher.update(pqc_ss);
    debug!("trad_ss: {}", buffer_to_hex(trad_ss));
    hasher.update(trad_ss);
    debug!("trad_ct: {}", buffer_to_hex(trad_ct));
    hasher.update(trad_ct);
    debug!("trad_pk: {}", buffer_to_hex(trad_pk));
    hasher.update(trad_pk);
    debug!("enc_domain: {}", buffer_to_hex(&enc_domain));
    hasher.update(&enc_domain);
    Ok(hasher.finalize().to_vec())
}

fn parse_composite_key(private_key_bytes: &[u8]) -> crate::Result<(Vec<u8>, Vec<u8>)> {
    // mlkemSeed || tradSK
    let (pqc_seed, trad_sk) = private_key_bytes.split_at(64);
    Ok((pqc_seed.to_vec(), trad_sk.to_vec()))
}

fn ml_kem768_rsa(
    kem_ct: &[u8],
    private_key_bytes: &[u8],
    domain: ObjectIdentifier,
) -> crate::Result<Vec<u8>> {
    let (pqc_ct, trad_ct) = kem_ct.split_at(1088);
    let (pqc_seed, trad_sk) = parse_composite_key(private_key_bytes)?;

    let dk_bytes = private_key_from_seed!(pqc_seed, MlKem768);
    let pqc_ss = decrypt_kem_rust_crypto!(pqc_ct, MlKem768, MlKem768Params, dk_bytes);

    let rsa = RsaKem::new(&trad_sk)?;
    let trad_ss = rsa.decap(trad_ct)?;
    let trad_pk = rsa.to_public_key().to_pkcs1_der().unwrap().to_vec();
    composite_ss(&pqc_ss, &trad_ss, trad_ct, &trad_pk, domain)
}

fn ml_kem1024_rsa(
    kem_ct: &[u8],
    private_key_bytes: &[u8],
    domain: ObjectIdentifier,
) -> crate::Result<Vec<u8>> {
    let (pqc_ct, trad_ct) = kem_ct.split_at(1568);
    let (pqc_seed, trad_sk) = parse_composite_key(private_key_bytes)?;

    let dk_bytes = private_key_from_seed!(pqc_seed, MlKem1024);
    let pqc_ss = decrypt_kem_rust_crypto!(pqc_ct, MlKem1024, MlKem1024Params, dk_bytes);

    let rsa = RsaKem::new(&trad_sk)?;
    let trad_ss = rsa.decap(trad_ct)?;
    let trad_pk = rsa.to_public_key().to_pkcs1_der().unwrap().to_vec();
    composite_ss(&pqc_ss, &trad_ss, trad_ct, &trad_pk, domain)
}

fn ml_kem768_ecdh<C>(
    kem_ct: &[u8],
    private_key_bytes: &[u8],
    domain: ObjectIdentifier,
) -> crate::Result<Vec<u8>>
where
    C: AssociatedOid + elliptic_curve::Curve + CurveArithmetic + ValidatePublicKey,
    FieldBytesSize<C>: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
{
    let (pqc_ct, trad_ct) = kem_ct.split_at(1088);
    let (pqc_seed, trad_sk) = parse_composite_key(private_key_bytes)?;

    let dk_bytes = private_key_from_seed!(pqc_seed, MlKem768);
    let pqc_ss = decrypt_kem_rust_crypto!(pqc_ct, MlKem768, MlKem768Params, dk_bytes);

    let oak = EcPrivateKey::from_der(&trad_sk)?;

    let ecdh = EcdhKem::<C>::new(oak.private_key.as_bytes())?;
    let trad_ss = ecdh.decap(trad_ct)?;
    let trad_pk = ecdh
        .to_public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    composite_ss(&pqc_ss, &trad_ss, trad_ct, &trad_pk, domain)
}

fn ml_kem1024_ecdh<C>(
    kem_ct: &[u8],
    private_key_bytes: &[u8],
    domain: ObjectIdentifier,
) -> crate::Result<Vec<u8>>
where
    C: AssociatedOid + elliptic_curve::Curve + CurveArithmetic + ValidatePublicKey,
    FieldBytesSize<C>: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
    <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
{
    let (pqc_ct, trad_ct) = kem_ct.split_at(1568);
    let (pqc_seed, trad_sk) = parse_composite_key(private_key_bytes)?;

    let dk_bytes = private_key_from_seed!(pqc_seed, MlKem1024);
    let pqc_ss = decrypt_kem_rust_crypto!(pqc_ct, MlKem1024, MlKem1024Params, dk_bytes);

    let oak = EcPrivateKey::from_der(&trad_sk)?;

    let ecdh = EcdhKem::<C>::new(oak.private_key.as_bytes())?;
    let trad_ss = ecdh.decap(trad_ct)?;
    let trad_pk = ecdh
        .to_public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    composite_ss(&pqc_ss, &trad_ss, trad_ct, &trad_pk, domain)
}
/// Process KemRecipientInfo using the provided private key
pub fn process_kemri(ori: &OtherRecipientInfo, private_key_bytes: &[u8]) -> crate::Result<Vec<u8>> {
    let ori_value = ori.ori_value.to_der()?;
    let kemri = cms::kemri::KemRecipientInfo::from_der(&ori_value)?;
    let kem_ct = kemri.kem_ct.as_bytes();
    let ss = match kemri.kem.oid {
        ID_ALG_ML_KEM_512 => {
            let ee_sk = extract_private_key(ID_ALG_ML_KEM_512, private_key_bytes)?;
            decrypt_kem_rust_crypto!(kem_ct, MlKem512, MlKem512Params, ee_sk)
        }
        ID_ALG_ML_KEM_768 => {
            let ee_sk = extract_private_key(ID_ALG_ML_KEM_768, private_key_bytes)?;
            decrypt_kem_rust_crypto!(kem_ct, MlKem768, MlKem768Params, ee_sk)
        }
        ID_ALG_ML_KEM_1024 => {
            let ee_sk = extract_private_key(ID_ALG_ML_KEM_1024, private_key_bytes)?;
            decrypt_kem_rust_crypto!(kem_ct, MlKem1024, MlKem1024Params, ee_sk)
        }
        ID_MLKEM768_RSA2048_SHA3_256 => {
            ml_kem768_rsa(kem_ct, private_key_bytes, ID_MLKEM768_RSA2048_SHA3_256)?
        }
        ID_MLKEM768_RSA3072_SHA3_256 => {
            ml_kem768_rsa(kem_ct, private_key_bytes, ID_MLKEM768_RSA3072_SHA3_256)?
        }
        ID_MLKEM768_RSA4096_SHA3_256 => {
            ml_kem768_rsa(kem_ct, private_key_bytes, ID_MLKEM768_RSA4096_SHA3_256)?
        }
        ID_MLKEM1024_RSA3072_SHA3_256 => {
            ml_kem1024_rsa(kem_ct, private_key_bytes, ID_MLKEM1024_RSA3072_SHA3_256)?
        }
        ID_MLKEM768_X25519_SHA3_256 => {
            todo!("Decrypt with EC variants")
        }
        ID_MLKEM768_ECDH_P256_SHA3_256 => ml_kem768_ecdh::<p256::NistP256>(
            kem_ct,
            private_key_bytes,
            ID_MLKEM768_ECDH_P256_SHA3_256,
        )?,
        ID_MLKEM768_ECDH_P384_SHA3_256 => ml_kem768_ecdh::<p384::NistP384>(
            kem_ct,
            private_key_bytes,
            ID_MLKEM768_ECDH_P384_SHA3_256,
        )?,
        ID_MLKEM1024_ECDH_P384_SHA3_256 => ml_kem1024_ecdh::<p384::NistP384>(
            kem_ct,
            private_key_bytes,
            ID_MLKEM1024_ECDH_P384_SHA3_256,
        )?,
        ID_MLKEM1024_X448_SHA3_256 => {
            todo!("Decrypt with EC variants")
        }
        ID_MLKEM1024_ECDH_P521_SHA3_256 => ml_kem1024_ecdh::<p521::NistP521>(
            kem_ct,
            private_key_bytes,
            ID_MLKEM1024_ECDH_P521_SHA3_256,
        )?,
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
            let kek: AesKw<Aes128> = AesKw::<Aes128>::new_from_slice(okm.as_slice())
                .map_err(|_e| Error::Unrecognized)?;
            if let Err(e) = kek.unwrap_key(kemri.encrypted_key.as_bytes(), &mut wrapped_key) {
                error!("Unwrap failed: {e:?}");
            }
            wrapped_key.to_vec()
        }
        ID_AES_192_WRAP => {
            let kek: AesKw<Aes192> = AesKw::<Aes192>::new_from_slice(okm.as_slice())
                .map_err(|_e| Error::Unrecognized)?;
            if let Err(e) = kek.unwrap_key(kemri.encrypted_key.as_bytes(), &mut wrapped_key) {
                error!("Unwrap failed: {e:?}");
            }
            wrapped_key.to_vec()
        }
        ID_AES_256_WRAP => {
            let kek: AesKw<Aes256> = AesKw::<Aes256>::new_from_slice(okm.as_slice())
                .map_err(|_e| Error::Unrecognized)?;
            if let Err(e) = kek.unwrap_key(kemri.encrypted_key.as_bytes(), &mut wrapped_key) {
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
    let oak = if 0x30 == ee_oak[0] {
        OneAsymmetricKey::from_der(ee_oak)?
    } else {
        OneAsymmetricKey::from_pem(ee_oak)?
    };
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
                return decrypt_block_mode!(&ct, Aes128, &key, iv)
                    .map_err(|_e| Error::Unrecognized);
            }
            ID_AES_192_CBC => {
                return decrypt_block_mode!(&ct, Aes192, &key, iv)
                    .map_err(|_e| Error::Unrecognized);
            }
            ID_AES_256_CBC => {
                return decrypt_block_mode!(&ct, Aes256, &key, iv)
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
    // todo: support new structure
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
        ID_ALG_ML_KEM_512 => "mlkem512".to_string(),
        ID_ALG_ML_KEM_768 => "mlkem768".to_string(),
        ID_ALG_ML_KEM_1024 => "mlkem1024".to_string(),
        ID_MLKEM768_RSA2048_SHA3_256 => "id-MLKEM768-RSA2048-SHA3-256".to_string(),
        ID_MLKEM768_RSA3072_SHA3_256 => "id-MLKEM768-RSA3072-SHA3-256".to_string(),
        ID_MLKEM768_RSA4096_SHA3_256 => "id-MLKEM768-RSA4096-SHA3-256".to_string(),
        ID_MLKEM1024_RSA3072_SHA3_256 => "id-MLKEM1024-RSA3072-SHA3-256".to_string(),
        ID_MLKEM768_X25519_SHA3_256 => "id-MLKEM768-x25519-SHA3-256".to_string(),
        ID_MLKEM768_ECDH_P256_SHA3_256 => "id-MLKEM768-ECDH-P256-SHA3-256".to_string(),
        ID_MLKEM768_ECDH_P384_SHA3_256 => "id-MLKEM768-ECDH-P384-SHA3-256".to_string(),
        ID_MLKEM1024_ECDH_P384_SHA3_256 => "id-MLKEM1024-ECDH-P384-SHA3-256".to_string(),
        ID_MLKEM1024_X448_SHA3_256 => "id-MLKEM768-RSA2048-SHA3-256".to_string(),
        ID_MLKEM1024_ECDH_P521_SHA3_256 => "id-MLKEM1024-ECDH-P521-SHA3-256".to_string(),
        ID_ML_DSA_44 => "ml-dsa-44".to_string(),
        ID_ML_DSA_65 => "ml-dsa-65".to_string(),
        ID_ML_DSA_87 => "ml-dsa-87".to_string(),
        ID_SLH_DSA_SHA_2_128_S => "slh-dsa-sha2-128s".to_string(),
        ID_SLH_DSA_SHA_2_128_F => "slh-dsa-sha2-128f".to_string(),
        ID_SLH_DSA_SHA_2_192_S => "slh-dsa-sha2-192s".to_string(),
        ID_SLH_DSA_SHA_2_192_F => "slh-dsa-sha2-192f".to_string(),
        ID_SLH_DSA_SHA_2_256_S => "slh-dsa-sha2-256s".to_string(),
        ID_SLH_DSA_SHA_2_256_F => "slh-dsa-sha2-256f".to_string(),
        ID_SLH_DSA_SHAKE_128_S => "slh-dsa-shake-128s".to_string(),
        ID_SLH_DSA_SHAKE_128_F => "slh-dsa-shake-128f".to_string(),
        ID_SLH_DSA_SHAKE_192_S => "slh-dsa-shake-192s".to_string(),
        ID_SLH_DSA_SHAKE_192_F => "slh-dsa-shake-192f".to_string(),
        ID_SLH_DSA_SHAKE_256_S => "slh-dsa-shake-256s".to_string(),
        ID_SLH_DSA_SHAKE_256_F => "slh-dsa-shake-256f".to_string(),
        ID_MLDSA44_RSA2048_PSS_SHA256 => "ml-dsa-44-rsa2048-pss".to_string(),
        ID_MLDSA44_RSA2048_PKCS15_SHA256 => "ml-dsa-44-rsa2048-pkcs15".to_string(),
        ID_MLDSA44_ED25519_SHA512 => "ml-dsa-44-ed25519".to_string(),
        ID_MLDSA44_ECDSA_P256_SHA256 => "ml-dsa-44-ecdsa-p256".to_string(),
        ID_MLDSA65_RSA3072_PSS_SHA512 => "ml-dsa-65-rsa3072-pss".to_string(),
        ID_MLDSA65_RSA4096_PSS_SHA512 => "ml-dsa-65-rsa4096-pss".to_string(),
        ID_MLDSA65_RSA4096_PKCS15_SHA512 => "ml-dsa-65-rsa4096-pkcs15".to_string(),
        ID_MLDSA65_ECDSA_P256_SHA512 => "ml-dsa-65-ecdsa-p256".to_string(),
        ID_MLDSA65_ECDSA_P384_SHA512 => "ml-dsa-65-ecdsa-p384".to_string(),
        ID_MLDSA65_ED25519_SHA512 => "ml-dsa-65-ed25519".to_string(),
        ID_MLDSA87_ECDSA_P384_SHA512 => "ml-dsa-87-ecdsa-p384".to_string(),
        ID_MLDSA87_ED448_SHAKE256 => "ml-dsa-87-ed448".to_string(),
        ID_MLDSA87_RSA3072_PSS_SHA512 => "ml-dsa-87-rsa3072-pss".to_string(),
        ID_MLDSA87_RSA4096_PSS_SHA512 => "ml-dsa-87-rsa4096-pss".to_string(),
        ID_MLDSA87_ECDSA_P521_SHA512 => "ml-dsa-87-ecdsa-p521".to_string(),
        _ => "Unrecognized".to_string(),
    }
}

#[cfg(test)]
fn get_kem_oid_from_file_name(file_name: &str) -> Option<String> {
    if file_name.contains("1.3.6.1.5.5.7.6.55") {
        Some("1.3.6.1.5.5.7.6.55".to_string())
    } else if file_name.contains("1.3.6.1.5.5.7.6.56") {
        Some("1.3.6.1.5.5.7.6.56".to_string())
    } else if file_name.contains("1.3.6.1.5.5.7.6.57") {
        Some("1.3.6.1.5.5.7.6.57".to_string())
    } else if file_name.contains("1.3.6.1.5.5.7.6.58") {
        Some("1.3.6.1.5.5.7.6.58".to_string())
    } else if file_name.contains("1.3.6.1.5.5.7.6.59") {
        Some("1.3.6.1.5.5.7.6.59".to_string())
    } else if file_name.contains("1.3.6.1.5.5.7.6.60") {
        Some("1.3.6.1.5.5.7.6.60".to_string())
    } else if file_name.contains("1.3.6.1.5.5.7.6.61") {
        Some("1.3.6.1.5.5.7.6.61".to_string())
    } else if file_name.contains("1.3.6.1.5.5.7.6.62") {
        Some("1.3.6.1.5.5.7.6.62".to_string())
    } else if file_name.contains("1.3.6.1.5.5.7.6.63") {
        Some("1.3.6.1.5.5.7.6.63".to_string())
    } else if file_name.contains("1.3.6.1.5.5.7.6.64") {
        Some("1.3.6.1.5.5.7.6.64".to_string())
    } else if file_name.contains("1.3.6.1.5.5.7.6.65") {
        Some("1.3.6.1.5.5.7.6.65".to_string())
    } else if file_name.contains("1.3.6.1.5.5.7.6.66") {
        Some("1.3.6.1.5.5.7.6.66".to_string())
    } else {
        None
    }
}

// key_type_part is _expandedkey for expanded, _seed for seed only, _both for both
#[cfg(test)]
fn test_decrypt(key_folder: &str, artifact_folder: &str, key_type_part: &str) -> Result<(), Error> {
    use crate::KemAlgorithms;
    use std::collections::BTreeMap;

    let expected_plaintext = get_file_as_byte_vec(Path::new(&format!(
        "{}/expected_plaintext.txt",
        artifact_folder
    )))
    .unwrap();

    // read in three private keys (not using include bytes so that when OID changes, files will be read)
    let mut key_map = BTreeMap::new();
    if !key_type_part.is_empty() {
        key_map.insert(
            ID_ALG_ML_KEM_512.to_string(),
            get_file_as_byte_vec(Path::new(&format!(
                "{}/{}{}_priv.der",
                key_folder,
                KemAlgorithms::MlKem512.filename(),
                key_type_part
            )))?,
        );
        key_map.insert(
            ID_ALG_ML_KEM_768.to_string(),
            get_file_as_byte_vec(Path::new(&format!(
                "{}/{}{}_priv.der",
                key_folder,
                KemAlgorithms::MlKem768.filename(),
                key_type_part
            )))?,
        );
        key_map.insert(
            ID_ALG_ML_KEM_1024.to_string(),
            get_file_as_byte_vec(Path::new(&format!(
                "{}/{}{}_priv.der",
                key_folder,
                KemAlgorithms::MlKem1024.filename(),
                key_type_part
            )))?,
        );
    } else {
        key_map.insert(
            ID_MLKEM768_RSA2048_SHA3_256.to_string(),
            get_file_as_byte_vec(Path::new(&format!(
                "{}/{}{}_priv.der",
                key_folder,
                KemAlgorithms::MlKem768Rsa2048Sha3_256.filename(),
                key_type_part
            )))?,
        );
        key_map.insert(
            ID_MLKEM768_RSA3072_SHA3_256.to_string(),
            get_file_as_byte_vec(Path::new(&format!(
                "{}/{}{}_priv.der",
                key_folder,
                KemAlgorithms::MlKem768Rsa3072Sha3_256.filename(),
                key_type_part
            )))?,
        );
        key_map.insert(
            ID_MLKEM768_RSA4096_SHA3_256.to_string(),
            get_file_as_byte_vec(Path::new(&format!(
                "{}/{}{}_priv.der",
                key_folder,
                KemAlgorithms::MlKem768Rsa4096Sha3_256.filename(),
                key_type_part
            )))?,
        );
        key_map.insert(
            ID_MLKEM768_ECDH_P256_SHA3_256.to_string(),
            get_file_as_byte_vec(Path::new(&format!(
                "{}/{}{}_priv.der",
                key_folder,
                KemAlgorithms::MlKem768EcdhP256Sha3_256.filename(),
                key_type_part
            )))?,
        );
        key_map.insert(
            ID_MLKEM768_ECDH_P384_SHA3_256.to_string(),
            get_file_as_byte_vec(Path::new(&format!(
                "{}/{}{}_priv.der",
                key_folder,
                KemAlgorithms::MlKem768EcdhP384Sha3_256.filename(),
                key_type_part
            )))?,
        );
        key_map.insert(
            ID_MLKEM1024_RSA3072_SHA3_256.to_string(),
            get_file_as_byte_vec(Path::new(&format!(
                "{}/{}{}_priv.der",
                key_folder,
                KemAlgorithms::MlKem1024Rsa3072Sha3_256.filename(),
                key_type_part
            )))?,
        );
        key_map.insert(
            ID_MLKEM1024_ECDH_P384_SHA3_256.to_string(),
            get_file_as_byte_vec(Path::new(&format!(
                "{}/{}{}_priv.der",
                key_folder,
                KemAlgorithms::MlKem1024EcdhP384Sha3_256.filename(),
                key_type_part
            )))?,
        );
        key_map.insert(
            ID_MLKEM1024_ECDH_P521_SHA3_256.to_string(),
            get_file_as_byte_vec(Path::new(&format!(
                "{}/{}{}_priv.der",
                key_folder,
                KemAlgorithms::MlKem1024EcdhP521Sha3_256.filename(),
                key_type_part
            )))?,
        );


    }

    let paths = std::fs::read_dir(artifact_folder).unwrap();
    let mut success = 0;
    for path in paths.flatten() {
        if let Some(file_name) = path.file_name().to_str() {
            if file_name.contains("_priv")
                || file_name.contains("_ee")
                || file_name.contains("_ss.bin")
                || file_name.contains("_ciphertext.bin")
                || file_name.contains(".txt")
            {
                continue;
            } else if let Some(oid) = get_kem_oid_from_file_name(file_name) {
                if let Some(key) = key_map.get(&oid.to_string()) {
                    if let Ok(ci) = get_file_as_byte_vec(&path.path()) {
                        println!("Processing {:?}", path.path());
                        match process_content_info(&ci, key) {
                            Ok(pt) => {
                                assert_eq!(pt, expected_plaintext);
                                success += 1;
                            }
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
    assert!(success > 0);
    Ok(())
}

#[test]
fn decrypt_cryptonext_composite() {
    assert!(
        test_decrypt(
            "tests/artifacts/cryptonext",
            "tests/artifacts/cryptonext",
            ""
        )
            .is_ok()
    );
}

#[test]
fn decrypt_kemri_toy_composite() {
    assert!(
        test_decrypt(
            "tests/artifacts/kemri_toy",
            "tests/artifacts/kemri_toy",
            ""
        )
            .is_ok()
    );
}

#[test]
fn decrypt_wrong_keys() {
    assert!(test_decrypt("tests/artifacts/cryptonext", "tests/artifacts/kemri_toy", "").is_err());
}

#[cfg(test)]
fn test_encrypt(key_folder: &str) -> Result<(), Error> {
    use crate::args::{AeadAlgorithms, EncAlgorithms, KdfAlgorithms, KemAlgorithms};
    use std::collections::BTreeMap;

    // read in three private keys (not using include bytes so that when OID changes, files will be read)
    let mut key_map = BTreeMap::new();
    key_map.insert(
        ID_ALG_ML_KEM_512.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_expandedkey_priv.der",
            key_folder,
            KemAlgorithms::MlKem512.filename()
        )))?,
    );
    key_map.insert(
        ID_ALG_ML_KEM_768.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_expandedkey_priv.der",
            key_folder,
            KemAlgorithms::MlKem768.filename()
        )))?,
    );
    key_map.insert(
        ID_ALG_ML_KEM_1024.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_expandedkey_priv.der",
            key_folder,
            KemAlgorithms::MlKem1024.filename()
        )))?,
    );

    let mut cert_map = BTreeMap::new();
    cert_map.insert(
        ID_ALG_ML_KEM_512.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_ee.der",
            key_folder,
            KemAlgorithms::MlKem512.filename()
        )))?,
    );
    cert_map.insert(
        ID_ALG_ML_KEM_768.to_string(),
        get_file_as_byte_vec(Path::new(&format!(
            "{}/{}_ee.der",
            key_folder,
            KemAlgorithms::MlKem768.filename()
        )))?,
    );
    cert_map.insert(
        ID_ALG_ML_KEM_1024.to_string(),
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
    use cms::enveloped_data::RecipientInfos;
    use cms::kemri::KemRecipientInfo;
    let expected_plaintext =
        include_bytes!("../../tests/artifacts/kemri_toy/expected_plaintext.txt");
    let ml_kem_512_key = include_bytes!(
        "../../tests/artifacts/kemri_toy/mlkem512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der"
    );
    let auth_data_bytes = include_bytes!(
        "../../tests/artifacts/kemri_toy/mlkem512-2.16.840.1.101.3.4.4.1_kemri_auth_id-alg-hkdf-with-sha256.der"
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

// #[test]
// fn composite_test() {
//     let _ = do_stuff();
// }
// #[test]
// fn do_stuff() -> crate::Result<()> {
//     use hex_literal::hex;
//     let kem_ct = hex!(
//         "f64c871884a7510b17918f2303808821597fbfb6bebcfe309a7ed77600c968d233aaf7257d22da28dd956182a54ac63dd1a1c9bb16f0aa238389ce3d0f578b6b47e3c095a4472c7c438a2795dadcdda7e09c4bfd0065ba8164209ca15988e46985343e6110c777c586f965fb3d5f1d184541c1b1dba1011b0bf2441a59d44347dbdbdc85b2fe418b09f7a7775072b6c8ca6590fbbb29d84a2e64d951a410cdc2856fda23e6ef5cabe2acf913259bedf3c0d3f309d06c6f45ba6bbbc03161374e72f3cd51c0f8ac4044690ff86b750cf8a9a6e0a3f75bb5ecadeda28162b8a7e498fbf2265ea65dbf52a1e95e689db287dcfad67f07690a3e75fa17c3f4aa692c47e5dc6102931fc7ebc80162aaf812edfb1a0360093e5674bd1c34e4e4c6588b2300a5ab630bf2b8e1d00345eb2b0156db309abf9f2402bb9a60268737ac3263679fabefdd0d1e564e2e01e8c33c280b59c4d186cc44fff17f10acb3115de1c27820f699f07546590c8645a5b716fbe7c3b30201a8effe59811dba30b5bb6337c0061e71125d9b478e5a181984f3b83661aca1779a13eae1a2f497098826e07c6358e4d29273d6fcbdf82df78c81b728d8937ed92ca620671c4d2a704e56ee1de71c32fee0024a01eb45f4ad39f7fc74c6244a0e9cfb285378b5fe33b6ca5a8da70c73a1f539b0f994c814f4a6433fa0aa204537db5e14b55d570335ec66ef2e237ea99f000e67aef8a072b814f3632d59bcc6aedd77914c440200e3245479950248e6f908cd61465427af0086729fb7c0ee16c23fc7f70420c7dbb855c1ee7e2753956b835d14dc4f42e54a218fc81a9652125984a9f0a862c854700a20082e30802e80a1f2ebf44a931ac0fce9e64b92d81faec9d87085e52737c4c066066d9f0a48d65c3706cfe9e240d1b9af9585009f32656a5cbf7c25b3bb39ea4f461c0adbc8f278d1b78c5760743e875c3b5c227ea0adf48274f7d5422eb638ff72a7ea82c9eab316b3607e2a5aa75879475c267b5adba7ce27a78d1820ce7c8a66f6341b81fd2a6037347998ac46ec3aed54d1c7c9f25180e7428ed5a0197ed60f7f3c87d3a44621bbaedb1024680f3aa9bd8225abaff8f0ada6246fde86cae9ac80b4317e4643d1aa07844916ba93e6500cd290a5b50d0df7e9f5a2f7fac1190899ba7334869c1c96908c82f284742ef99911c1cd5caf6b1bdb91a561f93cbaab4390590d3b2ae1af2a9419fc24ba760e26dfbd17861777e8123f26202900cd9544dd9afd5c917ca1ee618bec47c079a34f8b990bf461717039a3c09d6bfe14a15cf804e300352410a255e76da99d033280115ad8745b3492ec73572dd1d2365b8c8c296123501d1cb50e1bf79f5e91bf36beaa0d57664978a122f8224d1c916c86b6309103c5574f85bbfedc45e41aca48e1d852b796b340cc0447bfc346259d6bbd370cacf1965c11176748a161033b3bf88a7d28358695165852fc06d3009f5484ee29f12cf6d21fd4676713c09bfab41c7101ecd5b248fc3d1f7cbd61586f5a04e5580e9109c71d4881665f307264175c6395afb64c3d304846dacd1b936850234a295b2485d3ec27f6686c20e12f26034ad6decc9e1461b4c9568c2236016cb3022e182fc7bd536af5d826140fb4bc3d1453b1e7b94a75c9a27710953f35480b3ddc640fd59175405e2deaa5c632e2553af2233331f8694b58f3eeea0d578f8e2ad43b83aacbbbc11efe9f2d97fb560d6cab8f2e4425f46e9b39ceb121de93cf4257d376e021eabaf5eb506a02f97dffd4cb92c5744f2935e33bb9e209048777265538271fa8fcd3d5e07179f64a5acea145d1afe615cd6cef4f1b5746b0a5c872dd48cb6ffe4055fa0d53aa70405dced78aaf65d660e721eedbe8c32d3840"
//     );
//
//     let private_key_bytes = hex!(
//         "f0040b6b293a1e5da194409a5e37f1c2f6781f634467e1762a801a7f0a50a9782d336809d36adb7700340bc442dcab2bd2fe4e71bba4e250c9f687f165a05df4308204a40201000282010100a5421e94465e8b1d3c09e93685cb27ddada7680e54c1d5075a8c0777ef1103a0cec47caace8f6f297ca51e7321b719fbb6149e8e78e259dd0235498b84dc9f1332086fcca913fb099d58e33c100d2af142f02780b28721eb5d5720e1b7408f7933613a4dbceb65942ac93fba04970d2ef73a798c78d36d938e223edc61a6ab5db23a2bc9596e72a2358677d49d4b5a93bb021745225f4efcf37aec29d3dee9a6897584eec2db70e27dfbe7130eb895166d6819fc31eae201533d20e9f4fbfcf2e95cf02020090234214c456e35e24f162d9b2c5f1ca2bc2d3d2caa5bca5a739243696c5d413603167584cda7bd12283e64948d1936460c68ab08bd3b9b59674d0203010001028201000b3612e6ddd420945ccb003163a7d66e2ceaf7b901be4bc5d495d014c0cb70a0801faba4a044a8f6baa140c8397a652c82c51fc3be794786fd79b78fa507c1bf42210b653340af8bb35d6107f7bfa9835a71d5b6835cebb063365733cd7b2e45292dd1a28dc3247bcf294705d990de1a06379069db9602ab44a24e8d91ea187efd127bb59d6b9ab84b0c214ea9678939000111d7549ac02787fed777ecc03fb63590447a352fc4272346d3fbda21cc18652d11da6ad21f9bb8560a01cbce07c0419864c603d322c2b2a1491be4a5f74f66e39936a24dd3a4649efe4c8796b31e6483547f728cf899223ace4a4b06476ef7f3820a4d08f513d82aa2ed5a2508eb02818100d10f0810743b06514a6f9867b51be19a4c3492e5fc03e8cf40df8f68c94784527cd8a7d42cb94237767ebb9e7a026b1354613bd604869a740c04ac86e9ce6270708d60c559417adf3ae385e065e28ef23585f40f8351654bff706e605ed619b14b9651f811e10a0b57d51ded72ad5fd61f04cadbac5232e670b5cf9844e5b32f02818100ca5d61a9cd5acc8c77e403a682bea29e47d26c9f3bf3e2d866ff22e6941363daaf93249098ec69af0c214ff00e6cc11cdf95eccecdb9e2042e8fd3ccf0225f58e68b20735514c629f80aa79740c24dcbdebd6b25e0baee0c83547f8664a7f07ab77df5af5f5ea985597703ea2b7f99c00103e44e223be1f3898dbb44fc841e4302818100a6b4b9d58519dc3bce8396a07c47336b7b012172cbb7c25a227d233a87e6c399937ca0b80cc1de0fa42a032aa8586d5208a350b7a4fc4105f0df79444c050b72660e16f0c7eff32f37225f8b453398918424c12deda5668567b81c0c3513bd8127a942cbf255e5508e459f8bcd3a7b859f4e8f050530b6ee134aa7b3e09cda790281810090bf1ca55562d61ebf7ed3f19d61787618cf75acac387590ee931e46a9b1f8e1aa666868194a3909e1764e745a0d06507dc9027aa602889d0f25078d76524fbb0a2487d09711e5f08d2029e1f18b4a14423d60cfd6203f37aa149da6e6868d6769aa6a3ac7cfb117d5f76050764eae0dfd6be838cf19e033cfb71635711d9b7b0281801fd270e8006d8b6e7ef786be8b3ecaf7454ea397df3cfb8a7a571413cd0a3e9930f0c27ebaa30c007087818b916b7b4f85c776a1e2acbec82f30d07985a409a15fa520e2aa0caa96704216a8f4bdb9a3176c164ae944f1635998b8ef75aeb51f8ed34588bfbc94c8f12f01bd4e9882792d66682c99cffdbebdec8bf46252d1be"
//     );
//
//     let ss = ml_kem768_rsa::<MlKem1024, MlKem1024Params, Hmac<Sha256>>(
//         &kem_ct,
//         &private_key_bytes,
//         ID_MLKEM768_RSA2048_SHA3_256,
//     )?;
//     println!("SS Act: {}", buffer_to_hex(&ss));
//     let ss_exp = hex!("7c5958cf2eaefd34a2006f4f7004eb0a059d867c3e945126ba93a4e20a5def1a");
//     println!("SS Exp: {}", buffer_to_hex(&ss_exp));
//     Ok(())
// }
