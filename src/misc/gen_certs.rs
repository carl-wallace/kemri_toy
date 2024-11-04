//! Utilities to generate test certificates features ML_KEM_XXX_IPD keys signed with ML_DSA_44_IPD

use crate::asn1::composite::{ML_KEM_512_RSA2048, ML_KEM_512_RSA3072};
use const_oid::db::rfc5912::RSA_ENCRYPTION;
use std::{
    fs::File,
    io::Write,
    path::Path,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use log::error;
use rand_core::{OsRng, RngCore};

use pqcrypto_mldsa::mldsa44;
use pqcrypto_mlkem::{mlkem1024, mlkem512, mlkem768};
use pqcrypto_traits::{
    kem::{PublicKey as KemPublicKey, SecretKey},
    sign::PublicKey,
};

use crate::{
    args::{
        KemAlgorithms,
        KemAlgorithms::{MlKem1024, MlKem512, MlKem512Rsa2048, MlKem512Rsa3072, MlKem768},
    },
    misc::signer::{Mldsa44KeyPair, Mldsa44PublicKey},
    Error, ML_DSA_44, ML_KEM_1024, ML_KEM_512, ML_KEM_768,
};
use der::{
    asn1::{BitString, UtcTime},
    Encode,
};
use pqckeys::oak::{OneAsymmetricKey, PrivateKey, Version};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::EncodePrivateKey;
use spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::{
    builder::{
        Builder, CertificateBuilder,
    },
    name::Name,
    serial_number::SerialNumber,
    time::{Time, Validity},
    Certificate,
};
use x509_cert::builder::profile::cabf::Root;
use crate::asn1::composite::{CompositeKemPublicKey, RsaCompositeKemPublicKey};
use crate::misc::builder_profiles::KemCert;

/// Buffer to hex conversion for logging
pub fn buffer_to_hex(buffer: &[u8]) -> String {
    std::str::from_utf8(&subtle_encoding::hex::encode_upper(buffer))
        .unwrap_or_default()
        .to_string()
}

/// Get Validity with current time as not before and not after set to current time plus the provided number or years
fn get_validity(years: i8) -> crate::Result<Validity> {
    let years_duration = Duration::from_secs(365 * 24 * 60 * 60 * years as u64);
    let years_time = match SystemTime::now().checked_add(years_duration) {
        Some(yt) => yt,
        None => return Err(Error::Unrecognized),
    };

    Ok(Validity {
        not_before: Time::UtcTime(UtcTime::from_unix_duration(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(),
        )?),
        not_after: Time::UtcTime(UtcTime::from_unix_duration(
            years_time.duration_since(UNIX_EPOCH).unwrap_or_default(),
        )?),
    })
}

/// Return a random SerialNumber value
fn get_random_serial() -> crate::Result<SerialNumber> {
    let mut serial = [0u8; 20];
    OsRng.fill_bytes(&mut serial);
    serial[0] = 0x01;
    Ok(SerialNumber::new(&serial)?)
}

/// Generate a new self-signed trust anchor certificate containing an ML_DSA_44_IPD key
pub fn generate_ta() -> crate::Result<(Mldsa44KeyPair, Certificate)> {
    let (ca_pk, ca_sk) = mldsa44::keypair();
    let signer = Mldsa44KeyPair {
        public_key: Mldsa44PublicKey(ca_pk),
        secret_key: ca_sk,
    };
    let ca_pk_bytes = ca_pk.as_bytes().to_vec();

    let spki_algorithm = AlgorithmIdentifierOwned {
        oid: ML_DSA_44,
        parameters: None, // Params absent for Dilithium keys per draft-ietf-lamps-dilithium-certificates-02 section 7
    };
    let ee_spki = SubjectPublicKeyInfoOwned {
        algorithm: spki_algorithm,
        subject_public_key: BitString::from_bytes(&ca_pk_bytes)?,
    };

    let dn_str = "cn=ML DSA 44 TA,o=Test,c=US".to_string();
    let dn = Name::from_str(&dn_str)?;

    // todo - make a profile a la old Leaf
    let profile = Root::new(false, dn).unwrap();

    let builder = CertificateBuilder::new(
        profile,
        get_random_serial()?,
        get_validity(10)?,
        //dn.clone(),
        ee_spki,
        //&signer,
    )?;

    let ca_cert = builder.build(&signer)?;

    Ok((signer, ca_cert))
}

/// Macro to generate a fresh KEM keypair and an end entity certificate containing a KEM key signed using ML_DSA_44_IPD
macro_rules! generate_cert {
    ($signer:ident, $cert:ident, $pk:ty, $sk:ty, $keypair:expr, $alg:ident) => {{
        let (ee_pk, ee_sk) = $keypair();
        let cert = generate_ml_kem_cert(&$signer, &$cert, ee_pk, $alg)?;
        Ok((ee_pk, ee_sk, cert))
    }};
}

pub fn generate_composite(
    signer: &Mldsa44KeyPair,
    cert: &Certificate,
    ee_pk: &CompositeKemPublicKey,
    alg: KemAlgorithms,
) -> crate::Result<Certificate> {
    let ee_pk_bytes = match ee_pk {
        CompositeKemPublicKey::Rsa(rsa) => rsa.to_der()?.to_vec(),
        _ => {
            error!("Composite certificate generation failed because public key type was not recognized");
            return Err(Error::Unrecognized);
        }
    };

    let oid = match alg {
        MlKem512Rsa2048 => ML_KEM_512_RSA2048,
        MlKem512Rsa3072 => ML_KEM_512_RSA3072,
        _ => {
            error!("Composite certificate generation failed because {alg} is not a recognized composite KEM algorithm");
            return Err(Error::Unrecognized);
        }
    };

    let spki_algorithm = AlgorithmIdentifierOwned {
        oid,
        parameters: None, // Params absent for Kyber keys per draft-ietf-lamps-kyber-certificates-02 section 4
    };
    let ca_spki = SubjectPublicKeyInfoOwned {
        algorithm: spki_algorithm,
        subject_public_key: BitString::from_bytes(&ee_pk_bytes)?,
    };
    let dn_str = format!("cn={alg} EE,o=Test,c=US");
    let dn = Name::from_str(&dn_str)?;

    let profile = KemCert {
        issuer: cert.tbs_certificate.subject.clone(),
        subject: dn,
    };

    let builder = CertificateBuilder::new(
        profile,
        get_random_serial()?,
        get_validity(5)?,
        //dn.clone(),
        ca_spki,
        //signer,
    )?;

    Ok(builder.build(signer)?)
}

/// Generate an end entity certificate containing a KEM key signed using ML_DSA_44_IPD
pub fn generate_ml_kem_cert<PK: KemPublicKey>(
    signer: &Mldsa44KeyPair,
    cert: &Certificate,
    ee_pk: PK,
    alg: KemAlgorithms,
) -> crate::Result<Certificate> {
    let ee_pk_bytes = ee_pk.as_bytes().to_vec();

    let oid = match alg {
        MlKem512 => ML_KEM_512,
        MlKem768 => ML_KEM_768,
        MlKem1024 => ML_KEM_1024,
        MlKem512Rsa2048 => ML_KEM_512_RSA2048,
        MlKem512Rsa3072 => ML_KEM_512_RSA3072,
    };

    let spki_algorithm = AlgorithmIdentifierOwned {
        oid,
        parameters: None, // Params absent for Kyber keys per draft-ietf-lamps-mlkem-certificates-02 section 4
    };
    let ca_spki = SubjectPublicKeyInfoOwned {
        algorithm: spki_algorithm,
        subject_public_key: BitString::from_bytes(&ee_pk_bytes)?,
    };

    // todo - affirm DN source
    let dn_str = format!("cn={alg} EE,o=Test,c=US");
    let dn = Name::from_str(&dn_str)?;

    let profile = KemCert{ issuer: cert.tbs_certificate.subject.clone(), subject: dn };

    let builder = CertificateBuilder::new(
        profile,
        get_random_serial()?,
        get_validity(5)?,
        //dn.clone(),
        ca_spki,
        //signer,
    )?;

    Ok(builder.build(signer)?)
}

/// Generate new dilithium TA and end-entity KEM certificate based on KemriToyArgs with files output to the given output folder
pub fn generate_pki(kem: &KemAlgorithms, output_folder: &Path) -> crate::Result<Certificate> {
    let (signer, ta_cert) = match generate_ta() {
        Ok((signer, ta_cert)) => (signer, ta_cert),
        Err(e) => {
            error!("Failed to generate TA cert: {e:?}");
            return Err(e);
        }
    };
    let mut ta_file = File::create(output_folder.join("ta.der"))?;
    let _ = ta_file.write_all(&ta_cert.to_der()?);

    let (private_key_bytes, new_cert) = match kem {
        MlKem512 => {
            let (_ee_public_key, ee_secret_key, ee_cert) = match generate_cert!(
                signer,
                ta_cert,
                mlkem512::PublicKey,
                mlkem512::SecretKey,
                mlkem512::keypair,
                MlKem512
            ) {
                Ok((ee_public_key, ee_secret_key, ee_cert)) => {
                    (ee_public_key, ee_secret_key, ee_cert)
                }
                Err(e) => {
                    error!("Failed to generate KEM certificate: {e:?}");
                    return Err(e);
                }
            };
            (Some(ee_secret_key.as_bytes().to_vec()), Some(ee_cert))
        }
        MlKem768 => {
            let (_ee_public_key, ee_secret_key, ee_cert) = match generate_cert!(
                signer,
                ta_cert,
                mlkem768::PublicKey,
                mlkem768::SecretKey,
                mlkem768::keypair,
                MlKem768
            ) {
                Ok((ee_public_key, ee_secret_key, ee_cert)) => {
                    (ee_public_key, ee_secret_key, ee_cert)
                }
                Err(e) => {
                    error!("Failed to generate KEM certificate: {e:?}");
                    return Err(e);
                }
            };
            (Some(ee_secret_key.as_bytes().to_vec()), Some(ee_cert))
        }
        MlKem1024 => {
            let (_ee_public_key, ee_secret_key, ee_cert) = match generate_cert!(
                signer,
                ta_cert,
                mlkem1024::PublicKey,
                mlkem1024::SecretKey,
                mlkem1024::keypair,
                MlKem1024
            ) {
                Ok((ee_public_key, ee_secret_key, ee_cert)) => {
                    (ee_public_key, ee_secret_key, ee_cert)
                }
                Err(e) => {
                    error!("Failed to generate KEM certificate: {e:?}");
                    return Err(e);
                }
            };
            (Some(ee_secret_key.as_bytes().to_vec()), Some(ee_cert))
        }
        MlKem512Rsa2048 => {
            let (ml_kem_pub, ml_kem_priv) = mlkem512::keypair();
            let ml_kem_pub_bytes = ml_kem_pub.as_bytes();
            let ml_key_priv_bytes = ml_kem_priv.as_bytes();
            let ml_kem_oak = OneAsymmetricKey {
                version: Version::V1,
                private_key_alg: AlgorithmIdentifier {
                    oid: ML_KEM_512,
                    parameters: None,
                },
                private_key: PrivateKey::new(ml_key_priv_bytes)?,
                attributes: None,
                public_key: None,
            };

            let mut rng = rand::thread_rng();
            let rsa_priv_key =
                RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
            let rsa_pub = RsaPublicKey::from(&rsa_priv_key);
            let rsa_pub_bytes = rsa_pub
                .to_pkcs1_der()
                .map_err(|_| Error::Builder("Failed to parse RSA public key".to_string()))?;
            let rsa_priv_bytes = rsa_priv_key.to_pkcs8_der()?;
            let rsa_oak = OneAsymmetricKey {
                version: Version::V1,
                private_key_alg: AlgorithmIdentifier {
                    oid: RSA_ENCRYPTION,
                    parameters: None,
                },
                private_key: PrivateKey::new(rsa_priv_bytes.as_bytes())?,
                attributes: None,
                public_key: None,
            };

            let rsa_composite_pub = RsaCompositeKemPublicKey {
                first_public_key: BitString::from_bytes(ml_kem_pub_bytes)?,
                second_public_key: BitString::from_bytes(rsa_pub_bytes.as_bytes())?,
            };

            let composite_pub = CompositeKemPublicKey::Rsa(rsa_composite_pub);
            let composite_priv = [ml_kem_oak, rsa_oak];

            let certificate =
                generate_composite(&signer, &ta_cert, &composite_pub, MlKem512Rsa2048)?;
            (Some(composite_priv.to_der()?.to_vec()), Some(certificate))
        }
        MlKem512Rsa3072 => {
            let (ml_kem_pub, ml_kem_priv) = mlkem512::keypair();
            let ml_kem_pub_bytes = ml_kem_pub.as_bytes();
            let ml_key_priv_bytes = ml_kem_priv.as_bytes();
            let ml_kem_oak = OneAsymmetricKey {
                version: Version::V1,
                private_key_alg: AlgorithmIdentifier {
                    oid: ML_KEM_512,
                    parameters: None,
                },
                private_key: PrivateKey::new(ml_key_priv_bytes)?,
                attributes: None,
                public_key: None,
            };

            let mut rng = rand::thread_rng();
            let rsa_priv_key =
                RsaPrivateKey::new(&mut rng, 3072).expect("failed to generate a key");
            let rsa_pub = RsaPublicKey::from(&rsa_priv_key);
            let rsa_pub_bytes = rsa_pub.to_pkcs1_der()?;
            let rsa_priv_bytes = rsa_priv_key.to_pkcs8_der()?;
            let rsa_oak = OneAsymmetricKey {
                version: Version::V1,
                private_key_alg: AlgorithmIdentifier {
                    oid: RSA_ENCRYPTION,
                    parameters: None,
                },
                private_key: PrivateKey::new(rsa_priv_bytes.as_bytes())?,
                attributes: None,
                public_key: None,
            };

            let rsa_composite_pub = RsaCompositeKemPublicKey {
                first_public_key: BitString::from_bytes(ml_kem_pub_bytes)?,
                second_public_key: BitString::from_bytes(rsa_pub_bytes.as_bytes())?,
            };

            let composite_pub = CompositeKemPublicKey::Rsa(rsa_composite_pub);
            let composite_priv = [ml_kem_oak, rsa_oak];

            let certificate =
                generate_composite(&signer, &ta_cert, &composite_pub, MlKem512Rsa3072)?;
            (Some(composite_priv.to_der()?.to_vec()), Some(certificate))
        }
    };

    let cert = match new_cert {
        Some(cert) => cert,
        None => {
            error!("Failed to generate new KEM cert");
            return Err(Error::Unrecognized);
        }
    };
    let private_key = match private_key_bytes {
        Some(private_key) => private_key,
        None => {
            error!("Failed to generate new KEM key");
            return Err(Error::Unrecognized);
        }
    };

    let mut ee_file = File::create(output_folder.join(format!("{}_ee.der", kem.filename())))?;
    let _ = ee_file.write_all(&cert.to_der()?);

    let oak_leaf = OneAsymmetricKey {
        version: Version::V1, // V1 per rfc5958 section 2
        private_key_alg: AlgorithmIdentifier {
            oid: kem.oid(),
            parameters: None, // Params absent for Kyber keys per draft-ietf-lamps-mlkem-certificates-02 section 6
        },
        private_key: PrivateKey::new(private_key)?,
        attributes: None,
        public_key: None,
    };
    let der_oak = oak_leaf
        .to_der()
        .expect("Failed to encode private key as OneAsymmetricKey");

    let mut ee_key_file = File::create(output_folder.join(format!("{}_priv.der", kem.filename())))?;
    let _ = ee_key_file.write_all(&der_oak);

    Ok(cert)
}
