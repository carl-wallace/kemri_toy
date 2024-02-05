//! Utilities to generate test certificates features ML_KEM_XXX_IPD keys signed with ML_DSA_44_IPD

use std::{
    fs::File,
    io::Write,
    path::Path,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use log::error;
use rand_core::{OsRng, RngCore};

use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::{
    kem::{PublicKey as KemPublicKey, SecretKey},
    sign::PublicKey,
};

use der::{
    asn1::{BitString, OctetString, UtcTime},
    Encode,
};
use pqckeys::oak::OneAsymmetricKey;
use spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    name::Name,
    serial_number::SerialNumber,
    time::{Time, Validity},
    Certificate,
};

use crate::{
    args::{
        KemAlgorithms,
        KemAlgorithms::{MlKem1024, MlKem512, MlKem768},
        KemriToyArgs,
    },
    misc::signer::{Dilithium2KeyPair, DilithiumPublicKey},
    Error, ML_DSA_44_IPD, ML_KEM_1024_IPD, ML_KEM_512_IPD, ML_KEM_768_IPD,
};

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
pub fn generate_ta() -> crate::Result<(Dilithium2KeyPair, Certificate)> {
    let (ca_pk, ca_sk) = dilithium2::keypair();
    let signer = Dilithium2KeyPair {
        public_key: DilithiumPublicKey(ca_pk),
        secret_key: ca_sk,
    };
    let ca_pk_bytes = ca_pk.as_bytes().to_vec();

    let spki_algorithm = AlgorithmIdentifierOwned {
        oid: ML_DSA_44_IPD,
        parameters: None, // Params absent for Dilithium keys per draft-ietf-lamps-dilithium-certificates-02 section 7
    };
    let ee_spki = SubjectPublicKeyInfoOwned {
        algorithm: spki_algorithm,
        subject_public_key: BitString::from_bytes(&ca_pk_bytes)?,
    };

    let dn_str = "cn=Dilithium TA,c=US".to_string();
    let dn = Name::from_str(&dn_str)?;

    let profile = Profile::Leaf {
        issuer: dn.clone(),
        enable_key_agreement: false,
        enable_key_encipherment: false,
        include_subject_key_identifier: true,
    };

    let builder = CertificateBuilder::new(
        profile,
        get_random_serial()?,
        get_validity(10)?,
        dn.clone(),
        ee_spki,
        &signer,
    )?;

    let ca_cert = builder.build()?;

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

/// Generate an end entity certificate containing a KEM key signed using ML_DSA_44_IPD
pub fn generate_ml_kem_cert<PK: KemPublicKey>(
    signer: &Dilithium2KeyPair,
    cert: &Certificate,
    ee_pk: PK,
    alg: KemAlgorithms,
) -> crate::Result<Certificate> {
    let ee_pk_bytes = ee_pk.as_bytes().to_vec();

    let oid = match alg {
        MlKem512 => ML_KEM_512_IPD,
        MlKem768 => ML_KEM_768_IPD,
        MlKem1024 => ML_KEM_1024_IPD,
    };

    let spki_algorithm = AlgorithmIdentifierOwned {
        oid,
        parameters: None, // Params absent for Kyber keys per draft-ietf-lamps-kyber-certificates-02 section 4
    };
    let ca_spki = SubjectPublicKeyInfoOwned {
        algorithm: spki_algorithm,
        subject_public_key: BitString::from_bytes(&ee_pk_bytes)?,
    };
    let dn_str = format!("cn={alg} EE,c=US");
    let dn = Name::from_str(&dn_str)?;

    let profile = Profile::Leaf {
        issuer: cert.tbs_certificate.subject.clone(),
        enable_key_agreement: false,
        enable_key_encipherment: true,
        include_subject_key_identifier: true,
    };

    let builder = CertificateBuilder::new(
        profile,
        get_random_serial()?,
        get_validity(5)?,
        dn.clone(),
        ca_spki,
        signer,
    )?;

    Ok(builder.build()?)
}

/// Generate new dilithium TA and end-entity KEM certificate based on KemriToyArgs with files output to the given output folder
pub fn generate_pki(args: &KemriToyArgs, output_folder: &Path) -> crate::Result<Certificate> {
    let (signer, ta_cert) = match generate_ta() {
        Ok((signer, ta_cert)) => (signer, ta_cert),
        Err(e) => {
            error!("Failed to generate TA cert: {e:?}");
            return Err(e);
        }
    };
    let mut ta_file = File::create(output_folder.join("ta.der"))?;
    let _ = ta_file.write_all(&ta_cert.to_der()?);

    let (private_key_bytes, new_cert) = match &args.kem {
        MlKem512 => {
            let (_ee_public_key, ee_secret_key, ee_cert) = match generate_cert!(
                signer,
                ta_cert,
                kyber512::PublicKey,
                kyber512::SecretKey,
                kyber512::keypair,
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
                kyber768::PublicKey,
                kyber768::SecretKey,
                kyber768::keypair,
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
                kyber1024::PublicKey,
                kyber1024::SecretKey,
                kyber1024::keypair,
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

    let mut ee_file = File::create(output_folder.join(format!("{}_ee.der", args.kem.filename())))?;
    let _ = ee_file.write_all(&cert.to_der()?);

    let oak_leaf = OneAsymmetricKey {
        version: pqckeys::oak::Version::V1, // V1 per rfc5958 section 2
        private_key_alg: AlgorithmIdentifier {
            oid: args.kem.oid(),
            parameters: None, // Params absent for Kyber keys per draft-ietf-lamps-kyber-certificates-02 section 6
        },
        private_key: OctetString::new(private_key)?,
        attributes: None,
        public_key: None,
    };
    let der_oak = oak_leaf
        .to_der()
        .expect("Failed to encode private key as OneAsymmetricKey");

    let mut ee_key_file =
        File::create(output_folder.join(format!("{}_priv.der", args.kem.filename())))?;
    let _ = ee_key_file.write_all(&der_oak);

    Ok(cert)
}
