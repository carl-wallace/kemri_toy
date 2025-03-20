//! Utilities to generate test certificates features ML_KEM_XXX_IPD keys signed with ML_DSA_44_IPD

use std::{
    fs::File,
    io::Write,
    path::Path,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use log::error;
use rand::RngCore;
use rand::rngs::OsRng;
use rand_core::TryRngCore;

use cipher::rand_core::CryptoRng;
use ml_kem::{
    ArraySize, B32, EncodedSizeUser, KemCore, MlKem512, MlKem768, MlKem1024,
    array::Array,
    kem::{Decapsulate, Encapsulate},
};

use der::{
    Encode,
    asn1::{BitString, UtcTime},
};
use spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::{
    Certificate,
    builder::{Builder, CertificateBuilder, profile::cabf::Root},
    name::Name,
    serial_number::SerialNumber,
    time::{Time, Validity},
};

use pqckeys::oak::{OneAsymmetricKey, PrivateKey};

use crate::{
    Error, ML_KEM_512, ML_KEM_768, ML_KEM_1024,
    args::{
        KemAlgorithms,
        KemAlgorithms::{
            MlKem512 as OtherMlKem512, MlKem768 as OtherMlKem768, MlKem1024 as OtherMlKem1024,
        },
        SigAlgorithms,
    },
    asn1::private_key::{
        MlKem512Both, MlKem512Expanded, MlKem512PrivateKey, MlKem768Both, MlKem768Expanded,
        MlKem768PrivateKey, MlKem1024Both, MlKem1024Expanded, MlKem1024PrivateKey, MlKemSeed,
    },
    misc::{builder_profiles::KemCert, signer::PqcSigner},
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

    Ok(Validity::new(
        Time::UtcTime(UtcTime::from_unix_duration(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(),
        )?),
        Time::UtcTime(UtcTime::from_unix_duration(
            years_time.duration_since(UNIX_EPOCH).unwrap_or_default(),
        )?),
    ))
}

/// Return a random SerialNumber value
fn get_random_serial() -> crate::Result<SerialNumber> {
    let mut serial = [0u8; 20];
    OsRng.unwrap_err().fill_bytes(&mut serial);
    serial[0] = 0x01;
    Ok(SerialNumber::new(&serial)?)
}

/// Generate a new self-signed trust anchor certificate containing an ML_DSA_44_IPD key
pub fn generate_ta(sig: &SigAlgorithms) -> crate::Result<(PqcSigner, Certificate)> {
    let signer = sig.generate_key_pair()?;
    let ca_pk_bytes = signer.public_key();

    let spki_algorithm = AlgorithmIdentifierOwned {
        oid: signer.oid(),
        parameters: None, // Params absent for Dilithium keys per draft-ietf-lamps-dilithium-certificates-02 section 7
    };
    let ee_spki = SubjectPublicKeyInfoOwned {
        algorithm: spki_algorithm,
        subject_public_key: BitString::from_bytes(&ca_pk_bytes)?,
    };

    let dn_str = format!("cn={} TA,o=Test,c=US", sig.filename());
    let dn = Name::from_str(&dn_str)?;

    // todo - make a profile a la old Leaf
    let profile = Root::new(false, dn)?;

    let builder =
        CertificateBuilder::new(profile, get_random_serial()?, get_validity(10)?, ee_spki)?;

    let ca_cert = builder.build(&signer)?;

    Ok((signer, ca_cert))
}

pub fn rand<L: ArraySize>(rng: &mut impl CryptoRng) -> Array<u8, L> {
    let mut val = Array::default();
    rng.fill_bytes(&mut val);
    val
}

fn get_seed(d: &B32, z: &B32) -> Vec<u8> {
    let mut seed = vec![];
    seed.append(&mut d.to_vec());
    seed.append(&mut z.to_vec());
    seed
}

/// Macro to generate a fresh KEM keypair and an end entity certificate containing a KEM key signed using ML_DSA_44_IPD
macro_rules! generate_kem_cert {
    ($signer:ident, $cert:ident, $keypair:expr, $alg:ident) => {{
        let mut rng = OsRng.unwrap_err();
        let d: B32 = rand(&mut rng);
        let z: B32 = rand(&mut rng);
        let (ee_sk, ee_pk) = $keypair(&d, &z);
        let cert = generate_ml_kem_cert(&$signer, &$cert, ee_pk.as_bytes().as_slice(), $alg)?;
        Ok((ee_pk, ee_sk, cert, get_seed(&d, &z)))
    }};
}
pub fn generate_ml_kem_cert(
    signer: &PqcSigner,
    cert: &Certificate,
    ee_pk_bytes: &[u8],
    alg: KemAlgorithms,
) -> crate::Result<Certificate> {
    let oid = match alg {
        OtherMlKem512 => ML_KEM_512,
        OtherMlKem768 => ML_KEM_768,
        OtherMlKem1024 => ML_KEM_1024,
    };

    let spki_algorithm = AlgorithmIdentifierOwned {
        oid,
        parameters: None, // Params absent for Kyber keys per draft-ietf-lamps-mlkem-certificates-02 section 4
    };
    let ca_spki = SubjectPublicKeyInfoOwned {
        algorithm: spki_algorithm,
        subject_public_key: BitString::from_bytes(ee_pk_bytes)?,
    };

    let dn_str = format!("cn={alg} EE,o=Test,c=US");
    let dn = Name::from_str(&dn_str)?;

    let profile = KemCert {
        issuer: cert.tbs_certificate().subject().clone(),
        subject: dn,
    };

    let builder =
        CertificateBuilder::new(profile, get_random_serial()?, get_validity(5)?, ca_spki)?;

    Ok(builder.build(signer)?)
}

fn encode_kem_private_key(kem: &KemAlgorithms, private_key_bytes: &[u8]) -> crate::Result<Vec<u8>> {
    let oak_leaf_seed = OneAsymmetricKey {
        version: pqckeys::oak::Version::V1, // V1 per rfc5958 section 2
        private_key_alg: AlgorithmIdentifier {
            oid: kem.oid(),
            parameters: None, // Params absent for Kyber keys per draft-ietf-lamps-mlkem-certificates-02 section 6
        },
        private_key: PrivateKey::new(private_key_bytes)?,
        attributes: None,
        public_key: None,
    };
    Ok(oak_leaf_seed.to_der()?)
}

/// Generate new dilithium TA and end-entity KEM certificate based on KemriToyArgs with files output to the given output folder
pub fn generate_pki(kem: &KemAlgorithms, output_folder: &Path) -> crate::Result<Certificate> {
    let (signer, ta_cert) = match generate_ta(&SigAlgorithms::MlDsa44) {
        Ok((signer, ta_cert)) => (signer, ta_cert),
        Err(e) => {
            error!("Failed to generate TA cert: {e:?}");
            return Err(e);
        }
    };
    let mut ta_file = File::create(output_folder.join("ta.der"))?;
    let _ = ta_file.write_all(&signer.private_key());

    let mut ta_file = File::create(output_folder.join("ta.der"))?;
    let _ = ta_file.write_all(&ta_cert.to_der()?);

    let (private_key_bytes, new_cert, seed, ct, ss) = match kem {
        OtherMlKem512 => {
            let (ee_public_key, ee_secret_key, ee_cert, seed) = match generate_kem_cert!(
                signer,
                ta_cert,
                MlKem512::generate_deterministic,
                OtherMlKem512
            ) {
                Ok((ee_public_key, ee_secret_key, ee_cert, seed)) => {
                    (ee_public_key, ee_secret_key, ee_cert, seed)
                }
                Err(e) => {
                    error!("Failed to generate KEM certificate: {e:?}");
                    return Err(e);
                }
            };
            let (ct, ss) = ee_public_key.encapsulate(&mut OsRng.unwrap_err()).unwrap();
            let ss2 = ee_secret_key.decapsulate(&ct).unwrap();
            assert_eq!(ss, ss2);

            (
                Some(ee_secret_key.as_bytes().to_vec()),
                Some(ee_cert),
                seed,
                ct.as_slice().to_vec(),
                ss.as_slice().to_vec(),
            )
        }
        OtherMlKem768 => {
            let (ee_public_key, ee_secret_key, ee_cert, seed) = match generate_kem_cert!(
                signer,
                ta_cert,
                MlKem768::generate_deterministic,
                OtherMlKem768
            ) {
                Ok((ee_public_key, ee_secret_key, ee_cert, seed)) => {
                    (ee_public_key, ee_secret_key, ee_cert, seed)
                }
                Err(e) => {
                    error!("Failed to generate KEM certificate: {e:?}");
                    return Err(e);
                }
            };
            let (ct, ss) = ee_public_key.encapsulate(&mut OsRng.unwrap_err()).unwrap();
            let ss2 = ee_secret_key.decapsulate(&ct).unwrap();
            assert_eq!(ss, ss2);

            (
                Some(ee_secret_key.as_bytes().to_vec()),
                Some(ee_cert),
                seed,
                ct.as_slice().to_vec(),
                ss.as_slice().to_vec(),
            )
        }
        OtherMlKem1024 => {
            let (ee_public_key, ee_secret_key, ee_cert, seed) = match generate_kem_cert!(
                signer,
                ta_cert,
                MlKem1024::generate_deterministic,
                OtherMlKem1024
            ) {
                Ok((ee_public_key, ee_secret_key, ee_cert, seed)) => {
                    (ee_public_key, ee_secret_key, ee_cert, seed)
                }
                Err(e) => {
                    error!("Failed to generate KEM certificate: {e:?}");
                    return Err(e);
                }
            };
            let (ct, ss) = ee_public_key.encapsulate(&mut OsRng.unwrap_err()).unwrap();
            let ss2 = ee_secret_key.decapsulate(&ct).unwrap();
            assert_eq!(ss, ss2);

            (
                Some(ee_secret_key.as_bytes().to_vec()),
                Some(ee_cert),
                seed,
                ct.as_slice().to_vec(),
                ss.as_slice().to_vec(),
            )
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

    let mut ct_file =
        File::create(output_folder.join(format!("{}_ciphertext.bin", kem.filename())))?;
    let _ = ct_file.write_all(&ct);

    let mut ss_file = File::create(output_folder.join(format!("{}_ss.bin", kem.filename())))?;
    let _ = ss_file.write_all(&ss);

    let private_key_bytes = match kem {
        KemAlgorithms::MlKem512 => {
            let pk = MlKem512PrivateKey::ExpandedKey(
                MlKem512Expanded::new(private_key.clone())
                    .map_err(|e| Error::MlKem(format!("{e:?}")))?,
            );
            pk.to_der()?
        }
        KemAlgorithms::MlKem768 => {
            let pk = MlKem768PrivateKey::ExpandedKey(
                MlKem768Expanded::new(private_key.clone())
                    .map_err(|e| Error::MlKem(format!("{e:?}")))?,
            );
            pk.to_der()?
        }
        KemAlgorithms::MlKem1024 => {
            let pk = MlKem1024PrivateKey::ExpandedKey(
                MlKem1024Expanded::new(private_key.clone())
                    .map_err(|e| Error::MlKem(format!("{e:?}")))?,
            );
            pk.to_der()?
        }
    };

    let mut ee_file = File::create(output_folder.join(format!("{}_ee.der", kem.filename())))?;
    let _ = ee_file.write_all(&cert.to_der()?);

    let der_oak = encode_kem_private_key(kem, &private_key_bytes)
        .expect("Failed to encode private key w/expanded key as OneAsymmetricKey");

    let mut ee_key_file =
        File::create(output_folder.join(format!("{}_expandedkey_priv.der", kem.filename())))?;
    let _ = ee_key_file.write_all(&der_oak);

    let private_key_bytes_seed = match kem {
        KemAlgorithms::MlKem512 => {
            let pk = MlKem512PrivateKey::Seed(
                MlKemSeed::new(seed.clone()).map_err(|e| Error::MlKem(format!("{e:?}")))?,
            );
            pk.to_der()?
        }
        KemAlgorithms::MlKem768 => {
            let pk = MlKem768PrivateKey::Seed(
                MlKemSeed::new(seed.clone()).map_err(|e| Error::MlKem(format!("{e:?}")))?,
            );
            pk.to_der()?
        }
        KemAlgorithms::MlKem1024 => {
            let pk = MlKem1024PrivateKey::Seed(
                MlKemSeed::new(seed.clone()).map_err(|e| Error::MlKem(format!("{e:?}")))?,
            );
            pk.to_der()?
        }
    };

    let der_oak_seed = encode_kem_private_key(kem, &private_key_bytes_seed)
        .expect("Failed to encode private key w/seed as OneAsymmetricKey");

    let mut ee_key_file =
        File::create(output_folder.join(format!("{}_seed_priv.der", kem.filename())))?;
    let _ = ee_key_file.write_all(&der_oak_seed);

    let private_key_bytes_both = match kem {
        KemAlgorithms::MlKem512 => {
            let pk = MlKem512Both {
                seed: MlKemSeed::new(seed).map_err(|e| Error::MlKem(format!("{e:?}")))?,
                expanded_key: MlKem512Expanded::new(private_key)
                    .map_err(|e| Error::MlKem(format!("{e:?}")))?,
            };
            pk.to_der()?
        }
        KemAlgorithms::MlKem768 => {
            let pk = MlKem768Both {
                seed: MlKemSeed::new(seed).map_err(|e| Error::MlKem(format!("{e:?}")))?,
                expanded_key: MlKem768Expanded::new(private_key)
                    .map_err(|e| Error::MlKem(format!("{e:?}")))?,
            };
            pk.to_der()?
        }
        KemAlgorithms::MlKem1024 => {
            let pk = MlKem1024Both {
                seed: MlKemSeed::new(seed).map_err(|e| Error::MlKem(format!("{e:?}")))?,
                expanded_key: MlKem1024Expanded::new(private_key)
                    .map_err(|e| Error::MlKem(format!("{e:?}")))?,
            };
            pk.to_der()?
        }
    };

    let der_oak_both = encode_kem_private_key(kem, &private_key_bytes_both)
        .expect("Failed to encode private key w/both as OneAsymmetricKey");

    let mut ee_key_file =
        File::create(output_folder.join(format!("{}_both_priv.der", kem.filename())))?;
    let _ = ee_key_file.write_all(&der_oak_both);

    Ok(cert)
}
