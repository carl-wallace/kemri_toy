//! Arguments for the `kemri_toy` utility

use core::fmt;
use ml_dsa::KeyGen;
use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};

use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s, SigningKey,
};

use crate::misc::gen_certs::rand;
use crate::misc::signer::{PqcKeyPair, PqcSigner};
use crate::misc::utils::get_filename_from_oid;
use crate::{
    Error, ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384, ID_ALG_HKDF_WITH_SHA512, ID_KMAC128,
    ID_KMAC256, ML_KEM_512, ML_KEM_768, ML_KEM_1024, Result,
};
use const_oid::{
    ObjectIdentifier,
    db::rfc5911::{
        ID_AES_128_CBC, ID_AES_128_GCM, ID_AES_128_WRAP, ID_AES_192_CBC, ID_AES_192_WRAP,
        ID_AES_256_CBC, ID_AES_256_GCM, ID_AES_256_WRAP,
    },
};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use pqckeys::pqc_oids::{
    ML_DSA_44, ML_DSA_65, ML_DSA_87, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S, SLH_DSA_SHA2_192F,
    SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256F, SLH_DSA_SHA2_256S, SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_128S, SLH_DSA_SHAKE_192F, SLH_DSA_SHAKE_192S, SLH_DSA_SHAKE_256F,
    SLH_DSA_SHAKE_256S,
};

/// KEM algorithms available via command line argument
#[derive(Clone, Serialize, Deserialize, Debug, Default, clap::ValueEnum)]
pub enum KemAlgorithms {
    #[default]
    MlKem512,
    MlKem768,
    MlKem1024,
}
impl fmt::Display for KemAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KemAlgorithms::MlKem512 => write!(f, "ml-kem512"),
            KemAlgorithms::MlKem768 => write!(f, "ml-kem768"),
            KemAlgorithms::MlKem1024 => write!(f, "ml-kem1024"),
        }
    }
}

impl KemAlgorithms {
    /// Get KemAlgorithms instance from an object identifier.
    pub fn from_oid(oid: ObjectIdentifier) -> Result<KemAlgorithms> {
        match oid {
            ML_KEM_512 => Ok(KemAlgorithms::MlKem512),
            ML_KEM_768 => Ok(KemAlgorithms::MlKem768),
            ML_KEM_1024 => Ok(KemAlgorithms::MlKem1024),
            _ => Err(Error::Unrecognized),
        }
    }

    /// Get object identifier from KemAlgorithms instance.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            KemAlgorithms::MlKem512 => ML_KEM_512,
            KemAlgorithms::MlKem768 => ML_KEM_768,
            KemAlgorithms::MlKem1024 => ML_KEM_1024,
        }
    }

    /// Get filename component for KemAlgorithms instance.
    pub fn filename(&self) -> String {
        match self {
            KemAlgorithms::MlKem512 => {
                format!("{}-{}", get_filename_from_oid(ML_KEM_512), ML_KEM_512)
            }
            KemAlgorithms::MlKem768 => {
                format!("{}-{}", get_filename_from_oid(ML_KEM_768), ML_KEM_768)
            }
            KemAlgorithms::MlKem1024 => {
                format!("{}-{}", get_filename_from_oid(ML_KEM_1024), ML_KEM_1024)
            }
        }
    }
}

/// KEM algorithms available via command line argument
#[derive(Clone, Serialize, Deserialize, Debug, Default, clap::ValueEnum)]
pub enum SigAlgorithms {
    #[default]
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaSha2_128s,
    SlhDsaSha2_128f,
    SlhDsaSha2_192s,
    SlhDsaSha2_192f,
    SlhDsaSha2_256s,
    SlhDsaSha2_256f,
    SlhDsaShake128s,
    SlhDsaShake128f,
    SlhDsaShake192s,
    SlhDsaShake192f,
    SlhDsaShake256s,
    SlhDsaShake256f,
}
impl fmt::Display for SigAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigAlgorithms::MlDsa44 => write!(f, "ml-dsa44"),
            SigAlgorithms::MlDsa65 => write!(f, "ml-dsa65"),
            SigAlgorithms::MlDsa87 => write!(f, "ml-dsa87"),
            SigAlgorithms::SlhDsaSha2_128s => write!(f, "slh-dsa-sha2-128s"),
            SigAlgorithms::SlhDsaSha2_128f => write!(f, "slh-dsa-sha2-128f"),
            SigAlgorithms::SlhDsaSha2_192s => write!(f, "slh-dsa-sha2-192s"),
            SigAlgorithms::SlhDsaSha2_192f => write!(f, "slh-dsa-sha2-192f"),
            SigAlgorithms::SlhDsaSha2_256s => write!(f, "slh-dsa-sha2-256s"),
            SigAlgorithms::SlhDsaSha2_256f => write!(f, "slh-dsa-sha2-256f"),
            SigAlgorithms::SlhDsaShake128s => write!(f, "slh-dsa-shake-128s"),
            SigAlgorithms::SlhDsaShake128f => write!(f, "slh-dsa-shake-128f"),
            SigAlgorithms::SlhDsaShake192s => write!(f, "slh-dsa-shake-192s"),
            SigAlgorithms::SlhDsaShake192f => write!(f, "slh-dsa-shake-192f"),
            SigAlgorithms::SlhDsaShake256s => write!(f, "slh-dsa-shake-256s"),
            SigAlgorithms::SlhDsaShake256f => write!(f, "slh-dsa-shake-256f"),
        }
    }
}

impl SigAlgorithms {
    pub fn generate_key_pair(&self) -> Result<PqcSigner> {
        let mut rng = rand::rng();

        match self {
            SigAlgorithms::MlDsa44 => {
                let xi: ml_dsa::B32 = rand(&mut rng);
                Ok(PqcSigner::new(
                    xi.clone().as_slice(),
                    PqcKeyPair::MlDsa44(Box::new(MlDsa44::key_gen_internal(&xi))),
                ))
            }
            SigAlgorithms::MlDsa65 => {
                let xi: ml_dsa::B32 = rand(&mut rng);
                Ok(PqcSigner::new(
                    xi.clone().as_slice(),
                    PqcKeyPair::MlDsa65(Box::new(MlDsa65::key_gen_internal(&xi))),
                ))
            }
            SigAlgorithms::MlDsa87 => {
                let xi: ml_dsa::B32 = rand(&mut rng);
                Ok(PqcSigner::new(
                    xi.clone().as_slice(),
                    PqcKeyPair::MlDsa87(Box::new(MlDsa87::key_gen_internal(&xi))),
                ))
            }
            SigAlgorithms::SlhDsaSha2_128s => Ok(PqcSigner::new(
                &[],
                PqcKeyPair::Sha2_128s(Box::new(SigningKey::<Sha2_128s>::new(&mut rng))),
            )),
            SigAlgorithms::SlhDsaSha2_128f => Ok(PqcSigner::new(
                &[],
                PqcKeyPair::Sha2_128f(Box::new(SigningKey::<Sha2_128f>::new(&mut rng))),
            )),
            SigAlgorithms::SlhDsaSha2_192f => Ok(PqcSigner::new(
                &[],
                PqcKeyPair::Sha2_192f(Box::new(SigningKey::<Sha2_192f>::new(&mut rng))),
            )),
            SigAlgorithms::SlhDsaSha2_192s => Ok(PqcSigner::new(
                &[],
                PqcKeyPair::Sha2_192s(Box::new(SigningKey::<Sha2_192s>::new(&mut rng))),
            )),
            SigAlgorithms::SlhDsaSha2_256f => Ok(PqcSigner::new(
                &[],
                PqcKeyPair::Sha2_256f(Box::new(SigningKey::<Sha2_256f>::new(&mut rng))),
            )),
            SigAlgorithms::SlhDsaSha2_256s => Ok(PqcSigner::new(
                &[],
                PqcKeyPair::Sha2_256s(Box::new(SigningKey::<Sha2_256s>::new(&mut rng))),
            )),
            SigAlgorithms::SlhDsaShake128f => Ok(PqcSigner::new(
                &[],
                PqcKeyPair::Shake128f(Box::new(SigningKey::<Shake128f>::new(&mut rng))),
            )),
            SigAlgorithms::SlhDsaShake128s => Ok(PqcSigner::new(
                &[],
                PqcKeyPair::Shake128s(Box::new(SigningKey::<Shake128s>::new(&mut rng))),
            )),
            SigAlgorithms::SlhDsaShake192f => Ok(PqcSigner::new(
                &[],
                PqcKeyPair::Shake192f(Box::new(SigningKey::<Shake192f>::new(&mut rng))),
            )),
            SigAlgorithms::SlhDsaShake192s => Ok(PqcSigner::new(
                &[],
                PqcKeyPair::Shake192s(Box::new(SigningKey::<Shake192s>::new(&mut rng))),
            )),
            SigAlgorithms::SlhDsaShake256f => Ok(PqcSigner::new(
                &[],
                PqcKeyPair::Shake256f(Box::new(SigningKey::<Shake256f>::new(&mut rng))),
            )),
            SigAlgorithms::SlhDsaShake256s => Ok(PqcSigner::new(
                &[],
                PqcKeyPair::Shake256s(Box::new(SigningKey::<Shake256s>::new(&mut rng))),
            )),
        }
    }

    /// Get KemAlgorithms instance from an object identifier.
    pub fn from_oid(oid: ObjectIdentifier) -> Result<SigAlgorithms> {
        match oid {
            ML_DSA_44 => Ok(SigAlgorithms::MlDsa44),
            ML_DSA_65 => Ok(SigAlgorithms::MlDsa65),
            ML_DSA_87 => Ok(SigAlgorithms::MlDsa87),
            SLH_DSA_SHA2_128S => Ok(SigAlgorithms::SlhDsaSha2_128s),
            SLH_DSA_SHA2_128F => Ok(SigAlgorithms::SlhDsaSha2_128f),
            SLH_DSA_SHA2_192S => Ok(SigAlgorithms::SlhDsaSha2_192s),
            SLH_DSA_SHA2_192F => Ok(SigAlgorithms::SlhDsaSha2_192f),
            SLH_DSA_SHA2_256S => Ok(SigAlgorithms::SlhDsaSha2_256s),
            SLH_DSA_SHA2_256F => Ok(SigAlgorithms::SlhDsaSha2_256f),
            SLH_DSA_SHAKE_128S => Ok(SigAlgorithms::SlhDsaShake128s),
            SLH_DSA_SHAKE_128F => Ok(SigAlgorithms::SlhDsaShake128f),
            SLH_DSA_SHAKE_192S => Ok(SigAlgorithms::SlhDsaShake192s),
            SLH_DSA_SHAKE_192F => Ok(SigAlgorithms::SlhDsaShake192f),
            SLH_DSA_SHAKE_256S => Ok(SigAlgorithms::SlhDsaShake256s),
            SLH_DSA_SHAKE_256F => Ok(SigAlgorithms::SlhDsaShake256f),
            _ => Err(Error::Unrecognized),
        }
    }

    /// Get object identifier from KemAlgorithms instance.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            SigAlgorithms::MlDsa44 => ML_DSA_44,
            SigAlgorithms::MlDsa65 => ML_DSA_65,
            SigAlgorithms::MlDsa87 => ML_DSA_87,
            SigAlgorithms::SlhDsaSha2_128s => SLH_DSA_SHA2_128S,
            SigAlgorithms::SlhDsaSha2_128f => SLH_DSA_SHA2_128F,
            SigAlgorithms::SlhDsaSha2_192s => SLH_DSA_SHA2_192S,
            SigAlgorithms::SlhDsaSha2_192f => SLH_DSA_SHA2_192F,
            SigAlgorithms::SlhDsaSha2_256s => SLH_DSA_SHA2_256S,
            SigAlgorithms::SlhDsaSha2_256f => SLH_DSA_SHA2_256F,
            SigAlgorithms::SlhDsaShake128s => SLH_DSA_SHAKE_128S,
            SigAlgorithms::SlhDsaShake128f => SLH_DSA_SHAKE_128F,
            SigAlgorithms::SlhDsaShake192s => SLH_DSA_SHAKE_192S,
            SigAlgorithms::SlhDsaShake192f => SLH_DSA_SHAKE_192F,
            SigAlgorithms::SlhDsaShake256s => SLH_DSA_SHAKE_256S,
            SigAlgorithms::SlhDsaShake256f => SLH_DSA_SHAKE_256F,
        }
    }

    /// Get filename component for KemAlgorithms instance.
    pub fn filename(&self) -> String {
        match self {
            SigAlgorithms::MlDsa44 => {
                format!("{}-{}", get_filename_from_oid(ML_DSA_44), ML_DSA_44)
            }
            SigAlgorithms::MlDsa65 => {
                format!("{}-{}", get_filename_from_oid(ML_DSA_65), ML_DSA_65)
            }
            SigAlgorithms::MlDsa87 => {
                format!("{}-{}", get_filename_from_oid(ML_DSA_87), ML_DSA_87)
            }
            SigAlgorithms::SlhDsaSha2_128s => {
                format!(
                    "{}-{}",
                    get_filename_from_oid(SLH_DSA_SHA2_128S),
                    SLH_DSA_SHA2_128S
                )
            }
            SigAlgorithms::SlhDsaSha2_128f => {
                format!(
                    "{}-{}",
                    get_filename_from_oid(SLH_DSA_SHA2_128F),
                    SLH_DSA_SHA2_128F
                )
            }
            SigAlgorithms::SlhDsaSha2_192s => {
                format!(
                    "{}-{}",
                    get_filename_from_oid(SLH_DSA_SHA2_192S),
                    SLH_DSA_SHA2_192S,
                )
            }
            SigAlgorithms::SlhDsaSha2_192f => {
                format!(
                    "{}-{}",
                    get_filename_from_oid(SLH_DSA_SHA2_192F),
                    SLH_DSA_SHA2_192F
                )
            }
            SigAlgorithms::SlhDsaSha2_256s => {
                format!(
                    "{}-{}",
                    get_filename_from_oid(SLH_DSA_SHA2_256S),
                    SLH_DSA_SHA2_256S
                )
            }
            SigAlgorithms::SlhDsaSha2_256f => {
                format!(
                    "{}-{}",
                    get_filename_from_oid(SLH_DSA_SHA2_256F),
                    SLH_DSA_SHA2_256F
                )
            }
            SigAlgorithms::SlhDsaShake128s => {
                format!(
                    "{}-{}",
                    get_filename_from_oid(SLH_DSA_SHAKE_128S),
                    SLH_DSA_SHAKE_128S
                )
            }
            SigAlgorithms::SlhDsaShake128f => {
                format!(
                    "{}-{}",
                    get_filename_from_oid(SLH_DSA_SHAKE_128F),
                    SLH_DSA_SHAKE_128F,
                )
            }
            SigAlgorithms::SlhDsaShake192s => {
                format!(
                    "{}-{}",
                    get_filename_from_oid(SLH_DSA_SHAKE_192S),
                    SLH_DSA_SHAKE_192S,
                )
            }
            SigAlgorithms::SlhDsaShake192f => {
                format!(
                    "{}-{}",
                    get_filename_from_oid(SLH_DSA_SHAKE_192F),
                    SLH_DSA_SHAKE_192F,
                )
            }
            SigAlgorithms::SlhDsaShake256s => {
                format!(
                    "{}-{}",
                    get_filename_from_oid(SLH_DSA_SHAKE_256S),
                    SLH_DSA_SHAKE_256S,
                )
            }
            SigAlgorithms::SlhDsaShake256f => {
                format!(
                    "{}-{}",
                    get_filename_from_oid(SLH_DSA_SHAKE_256F),
                    SLH_DSA_SHAKE_256F
                )
            }
        }
    }
}

/// AEAD algorithms available via command line argument
#[derive(Clone, Serialize, Deserialize, Debug, Default, clap::ValueEnum)]
pub enum AeadAlgorithms {
    #[default]
    Aes128Gcm,
    Aes256Gcm,
}

impl fmt::Display for AeadAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AeadAlgorithms::Aes128Gcm => write!(f, "aes128-gcm"),
            AeadAlgorithms::Aes256Gcm => write!(f, "aes256-gcm"),
        }
    }
}

impl AeadAlgorithms {
    /// Get object identifier from AeadAlgorithms instance.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            AeadAlgorithms::Aes128Gcm => ID_AES_128_GCM,
            AeadAlgorithms::Aes256Gcm => ID_AES_256_GCM,
        }
    }
    /// Get object identifier for wrap algorithm corresponding to from AeadAlgorithms instance.
    pub fn wrap(&self) -> ObjectIdentifier {
        match self {
            AeadAlgorithms::Aes128Gcm => ID_AES_128_WRAP,
            AeadAlgorithms::Aes256Gcm => ID_AES_256_WRAP,
        }
    }
}

/// Encryption algorithms available via command line argument
#[derive(Clone, Serialize, Deserialize, Debug, Default, clap::ValueEnum)]
pub enum EncAlgorithms {
    #[default]
    Aes128,
    Aes192,
    Aes256,
}

impl fmt::Display for EncAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncAlgorithms::Aes128 => write!(f, "aes128"),
            EncAlgorithms::Aes192 => write!(f, "aes192"),
            EncAlgorithms::Aes256 => write!(f, "aes256"),
        }
    }
}

impl EncAlgorithms {
    /// Get object identifier from EncAlgorithms instance.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            EncAlgorithms::Aes128 => ID_AES_128_CBC,
            EncAlgorithms::Aes192 => ID_AES_192_CBC,
            EncAlgorithms::Aes256 => ID_AES_256_CBC,
        }
    }
    /// Get object identifier for wrap algorithm corresponding to from EncAlgorithms instance.
    pub fn wrap(&self) -> ObjectIdentifier {
        match self {
            EncAlgorithms::Aes128 => ID_AES_128_WRAP,
            EncAlgorithms::Aes192 => ID_AES_192_WRAP,
            EncAlgorithms::Aes256 => ID_AES_256_WRAP,
        }
    }
}

/// KDF algorithms available via command line argument
#[derive(Clone, Serialize, Deserialize, Debug, Default, clap::ValueEnum)]
pub enum KdfAlgorithms {
    #[default]
    HkdfSha256,
    HkdfSha384,
    HkdfSha512,
    Kmac128,
    Kmac256,
}
impl fmt::Display for KdfAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KdfAlgorithms::HkdfSha256 => write!(f, "hkdf-sha256"),
            KdfAlgorithms::HkdfSha384 => write!(f, "hkdf-sha384"),
            KdfAlgorithms::HkdfSha512 => write!(f, "hkdf-sha512"),
            KdfAlgorithms::Kmac128 => write!(f, "kmac128"),
            KdfAlgorithms::Kmac256 => write!(f, "kmac256"),
        }
    }
}

impl KdfAlgorithms {
    /// Get object identifier from KdfAlgorithms instance.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            KdfAlgorithms::HkdfSha256 => ID_ALG_HKDF_WITH_SHA256,
            KdfAlgorithms::HkdfSha384 => ID_ALG_HKDF_WITH_SHA384,
            KdfAlgorithms::HkdfSha512 => ID_ALG_HKDF_WITH_SHA512,
            KdfAlgorithms::Kmac128 => ID_KMAC128,
            KdfAlgorithms::Kmac256 => ID_KMAC256,
        }
    }
    /// Get filename component from KdfAlgorithms instance.
    pub fn filename(&self) -> String {
        match self {
            KdfAlgorithms::HkdfSha256 => "id-alg-hkdf-with-sha256".to_string(),
            KdfAlgorithms::HkdfSha384 => "id-alg-hkdf-with-sha384".to_string(),
            KdfAlgorithms::HkdfSha512 => "id-alg-hkdf-with-sha512".to_string(),
            KdfAlgorithms::Kmac128 => "id-kmac128".to_string(),
            KdfAlgorithms::Kmac256 => "id-kmac256".to_string(),
        }
    }
}

/// Command line arguments
/// ```text
/// Usage: kemri_toy [OPTIONS]
///
/// Options:
///   -h, --help     Print help (see more with '--help')
///   -V, --version  Print version
///
/// Common:
///   -o, --output-folder <OUTPUT_FOLDER>
///           Folder to which generated certificates, keys, EnvelopedData objects, and non-default decrypted payloads should be written
///   -l, --logging-config <LOGGING_CONFIG>
///           Full path and filename of YAML-formatted configuration file for log4rs logging mechanism. See https://docs.rs/log4rs/latest/log4rs/ for details
///   -i, --input-file <INPUT_FILE>
///           When encrypting, file that contains data to encrypt (abc is used when absent). When decrypting, file that contains DER-encoded EnvelopedData or AuthEnvelopedData object
///
/// Encryption:
///       --kem <KEM>                    KEM algorithm to use when generating fresh keys, i.e., when encrypting and no ee_cert_file was provided [default: ml-kem512] [possible values: ml-kem512, ml-kem768, ml-kem1024]
///       --kdf <KDF>                    KDF algorithm to use when preparing an EnvelopedData or AuthEnvelopedData object [default: hkdf-sha256] [possible values: hkdf-sha256, hkdf-sha384, hkdf-sha512]
///       --enc <ENC>                    Symmetric encryption algorithm to use when preparing an EnvelopedData object [default: aes128] [possible values: aes128, aes192, aes256]
///       --aead <AEAD>                  AEAD encryption algorithm to use when preparing an AuthEnvelopedData object [default: aes128-gcm] [possible values: aes128-gcm, aes256-gcm]
///   -a, --auth-env-data                Generate AuthEnvelopedData instead of EnvelopedData (using --aead value, not --enc)
///   -c, --ee-cert-file <EE_CERT_FILE>  File that contains a DER-encoded certificate containing public key to use to encrypt data
///   -u, --ukm <UKM>                    String value to use as UserKeyingMaterial to provide context for the KDF
///
/// Decryption:
///   -k, --ee-key-file <EE_KEY_FILE>  File that contains a private key used to decrypt data as a DER-encoded OneAsymmetricKey
/// ```
#[allow(rustdoc::bare_urls)]
#[derive(Parser, Debug, Default)]
#[command(author, version, about = "", long_about = "")]
pub struct KemriToyArgs {
    /// Folder to which generated certificates, keys, EnvelopedData objects, and non-default decrypted payloads should be written
    #[clap(long, short, help_heading = "Common")]
    pub output_folder: Option<PathBuf>,
    /// Full path and filename of YAML-formatted configuration file for log4rs logging mechanism.
    /// See https://docs.rs/log4rs/latest/log4rs/ for details.
    #[clap(short, long, help_heading = "Common")]
    pub logging_config: Option<String>,
    /// When encrypting, file that contains data to encrypt (abc is used when absent). When decrypting, file that contains
    /// DER-encoded EnvelopedData or AuthEnvelopedData object.
    #[clap(long, short, help_heading = "Common")]
    pub input_file: Option<PathBuf>,

    /// KEM algorithm to use when generating fresh keys, i.e., when encrypting and no ee_cert_file was provided
    #[clap(long, default_value_t, help_heading = "Encryption")]
    pub kem: KemAlgorithms,
    /// KDF algorithm to use when preparing an EnvelopedData or AuthEnvelopedData object
    #[clap(long, default_value_t, help_heading = "Encryption")]
    pub kdf: KdfAlgorithms,
    /// Symmetric encryption algorithm to use when preparing an EnvelopedData object
    #[clap(
        long,
        default_value_t,
        help_heading = "Encryption",
        conflicts_with = "aead"
    )]
    pub enc: EncAlgorithms,
    /// AEAD encryption algorithm to use when preparing an AuthEnvelopedData object
    #[clap(
        long,
        default_value_t,
        help_heading = "Encryption",
        conflicts_with = "enc"
    )]
    pub aead: AeadAlgorithms,
    /// Generate AuthEnvelopedData instead of EnvelopedData (using --aead value, not --enc)
    #[clap(
        action,
        long,
        short,
        conflicts_with = "enc",
        help_heading = "Encryption"
    )]
    pub auth_env_data: bool,
    /// File that contains a DER-encoded certificate containing public key to use to encrypt data
    #[clap(
        long,
        short = 'c',
        conflicts_with = "ee_key_file",
        help_heading = "Encryption"
    )]
    pub ee_cert_file: Option<PathBuf>,
    /// String value to use as UserKeyingMaterial to provide context for the KDF
    #[clap(short, long, help_heading = "Encryption")]
    pub ukm: Option<String>,

    /// File that contains a DER-encoded OneAsymmetricKey private key to use when decrypting data
    #[clap(
        long,
        short = 'k',
        conflicts_with = "ee_cert_file",
        conflicts_with = "kem",
        conflicts_with = "kdf",
        conflicts_with = "enc",
        conflicts_with = "aead",
        conflicts_with = "auth_env_data",
        conflicts_with = "ee_cert_file",
        conflicts_with = "ukm",
        help_heading = "Decryption"
    )]
    pub ee_key_file: Option<PathBuf>,

    /// Signature algorithm to use when preparing a certificate or SignedData object
    #[clap(
        long,
        default_value_t,
        help_heading = "Signing",
        conflicts_with = "enc",
        conflicts_with = "aead",
        conflicts_with = "kem",
        conflicts_with = "auth_env_data",
        conflicts_with = "ukm"
    )]
    pub sig: SigAlgorithms,

    /// File that contains a DER-encoded OneAsymmetricKey private key to use when generating a certificate
    #[clap(
        long,
        conflicts_with = "ee_cert_file",
        conflicts_with = "kem",
        conflicts_with = "kdf",
        conflicts_with = "enc",
        conflicts_with = "aead",
        conflicts_with = "auth_env_data",
        conflicts_with = "ee_cert_file",
        conflicts_with = "ukm",
        conflicts_with = "ee_key_file",
        help_heading = "Certificate Generation"
    )]
    pub pub_key_file: Option<PathBuf>,

    /// Generate a certificate from a public key (so all the other stuff can work)
    #[clap(
        action,
        long,
        short,
        conflicts_with = "ee_cert_file",
        conflicts_with = "kem",
        conflicts_with = "kdf",
        conflicts_with = "enc",
        conflicts_with = "aead",
        conflicts_with = "auth_env_data",
        conflicts_with = "ee_cert_file",
        conflicts_with = "ukm",
        conflicts_with = "ee_key_file",
        help_heading = "Certificate Processing"
    )]
    pub generate_cert: bool,

    /// Generate a SignedData using the given private key
    #[clap(
        action,
        long,
        conflicts_with = "ee_cert_file",
        conflicts_with = "kem",
        conflicts_with = "kdf",
        conflicts_with = "enc",
        conflicts_with = "aead",
        conflicts_with = "auth_env_data",
        conflicts_with = "ee_cert_file",
        conflicts_with = "ukm",
        conflicts_with = "ee_key_file",
        help_heading = "Signed Data Processing"
    )]
    pub generate_signed_data: bool,

    /// Generate a certificate from --pub-key-file, if present, or a freshly generated public key
    #[clap(
        action,
        long,
        short,
        requires = "input_file",
        help_heading = "Signed Data Processing"
    )]
    pub verify_signed_data: bool,

    /// Generate a certificate from --pub-key-file, if present, or a freshly generated public key
    #[clap(
        action,
        long,
        requires = "ee_cert_file",
        requires = "input_file",
        help_heading = "Common"
    )]
    pub check_private_key: bool,
}
