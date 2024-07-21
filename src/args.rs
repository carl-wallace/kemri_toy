//! Arguments for the `kemri_toy` utility

use core::fmt;
use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};

use const_oid::{
    db::rfc5911::{
        ID_AES_128_CBC, ID_AES_128_GCM, ID_AES_128_WRAP, ID_AES_192_CBC, ID_AES_192_WRAP,
        ID_AES_256_CBC, ID_AES_256_GCM, ID_AES_256_WRAP,
    },
    ObjectIdentifier,
};

use crate::asn1::composite::{ML_KEM_512_RSA2048, ML_KEM_512_RSA3072};
use crate::misc::utils::get_filename_from_oid;
use crate::{
    Error, Result, ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384, ID_ALG_HKDF_WITH_SHA512,
    ID_KMAC128, ID_KMAC256, ML_KEM_1024_IPD, ML_KEM_512_IPD, ML_KEM_768_IPD,
};

/// KEM algorithms available via command line argument
#[derive(Clone, Serialize, Deserialize, Debug, Default, clap::ValueEnum)]
pub enum KemAlgorithms {
    #[default]
    MlKem512,
    MlKem768,
    MlKem1024,
    MlKem512Rsa2048,
    MlKem512Rsa3072,
}
impl fmt::Display for KemAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KemAlgorithms::MlKem512 => write!(f, "ml-kem512"),
            KemAlgorithms::MlKem768 => write!(f, "ml-kem768"),
            KemAlgorithms::MlKem1024 => write!(f, "ml-kem1024"),
            KemAlgorithms::MlKem512Rsa2048 => write!(f, "ml-kem1024;rsa2048"),
            KemAlgorithms::MlKem512Rsa3072 => write!(f, "ml-kem1024;rsa3072"),
        }
    }
}

impl KemAlgorithms {
    /// Get KemAlgorithms instance from an object identifier.
    pub fn from_oid(oid: ObjectIdentifier) -> Result<KemAlgorithms> {
        match oid {
            ML_KEM_512_IPD => Ok(KemAlgorithms::MlKem512),
            ML_KEM_768_IPD => Ok(KemAlgorithms::MlKem768),
            ML_KEM_1024_IPD => Ok(KemAlgorithms::MlKem1024),
            ML_KEM_512_RSA2048 => Ok(KemAlgorithms::MlKem512Rsa2048),
            ML_KEM_512_RSA3072 => Ok(KemAlgorithms::MlKem512Rsa3072),
            _ => Err(Error::Unrecognized),
        }
    }

    /// Get object identifier from KemAlgorithms instance.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            KemAlgorithms::MlKem512 => ML_KEM_512_IPD,
            KemAlgorithms::MlKem768 => ML_KEM_768_IPD,
            KemAlgorithms::MlKem1024 => ML_KEM_1024_IPD,
            KemAlgorithms::MlKem512Rsa2048 => ML_KEM_512_RSA2048,
            KemAlgorithms::MlKem512Rsa3072 => ML_KEM_512_RSA3072,
        }
    }

    /// Get filename component for KemAlgorithms instance.
    pub fn filename(&self) -> String {
        match self {
            KemAlgorithms::MlKem512 => format!(
                "{}_{}",
                ML_KEM_512_IPD,
                get_filename_from_oid(ML_KEM_512_IPD)
            ),
            KemAlgorithms::MlKem768 => format!(
                "{}_{}",
                ML_KEM_768_IPD,
                get_filename_from_oid(ML_KEM_768_IPD)
            ),
            KemAlgorithms::MlKem1024 => format!(
                "{}_{}",
                ML_KEM_1024_IPD,
                get_filename_from_oid(ML_KEM_1024_IPD)
            ),
            KemAlgorithms::MlKem512Rsa2048 => format!(
                "{}_{}",
                ML_KEM_512_RSA2048,
                get_filename_from_oid(ML_KEM_512_RSA2048)
            ),
            KemAlgorithms::MlKem512Rsa3072 => format!(
                "{}_{}",
                ML_KEM_512_RSA3072,
                get_filename_from_oid(ML_KEM_512_RSA3072)
            ),
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
}
