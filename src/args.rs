//! Arguments for the `kemri_toy` utility

use std::path::PathBuf;

use clap::Parser;

use crate::misc::algs::{
    AeadAlgorithms, EncAlgorithms, KdfAlgorithms, KemAlgorithms, SigAlgorithms,
};

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
    /// Log output to the console
    #[clap(
        long,
        short = 'c',
        action,
        help_heading = "Logging",
        conflicts_with = "logging_config"
    )]
    pub log_to_console: bool,

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
    /// Generate a SignedData using the private key from --ee-key-file
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
        help_heading = "Signing"
    )]
    pub generate_signed_data: bool,

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
        help_heading = "Certificate Generation"
    )]
    pub generate_cert: bool,

    /// Perform consistency checks for a private key --input-file and public key from certificate from
    /// --ee-cert-file
    #[clap(
        action,
        long,
        requires = "ee_cert_file",
        requires = "input_file",
        help_heading = "Verification"
    )]
    pub check_private_key: bool,
    /// Verify a SignedData from --input-file
    #[clap(
        action,
        long,
        short,
        requires = "input_file",
        help_heading = "Verification"
    )]
    pub verify_signed_data: bool,
}
