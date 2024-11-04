#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_qualifications,
    clippy::unwrap_used
)]

mod args;
mod asn1;
#[macro_use]
mod misc;

use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use log::{debug, error, LevelFilter};
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};

use const_oid::ObjectIdentifier;

use crate::{
    args::{KemAlgorithms, KemriToyArgs},
    misc::{
        gen_certs::generate_pki,
        utils::{
            generate_auth_enveloped_data, generate_enveloped_data, get_buffer_from_file_arg,
            get_cert_from_file_arg, process_content_info,
        },
    },
};

/// Result type for kemri_toy
pub type Result<T> = core::result::Result<T, Error>;

/// Error type for kemri_toy
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum Error {
    Unrecognized,
    Asn1(der::Error),
    Builder(String),
    Pqc,
    CertBuilder,
    Io,
}
impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        error!("std::io::Error: {err:?}");
        Error::Io
    }
}
impl From<x509_cert::builder::Error> for Error {
    fn from(err: x509_cert::builder::Error) -> Error {
        error!("x509_cert::builder::Error: {err:?}");
        Error::CertBuilder
    }
}

impl From<pqcrypto_traits::Error> for Error {
    fn from(err: pqcrypto_traits::Error) -> Error {
        error!("pqcrypto_traits::Error: {err:?}");
        Error::Pqc
    }
}

/// OID for the ML-DSA-44 parameter set as defined in [NIST CSOR].
/// ```text
/// id-ml-dsa-44 OBJECT IDENTIFIER ::= { sigAlgs 17 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");

/// OID for the ML-KEM-512 parameter set as defined in [NIST CSOR].
/// ```text
/// id-alg-ml-kem-512 OBJECT IDENTIFIER ::= { sigAlgs 17 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#KEM
pub const ML_KEM_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.1");

/// OID for the ML-KEM-512 parameter set as defined in [NIST CSOR].
/// ```text
/// id-alg-ml-kem-768 OBJECT IDENTIFIER ::= { sigAlgs 17 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#KEM
pub const ML_KEM_768: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.2");

/// OID for the ML-KEM-1024 parameter set as defined in [NIST CSOR].
/// ```text
/// id-alg-ml-kem-1024 OBJECT IDENTIFIER ::= { sigAlgs 17 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#KEM
pub const ML_KEM_1024: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.3");

/// From [draft-ietf-lamps-cms-kemri-07 Section 3]
/// ```text
///   id-ori OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
///     rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) 13 }
///
///   id-ori-kem OBJECT IDENTIFIER ::= { id-ori 3 }
/// ```
/// [draft-ietf-lamps-cms-kemri-07 Section 3]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-kemri-07#section-3
pub const ID_ORI_KEM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.13.3");

/// From [RFC 8619 Section 2]
/// ```text
///   id-alg-hkdf-with-sha256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
///        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 28 }
/// ```
/// [RFC 8619 Section 2]: https://datatracker.ietf.org/doc/html/rfc8619#section-2
pub const ID_ALG_HKDF_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.28");

/// From [RFC 8619 Section 2]
/// ```text
///    id-alg-hkdf-with-sha384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
///        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 29 }
/// ```
/// [RFC 8619 Section 2]: https://datatracker.ietf.org/doc/html/rfc8619#section-2
pub const ID_ALG_HKDF_WITH_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.29");

/// From [RFC 8619 Section 2]
/// ```text
///    id-alg-hkdf-with-sha512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
///        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 30 }
/// ```
/// [RFC 8619 Section 2]: https://datatracker.ietf.org/doc/html/rfc8619#section-2
pub const ID_ALG_HKDF_WITH_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.30");

/// From [draft-ietf-lamps-cms-sha3-hash Section 5.3]
/// ```text
///    hashAlgs OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16)
///        us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) 2 }
///
///    id-kmac128 OBJECT IDENTIFIER ::= { hashAlgs 21 }
/// ```
/// [draft-ietf-lamps-cms-sha3-hash Section 5.3]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sha3-hash-01#section-5.3
pub const ID_KMAC128: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.21");

/// From [draft-ietf-lamps-cms-sha3-hash Section 5.3]
/// ```text
///    hashAlgs OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16)
///        us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) 2 }
///
///    id-kmac256 OBJECT IDENTIFIER ::= { hashAlgs 22 }
/// ```
/// [draft-ietf-lamps-cms-sha3-hash Section 5.3]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sha3-hash-01#section-5.3
pub const ID_KMAC256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.22");

/// kemri_toy implementation
fn main() -> Result<()> {
    let mut args = KemriToyArgs::parse();

    let mut logging_configured = false;

    if let Some(logging_config) = &args.logging_config {
        if let Err(e) = log4rs::init_file(logging_config, Default::default()) {
            println!(
                "ERROR: failed to configure logging using {} with {:?}. Continuing without logging.",
                logging_config, e
            );
        } else {
            logging_configured = true;
        }
    }

    if !logging_configured {
        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new("{m}{n}")))
            .build();
        match Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .build(Root::builder().appender("stdout").build(LevelFilter::Info))
        {
            Ok(config) => {
                let handle = log4rs::init_config(config);
                if let Err(e) = handle {
                    println!(
                        "ERROR: failed to configure logging for stdout with {:?}. Continuing without logging.",
                        e
                    );
                }
            }
            Err(e) => {
                println!("ERROR: failed to prepare default logging configuration with {:?}. Continuing without logging", e);
            }
        }
    }

    let output_folder = match &args.output_folder {
        Some(of) => {
            if of.exists() {
                of.clone()
            } else {
                error!("Specified output_folder does not exist. Using current directory.");
                PathBuf::from(".")
            }
        }
        None => PathBuf::from("."),
    };

    if args.ee_key_file.is_some() {
        let private_key_bytes = match get_buffer_from_file_arg(&args.ee_key_file) {
            Ok(private_key_bytes) => private_key_bytes,
            Err(e) => {
                error!("ee_key_file must be provided and exist: {e:?}");
                return Err(e);
            }
        };
        let input_file = match get_buffer_from_file_arg(&args.input_file) {
            Ok(input_file) => input_file,
            Err(e) => {
                error!("input_file must be provided and exist: {e:?}");
                return Err(e);
            }
        };

        let recovered = match process_content_info(&input_file, &private_key_bytes) {
            Ok(recovered) => recovered,
            Err(e) => {
                error!("Failed to process input_file: {e:?}");
                return Err(e);
            }
        };

        let input_filename = match args.input_file {
            Some(input_file) => input_file
                .file_name()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default()
                .to_string(),
            None => "".to_string(),
        };

        if "abc".as_bytes() == recovered {
            println!(
                "Decrypted default data from {}: {}",
                input_filename,
                std::str::from_utf8(&recovered).unwrap_or_default()
            );
        } else {
            let filename = format!("decrypted_{input_filename}.der");

            let mut ee_key_file = File::create(output_folder.join(&filename))?;
            let _ = ee_key_file.write_all(&recovered);
            println!(
                "Decrypted data from {} written to: {filename}",
                input_filename
            );
        }
    } else {
        let cert_arg = match get_cert_from_file_arg(&args.ee_cert_file) {
            Ok(cert) => {
                args.kem = match KemAlgorithms::from_oid(
                    cert.tbs_certificate.subject_public_key_info.algorithm.oid,
                ) {
                    Ok(ka) => ka,
                    Err(e) => {
                        error!(
                            "Unrecognized KEM algorithm in ee_cert_file: {}",
                            cert.tbs_certificate.subject_public_key_info.algorithm.oid
                        );
                        return Err(e);
                    }
                };
                Some(cert)
            }
            Err(e) => {
                debug!("Failed to open ee_cert_file: {e:?}. Generating new and continuing...");
                None
            }
        };

        let cert = match &cert_arg {
            Some(cert) => cert.clone(),
            None => generate_pki(&args.kem, &output_folder)?,
        };

        let plaintext = get_buffer_from_file_arg(&args.input_file)
            .unwrap_or_else(|_e| "abc".as_bytes().to_vec());

        let ukm = args.ukm.map(|ukm| ukm.as_bytes().to_vec());

        if args.auth_env_data {
            let output_file_name = match &ukm {
                Some(_) => format!(
                    "{}_kemri_auth_{}_ukm.der",
                    args.kem.filename(),
                    args.kdf.filename()
                ),
                None => format!(
                    "{}_kemri_auth_{}.der",
                    args.kem.filename(),
                    args.kdf.filename()
                ),
            };
            let enveloped_data = generate_auth_enveloped_data(
                &plaintext,
                &cert,
                args.kdf.oid(),
                ukm,
                args.aead.wrap(),
                args.aead.oid(),
            )?;

            let mut ed_file = File::create(output_folder.join(&output_file_name))?;
            let _ = ed_file.write_all(&enveloped_data);
            println!("AuthEnvelopedData written to: {output_file_name}");
        } else {
            let output_file_name = match &ukm {
                Some(_) => format!(
                    "{}_kemri_{}_ukm.der",
                    args.kem.filename(),
                    args.kdf.filename()
                ),
                None => format!("{}_kemri_{}.der", args.kem.filename(), args.kdf.filename()),
            };

            let enveloped_data = generate_enveloped_data(
                &plaintext,
                &cert,
                args.kdf.oid(),
                ukm,
                args.enc.wrap(),
                args.enc.oid(),
            )?;

            let mut ed_file = File::create(output_folder.join(&output_file_name))?;
            let _ = ed_file.write_all(&enveloped_data);
            println!("EnvelopedData written to: {output_file_name}");
        }
    }
    Ok(())
}
