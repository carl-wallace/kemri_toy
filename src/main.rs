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
    Spki(spki::Error),
    Pkcs8(rsa::pkcs8::Error),
    Pkcs1(rsa::pkcs1::Error),
    Rsa,
}
impl From<rsa::Error> for Error {
    fn from(err: rsa::Error) -> Error {
        error!("rsa::Error: {err:?}");
        Error::Rsa
    }
}
impl From<rsa::pkcs1::Error> for Error {
    fn from(err: rsa::pkcs1::Error) -> Error {
        Error::Pkcs1(err)
    }
}
impl From<rsa::pkcs8::Error> for Error {
    fn from(err: rsa::pkcs8::Error) -> Error {
        Error::Pkcs8(err)
    }
}
impl From<spki::Error> for Error {
    fn from(err: spki::Error) -> Error {
        Error::Spki(err)
    }
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

/// From PQC Certificate hackathon's [OID mapping](https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oid_mapping.md)
pub const ML_DSA_44_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.12.4.4");

/// From PQC Certificate hackathon's [OID mapping](https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oid_mapping.md)
pub const ML_KEM_512_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.22554.5.6.1");
/// From PQC Certificate hackathon's [OID mapping](https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oid_mapping.md)
pub const ML_KEM_768_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.22554.5.6.2");
/// From PQC Certificate hackathon's [OID mapping](https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oid_mapping.md)
pub const ML_KEM_1024_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.22554.5.6.3");

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

/// From [draft-ietf-lamps-cms-sha3-hash Section 5.1]
/// ```text
///    id-alg-hkdf-with-sha3-224 OBJECT IDENTIFIER ::= { id-alg TBD1 }
// ```
/// [draft-ietf-lamps-cms-sha3-hash Section 5.1]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sha3-hash-04#section-5.1
pub const ID_ALG_HKDF_WITH_SHA3_224: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.96");

/// From [draft-ietf-lamps-cms-sha3-hash Section 5.1]
/// ```text
///    id-alg OBJECT IDENTIFIER ::= { iso(1) member-body(2)
///        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) 3 }
///    id-alg-hkdf-with-sha3-256 OBJECT IDENTIFIER ::= { id-alg TBD2 }
/// ```
/// [draft-ietf-lamps-cms-sha3-hash Section 5.1]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sha3-hash-04#section-5.1
pub const ID_ALG_HKDF_WITH_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.97");

/// From [draft-ietf-lamps-cms-sha3-hash Section 5.1]
/// ```text
///    id-alg-hkdf-with-sha3-384 OBJECT IDENTIFIER ::= { id-alg TBD3 }
/// ```
/// [draft-ietf-lamps-cms-sha3-hash Section 5.1]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sha3-hash-04#section-5.1
pub const ID_ALG_HKDF_WITH_SHA3_384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.98");

/// From [draft-ietf-lamps-cms-sha3-hash Section 5.1]
/// ```text
///    id-alg-hkdf-with-sha3-512 OBJECT IDENTIFIER ::= { id-alg TBD4 }
/// ```
/// [draft-ietf-lamps-cms-sha3-hash Section 5.1]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sha3-hash-04#section-5.1
pub const ID_ALG_HKDF_WITH_SHA3_512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.99");

/// From [draft-ietf-lamps-cms-sha3-hash Section 2]
/// ```text
///    id-sha3-224 OBJECT IDENTIFIER ::= { hashAlgs 7 }
/// ```
/// [draft-ietf-lamps-cms-sha3-hash Section 2]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sha3-hash-04#section-2
pub const ID_SHA3_224: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.7");

/// From [draft-ietf-lamps-cms-sha3-hash Section 2]
/// ```text
///    hashAlgs OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16)
///        us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) 2 }
///    id-sha3-256 OBJECT IDENTIFIER ::= { hashAlgs 8 }
/// ```
/// [draft-ietf-lamps-cms-sha3-hash Section 2]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sha3-hash-04#section-2
pub const ID_SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");

/// From [draft-ietf-lamps-cms-sha3-hash Section 2]
/// ```text
///    id-sha3-384 OBJECT IDENTIFIER ::= { hashAlgs 9 }
/// ```
/// [draft-ietf-lamps-cms-sha3-hash Section 2]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sha3-hash-04#section-2
pub const ID_SHA3_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.9");

/// From [draft-ietf-lamps-cms-sha3-hash Section 2]
/// ```text
///    id-sha3-512 OBJECT IDENTIFIER ::= { hashAlgs 10 }
/// ```
/// [draft-ietf-lamps-cms-sha3-hash Section 2]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sha3-hash-04#section-2
pub const ID_SHA3_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.10");

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
            let filename = format!("decrypted_{input_filename}.bin");

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
