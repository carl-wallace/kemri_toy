#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
// todo - restore this (and remove various allow(dead_code) instances)
// clippy::unwrap_used

mod args;
mod asn1;
#[macro_use]
mod misc;
mod error;
mod pqc;

use certval::PkiEnvironment;
pub use error::Result;
pub use misc::gen_certs::buffer_to_hex;
pub use misc::utils::recipient_identifier_from_cert;

use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use clap::Parser;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use log::{debug, error};

use der::{Decode, DecodePem, Encode};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfoOwned};

use crate::misc::logging::configure_logging;
use crate::misc::signed_data::{
    check_message_digest_attr, get_candidate_signer_cert, get_encap_content, get_signed_data,
    hash_content,
};
use crate::{
    args::KemriToyArgs,
    asn1::private_key::{
        MlDsa44Both, MlDsa44Expanded, MlDsa44PrivateKey, MlDsa65Both, MlDsa65Expanded,
        MlDsa65PrivateKey, MlDsa87Both, MlDsa87Expanded, MlDsa87PrivateKey, MlDsaSeed,
    },
    misc::{
        check_private_key::check_private_key,
        gen_certs::{generate_ml_kem_cert, generate_pki, generate_ta},
        utils::{
            generate_auth_enveloped_data, generate_enveloped_data, get_buffer_from_file_arg,
            get_cert_from_file_arg, process_content_info,
        },
    },
};
use error::Error;
use misc::algs::{KemAlgorithms, SigAlgorithms};
use pqckeys::oak::{OneAsymmetricKey, PrivateKey};

/// kemri_toy implementation
#[tokio::main]
async fn main() -> Result<()> {
    let mut args = KemriToyArgs::parse();
    configure_logging(&args);

    if args.verify_signed_data {
        let input_file = match get_buffer_from_file_arg(&args.input_file) {
            Ok(input_file) => input_file,
            Err(e) => {
                error!("input_file must be provided and exist: {e:?}");
                return Err(e);
            }
        };
        let ci = ContentInfo::from_der(&input_file)?;
        let sd = SignedData::from_der(&ci.content.to_der()?)?;

        let xml = match get_encap_content(&sd.encap_content_info) {
            Ok(xml) => xml,
            Err(e) => {
                error!("Failed to read encapsulated content from request: {e:?}");
                return Err(e);
            }
        };

        let hashes = hash_content(&sd, &xml)?;

        let mut pe = PkiEnvironment::default();
        pe.populate_5280_pki_environment();

        let (_intermediate_ca_certs, leaf_cert) = get_candidate_signer_cert(&sd)?;
        for si in sd.signer_infos.0.iter() {
            if check_message_digest_attr(&hashes, si).is_err() {
                continue;
            }

            let data_to_verify = si.signed_attrs.to_der()?;
            match pe.verify_signature_message(
                &pe,
                &data_to_verify[..],
                si.signature.as_bytes(),
                &si.signature_algorithm,
                leaf_cert.tbs_certificate().subject_public_key_info(),
            ) {
                Ok(_) => {
                    println!(
                        "Signature verification succeeded for {:?}.",
                        args.input_file
                    );
                    return Ok(());
                }
                Err(e) => {
                    println!(
                        "Signature verification failed for {:?}: {e:?}.",
                        args.input_file
                    );
                    return Err(Error::Unrecognized);
                }
            }
        }
        println!("Signature verification failed for {:?}.", args.input_file);
        return Err(Error::Unrecognized);
    }

    let mut output_folder = args.output_folder.unwrap_or_default();
    if !output_folder.exists() {
        error!("Specified output_folder does not exist. Using current directory.");
        output_folder = PathBuf::from(".");
    }

    if args.pub_key_file.is_some() {
        let public_key_bytes = match get_buffer_from_file_arg(&args.pub_key_file) {
            Ok(public_key_bytes) => {
                if public_key_bytes[0] == 0x30 {
                    public_key_bytes
                } else {
                    let sk = SubjectPublicKeyInfoOwned::from_pem(&public_key_bytes)?;
                    sk.to_der()?
                }
            }
            Err(e) => {
                error!("pub_key_file must be provided and exist: {e:?}");
                return Err(e);
            }
        };

        let spki = SubjectPublicKeyInfoOwned::from_der(&public_key_bytes)?;
        let pk = match spki.subject_public_key.as_bytes() {
            Some(pk) => pk,
            None => {
                error!(
                    "Failed to read public key from SubjectPublicKeyInfo read from pub_key_file"
                );
                return Err(Error::Unrecognized);
            }
        };
        let kem = KemAlgorithms::from_oid(spki.algorithm.oid)?;

        let ta_key_file = output_folder.join("ta.der");
        let ta_cert_file = output_folder.join("ta.der");
        let (signer, ta_cert) =
            if Path::new(&ta_key_file).exists() && Path::new(&ta_cert_file).exists() {
                // let ta_cert = get_cert_from_file_arg(&Some(ta_cert_file))?;
                // let public_key_bytes = match ta_cert
                //     .tbs_certificate()
                //     .subject_public_key_info()
                //     .subject_public_key
                //     .as_bytes()
                // {
                //     Some(pk) => pk,
                //     None => {
                //         error!(
                //             "Failed to read public key from SubjectPublicKeyInfo read from ta.der"
                //         );
                //         return Err(Error::Unrecognized);
                //     }
                // };
                // let key_bytes = get_buffer_from_file_arg(&Some(ta_key_file))?;

                // let public_key = mldsa44::PublicKey::from_bytes(public_key_bytes)?;
                // let secret_key = mldsa44::SecretKey::from_bytes(&key_bytes)?;
                // let signer = Mldsa44KeyPair {
                //     public_key: Mldsa44PublicKey(public_key),
                //     secret_key,
                // };
                // (signer, ta_cert)
                todo!("deserialize TA")
            } else {
                let (signer, ta_cert) = match generate_ta(&args.sig) {
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
                (signer, ta_cert)
            };
        let cert = generate_ml_kem_cert(&signer, &ta_cert, pk, kem.clone())?;
        let mut ta_file = File::create(output_folder.join(format!("{kem}_cert.der")))?;
        let _ = ta_file.write_all(&cert.to_der()?);
        return Ok(());
    }

    if args.generate_cert {
        let (signer, ta_cert) = match generate_ta(&args.sig) {
            Ok((signer, ta_cert)) => (signer, ta_cert),
            Err(e) => {
                error!("Failed to generate TA cert: {e:?}");
                return Err(e);
            }
        };

        if args.generate_signed_data {
            let plaintext = get_buffer_from_file_arg(&args.input_file)
                .unwrap_or_else(|_e| "abc".as_bytes().to_vec());

            let signed_data = get_signed_data(&signer, &ta_cert, &plaintext, None, true)?;
            let mut signed_data_file =
                File::create(output_folder.join(format!("{}_signed.bin", args.sig.filename())))?;
            let _ = signed_data_file.write_all(&signed_data);
        }

        let seed = signer.seed.clone();
        let private_key = signer.private_key();
        let private_key_bytes = match &args.sig {
            SigAlgorithms::MlDsa44 => {
                let pk = MlDsa44PrivateKey::ExpandedKey(
                    MlDsa44Expanded::new(private_key.clone())
                        .map_err(|e| Error::MlKem(format!("{e:?}")))?,
                );
                pk.to_der()?
            }
            SigAlgorithms::MlDsa65 => {
                let pk = MlDsa65PrivateKey::ExpandedKey(
                    MlDsa65Expanded::new(private_key.clone())
                        .map_err(|e| Error::MlKem(format!("{e:?}")))?,
                );
                pk.to_der()?
            }
            SigAlgorithms::MlDsa87 => {
                let pk = MlDsa87PrivateKey::ExpandedKey(
                    MlDsa87Expanded::new(private_key.clone())
                        .map_err(|e| Error::MlKem(format!("{e:?}")))?,
                );
                pk.to_der()?
            }
            _ => private_key.clone(),
        };

        let oak_leaf = OneAsymmetricKey {
            version: pqckeys::oak::Version::V1, // V1 per rfc5958 section 2
            private_key_alg: AlgorithmIdentifier {
                oid: args.sig.oid(),
                parameters: None, // Params absent for Kyber keys per draft-ietf-lamps-mlkem-certificates-02 section 6
            },
            private_key: PrivateKey::new(private_key_bytes)?,
            attributes: None,
            public_key: None,
        };
        let der_oak = oak_leaf
            .to_der()
            .expect("Failed to encode private key as OneAsymmetricKey");

        let mut ta_file =
            File::create(output_folder.join(format!("{}_ta.der", args.sig.filename())))?;
        let _ = ta_file.write_all(&ta_cert.to_der()?);

        if !signer.seed.is_empty() {
            let mut ta_file = File::create(
                output_folder.join(format!("{}_expandedkey_priv.der", args.sig.filename())),
            )?;
            let _ = ta_file.write_all(&der_oak);

            let private_key_bytes_seed = match args.sig {
                SigAlgorithms::MlDsa44 => {
                    let pk = MlDsa44PrivateKey::Seed(
                        MlDsaSeed::new(seed.clone()).map_err(|e| Error::MlKem(format!("{e:?}")))?,
                    );
                    pk.to_der()?
                }
                SigAlgorithms::MlDsa65 => {
                    let pk = MlDsa65PrivateKey::Seed(
                        MlDsaSeed::new(seed.clone()).map_err(|e| Error::MlKem(format!("{e:?}")))?,
                    );
                    pk.to_der()?
                }
                SigAlgorithms::MlDsa87 => {
                    let pk = MlDsa87PrivateKey::Seed(
                        MlDsaSeed::new(seed.clone()).map_err(|e| Error::MlKem(format!("{e:?}")))?,
                    );
                    pk.to_der()?
                }
                _ => {
                    vec![]
                }
            };

            let oak_leaf_seed = OneAsymmetricKey {
                version: pqckeys::oak::Version::V1, // V1 per rfc5958 section 2
                private_key_alg: AlgorithmIdentifier {
                    oid: args.sig.oid(),
                    parameters: None, // Params absent for Kyber keys per draft-ietf-lamps-mlkem-certificates-02 section 6
                },
                private_key: PrivateKey::new(private_key_bytes_seed)?,
                attributes: None,
                public_key: None,
            };
            let der_oak_seed = oak_leaf_seed
                .to_der()
                .expect("Failed to encode private key as OneAsymmetricKey");

            let mut ee_key_file =
                File::create(output_folder.join(format!("{}_seed_priv.der", args.sig.filename())))?;
            let _ = ee_key_file.write_all(&der_oak_seed);

            let private_key_bytes_both = match args.sig {
                SigAlgorithms::MlDsa44 => {
                    let pk = MlDsa44Both {
                        seed: MlDsaSeed::new(seed).map_err(|e| Error::MlKem(format!("{e:?}")))?,
                        expanded_key: MlDsa44Expanded::new(private_key)
                            .map_err(|e| Error::MlKem(format!("{e:?}")))?,
                    };
                    pk.to_der()?
                }
                SigAlgorithms::MlDsa65 => {
                    let pk = MlDsa65Both {
                        seed: MlDsaSeed::new(seed).map_err(|e| Error::MlKem(format!("{e:?}")))?,
                        expanded_key: MlDsa65Expanded::new(private_key)
                            .map_err(|e| Error::MlKem(format!("{e:?}")))?,
                    };
                    pk.to_der()?
                }
                SigAlgorithms::MlDsa87 => {
                    let pk = MlDsa87Both {
                        seed: MlDsaSeed::new(seed).map_err(|e| Error::MlKem(format!("{e:?}")))?,
                        expanded_key: MlDsa87Expanded::new(private_key)
                            .map_err(|e| Error::MlKem(format!("{e:?}")))?,
                    };
                    pk.to_der()?
                }
                _ => {
                    vec![]
                }
            };

            let oak_leaf_both = OneAsymmetricKey {
                version: pqckeys::oak::Version::V1, // V1 per rfc5958 section 2
                private_key_alg: AlgorithmIdentifier {
                    oid: args.sig.oid(),
                    parameters: None, // Params absent for Kyber keys per draft-ietf-lamps-mlkem-certificates-02 section 6
                },
                private_key: PrivateKey::new(private_key_bytes_both)?,
                attributes: None,
                public_key: None,
            };
            let der_oak_both = oak_leaf_both
                .to_der()
                .expect("Failed to encode private key as OneAsymmetricKey");

            let mut ee_key_file =
                File::create(output_folder.join(format!("{}_both_priv.der", args.sig.filename())))?;
            let _ = ee_key_file.write_all(&der_oak_both);
        } else {
            let mut ta_file =
                File::create(output_folder.join(format!("{}_priv.der", args.sig.filename())))?;
            let _ = ta_file.write_all(&der_oak);
        }

        return Ok(());
    }

    if args.check_private_key {
        let input_file = match get_buffer_from_file_arg(&args.input_file) {
            Ok(input_file) => input_file,
            Err(e) => {
                error!("input-file must be provided and exist: {e:?}");
                return Err(e);
            }
        };
        let cert = match get_cert_from_file_arg(&args.ee_cert_file) {
            Ok(cert) => cert,
            Err(e) => {
                error!("ee-cert-file must be provided and exist: {e:?}");
                return Err(e);
            }
        };
        let input_file_name = args
            .input_file
            .unwrap_or_default()
            .into_os_string()
            .into_string()
            .unwrap_or_default();
        check_private_key(
            &input_file,
            cert.tbs_certificate().subject_public_key_info(),
            &input_file_name,
        )?;
        return Ok(());
    }

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

        let input_filename = match &args.input_file {
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
            println!("Decrypted data from {input_filename} written to: {filename}");
        }
    } else {
        let cert_arg = match get_cert_from_file_arg(&args.ee_cert_file) {
            Ok(cert) => {
                args.kem = match KemAlgorithms::from_oid(
                    cert.tbs_certificate()
                        .subject_public_key_info()
                        .algorithm
                        .oid,
                ) {
                    Ok(ka) => ka,
                    Err(e) => {
                        error!(
                            "Unrecognized KEM algorithm in ee_cert_file: {}",
                            cert.tbs_certificate()
                                .subject_public_key_info()
                                .algorithm
                                .oid
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
            let kem_from_cert = KemAlgorithms::from_oid(
                cert.tbs_certificate()
                    .subject_public_key_info()
                    .algorithm
                    .oid,
            )?;

            let output_file_name = match &ukm {
                Some(_) => format!(
                    "{}_kemri_auth_{}_ukm.der",
                    kem_from_cert.filename(),
                    args.kdf.filename()
                ),
                None => format!(
                    "{}_kemri_auth_{}.der",
                    kem_from_cert.filename(),
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
