use crate::error::{Error, Result};
use crate::pqc::signer::get_hash_alg;
use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo};
use const_oid::ObjectIdentifier;
use const_oid::db::rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_SUBJECT_KEY_IDENTIFIER};
use const_oid::db::rfc5911::ID_MESSAGE_DIGEST;
use der::asn1::OctetString;
use der::{Any, AnyRef, Decode, Encode, Tag};
use log::error;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::{Keypair, Signer};
use spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    SignatureBitStringEncoding,
};
use std::collections::BTreeMap;
use x509_cert::Certificate;
use x509_cert::ext::pkix::{BasicConstraints, SubjectKeyIdentifier};

pub fn get_signed_data<S, Signature>(
    signer: &S,
    signers_cert: &Certificate,
    data_to_sign: &[u8],
    encap_type: Option<ObjectIdentifier>,
    use_skid: bool,
) -> Result<Vec<u8>>
where
    S: Keypair + DynSignatureAlgorithmIdentifier + Signer<Signature>,
    <S as Keypair>::VerifyingKey: EncodePublicKey,
    Signature: SignatureBitStringEncoding,
{
    let econtent_type = encap_type.unwrap_or(const_oid::db::rfc5911::ID_DATA);

    let content = EncapsulatedContentInfo {
        econtent_type,
        econtent: Some(Any::new(Tag::OctetString, data_to_sign)?),
    };

    let signature_alg = signer
        .signature_algorithm_identifier()
        .map_err(|e| Error::Misc(format!("{e:?}")))?;
    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: get_hash_alg(signature_alg.oid)?,
        parameters: Some(Any::from(AnyRef::NULL)),
    };

    let si = signer_identifier_from_cert(signers_cert, use_skid)?;

    let external_message_digest = None;
    let signer_info_builder_1 = match SignerInfoBuilder::new(
        si,
        digest_algorithm.clone(),
        &content,
        external_message_digest,
    ) {
        Ok(sib) => sib,
        Err(e) => {
            error!("Failed to create SignerInfoBuilder: {e:?}");
            return Err(Error::Unrecognized);
        }
    };

    let mut builder = SignedDataBuilder::new(&content);

    let signed_data_pkcs7 = builder
        .add_digest_algorithm(digest_algorithm)
        .map_err(|_err| Error::Unrecognized)?
        .add_certificate(CertificateChoices::Certificate(signers_cert.clone()))
        .map_err(|_err| Error::Unrecognized)?
        .add_signer_info(signer_info_builder_1, signer)
        .map_err(|_err| Error::Unrecognized)?
        .build()
        .map_err(|_err| Error::Unrecognized)?;

    let signed_data_pkcs7_der = match signed_data_pkcs7.to_der() {
        Ok(d) => d,
        Err(e) => {
            error!("Failed to encoded SignedData: {e:?}");
            return Err(Error::Asn1(e));
        }
    };
    Ok(signed_data_pkcs7_der)
}

pub fn signer_identifier_from_cert(cert: &Certificate, use_skid: bool) -> Result<SignerIdentifier> {
    if use_skid {
        let skid_bytes = skid_from_cert(cert)?;
        let os = match OctetString::new(skid_bytes) {
            Ok(os) => os,
            Err(e) => return Err(Error::Asn1(e)),
        };
        let skid = SubjectKeyIdentifier::from(os);

        Ok(SignerIdentifier::SubjectKeyIdentifier(skid))
    } else {
        let ias = IssuerAndSerialNumber {
            issuer: cert.tbs_certificate().issuer().clone(),
            serial_number: cert.tbs_certificate().serial_number().clone(),
        };
        Ok(SignerIdentifier::IssuerAndSerialNumber(ias))
    }
}

pub fn skid_from_cert(cert: &Certificate) -> Result<Vec<u8>> {
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

    let working_spki = cert.tbs_certificate().subject_public_key_info();
    match working_spki.subject_public_key.as_bytes() {
        Some(spki) => Ok(Sha256::digest(spki).to_vec()),
        None => {
            error!("Failed to render SPKI as bytes");
            Err(Error::Unrecognized)
        }
    }
}

pub fn get_candidate_signer_cert(sd: &SignedData) -> Result<(Vec<Certificate>, Certificate)> {
    let mut cas = vec![];
    let mut candidate_signer_cert = None;

    match &sd.certificates {
        Some(certs) => {
            for cert_choice in certs.0.iter() {
                match cert_choice {
                    CertificateChoices::Certificate(cert) => {
                        if is_ca(cert) {
                            cas.push(cert.clone());
                        } else {
                            candidate_signer_cert = Some(cert.clone());
                        }
                    }
                    _ => {
                        error!(
                            "SignedData contains unrecognized certificate choice type. Ignoring."
                        );
                    }
                }
            }
        }
        None => {
            error!("SignedData does not contain any certificates");
            return Err(Error::Unrecognized);
        }
    }

    match candidate_signer_cert {
        Some(cert) => Ok((cas, cert)),
        None => {
            error!("SignedData does not contain any end entity certificates");
            match cas.first() {
                Some(c) => Ok((cas.clone(), c.clone())),
                None => Err(Error::Unrecognized),
            }
        }
    }
}

pub(crate) fn is_ca(cert: &Certificate) -> bool {
    if let Some(exts) = cert.tbs_certificate().extensions() {
        if let Some(i) = exts
            .iter()
            .find(|&ext| ext.extn_id == ID_CE_BASIC_CONSTRAINTS)
        {
            let v = i.extn_value.as_bytes();
            return match BasicConstraints::from_der(v) {
                Ok(bc) => bc.ca,
                Err(_) => false,
            };
        }
    }
    false
}

pub fn get_encap_content(eci: &EncapsulatedContentInfo) -> Result<Vec<u8>> {
    let encap = match &eci.econtent {
        Some(e) => e,
        None => return Err(Error::Unrecognized),
    };

    let enc_os = encap.to_der()?;
    let os = OctetString::from_der(&enc_os)?;
    Ok(os.as_bytes().to_vec())
}

pub fn hash_content(
    sd: &SignedData,
    content: &[u8],
) -> Result<BTreeMap<ObjectIdentifier, Vec<u8>>> {
    let mut map = BTreeMap::new();
    for alg in sd.digest_algorithms.iter() {
        match alg.oid {
            const_oid::db::rfc5912::ID_SHA_256 => {
                let mut hasher = Sha256::new();
                hasher.update(content);
                let hash = hasher.finalize().to_vec();
                map.insert(alg.oid, hash);
            }
            const_oid::db::rfc5912::ID_SHA_384 => {
                let mut hasher = Sha384::new();
                hasher.update(content);
                let hash = hasher.finalize().to_vec();
                map.insert(alg.oid, hash);
            }
            const_oid::db::rfc5912::ID_SHA_512 => {
                let mut hasher = Sha512::new();
                hasher.update(content);
                let hash = hasher.finalize().to_vec();
                map.insert(alg.oid, hash);
            }
            const_oid::db::fips202::ID_SHAKE_128 => {
                use sha3::{
                    Shake128,
                    digest::{ExtendableOutput, Update, XofReader},
                };
                let mut hasher = Shake128::default();
                hasher.update(content);
                let mut reader = hasher.finalize_xof();
                let mut hash = [0u8; 32];
                reader.read(&mut hash);
                map.insert(alg.oid, hash.to_vec());
            }
            const_oid::db::fips202::ID_SHAKE_256 => {
                use sha3::{
                    Shake256,
                    digest::{ExtendableOutput, Update, XofReader},
                };
                let mut hasher = Shake256::default();
                hasher.update(content);
                let mut reader = hasher.finalize_xof();
                let mut hash = [0u8; 64];
                reader.read(&mut hash);
                map.insert(alg.oid, hash.to_vec());
            }
            _ => {
                error!(
                    "Unexpected hash algorithm found in SignedData::digest_algorithms field: {}",
                    alg.oid
                );
            }
        }
    }
    Ok(map)
}

pub fn check_message_digest_attr(
    hash: &BTreeMap<ObjectIdentifier, Vec<u8>>,
    si: &SignerInfo,
) -> Result<()> {
    let ref_hash = match hash.get(&si.digest_alg.oid) {
        Some(hash) => hash,
        None => {
            error!(
                "No hash value was found for target algorithm {:?}",
                si.digest_alg.oid
            );
            return Err(Error::Unrecognized);
        }
    };
    if let Some(attrs) = &si.signed_attrs {
        for attr in attrs.iter() {
            if attr.oid == ID_MESSAGE_DIGEST {
                for value in attr.values.iter() {
                    if value.value() == ref_hash {
                        return Ok(());
                    }
                }
                error!("Message digest attribute did not contain expected value");
                return Err(Error::Unrecognized);
            }
        }
    }
    error!("No message digest attribute was found");
    Err(Error::Unrecognized)
}
