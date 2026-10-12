//! Decode the FalconPrivateKey structure used by other IETF hackathon participants
//! (e.g., BouncyCastle and CHT) for round-3 Falcon private keys, per draft-uni-qsckeys.
//! kemri_toy emits raw fn-dsa signing keys in the OneAsymmetricKey privateKey field (in keeping
//! with the LAMPS preference for carrying raw key bytes rather than per-algorithm ASN.1
//! structures) but accepts this structure when checking keys produced by others:
//!
//! ```text
//! FalconPrivateKey ::= SEQUENCE {
//!     version    INTEGER 0,
//!     f          OCTET STRING,
//!     g          OCTET STRING,
//!     F          OCTET STRING,
//!     publicKey  FalconPublicKey OPTIONAL
//! }
//! FalconPublicKey ::= SEQUENCE { h OCTET STRING }
//! ```
//!
//! The f/g/F fields carry the round-3 reference bit packing, which is identical to the body of
//! an `fn-dsa` crate signing key (header byte `0x50 | logn` followed by f, g and F). The h field
//! is the `fn-dsa` verifying key without its leading header byte (`logn`). Conversion in either
//! direction is therefore concatenation/splitting, with no repacking.

use der::asn1::{ObjectIdentifier, OctetString};
use der::{Decode, Sequence};
use pqckeys::pqc_oids::{
    OQ_FALCON_512, OQ_FALCON_1024, OQ_FALCON_PADDED_512, OQ_FALCON_PADDED_1024,
};

use crate::error::Error;

/// FalconPublicKey per draft-uni-qsckeys
#[derive(Sequence)]
struct FalconPublicKey {
    /// Public key h using the round-3 reference packing (fn-dsa verifying key sans header byte)
    h: OctetString,
}

/// FalconPrivateKey per draft-uni-qsckeys
#[derive(Sequence)]
struct FalconPrivateKey {
    /// Always 0
    version: u8,
    /// Polynomial f using the round-3 reference bit packing
    f: OctetString,
    /// Polynomial g using the round-3 reference bit packing
    g: OctetString,
    /// Polynomial F using the round-3 reference bit packing
    big_f: OctetString,
    /// Optional copy of the public key
    public_key: Option<FalconPublicKey>,
}

/// Returns (logn, f/g length in bytes) for a Falcon OID; F length is `1 << logn`
fn falcon_params(oid: ObjectIdentifier) -> crate::error::Result<(u32, usize)> {
    match oid {
        OQ_FALCON_512 | OQ_FALCON_PADDED_512 => Ok((9, 384)),
        OQ_FALCON_1024 | OQ_FALCON_PADDED_1024 => Ok((10, 640)),
        _ => Err(Error::Builder(format!("Unrecognized Falcon OID: {oid}"))),
    }
}

/// Returns an fn-dsa encoded signing key given the contents of the privateKey field of a
/// OneAsymmetricKey containing a draft-uni-qsckeys FalconPrivateKey
pub(crate) fn fn_dsa_sk_from_falcon_private_key(
    oid: ObjectIdentifier,
    bytes: &[u8],
) -> crate::error::Result<Vec<u8>> {
    let (logn, flen) = falcon_params(oid)?;
    let n = 1usize << logn;
    let fpk = FalconPrivateKey::from_der(bytes)?;
    if fpk.f.as_bytes().len() != flen
        || fpk.g.as_bytes().len() != flen
        || fpk.big_f.as_bytes().len() != n
    {
        return Err(Error::Builder(format!(
            "FalconPrivateKey field lengths ({}, {}, {}) do not match Falcon-{n} ({flen}, {flen}, {n})",
            fpk.f.as_bytes().len(),
            fpk.g.as_bytes().len(),
            fpk.big_f.as_bytes().len()
        )));
    }
    let mut sk = Vec::with_capacity(1 + 2 * flen + n);
    sk.push(0x50 | logn as u8);
    sk.extend_from_slice(fpk.f.as_bytes());
    sk.extend_from_slice(fpk.g.as_bytes());
    sk.extend_from_slice(fpk.big_f.as_bytes());
    Ok(sk)
}

#[cfg(test)]
mod tests {
    use crate::misc::check_private_key::check_private_key;
    use der::Decode;
    use pqckeys::oak::OneAsymmetricKey;
    use x509_cert::Certificate;

    /// Runs the sign/verify consistency check for a OneAsymmetricKey file against the SPKI from
    /// the corresponding certificate file, returning the leading byte of the privateKey contents
    /// so callers can assert which encoding was exercised. Runs on a thread with an 8MB stack:
    /// Falcon signing exceeds the 2MB default given to Rust test threads in debug builds.
    #[allow(clippy::unwrap_used)]
    fn check_pair(priv_path: &str, ta_path: &str) -> u8 {
        let priv_path = priv_path.to_string();
        let ta_path = ta_path.to_string();
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let oak_bytes = std::fs::read(&priv_path).unwrap();
                let oak = OneAsymmetricKey::from_der(&oak_bytes).unwrap();
                let first = oak.private_key.as_bytes()[0];
                let cert = Certificate::from_der(&std::fs::read(&ta_path).unwrap()).unwrap();
                let spki = cert.tbs_certificate().subject_public_key_info().clone();
                assert!(
                    check_private_key(&oak_bytes, &spki, &priv_path).unwrap(),
                    "consistency check failed for {priv_path}"
                );
                first
            })
            .unwrap()
            .join()
            .unwrap()
    }

    /// BouncyCastle hackathon artifacts wrap Falcon private keys in the draft-uni-qsckeys
    /// FalconPrivateKey SEQUENCE inside the OneAsymmetricKey privateKey field
    #[test]
    fn parses_bc_qsckeys_falcon_keys() {
        for (priv_f, ta_f) in [
            (
                "tests/artifacts/bc/falcon-512-1.3.9999.3.11_priv.der",
                "tests/artifacts/bc/falcon-512-1.3.9999.3.11_ta.der",
            ),
            (
                "tests/artifacts/bc/falcon-1024-1.3.9999.3.14_priv.der",
                "tests/artifacts/bc/falcon-1024-1.3.9999.3.14_ta.der",
            ),
        ] {
            let first = check_pair(priv_f, ta_f);
            assert_eq!(first, 0x30, "expected a SEQUENCE tag (qsckeys) in {priv_f}");
        }
    }

    /// kemri_toy writes the raw fn-dsa signing key (header byte 0x50 | logn) into the
    /// OneAsymmetricKey privateKey field
    #[test]
    fn parses_kemri_toy_raw_falcon_keys() {
        for (priv_f, ta_f, header) in [
            (
                "tests/artifacts/kemri_toy/fn-dsa-512-1.3.9999.3.11_priv.der",
                "tests/artifacts/kemri_toy/fn-dsa-512-1.3.9999.3.11_ta.der",
                0x59,
            ),
            (
                "tests/artifacts/kemri_toy/fn-dsa-1024-1.3.9999.3.14_priv.der",
                "tests/artifacts/kemri_toy/fn-dsa-1024-1.3.9999.3.14_ta.der",
                0x5a,
            ),
        ] {
            let first = check_pair(priv_f, ta_f);
            assert_eq!(
                first, header,
                "expected a raw fn-dsa signing key header in {priv_f}"
            );
        }
    }
}
