//! FN-DSA (Falcon) signature verification, registered on the certval [`PkiEnvironment`] used by
//! kemri_toy.
//!
//! FN-DSA is pre-standard (the FIPS 206 draft is not yet published), so this verifier lives here
//! rather than in certval's published surface; it can move back into certval once a FIPS 206
//! implementation is available. Falcon is not implemented by the RustCrypto project, so this wraps
//! the verify-only [`fn-dsa-vrfy`] crate.
//!
//! The hackathon/OQS Falcon OIDs (`1.3.9999.3.6`, `.9`, `.11`, `.14`) all identify the NIST round-3
//! Falcon finalist, so verification uses the "original Falcon" hashing (`SHAKE256(nonce || message)`)
//! with no domain-separation context. The unpublished FN-DSA draft may introduce a different
//! pre-hash/domain-separation scheme; only the frozen round-3 behavior these certificates were
//! produced with is implemented here.
//!
//! X.509 Falcon signatures carry the variable-length *compressed* signature encoding, whereas
//! `fn-dsa-vrfy` expects the fixed ("padded") length; this module zero-pads the signature up to that
//! fixed size before verifying (padded Falcon is the compressed signature followed by zero octets).
//!
//! [`fn-dsa-vrfy`]: https://crates.io/crates/fn-dsa-vrfy

use log::error;

use fn_dsa_vrfy::{
    DOMAIN_NONE, FN_DSA_LOGN_512, FN_DSA_LOGN_1024, HASH_ID_ORIGINAL_FALCON, VerifyingKey,
    VerifyingKey512, VerifyingKey1024, signature_size,
};
use pqckeys::pqc_oids::{
    OQ_FALCON_512, OQ_FALCON_1024, OQ_FALCON_PADDED_512, OQ_FALCON_PADDED_1024,
};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use certval::{Error, PkiEnvironment};

/// Decode a Falcon verifying key of the given degree, normalize the signature to the fixed
/// length expected by `fn-dsa-vrfy`, and verify it against `message_to_verify`.
fn verify_falcon<VK: VerifyingKey>(
    logn: u32,
    message_to_verify: &[u8],
    spki_val: &[u8],
    signature: &[u8],
) -> certval::Result<()> {
    let vk = VK::decode(spki_val).ok_or(Error::PqcValidation)?;

    // X.509 Falcon signatures use the variable-length compressed encoding; fn-dsa-vrfy
    // requires exactly the fixed ("padded") size, so zero-pad a short signature. A
    // signature longer than the fixed size is malformed for this scheme.
    let target = signature_size(logn);
    let sig = match signature.len() {
        n if n == target => signature.to_vec(),
        n if n < target => {
            let mut s = Vec::with_capacity(target);
            s.extend_from_slice(signature);
            s.resize(target, 0);
            s
        }
        _ => {
            error!("FN-DSA (Falcon) signature exceeds the fixed size for the algorithm");
            return Err(Error::PqcValidation);
        }
    };

    if vk.verify(
        &sig,
        &DOMAIN_NONE,
        &HASH_ID_ORIGINAL_FALCON,
        message_to_verify,
    ) {
        Ok(())
    } else {
        error!("Failed to verify FN-DSA (Falcon) signature");
        Err(Error::Unrecognized)
    }
}

/// Verify FN-DSA (Falcon) signatures. Register on a certval [`PkiEnvironment`] via
/// `add_verify_signature_message_callback`.
///
/// Returns [`Error::Unrecognized`] for algorithm identifiers this callback does not handle, so the
/// [`PkiEnvironment`] can fall through to the next `verify_signature_message` callback.
pub fn verify_signature_message_fndsa(
    _pe: &PkiEnvironment,
    message_to_verify: &[u8],                 // buffer to verify
    signature: &[u8],                         // signature
    signature_alg: &AlgorithmIdentifierOwned, // signature algorithm
    spki: &SubjectPublicKeyInfoOwned,         // public key
) -> certval::Result<()> {
    let spki_val = spki.subject_public_key.raw_bytes();
    if OQ_FALCON_512 == signature_alg.oid || OQ_FALCON_PADDED_512 == signature_alg.oid {
        verify_falcon::<VerifyingKey512>(FN_DSA_LOGN_512, message_to_verify, spki_val, signature)
    } else if OQ_FALCON_1024 == signature_alg.oid || OQ_FALCON_PADDED_1024 == signature_alg.oid {
        verify_falcon::<VerifyingKey1024>(FN_DSA_LOGN_1024, message_to_verify, spki_val, signature)
    } else {
        Err(Error::Unrecognized)
    }
}

#[cfg(test)]
mod tests {
    //! Verify real FN-DSA (Falcon) self-signed trust anchors through the kemri_toy-registered
    //! callback. Artifacts are self-signed CA certificates from the IETF hackathon pqc-certificates
    //! project (BouncyCastle provider), covering both the round-4 (unpadded) Falcon OIDs
    //! (`1.3.9999.3.6` / `.9`) and the round-5 (padded) OIDs (`1.3.9999.3.11` / `.14`).
    #![allow(clippy::unwrap_used)]
    use super::verify_signature_message_fndsa;
    use certval::{DeferDecodeSigned, PkiEnvironment};
    use der::Decode;
    use x509_cert::Certificate;

    /// A self-signed cert verifies when its own SPKI validates the signature over its TBS.
    fn assert_self_signed_verifies(der: &[u8]) {
        let cert = Certificate::from_der(der).unwrap();
        let parts = DeferDecodeSigned::from_der(der).unwrap();
        let spki = cert.tbs_certificate().subject_public_key_info();

        // Directly through the FN-DSA callback.
        let pe = PkiEnvironment::new();
        verify_signature_message_fndsa(
            &pe,
            &parts.tbs_field,
            parts.signature.raw_bytes(),
            &parts.signature_algorithm,
            spki,
        )
        .unwrap();

        // And through the full switchboard once the callback is registered (certval no longer
        // registers FN-DSA by default; kemri_toy adds it).
        let mut pe = PkiEnvironment::default();
        pe.populate_5280_pki_environment();
        pe.add_verify_signature_message_callback(verify_signature_message_fndsa);
        pe.verify_signature_message(
            &pe,
            &parts.tbs_field,
            parts.signature.raw_bytes(),
            &parts.signature_algorithm,
            spki,
        )
        .unwrap();
    }

    #[test]
    fn falcon_512_unpadded_oid() {
        assert_self_signed_verifies(include_bytes!(
            "../../tests/examples/fndsa/falcon-512-1.3.9999.3.6_ta.der"
        ));
    }

    #[test]
    fn falcon_1024_unpadded_oid() {
        assert_self_signed_verifies(include_bytes!(
            "../../tests/examples/fndsa/falcon-1024-1.3.9999.3.9_ta.der"
        ));
    }

    #[test]
    fn falcon_512_padded_oid() {
        assert_self_signed_verifies(include_bytes!(
            "../../tests/examples/fndsa/falcon-512-1.3.9999.3.11_ta.der"
        ));
    }

    #[test]
    fn falcon_1024_padded_oid() {
        assert_self_signed_verifies(include_bytes!(
            "../../tests/examples/fndsa/falcon-1024-1.3.9999.3.14_ta.der"
        ));
    }

    /// A tampered TBS must not verify.
    #[test]
    fn falcon_512_rejects_tampered_message() {
        let der = include_bytes!("../../tests/examples/fndsa/falcon-512-1.3.9999.3.6_ta.der");
        let cert = Certificate::from_der(der).unwrap();
        let parts = DeferDecodeSigned::from_der(der).unwrap();
        let mut tbs = parts.tbs_field.clone();
        // Flip a byte deep in the TBS so it stays DER-parseable-length but content-altered.
        let last = tbs.len() - 1;
        tbs[last] ^= 0x01;

        let pe = PkiEnvironment::new();
        assert!(
            verify_signature_message_fndsa(
                &pe,
                &tbs,
                parts.signature.raw_bytes(),
                &parts.signature_algorithm,
                cert.tbs_certificate().subject_public_key_info(),
            )
            .is_err()
        );
    }
}
