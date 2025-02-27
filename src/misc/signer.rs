//! Signer implementation for mldsa44 key pairs

use signature::{Keypair, Signer};

use pqcrypto_mldsa::mldsa44;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

use crate::ML_DSA_44;
use der::{Decode, Document, Encode, asn1::BitString};
use spki::{
    AlgorithmIdentifier, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier,
    EncodePublicKey, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};

/// Type alias for mldsa44::PublicKey
#[derive(Clone)]
pub struct Mldsa44PublicKey(pub mldsa44::PublicKey);

impl EncodePublicKey for Mldsa44PublicKey {
    fn to_public_key_der(&self) -> Result<Document, spki::Error> {
        let spki_algorithm = AlgorithmIdentifierOwned {
            oid: ML_DSA_44,
            parameters: None, // Params absent for Dilithium keys per draft-ietf-lamps-dilithium-certificates-02 section 7
        };
        let ca_spki = SubjectPublicKeyInfoOwned {
            algorithm: spki_algorithm,
            subject_public_key: BitString::from_bytes(self.0.as_bytes())?,
        };
        Ok(Document::from_der(&ca_spki.to_der()?)?)
    }
}

/// Struct representing Dilithium 2 signatures
pub struct Mldsa44Signature(pub Vec<u8>);

impl SignatureBitStringEncoding for Mldsa44Signature {
    fn to_bitstring(&self) -> Result<BitString, der::Error> {
        BitString::from_bytes(&self.0)
    }
}

/// Structure containing a mldsa44::PublicKey and mldsa44::SecretKey
pub struct Mldsa44KeyPair {
    pub public_key: Mldsa44PublicKey,
    pub secret_key: mldsa44::SecretKey,
}

impl Signer<Mldsa44Signature> for Mldsa44KeyPair {
    fn try_sign(&self, tbs: &[u8]) -> Result<Mldsa44Signature, signature::Error> {
        let sm = mldsa44::detached_sign(tbs, &self.secret_key);
        Ok(Mldsa44Signature(sm.as_bytes().to_vec()))
    }
}

impl Keypair for Mldsa44KeyPair {
    type VerifyingKey = Mldsa44PublicKey;
    fn verifying_key(&self) -> <Self as Keypair>::VerifyingKey {
        self.public_key.clone()
    }
}

impl DynSignatureAlgorithmIdentifier for Mldsa44KeyPair {
    fn signature_algorithm_identifier(&self) -> Result<AlgorithmIdentifier<der::Any>, spki::Error> {
        let spki_algorithm = AlgorithmIdentifierOwned {
            oid: ML_DSA_44,
            parameters: None, // Params absent for Dilithium signatures per draft-ietf-lamps-dilithium-certificates-02 section 2
        };
        Ok(spki_algorithm)
    }
}
