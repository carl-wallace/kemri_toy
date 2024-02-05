//! Signer implementation for dilithium2 key pairs

use signature::{Keypair, Signer};

use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

use crate::ML_DSA_44_IPD;
use der::{asn1::BitString, Decode, Document, Encode};
use spki::{
    AlgorithmIdentifier, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier,
    EncodePublicKey, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};

/// Type alias for dilithium2::PublicKey
#[derive(Clone)]
pub struct DilithiumPublicKey(pub dilithium2::PublicKey);

impl EncodePublicKey for DilithiumPublicKey {
    fn to_public_key_der(&self) -> Result<Document, spki::Error> {
        let spki_algorithm = AlgorithmIdentifierOwned {
            oid: ML_DSA_44_IPD,
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
pub struct DilithiumSignature(pub Vec<u8>);

impl SignatureBitStringEncoding for DilithiumSignature {
    fn to_bitstring(&self) -> Result<BitString, der::Error> {
        BitString::from_bytes(&self.0)
    }
}

/// Structure containing a dilithium2::PublicKey and dilithium2::SecretKey
pub struct Dilithium2KeyPair {
    pub public_key: DilithiumPublicKey,
    pub secret_key: dilithium2::SecretKey,
}

impl Signer<DilithiumSignature> for Dilithium2KeyPair {
    fn try_sign(&self, tbs: &[u8]) -> Result<DilithiumSignature, signature::Error> {
        let sm = dilithium2::detached_sign(tbs, &self.secret_key);
        Ok(DilithiumSignature(sm.as_bytes().to_vec()))
    }
}

impl Keypair for Dilithium2KeyPair {
    type VerifyingKey = DilithiumPublicKey;
    fn verifying_key(&self) -> <Self as Keypair>::VerifyingKey {
        self.public_key.clone()
    }
}

impl DynSignatureAlgorithmIdentifier for Dilithium2KeyPair {
    fn signature_algorithm_identifier(&self) -> Result<AlgorithmIdentifier<der::Any>, spki::Error> {
        let spki_algorithm = AlgorithmIdentifierOwned {
            oid: ML_DSA_44_IPD,
            parameters: None, // Params absent for Dilithium signatures per draft-ietf-lamps-dilithium-certificates-02 section 2
        };
        Ok(spki_algorithm)
    }
}
