//! Signer implementation for mldsa44 key pairs

use const_oid::ObjectIdentifier;
use signature::{Keypair, RandomizedSigner, Signer};
use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s, SigningKey,
};

use der::{Decode, Document, Encode, asn1::BitString};
use ml_dsa::{KeyPair, MlDsa44, MlDsa65, MlDsa87, Signature, VerifyingKey};
use pqckeys::pqc_oids::{
    ML_DSA_44, ML_DSA_65, ML_DSA_87, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S, SLH_DSA_SHA2_192F,
    SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256F, SLH_DSA_SHA2_256S, SLH_DSA_SHAKE_128F,
    SLH_DSA_SHAKE_128S, SLH_DSA_SHAKE_192F, SLH_DSA_SHAKE_192S, SLH_DSA_SHAKE_256F,
    SLH_DSA_SHAKE_256S,
};
use spki::{
    AlgorithmIdentifier, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier,
    EncodePublicKey, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};
use zerocopy::AsBytes;

pub enum PqcKeyPair {
    MlDsa44(Box<KeyPair<MlDsa44>>),
    MlDsa65(Box<KeyPair<MlDsa65>>),
    MlDsa87(Box<KeyPair<MlDsa87>>),
    Sha2_128f(Box<SigningKey<Sha2_128f>>),
    Sha2_128s(Box<SigningKey<Sha2_128s>>),
    Sha2_192f(Box<SigningKey<Sha2_192f>>),
    Sha2_192s(Box<SigningKey<Sha2_192s>>),
    Sha2_256f(Box<SigningKey<Sha2_256f>>),
    Sha2_256s(Box<SigningKey<Sha2_256s>>),
    Shake128f(Box<SigningKey<Shake128f>>),
    Shake128s(Box<SigningKey<Shake128s>>),
    Shake192f(Box<SigningKey<Shake192f>>),
    Shake192s(Box<SigningKey<Shake192s>>),
    Shake256f(Box<SigningKey<Shake256f>>),
    Shake256s(Box<SigningKey<Shake256s>>),
}

pub struct PqcSigner {
    pub seed: Vec<u8>,
    pub keypair: PqcKeyPair,
}

#[derive(Clone)]
pub enum PqcVerifyingKey {
    MlDsa44(Box<VerifyingKey<MlDsa44>>),
    MlDsa65(Box<VerifyingKey<MlDsa65>>),
    MlDsa87(Box<VerifyingKey<MlDsa87>>),
    Sha2_128f(Box<slh_dsa::VerifyingKey<Sha2_128f>>),
    Sha2_128s(Box<slh_dsa::VerifyingKey<Sha2_128s>>),
    Sha2_192f(Box<slh_dsa::VerifyingKey<Sha2_192f>>),
    Sha2_192s(Box<slh_dsa::VerifyingKey<Sha2_192s>>),
    Sha2_256f(Box<slh_dsa::VerifyingKey<Sha2_256f>>),
    Sha2_256s(Box<slh_dsa::VerifyingKey<Sha2_256s>>),
    Shake128f(Box<slh_dsa::VerifyingKey<Shake128f>>),
    Shake128s(Box<slh_dsa::VerifyingKey<Shake128s>>),
    Shake192f(Box<slh_dsa::VerifyingKey<Shake192f>>),
    Shake192s(Box<slh_dsa::VerifyingKey<Shake192s>>),
    Shake256f(Box<slh_dsa::VerifyingKey<Shake256f>>),
    Shake256s(Box<slh_dsa::VerifyingKey<Shake256s>>),
}

pub enum PqcSignature {
    MlDsa44(Box<Signature<MlDsa44>>),
    MlDsa65(Box<Signature<MlDsa65>>),
    MlDsa87(Box<Signature<MlDsa87>>),
    Sha2_128f(Box<slh_dsa::Signature<Sha2_128f>>),
    Sha2_128s(Box<slh_dsa::Signature<Sha2_128s>>),
    Sha2_192f(Box<slh_dsa::Signature<Sha2_192f>>),
    Sha2_192s(Box<slh_dsa::Signature<Sha2_192s>>),
    Sha2_256f(Box<slh_dsa::Signature<Sha2_256f>>),
    Sha2_256s(Box<slh_dsa::Signature<Sha2_256s>>),
    Shake128f(Box<slh_dsa::Signature<Shake128f>>),
    Shake128s(Box<slh_dsa::Signature<Shake128s>>),
    Shake192f(Box<slh_dsa::Signature<Shake192f>>),
    Shake192s(Box<slh_dsa::Signature<Shake192s>>),
    Shake256f(Box<slh_dsa::Signature<Shake256f>>),
    Shake256s(Box<slh_dsa::Signature<Shake256s>>),
}

impl PqcVerifyingKey {
    pub(crate) fn oid(&self) -> ObjectIdentifier {
        match self {
            PqcVerifyingKey::MlDsa44(_) => ML_DSA_44,
            PqcVerifyingKey::MlDsa65(_) => ML_DSA_65,
            PqcVerifyingKey::MlDsa87(_) => ML_DSA_87,
            PqcVerifyingKey::Sha2_128f(_) => SLH_DSA_SHA2_128F,
            PqcVerifyingKey::Sha2_128s(_) => SLH_DSA_SHA2_128S,
            PqcVerifyingKey::Sha2_192f(_) => SLH_DSA_SHA2_192F,
            PqcVerifyingKey::Sha2_192s(_) => SLH_DSA_SHA2_192S,
            PqcVerifyingKey::Sha2_256f(_) => SLH_DSA_SHA2_256F,
            PqcVerifyingKey::Sha2_256s(_) => SLH_DSA_SHA2_256S,
            PqcVerifyingKey::Shake128f(_) => SLH_DSA_SHAKE_128F,
            PqcVerifyingKey::Shake128s(_) => SLH_DSA_SHAKE_128S,
            PqcVerifyingKey::Shake192f(_) => SLH_DSA_SHAKE_192F,
            PqcVerifyingKey::Shake192s(_) => SLH_DSA_SHAKE_192S,
            PqcVerifyingKey::Shake256f(_) => SLH_DSA_SHAKE_256F,
            PqcVerifyingKey::Shake256s(_) => SLH_DSA_SHAKE_256S,
        }
    }
    pub(crate) fn public_key(&self) -> Vec<u8> {
        match self {
            PqcVerifyingKey::MlDsa44(vk) => vk.encode().as_bytes().to_vec(),
            PqcVerifyingKey::MlDsa65(vk) => vk.encode().as_bytes().to_vec(),
            PqcVerifyingKey::MlDsa87(vk) => vk.encode().as_bytes().to_vec(),
            PqcVerifyingKey::Sha2_128f(vk) => vk.to_bytes().to_vec(),
            PqcVerifyingKey::Sha2_128s(vk) => vk.to_bytes().to_vec(),
            PqcVerifyingKey::Sha2_192f(vk) => vk.to_bytes().to_vec(),
            PqcVerifyingKey::Sha2_192s(vk) => vk.to_bytes().to_vec(),
            PqcVerifyingKey::Sha2_256f(vk) => vk.to_bytes().to_vec(),
            PqcVerifyingKey::Sha2_256s(vk) => vk.to_bytes().to_vec(),
            PqcVerifyingKey::Shake128f(vk) => vk.to_bytes().to_vec(),
            PqcVerifyingKey::Shake128s(vk) => vk.to_bytes().to_vec(),
            PqcVerifyingKey::Shake192f(vk) => vk.to_bytes().to_vec(),
            PqcVerifyingKey::Shake192s(vk) => vk.to_bytes().to_vec(),
            PqcVerifyingKey::Shake256f(vk) => vk.to_bytes().to_vec(),
            PqcVerifyingKey::Shake256s(vk) => vk.to_bytes().to_vec(),
        }
    }
}

impl PqcSigner {
    pub(crate) fn new(seed: &[u8], keypair: PqcKeyPair) -> Self {
        PqcSigner {
            seed: seed.to_vec(),
            keypair,
        }
    }

    pub(crate) fn oid(&self) -> ObjectIdentifier {
        match self.keypair {
            PqcKeyPair::MlDsa44(_) => ML_DSA_44,
            PqcKeyPair::MlDsa65(_) => ML_DSA_65,
            PqcKeyPair::MlDsa87(_) => ML_DSA_87,
            PqcKeyPair::Sha2_128f(_) => SLH_DSA_SHA2_128F,
            PqcKeyPair::Sha2_128s(_) => SLH_DSA_SHA2_128S,
            PqcKeyPair::Sha2_192f(_) => SLH_DSA_SHA2_192F,
            PqcKeyPair::Sha2_192s(_) => SLH_DSA_SHA2_192S,
            PqcKeyPair::Sha2_256f(_) => SLH_DSA_SHA2_256F,
            PqcKeyPair::Sha2_256s(_) => SLH_DSA_SHA2_256S,
            PqcKeyPair::Shake128f(_) => SLH_DSA_SHAKE_128F,
            PqcKeyPair::Shake128s(_) => SLH_DSA_SHAKE_128S,
            PqcKeyPair::Shake192f(_) => SLH_DSA_SHAKE_192F,
            PqcKeyPair::Shake192s(_) => SLH_DSA_SHAKE_192S,
            PqcKeyPair::Shake256f(_) => SLH_DSA_SHAKE_256F,
            PqcKeyPair::Shake256s(_) => SLH_DSA_SHAKE_256S,
        }
    }
    pub(crate) fn public_key(&self) -> Vec<u8> {
        match &self.keypair {
            PqcKeyPair::MlDsa44(kp) => {
                let vk = kp.verifying_key();
                vk.encode().as_bytes().to_vec()
            }
            PqcKeyPair::MlDsa65(kp) => {
                let vk = kp.verifying_key();
                vk.encode().as_bytes().to_vec()
            }
            PqcKeyPair::MlDsa87(kp) => {
                let vk = kp.verifying_key();
                vk.encode().as_bytes().to_vec()
            }
            PqcKeyPair::Sha2_128f(sk) => sk.verifying_key().to_vec(),
            PqcKeyPair::Sha2_128s(sk) => sk.verifying_key().to_vec(),
            PqcKeyPair::Sha2_192f(sk) => sk.verifying_key().to_vec(),
            PqcKeyPair::Sha2_192s(sk) => sk.verifying_key().to_vec(),
            PqcKeyPair::Sha2_256f(sk) => sk.verifying_key().to_vec(),
            PqcKeyPair::Sha2_256s(sk) => sk.verifying_key().to_vec(),
            PqcKeyPair::Shake128f(sk) => sk.verifying_key().to_vec(),
            PqcKeyPair::Shake128s(sk) => sk.verifying_key().to_vec(),
            PqcKeyPair::Shake192f(sk) => sk.verifying_key().to_vec(),
            PqcKeyPair::Shake192s(sk) => sk.verifying_key().to_vec(),
            PqcKeyPair::Shake256f(sk) => sk.verifying_key().to_vec(),
            PqcKeyPair::Shake256s(sk) => sk.verifying_key().to_vec(),
        }
    }
    pub(crate) fn private_key(&self) -> Vec<u8> {
        match &self.keypair {
            PqcKeyPair::MlDsa44(kp) => {
                let sk = kp.signing_key();
                sk.encode().as_bytes().to_vec()
            }
            PqcKeyPair::MlDsa65(kp) => {
                let sk = kp.signing_key();
                sk.encode().as_bytes().to_vec()
            }
            PqcKeyPair::MlDsa87(kp) => {
                let sk = kp.signing_key();
                sk.encode().as_bytes().to_vec()
            }
            PqcKeyPair::Sha2_128f(sk) => sk.to_vec(),
            PqcKeyPair::Sha2_128s(sk) => sk.to_vec(),
            PqcKeyPair::Sha2_192f(sk) => sk.to_vec(),
            PqcKeyPair::Sha2_192s(sk) => sk.to_vec(),
            PqcKeyPair::Sha2_256f(sk) => sk.to_vec(),
            PqcKeyPair::Sha2_256s(sk) => sk.to_vec(),
            PqcKeyPair::Shake128f(sk) => sk.to_vec(),
            PqcKeyPair::Shake128s(sk) => sk.to_vec(),
            PqcKeyPair::Shake192f(sk) => sk.to_vec(),
            PqcKeyPair::Shake192s(sk) => sk.to_vec(),
            PqcKeyPair::Shake256f(sk) => sk.to_vec(),
            PqcKeyPair::Shake256s(sk) => sk.to_vec(),
        }
    }
    pub(crate) fn verifying_key(&self) -> PqcVerifyingKey {
        match &self.keypair {
            PqcKeyPair::MlDsa44(kp) => {
                PqcVerifyingKey::MlDsa44(Box::new(kp.verifying_key().clone()))
            }
            PqcKeyPair::MlDsa65(kp) => {
                PqcVerifyingKey::MlDsa65(Box::new(kp.verifying_key().clone()))
            }
            PqcKeyPair::MlDsa87(kp) => {
                PqcVerifyingKey::MlDsa87(Box::new(kp.verifying_key().clone()))
            }
            PqcKeyPair::Sha2_128f(sk) => {
                PqcVerifyingKey::Sha2_128f(Box::new(sk.verifying_key().clone()))
            }
            PqcKeyPair::Sha2_128s(sk) => {
                PqcVerifyingKey::Sha2_128s(Box::new(sk.verifying_key().clone()))
            }
            PqcKeyPair::Sha2_192f(sk) => {
                PqcVerifyingKey::Sha2_192f(Box::new(sk.verifying_key().clone()))
            }
            PqcKeyPair::Sha2_192s(sk) => {
                PqcVerifyingKey::Sha2_192s(Box::new(sk.verifying_key().clone()))
            }
            PqcKeyPair::Sha2_256f(sk) => {
                PqcVerifyingKey::Sha2_256f(Box::new(sk.verifying_key().clone()))
            }
            PqcKeyPair::Sha2_256s(sk) => {
                PqcVerifyingKey::Sha2_256s(Box::new(sk.verifying_key().clone()))
            }
            PqcKeyPair::Shake128f(sk) => {
                PqcVerifyingKey::Shake128f(Box::new(sk.verifying_key().clone()))
            }
            PqcKeyPair::Shake128s(sk) => {
                PqcVerifyingKey::Shake128s(Box::new(sk.verifying_key().clone()))
            }
            PqcKeyPair::Shake192f(sk) => {
                PqcVerifyingKey::Shake192f(Box::new(sk.verifying_key().clone()))
            }
            PqcKeyPair::Shake192s(sk) => {
                PqcVerifyingKey::Shake192s(Box::new(sk.verifying_key().clone()))
            }
            PqcKeyPair::Shake256f(sk) => {
                PqcVerifyingKey::Shake256f(Box::new(sk.verifying_key().clone()))
            }
            PqcKeyPair::Shake256s(sk) => {
                PqcVerifyingKey::Shake256s(Box::new(sk.verifying_key().clone()))
            }
        }
    }
    pub(crate) fn sign(&self, msg: &[u8]) -> crate::Result<PqcSignature> {
        match &self.keypair {
            PqcKeyPair::MlDsa44(kp) => {
                Ok(PqcSignature::MlDsa44(Box::new(kp.signing_key().sign(msg))))
            }
            PqcKeyPair::MlDsa65(kp) => {
                Ok(PqcSignature::MlDsa65(Box::new(kp.signing_key().sign(msg))))
            }
            PqcKeyPair::MlDsa87(kp) => {
                Ok(PqcSignature::MlDsa87(Box::new(kp.signing_key().sign(msg))))
            }
            PqcKeyPair::Sha2_128f(sk) => {
                let mut rng = rand::rng();
                Ok(PqcSignature::Sha2_128f(Box::new(
                    sk.sign_with_rng(&mut rng, msg),
                )))
            }
            PqcKeyPair::Sha2_128s(sk) => {
                let mut rng = rand::rng();
                Ok(PqcSignature::Sha2_128s(Box::new(
                    sk.sign_with_rng(&mut rng, msg),
                )))
            }
            PqcKeyPair::Sha2_192f(sk) => {
                let mut rng = rand::rng();
                Ok(PqcSignature::Sha2_192f(Box::new(
                    sk.sign_with_rng(&mut rng, msg),
                )))
            }
            PqcKeyPair::Sha2_192s(sk) => {
                let mut rng = rand::rng();
                Ok(PqcSignature::Sha2_192s(Box::new(
                    sk.sign_with_rng(&mut rng, msg),
                )))
            }
            PqcKeyPair::Sha2_256f(sk) => {
                let mut rng = rand::rng();
                Ok(PqcSignature::Sha2_256f(Box::new(
                    sk.sign_with_rng(&mut rng, msg),
                )))
            }
            PqcKeyPair::Sha2_256s(sk) => {
                let mut rng = rand::rng();
                Ok(PqcSignature::Sha2_256s(Box::new(
                    sk.sign_with_rng(&mut rng, msg),
                )))
            }
            PqcKeyPair::Shake128f(sk) => {
                let mut rng = rand::rng();
                Ok(PqcSignature::Shake128f(Box::new(
                    sk.sign_with_rng(&mut rng, msg),
                )))
            }
            PqcKeyPair::Shake128s(sk) => {
                let mut rng = rand::rng();
                Ok(PqcSignature::Shake128s(Box::new(
                    sk.sign_with_rng(&mut rng, msg),
                )))
            }
            PqcKeyPair::Shake192f(sk) => {
                let mut rng = rand::rng();
                Ok(PqcSignature::Shake192f(Box::new(
                    sk.sign_with_rng(&mut rng, msg),
                )))
            }
            PqcKeyPair::Shake192s(sk) => {
                let mut rng = rand::rng();
                Ok(PqcSignature::Shake192s(Box::new(
                    sk.sign_with_rng(&mut rng, msg),
                )))
            }
            PqcKeyPair::Shake256f(sk) => {
                let mut rng = rand::rng();
                Ok(PqcSignature::Shake256f(Box::new(
                    sk.sign_with_rng(&mut rng, msg),
                )))
            }
            PqcKeyPair::Shake256s(sk) => {
                let mut rng = rand::rng();
                Ok(PqcSignature::Shake256s(Box::new(
                    sk.sign_with_rng(&mut rng, msg),
                )))
            }
        }
    }
}

impl EncodePublicKey for PqcSigner {
    fn to_public_key_der(&self) -> Result<Document, spki::Error> {
        let spki_algorithm = AlgorithmIdentifierOwned {
            oid: self.oid(),
            parameters: None, // Params absent for Dilithium keys per draft-ietf-lamps-dilithium-certificates-02 section 7
        };
        let ca_spki = SubjectPublicKeyInfoOwned {
            algorithm: spki_algorithm,
            subject_public_key: BitString::from_bytes(&self.public_key())?,
        };
        Ok(Document::from_der(&ca_spki.to_der()?)?)
    }
}

impl EncodePublicKey for PqcVerifyingKey {
    fn to_public_key_der(&self) -> Result<Document, spki::Error> {
        let spki_algorithm = AlgorithmIdentifierOwned {
            oid: self.oid(),
            parameters: None, // Params absent for Dilithium keys per draft-ietf-lamps-dilithium-certificates-02 section 7
        };
        let ca_spki = SubjectPublicKeyInfoOwned {
            algorithm: spki_algorithm,
            subject_public_key: BitString::from_bytes(&self.public_key())?,
        };
        Ok(Document::from_der(&ca_spki.to_der()?)?)
    }
}

impl PqcSignature {
    fn signature(&self) -> Vec<u8> {
        match self {
            PqcSignature::MlDsa44(sig) => sig.encode().as_bytes().to_vec(),
            PqcSignature::MlDsa65(sig) => sig.encode().as_bytes().to_vec(),
            PqcSignature::MlDsa87(sig) => sig.encode().as_bytes().to_vec(),
            PqcSignature::Sha2_128f(sig) => sig.to_vec(),
            PqcSignature::Sha2_128s(sig) => sig.to_vec(),
            PqcSignature::Sha2_192f(sig) => sig.to_vec(),
            PqcSignature::Sha2_192s(sig) => sig.to_vec(),
            PqcSignature::Sha2_256f(sig) => sig.to_vec(),
            PqcSignature::Sha2_256s(sig) => sig.to_vec(),
            PqcSignature::Shake128f(sig) => sig.to_vec(),
            PqcSignature::Shake128s(sig) => sig.to_vec(),
            PqcSignature::Shake192f(sig) => sig.to_vec(),
            PqcSignature::Shake192s(sig) => sig.to_vec(),
            PqcSignature::Shake256f(sig) => sig.to_vec(),
            PqcSignature::Shake256s(sig) => sig.to_vec(),
        }
    }
}

impl SignatureBitStringEncoding for PqcSignature {
    fn to_bitstring(&self) -> Result<BitString, der::Error> {
        BitString::from_bytes(&self.signature())
    }
}

impl Signer<PqcSignature> for PqcSigner {
    fn try_sign(&self, tbs: &[u8]) -> Result<PqcSignature, signature::Error> {
        match self.sign(tbs) {
            Ok(s) => Ok(s),
            Err(e) => {
                panic!("Failed to generate signature: {e:?}");
            }
        }
    }
}

impl Keypair for PqcSigner {
    type VerifyingKey = PqcVerifyingKey;
    fn verifying_key(&self) -> <Self as Keypair>::VerifyingKey {
        self.verifying_key()
    }
}

impl DynSignatureAlgorithmIdentifier for PqcSigner {
    fn signature_algorithm_identifier(&self) -> Result<AlgorithmIdentifier<der::Any>, spki::Error> {
        let spki_algorithm = AlgorithmIdentifierOwned {
            oid: self.oid(),
            parameters: None, // Params absent for Dilithium signatures per draft-ietf-lamps-dilithium-certificates-02 section 2
        };
        Ok(spki_algorithm)
    }
}
