//! Signer implementation for mldsa44 key pairs

use const_oid::ObjectIdentifier;
use signature::{Keypair, Signer};

use der::{Decode, Document, Encode, asn1::BitString};
use spki::{
    AlgorithmIdentifier, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier,
    EncodePublicKey, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};
use zerocopy::AsBytes;
use ml_dsa::{KeyGen, MlDsa44, MlDsa65, MlDsa87, Signature, SigningKey, VerifyingKey, B32, KeyPair};
use pqckeys::oak::PublicKey;
use pqckeys::pqc_oids::{ML_DSA_44, ML_DSA_65, ML_DSA_87};

pub enum PqcSigner {
    MlDsa44(Box<KeyPair<MlDsa44>>),
    MlDsa65(Box<KeyPair<MlDsa65>>),
    MlDsa87(Box<KeyPair<MlDsa87>>),
}

#[derive(Clone)]
pub enum PqcVerifyingKey {
    MlDsa44(Box<VerifyingKey<MlDsa44>>),
    MlDsa65(Box<VerifyingKey<MlDsa65>>),
    MlDsa87(Box<VerifyingKey<MlDsa87>>),
}

impl PqcVerifyingKey {
    pub(crate) fn oid(&self) -> ObjectIdentifier {
        match self {
            PqcVerifyingKey::MlDsa44(_) => {ML_DSA_44}
            PqcVerifyingKey::MlDsa65(_) => {ML_DSA_65}
            PqcVerifyingKey::MlDsa87(_) => {ML_DSA_87}
        }
    }
    pub(crate) fn public_key(&self) -> Vec<u8> {
        match self {
            PqcVerifyingKey::MlDsa44(vk) => {
                vk.encode().as_bytes().to_vec()
            }
            PqcVerifyingKey::MlDsa65(vk) => {
                vk.encode().as_bytes().to_vec()
            }
            PqcVerifyingKey::MlDsa87(vk) => {
                vk.encode().as_bytes().to_vec()
            }
        }
    }}

impl PqcSigner {
    pub(crate) fn oid(&self) -> ObjectIdentifier {
        match self {
            PqcSigner::MlDsa44(_) => {ML_DSA_44}
            PqcSigner::MlDsa65(_) => {ML_DSA_65}
            PqcSigner::MlDsa87(_) => {ML_DSA_87}
        }
    }
    pub(crate) fn public_key(&self) -> Vec<u8> {
        match self {
            PqcSigner::MlDsa44(kp) => {
                let vk = kp.verifying_key();
                vk.encode().as_bytes().to_vec()
            }
            PqcSigner::MlDsa65(kp) => {
                let vk = kp.verifying_key();
                vk.encode().as_bytes().to_vec()
            }
            PqcSigner::MlDsa87(kp) => {
                let vk = kp.verifying_key();
                vk.encode().as_bytes().to_vec()
            }
        }
    }
    pub(crate) fn private_key(&self) -> Vec<u8> {
        match self {
            PqcSigner::MlDsa44(kp) => {
                let sk = kp.signing_key();
                sk.encode().as_bytes().to_vec()
            }
            PqcSigner::MlDsa65(kp) => {
                let sk = kp.signing_key();
                sk.encode().as_bytes().to_vec()
            }
            PqcSigner::MlDsa87(kp) => {
                let sk = kp.signing_key();
                sk.encode().as_bytes().to_vec()
            }
        }
    }
    pub(crate) fn verifying_key(&self) -> PqcVerifyingKey {
        match self {
            PqcSigner::MlDsa44(kp) => {
                PqcVerifyingKey::MlDsa44(Box::new(kp.verifying_key().clone()))
            }
            PqcSigner::MlDsa65(kp) => {
                PqcVerifyingKey::MlDsa65(Box::new(kp.verifying_key().clone()))
            }
            PqcSigner::MlDsa87(kp) => {
                PqcVerifyingKey::MlDsa87(Box::new(kp.verifying_key().clone()))
            }
        }
    }
    pub(crate) fn sign(&self, msg: &[u8]) -> crate::Result<PqcSignature> {
        match self {
            PqcSigner::MlDsa44(kp) => {
                Ok(PqcSignature::MlDsa44(Box::new(kp.signing_key().sign(msg))))
            }
            PqcSigner::MlDsa65(kp) => {
                Ok(PqcSignature::MlDsa65(Box::new(kp.signing_key().sign(msg))))
            }
            PqcSigner::MlDsa87(kp) => {
                Ok(PqcSignature::MlDsa87(Box::new(kp.signing_key().sign(msg))))
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

pub enum PqcSignature {
    MlDsa44(Box<Signature<MlDsa44>>),
    MlDsa65(Box<Signature<MlDsa65>>),
    MlDsa87(Box<Signature<MlDsa87>>),
}
impl PqcSignature {
    fn oid(&self) -> ObjectIdentifier {
        match self {
            PqcSignature::MlDsa44(_) => {ML_DSA_44}
            PqcSignature::MlDsa65(_) => {ML_DSA_65}
            PqcSignature::MlDsa87(_) => {ML_DSA_87}
        }
    }
    fn signature(&self) -> Vec<u8> {
        match self {
            PqcSignature::MlDsa44(sig) => {
                sig.encode().as_bytes().to_vec()
            }
            PqcSignature::MlDsa65(sig) => {
                sig.encode().as_bytes().to_vec()
            }
            PqcSignature::MlDsa87(sig) => {
                sig.encode().as_bytes().to_vec()
            }
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
        //todo fix unwrap
        Ok(self.sign(tbs).unwrap())
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
