//! Signer implementation for mldsa44 key pairs

#![allow(dead_code)]

use sha2::{Sha384, Sha512};
use zerocopy::IntoBytes;

use ml_dsa::{KeyPair, MlDsa44, MlDsa65, MlDsa87, Signature, VerifyingKey};
use signature::{Keypair, RandomizedSigner, SignatureEncoding, Signer};
use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s, SigningKey,
};

use const_oid::{
    ObjectIdentifier,
    db::{fips204::*, fips205::*},
};
use der::{Decode, Document, Encode, asn1::BitString};
use ed448_goldilocks::Ed448;
use ed25519_dalek::Signer as OtherSigner;
use lazy_static::lazy_static;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPrivateKey};
use spki::{
    AlgorithmIdentifier, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier,
    EncodePublicKey, SignatureBitStringEncoding, SubjectPublicKeyInfoOwned,
};

use pqckeys::pqc_oids::*;
use sha2::{Digest, Sha256};
use x509_cert::SubjectPublicKeyInfo;

lazy_static! {
    // CompositeAlgorithmSignatures2025
    static ref PREFIX: [u8; 32] =
        hex_literal::hex!("436F6D706F73697465416C676F726974686D5369676E61747572657332303235");
}

fn hash_message(composite_oid: ObjectIdentifier, message: &[u8]) -> crate::error::Result<Vec<u8>> {
    if composite_oid == ID_MLDSA44_RSA2048_PKCS15_SHA256
        || composite_oid == ID_MLDSA44_RSA2048_PSS_SHA256
        || composite_oid == ID_MLDSA44_ECDSA_P256_SHA256
    {
        Ok(Sha256::digest(message).as_slice().to_vec())
    } else if composite_oid == ID_MLDSA87_ED448_SHAKE256 {
        todo!("support hashing for ID_MLDSA87_ED448_SHAKE256")
    } else {
        Ok(Sha512::digest(message).as_slice().to_vec())
    }
}

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
    Mldsa44Rsa2048PssSha256(Box<(KeyPair<MlDsa44>, RsaPrivateKey)>),
    Mldsa44Rsa2048Pkcs15Sha256(Box<(KeyPair<MlDsa44>, RsaPrivateKey)>),
    Mldsa44Ed25519Sha512(Box<(KeyPair<MlDsa44>, ed25519_dalek::SigningKey)>),
    Mldsa44EcdsaP256Sha256(Box<(KeyPair<MlDsa44>, p256::ecdsa::SigningKey)>),
    Mldsa65Rsa3072PssSha512(Box<(KeyPair<MlDsa65>, RsaPrivateKey)>),
    Mldsa65Rsa4096PssSha512(Box<(KeyPair<MlDsa65>, RsaPrivateKey)>),
    Mldsa65Rsa4096Pkcs15Sha512(Box<(KeyPair<MlDsa65>, RsaPrivateKey)>),
    Mldsa65EcdsaP256Sha512(Box<(KeyPair<MlDsa65>, p256::ecdsa::SigningKey)>),
    Mldsa65EcdsaP384Sha512(Box<(KeyPair<MlDsa65>, p384::ecdsa::SigningKey)>),
    Mldsa65Ed25519Sha512(Box<(KeyPair<MlDsa65>, ed25519_dalek::SigningKey)>),
    Mldsa87EcdsaP384Sha512(Box<(KeyPair<MlDsa87>, p384::ecdsa::SigningKey)>),
    Mldsa87Ed448Shake256(Box<(KeyPair<MlDsa87>, elliptic_curve::SecretKey<Ed448>)>),
    Mldsa87Rsa3072PssSha512(Box<(KeyPair<MlDsa87>, RsaPrivateKey)>),
    Mldsa87Rsa4096PssSha512(Box<(KeyPair<MlDsa87>, RsaPrivateKey)>),
    Mldsa87EcdsaP521Sha512(Box<(KeyPair<MlDsa87>, p521::ecdsa::SigningKey)>),
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
    Mldsa44Rsa2048PssSha256(Box<(VerifyingKey<MlDsa44>, RsaPublicKey)>),
    Mldsa44Rsa2048Pkcs15Sha256(Box<(VerifyingKey<MlDsa44>, RsaPublicKey)>),
    Mldsa44Ed25519Sha512(Box<(VerifyingKey<MlDsa44>, ed25519_dalek::VerifyingKey)>),
    Mldsa44EcdsaP256Sha256(Box<(VerifyingKey<MlDsa44>, p256::ecdsa::VerifyingKey)>),
    Mldsa65Rsa3072PssSha512(Box<(VerifyingKey<MlDsa65>, RsaPublicKey)>),
    Mldsa65Rsa4096PssSha512(Box<(VerifyingKey<MlDsa65>, RsaPublicKey)>),
    Mldsa65Rsa4096Pkcs15Sha512(Box<(VerifyingKey<MlDsa65>, RsaPublicKey)>),
    Mldsa65EcdsaP256Sha512(Box<(VerifyingKey<MlDsa65>, p256::ecdsa::VerifyingKey)>),
    Mldsa65EcdsaP384Sha512(Box<(VerifyingKey<MlDsa65>, p384::ecdsa::VerifyingKey)>),
    Mldsa65Ed25519Sha512(Box<(VerifyingKey<MlDsa65>, ed25519_dalek::VerifyingKey)>),
    Mldsa87EcdsaP384Sha512(Box<(VerifyingKey<MlDsa87>, p384::ecdsa::VerifyingKey)>),
    Mldsa87Ed448Shake256(Box<(VerifyingKey<MlDsa87>, elliptic_curve::PublicKey<Ed448>)>),
    Mldsa87Rsa3072PssSha512(Box<(VerifyingKey<MlDsa87>, RsaPublicKey)>),
    Mldsa87Rsa4096PssSha512(Box<(VerifyingKey<MlDsa87>, RsaPublicKey)>),
    Mldsa87EcdsaP521Sha512(Box<(VerifyingKey<MlDsa87>, p521::ecdsa::VerifyingKey)>),
}

impl PqcVerifyingKey {
    pub(crate) fn oid(&self) -> ObjectIdentifier {
        match self {
            PqcVerifyingKey::MlDsa44(_) => ID_ML_DSA_44,
            PqcVerifyingKey::MlDsa65(_) => ID_ML_DSA_65,
            PqcVerifyingKey::MlDsa87(_) => ID_ML_DSA_87,
            PqcVerifyingKey::Sha2_128f(_) => ID_SLH_DSA_SHA_2_128_F,
            PqcVerifyingKey::Sha2_128s(_) => ID_SLH_DSA_SHA_2_128_S,
            PqcVerifyingKey::Sha2_192f(_) => ID_SLH_DSA_SHA_2_192_F,
            PqcVerifyingKey::Sha2_192s(_) => ID_SLH_DSA_SHA_2_192_S,
            PqcVerifyingKey::Sha2_256f(_) => ID_SLH_DSA_SHA_2_256_F,
            PqcVerifyingKey::Sha2_256s(_) => ID_SLH_DSA_SHA_2_256_S,
            PqcVerifyingKey::Shake128f(_) => ID_SLH_DSA_SHAKE_128_F,
            PqcVerifyingKey::Shake128s(_) => ID_SLH_DSA_SHAKE_128_S,
            PqcVerifyingKey::Shake192f(_) => ID_SLH_DSA_SHAKE_192_F,
            PqcVerifyingKey::Shake192s(_) => ID_SLH_DSA_SHAKE_192_S,
            PqcVerifyingKey::Shake256f(_) => ID_SLH_DSA_SHAKE_256_F,
            PqcVerifyingKey::Shake256s(_) => ID_SLH_DSA_SHAKE_256_S,
            PqcVerifyingKey::Mldsa44Rsa2048PssSha256(_) => ID_MLDSA44_RSA2048_PSS_SHA256,
            PqcVerifyingKey::Mldsa44Rsa2048Pkcs15Sha256(_) => ID_MLDSA44_RSA2048_PKCS15_SHA256,
            PqcVerifyingKey::Mldsa44Ed25519Sha512(_) => ID_MLDSA44_ED25519_SHA512,
            PqcVerifyingKey::Mldsa44EcdsaP256Sha256(_) => ID_MLDSA44_ECDSA_P256_SHA256,
            PqcVerifyingKey::Mldsa65Rsa3072PssSha512(_) => ID_MLDSA65_RSA3072_PSS_SHA512,
            PqcVerifyingKey::Mldsa65Rsa4096PssSha512(_) => ID_MLDSA65_RSA4096_PSS_SHA512,
            PqcVerifyingKey::Mldsa65Rsa4096Pkcs15Sha512(_) => ID_MLDSA65_RSA4096_PKCS15_SHA512,
            PqcVerifyingKey::Mldsa65EcdsaP256Sha512(_) => ID_MLDSA65_ECDSA_P256_SHA512,
            PqcVerifyingKey::Mldsa65EcdsaP384Sha512(_) => ID_MLDSA65_ECDSA_P384_SHA512,
            PqcVerifyingKey::Mldsa65Ed25519Sha512(_) => ID_MLDSA65_ED25519_SHA512,
            PqcVerifyingKey::Mldsa87EcdsaP384Sha512(_) => ID_MLDSA87_ECDSA_P384_SHA512,
            PqcVerifyingKey::Mldsa87Ed448Shake256(_) => ID_MLDSA87_ED448_SHAKE256,
            PqcVerifyingKey::Mldsa87Rsa3072PssSha512(_) => ID_MLDSA87_RSA3072_PSS_SHA512,
            PqcVerifyingKey::Mldsa87Rsa4096PssSha512(_) => ID_MLDSA87_RSA4096_PSS_SHA512,
            PqcVerifyingKey::Mldsa87EcdsaP521Sha512(_) => ID_MLDSA87_ECDSA_P521_SHA512,
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
            PqcVerifyingKey::Mldsa44Rsa2048PssSha256(vk) => {
                let rsa = vk.1.to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = vk.0.encode().as_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcVerifyingKey::Mldsa44Rsa2048Pkcs15Sha256(vk) => {
                let rsa = vk.1.to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = vk.0.encode().as_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcVerifyingKey::Mldsa44Ed25519Sha512(vk) => {
                let mut mldsa = vk.0.encode().as_bytes().to_vec();
                let mut ecdsa = vk.1.as_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa);
                retval
            }
            PqcVerifyingKey::Mldsa44EcdsaP256Sha256(vk) => {
                let mut mldsa = vk.0.encode().as_bytes().to_vec();
                let ecdsa = vk.1.to_encoded_point(true);

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcVerifyingKey::Mldsa65Rsa3072PssSha512(vk) => {
                let rsa = vk.1.to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = vk.0.encode().as_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcVerifyingKey::Mldsa65Rsa4096PssSha512(vk) => {
                let rsa = vk.1.to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = vk.0.encode().as_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcVerifyingKey::Mldsa65Rsa4096Pkcs15Sha512(vk) => {
                let rsa = vk.1.to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = vk.0.encode().as_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcVerifyingKey::Mldsa65EcdsaP256Sha512(vk) => {
                let mut mldsa = vk.0.encode().as_bytes().to_vec();
                let ecdsa = vk.1.to_encoded_point(true);

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcVerifyingKey::Mldsa65EcdsaP384Sha512(vk) => {
                let mut mldsa = vk.0.encode().as_bytes().to_vec();
                let ecdsa = vk.1.to_encoded_point(true);

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcVerifyingKey::Mldsa65Ed25519Sha512(vk) => {
                let mut mldsa = vk.0.encode().as_bytes().to_vec();
                let mut ecdsa = vk.1.as_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa);
                retval
            }
            PqcVerifyingKey::Mldsa87EcdsaP384Sha512(vk) => {
                let mut mldsa = vk.0.encode().as_bytes().to_vec();
                let ecdsa = vk.1.to_encoded_point(true);

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcVerifyingKey::Mldsa87Ed448Shake256(_) => {
                todo!("support serializing Mldsa87Ed448Shake256 public key")
            }
            PqcVerifyingKey::Mldsa87Rsa3072PssSha512(vk) => {
                let rsa = vk.1.to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = vk.0.encode().as_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcVerifyingKey::Mldsa87Rsa4096PssSha512(vk) => {
                let rsa = vk.1.to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = vk.0.encode().as_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcVerifyingKey::Mldsa87EcdsaP521Sha512(vk) => {
                let mut mldsa = vk.0.encode().as_bytes().to_vec();
                let ecdsa = vk.1.to_encoded_point(true);

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
        }
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
    Mldsa44Rsa2048PssSha256(Box<(Signature<MlDsa44>, Vec<u8>)>),
    Mldsa44Rsa2048Pkcs15Sha256(Box<(Signature<MlDsa44>, Vec<u8>)>),
    Mldsa44Ed25519Sha512(Box<(Signature<MlDsa44>, ed25519_dalek::Signature)>),
    Mldsa44EcdsaP256Sha256(Box<(Signature<MlDsa44>, p256::ecdsa::Signature)>),
    Mldsa65Rsa3072PssSha512(Box<(Signature<MlDsa65>, Vec<u8>)>),
    Mldsa65Rsa4096PssSha512(Box<(Signature<MlDsa65>, Vec<u8>)>),
    Mldsa65Rsa4096Pkcs15Sha512(Box<(Signature<MlDsa65>, Vec<u8>)>),
    Mldsa65EcdsaP256Sha512(Box<(Signature<MlDsa65>, p256::ecdsa::Signature)>),
    Mldsa65EcdsaP384Sha512(Box<(Signature<MlDsa65>, p384::ecdsa::Signature)>),
    Mldsa65Ed25519Sha512(Box<(Signature<MlDsa65>, ed25519_dalek::Signature)>),
    Mldsa87EcdsaP384Sha512(Box<(Signature<MlDsa87>, p384::ecdsa::Signature)>),
    Mldsa87Ed448Shake256(Box<(Signature<MlDsa87>, Vec<u8>)>), //todo fix
    Mldsa87Rsa3072PssSha512(Box<(Signature<MlDsa87>, Vec<u8>)>),
    Mldsa87Rsa4096PssSha512(Box<(Signature<MlDsa87>, Vec<u8>)>),
    Mldsa87EcdsaP521Sha512(Box<(Signature<MlDsa87>, p521::ecdsa::Signature)>),
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
            PqcSignature::Mldsa44Rsa2048PssSha256(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut rsa = sig.1.clone();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa);
                retval
            }
            PqcSignature::Mldsa44Rsa2048Pkcs15Sha256(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut rsa = sig.1.clone();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa);
                retval
            }
            PqcSignature::Mldsa44Ed25519Sha512(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut ecdsa = sig.1.to_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa);
                retval
            }
            PqcSignature::Mldsa44EcdsaP256Sha256(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut ecdsa = sig.1.to_der().as_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa);
                retval
            }
            PqcSignature::Mldsa65Rsa3072PssSha512(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut rsa = sig.1.clone();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa);
                retval
            }
            PqcSignature::Mldsa65Rsa4096PssSha512(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut rsa = sig.1.clone();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa);
                retval
            }
            PqcSignature::Mldsa65Rsa4096Pkcs15Sha512(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut rsa = sig.1.clone();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa);
                retval
            }
            PqcSignature::Mldsa65EcdsaP256Sha512(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut ecdsa = sig.1.to_der().as_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa);
                retval
            }
            PqcSignature::Mldsa65EcdsaP384Sha512(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut ecdsa = sig.1.to_der().as_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa);
                retval
            }
            PqcSignature::Mldsa65Ed25519Sha512(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut ecdsa = sig.1.to_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa);
                retval
            }
            PqcSignature::Mldsa87EcdsaP384Sha512(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut ecdsa = sig.1.to_der().as_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa);
                retval
            }
            PqcSignature::Mldsa87Ed448Shake256(_) => {
                todo!("support serializing Mldsa87Ed448Shake256 signature")
            }
            PqcSignature::Mldsa87Rsa3072PssSha512(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut rsa = sig.1.clone();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa);
                retval
            }
            PqcSignature::Mldsa87Rsa4096PssSha512(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut rsa = sig.1.clone();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa);
                retval
            }
            PqcSignature::Mldsa87EcdsaP521Sha512(sig) => {
                let mut mldsa = sig.0.encode().as_bytes().to_vec();
                let mut ecdsa = sig.1.to_der().as_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa);
                retval
            }
        }
    }
}

impl SignatureBitStringEncoding for PqcSignature {
    fn to_bitstring(&self) -> Result<BitString, der::Error> {
        BitString::from_bytes(&self.signature())
    }
}

pub struct PqcSigner {
    pub seed: Vec<u8>,
    pub keypair: PqcKeyPair,
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
            PqcKeyPair::MlDsa44(_) => ID_ML_DSA_44,
            PqcKeyPair::MlDsa65(_) => ID_ML_DSA_65,
            PqcKeyPair::MlDsa87(_) => ID_ML_DSA_87,
            PqcKeyPair::Sha2_128f(_) => ID_SLH_DSA_SHA_2_128_F,
            PqcKeyPair::Sha2_128s(_) => ID_SLH_DSA_SHA_2_128_S,
            PqcKeyPair::Sha2_192f(_) => ID_SLH_DSA_SHA_2_192_F,
            PqcKeyPair::Sha2_192s(_) => ID_SLH_DSA_SHA_2_192_S,
            PqcKeyPair::Sha2_256f(_) => ID_SLH_DSA_SHA_2_256_F,
            PqcKeyPair::Sha2_256s(_) => ID_SLH_DSA_SHA_2_256_S,
            PqcKeyPair::Shake128f(_) => ID_SLH_DSA_SHAKE_128_F,
            PqcKeyPair::Shake128s(_) => ID_SLH_DSA_SHAKE_128_S,
            PqcKeyPair::Shake192f(_) => ID_SLH_DSA_SHAKE_192_F,
            PqcKeyPair::Shake192s(_) => ID_SLH_DSA_SHAKE_192_S,
            PqcKeyPair::Shake256f(_) => ID_SLH_DSA_SHAKE_256_F,
            PqcKeyPair::Shake256s(_) => ID_SLH_DSA_SHAKE_256_S,
            PqcKeyPair::Mldsa44Rsa2048PssSha256(_) => ID_MLDSA44_RSA2048_PSS_SHA256,
            PqcKeyPair::Mldsa44Rsa2048Pkcs15Sha256(_) => ID_MLDSA44_RSA2048_PKCS15_SHA256,
            PqcKeyPair::Mldsa44Ed25519Sha512(_) => ID_MLDSA44_ED25519_SHA512,
            PqcKeyPair::Mldsa44EcdsaP256Sha256(_) => ID_MLDSA44_ECDSA_P256_SHA256,
            PqcKeyPair::Mldsa65Rsa3072PssSha512(_) => ID_MLDSA65_RSA3072_PSS_SHA512,
            PqcKeyPair::Mldsa65Rsa4096PssSha512(_) => ID_MLDSA65_RSA4096_PSS_SHA512,
            PqcKeyPair::Mldsa65Rsa4096Pkcs15Sha512(_) => ID_MLDSA65_RSA4096_PKCS15_SHA512,
            PqcKeyPair::Mldsa65EcdsaP256Sha512(_) => ID_MLDSA65_ECDSA_P256_SHA512,
            PqcKeyPair::Mldsa65EcdsaP384Sha512(_) => ID_MLDSA65_ECDSA_P384_SHA512,
            PqcKeyPair::Mldsa65Ed25519Sha512(_) => ID_MLDSA65_ED25519_SHA512,
            PqcKeyPair::Mldsa87EcdsaP384Sha512(_) => ID_MLDSA87_ECDSA_P384_SHA512,
            PqcKeyPair::Mldsa87Ed448Shake256(_) => ID_MLDSA87_ED448_SHAKE256,
            PqcKeyPair::Mldsa87Rsa3072PssSha512(_) => ID_MLDSA87_RSA3072_PSS_SHA512,
            PqcKeyPair::Mldsa87Rsa4096PssSha512(_) => ID_MLDSA87_RSA4096_PSS_SHA512,
            PqcKeyPair::Mldsa87EcdsaP521Sha512(_) => ID_MLDSA87_ECDSA_P521_SHA512,
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
            PqcKeyPair::Mldsa44Rsa2048PssSha256(sk) => {
                let rsa = sk.1.to_public_key().to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcKeyPair::Mldsa44Rsa2048Pkcs15Sha256(sk) => {
                let rsa = sk.1.to_public_key().to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcKeyPair::Mldsa44Ed25519Sha512(sk) => {
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.verifying_key();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa44EcdsaP256Sha256(sk) => {
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.verifying_key().to_encoded_point(true);

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65Rsa3072PssSha512(sk) => {
                let rsa = sk.1.to_public_key().to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65Rsa4096PssSha512(sk) => {
                let rsa = sk.1.to_public_key().to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65Rsa4096Pkcs15Sha512(sk) => {
                let rsa = sk.1.to_public_key().to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65EcdsaP256Sha512(sk) => {
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.verifying_key().to_encoded_point(true);

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65EcdsaP384Sha512(sk) => {
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.verifying_key().to_encoded_point(true);

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65Ed25519Sha512(sk) => {
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.verifying_key();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa87EcdsaP384Sha512(sk) => {
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.verifying_key().to_encoded_point(true);

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa87Ed448Shake256(_) => {
                todo!("support serializing Mldsa87Ed448Shake256 public key")
            }
            PqcKeyPair::Mldsa87Rsa3072PssSha512(sk) => {
                let rsa = sk.1.to_public_key().to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcKeyPair::Mldsa87Rsa4096PssSha512(sk) => {
                let rsa = sk.1.to_public_key().to_public_key_der().unwrap();
                let spki = SubjectPublicKeyInfo::from_der(&rsa.to_vec()).unwrap();
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut spki.subject_public_key.as_bytes().unwrap().to_vec());
                retval
            }
            PqcKeyPair::Mldsa87EcdsaP521Sha512(sk) => {
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.verifying_key().to_encoded_point(true);

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
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
            PqcKeyPair::Mldsa44Rsa2048PssSha256(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa44Rsa2048Pkcs15Sha256(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa44Ed25519Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.to_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa44EcdsaP256Sha256(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.to_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65Rsa3072PssSha512(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65Rsa4096PssSha512(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65Rsa4096Pkcs15Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65EcdsaP256Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.to_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65EcdsaP384Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.to_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65Ed25519Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.to_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa87EcdsaP384Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.to_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa87Ed448Shake256(_) => {
                todo!("support serializing Mldsa87Ed448Shake256 private key")
            }
            PqcKeyPair::Mldsa87Rsa3072PssSha512(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa87Rsa4096PssSha512(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa87EcdsaP521Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.to_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
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
            PqcKeyPair::Mldsa44Rsa2048PssSha256(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let rsa_private = sk.1.clone();
                let rsa = rsa_private.to_public_key();
                PqcVerifyingKey::Mldsa44Rsa2048PssSha256(Box::new((mldsa, rsa)))
            }
            PqcKeyPair::Mldsa44Rsa2048Pkcs15Sha256(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let rsa_private = sk.1.clone();
                let rsa = rsa_private.to_public_key();
                PqcVerifyingKey::Mldsa44Rsa2048Pkcs15Sha256(Box::new((mldsa, rsa)))
            }
            PqcKeyPair::Mldsa44Ed25519Sha512(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let ecdsa = sk.1.verifying_key();
                PqcVerifyingKey::Mldsa44Ed25519Sha512(Box::new((mldsa, ecdsa)))
            }
            PqcKeyPair::Mldsa44EcdsaP256Sha256(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let ecdsa = sk.1.verifying_key();
                PqcVerifyingKey::Mldsa44EcdsaP256Sha256(Box::new((mldsa, *ecdsa)))
            }
            PqcKeyPair::Mldsa65Rsa3072PssSha512(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let rsa_private = sk.1.clone();
                let rsa = rsa_private.to_public_key();
                PqcVerifyingKey::Mldsa65Rsa3072PssSha512(Box::new((mldsa, rsa)))
            }
            PqcKeyPair::Mldsa65Rsa4096PssSha512(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let rsa_private = sk.1.clone();
                let rsa = rsa_private.to_public_key();
                PqcVerifyingKey::Mldsa65Rsa4096PssSha512(Box::new((mldsa, rsa)))
            }
            PqcKeyPair::Mldsa65Rsa4096Pkcs15Sha512(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let rsa_private = sk.1.clone();
                let rsa = rsa_private.to_public_key();
                PqcVerifyingKey::Mldsa65Rsa4096Pkcs15Sha512(Box::new((mldsa, rsa)))
            }
            PqcKeyPair::Mldsa65EcdsaP256Sha512(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let ecdsa = sk.1.verifying_key();
                PqcVerifyingKey::Mldsa65EcdsaP256Sha512(Box::new((mldsa, *ecdsa)))
            }
            PqcKeyPair::Mldsa65EcdsaP384Sha512(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let ecdsa = sk.1.verifying_key();
                PqcVerifyingKey::Mldsa65EcdsaP384Sha512(Box::new((mldsa, *ecdsa)))
            }
            PqcKeyPair::Mldsa65Ed25519Sha512(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let ecdsa = sk.1.verifying_key();
                PqcVerifyingKey::Mldsa65Ed25519Sha512(Box::new((mldsa, ecdsa)))
            }
            PqcKeyPair::Mldsa87EcdsaP384Sha512(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let ecdsa = sk.1.verifying_key();
                PqcVerifyingKey::Mldsa87EcdsaP384Sha512(Box::new((mldsa, *ecdsa)))
            }
            PqcKeyPair::Mldsa87Ed448Shake256(_) => {
                todo!("support serializing Mldsa87Ed448Shake256 public key")
            }
            PqcKeyPair::Mldsa87Rsa3072PssSha512(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let rsa_private = sk.1.clone();
                let rsa = rsa_private.to_public_key();
                PqcVerifyingKey::Mldsa87Rsa3072PssSha512(Box::new((mldsa, rsa)))
            }
            PqcKeyPair::Mldsa87Rsa4096PssSha512(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let rsa_private = sk.1.clone();
                let rsa = rsa_private.to_public_key();
                PqcVerifyingKey::Mldsa87Rsa4096PssSha512(Box::new((mldsa, rsa)))
            }
            PqcKeyPair::Mldsa87EcdsaP521Sha512(sk) => {
                let mldsa = sk.0.verifying_key().clone();
                let ecdsa = sk.1.verifying_key();
                PqcVerifyingKey::Mldsa87EcdsaP521Sha512(Box::new((mldsa, *ecdsa)))
            }
        }
    }

    fn prepare_message_rep(&self, message_to_verify: &[u8]) -> crate::error::Result<Vec<u8>> {
        let oid = self.oid();
        let domain = oid.to_der()?;
        let ctx_len = [0x00];
        let hash = hash_message(oid, message_to_verify)?;

        // Prefix || Label || len(ctx) || ctx || PH( M )
        let mut message_rep = vec![];
        message_rep.append(&mut PREFIX.to_vec());
        message_rep.append(&mut domain.to_vec());
        message_rep.append(&mut ctx_len.to_vec());
        message_rep.append(&mut hash.to_vec());

        Ok(message_rep)
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> crate::error::Result<PqcSignature> {
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
            PqcKeyPair::Mldsa44Rsa2048PssSha256(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let rsa_sk = rsa::pss::SigningKey::<Sha256>::new(sk.1.clone());
                let rsa = rsa_sk.sign_with_rng(&mut rand::rng(), &msg_rep).to_vec();
                Ok(PqcSignature::Mldsa44Rsa2048PssSha256(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa44Rsa2048Pkcs15Sha256(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let rsa_sk = rsa::pkcs1v15::SigningKey::<Sha256>::new(sk.1.clone());
                let rsa = rsa_sk.sign(&msg_rep).to_vec();
                Ok(PqcSignature::Mldsa44Rsa2048Pkcs15Sha256(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa44Ed25519Sha512(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let ecdsa = sk.1.sign(&msg_rep);
                Ok(PqcSignature::Mldsa44Ed25519Sha512(Box::new((mldsa, ecdsa))))
            }
            PqcKeyPair::Mldsa44EcdsaP256Sha256(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let ecdsa = sk.1.sign(&msg_rep);
                Ok(PqcSignature::Mldsa44EcdsaP256Sha256(Box::new((
                    mldsa, ecdsa,
                ))))
            }
            PqcKeyPair::Mldsa65Rsa3072PssSha512(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let rsa_sk = rsa::pss::SigningKey::<Sha384>::new(sk.1.clone());
                let rsa = rsa_sk.sign_with_rng(&mut rand::rng(), &msg_rep).to_vec();
                Ok(PqcSignature::Mldsa65Rsa3072PssSha512(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa65Rsa4096PssSha512(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let rsa_sk = rsa::pss::SigningKey::<Sha384>::new(sk.1.clone());
                let rsa = rsa_sk.sign_with_rng(&mut rand::rng(), &msg_rep).to_vec();
                Ok(PqcSignature::Mldsa65Rsa4096PssSha512(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa65Rsa4096Pkcs15Sha512(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let rsa_sk = rsa::pkcs1v15::SigningKey::<Sha384>::new(sk.1.clone());
                let rsa = rsa_sk.sign(&msg_rep).to_vec();
                Ok(PqcSignature::Mldsa65Rsa4096Pkcs15Sha512(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa65EcdsaP256Sha512(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let ecdsa = sk.1.sign(&msg_rep);
                Ok(PqcSignature::Mldsa65EcdsaP256Sha512(Box::new((
                    mldsa, ecdsa,
                ))))
            }
            PqcKeyPair::Mldsa65EcdsaP384Sha512(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let ecdsa = sk.1.sign(&msg_rep);
                Ok(PqcSignature::Mldsa65EcdsaP384Sha512(Box::new((
                    mldsa, ecdsa,
                ))))
            }
            PqcKeyPair::Mldsa65Ed25519Sha512(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let ecdsa = sk.1.sign(&msg_rep);
                Ok(PqcSignature::Mldsa65Ed25519Sha512(Box::new((mldsa, ecdsa))))
            }
            PqcKeyPair::Mldsa87EcdsaP384Sha512(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let ecdsa = sk.1.sign(&msg_rep);
                Ok(PqcSignature::Mldsa87EcdsaP384Sha512(Box::new((
                    mldsa, ecdsa,
                ))))
            }
            PqcKeyPair::Mldsa87Ed448Shake256(_) => {
                todo!("support signing with Mldsa87Ed448Shake256")
            }
            PqcKeyPair::Mldsa87Rsa3072PssSha512(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let rsa_sk = rsa::pss::SigningKey::<Sha384>::new(sk.1.clone());
                let rsa = rsa_sk.sign_with_rng(&mut rand::rng(), &msg_rep).to_vec();
                Ok(PqcSignature::Mldsa87Rsa3072PssSha512(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa87Rsa4096PssSha512(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let rsa_sk = rsa::pss::SigningKey::<Sha384>::new(sk.1.clone());
                let rsa = rsa_sk.sign_with_rng(&mut rand::rng(), &msg_rep).to_vec();
                Ok(PqcSignature::Mldsa87Rsa4096PssSha512(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa87EcdsaP521Sha512(sk) => {
                let msg_rep = self.prepare_message_rep(msg)?;
                let mldsa = sk.0.signing_key().sign(&msg_rep);
                let ecdsa = sk.1.sign(&msg_rep);
                Ok(PqcSignature::Mldsa87EcdsaP521Sha512(Box::new((
                    mldsa, ecdsa,
                ))))
            }
        }
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

impl Keypair for PqcSigner {
    type VerifyingKey = PqcVerifyingKey;
    fn verifying_key(&self) -> <Self as Keypair>::VerifyingKey {
        self.verifying_key()
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
