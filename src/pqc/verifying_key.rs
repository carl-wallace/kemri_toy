use const_oid::ObjectIdentifier;
use const_oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
use const_oid::db::fips205::{
    ID_SLH_DSA_SHA_2_128_F, ID_SLH_DSA_SHA_2_128_S, ID_SLH_DSA_SHA_2_192_F, ID_SLH_DSA_SHA_2_192_S,
    ID_SLH_DSA_SHA_2_256_F, ID_SLH_DSA_SHA_2_256_S, ID_SLH_DSA_SHAKE_128_F, ID_SLH_DSA_SHAKE_128_S,
    ID_SLH_DSA_SHAKE_192_F, ID_SLH_DSA_SHAKE_192_S, ID_SLH_DSA_SHAKE_256_F, ID_SLH_DSA_SHAKE_256_S,
};
use der::asn1::BitString;
use der::{Decode, Document, Encode};
use ed448_goldilocks::Ed448;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, VerifyingKey};
use pqckeys::pqc_oids::{
    ID_MLDSA44_ECDSA_P256_SHA256, ID_MLDSA44_ED25519_SHA512, ID_MLDSA44_RSA2048_PKCS15_SHA256,
    ID_MLDSA44_RSA2048_PSS_SHA256, ID_MLDSA65_ECDSA_P256_SHA512, ID_MLDSA65_ECDSA_P384_SHA512,
    ID_MLDSA65_ED25519_SHA512, ID_MLDSA65_RSA3072_PSS_SHA512, ID_MLDSA65_RSA4096_PKCS15_SHA512,
    ID_MLDSA65_RSA4096_PSS_SHA512, ID_MLDSA87_ECDSA_P384_SHA512, ID_MLDSA87_ECDSA_P521_SHA512,
    ID_MLDSA87_ED448_SHAKE256, ID_MLDSA87_RSA3072_PSS_SHA512, ID_MLDSA87_RSA4096_PSS_SHA512,
};
use rsa::RsaPublicKey;
use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s,
};
use spki::{
    AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned as SubjectPublicKeyInfo,
    SubjectPublicKeyInfoOwned,
};
use zerocopy::IntoBytes;

#[allow(dead_code)]
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
    #[allow(clippy::unwrap_used)] // todo - fix me
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
                let ecdsa = vk.1.to_sec1_point(true);

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
                let ecdsa = vk.1.to_sec1_point(true);

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcVerifyingKey::Mldsa65EcdsaP384Sha512(vk) => {
                let mut mldsa = vk.0.encode().as_bytes().to_vec();
                let ecdsa = vk.1.to_sec1_point(true);

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
                let ecdsa = vk.1.to_sec1_point(true);

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
                let ecdsa = vk.1.to_sec1_point(true);

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
