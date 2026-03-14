use const_oid::db::fips202::ID_SHAKE_256;
use zerocopy::IntoBytes;

use signature::{Keypair, RandomizedSigner, Signer};

use const_oid::ObjectIdentifier;
use der::{Decode, Document, Encode, asn1::BitString};
use spki::{
    AlgorithmIdentifier, AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier,
    EncodePublicKey, SubjectPublicKeyInfoOwned,
};

use crate::asn1::utils::get_domain;
use crate::pqc::key_pair::PqcKeyPair;
use crate::pqc::signature::PqcSignature;
use crate::pqc::verifying_key::PqcVerifyingKey;
use const_oid::db::fips204::{
    ID_HASH_ML_DSA_44_WITH_SHA_512, ID_HASH_ML_DSA_65_WITH_SHA_512, ID_HASH_ML_DSA_87_WITH_SHA_512,
    ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87,
};
use const_oid::db::fips205::{
    ID_HASH_SLH_DSA_SHA_2_128_F_WITH_SHA_256, ID_HASH_SLH_DSA_SHA_2_128_S_WITH_SHA_256,
    ID_HASH_SLH_DSA_SHA_2_192_F_WITH_SHA_512, ID_HASH_SLH_DSA_SHA_2_192_S_WITH_SHA_512,
    ID_HASH_SLH_DSA_SHA_2_256_F_WITH_SHA_512, ID_HASH_SLH_DSA_SHA_2_256_S_WITH_SHA_512,
    ID_HASH_SLH_DSA_SHAKE_128_F_WITH_SHAKE_128, ID_HASH_SLH_DSA_SHAKE_128_S_WITH_SHAKE_128,
    ID_HASH_SLH_DSA_SHAKE_192_F_WITH_SHAKE_256, ID_HASH_SLH_DSA_SHAKE_192_S_WITH_SHAKE_256,
    ID_HASH_SLH_DSA_SHAKE_256_F_WITH_SHAKE_256, ID_HASH_SLH_DSA_SHAKE_256_S_WITH_SHAKE_256,
    ID_SLH_DSA_SHA_2_128_F, ID_SLH_DSA_SHA_2_128_S, ID_SLH_DSA_SHA_2_192_F, ID_SLH_DSA_SHA_2_192_S,
    ID_SLH_DSA_SHA_2_256_F, ID_SLH_DSA_SHA_2_256_S, ID_SLH_DSA_SHAKE_128_F, ID_SLH_DSA_SHAKE_128_S,
    ID_SLH_DSA_SHAKE_192_F, ID_SLH_DSA_SHAKE_192_S, ID_SLH_DSA_SHAKE_256_F, ID_SLH_DSA_SHAKE_256_S,
};
use const_oid::db::rfc5912::{ID_SHA_256, ID_SHA_512};
use lazy_static::lazy_static;
use pqckeys::pqc_oids::{
    ID_MLDSA44_ECDSA_P256_SHA256, ID_MLDSA44_ED25519_SHA512, ID_MLDSA44_RSA2048_PKCS15_SHA256,
    ID_MLDSA44_RSA2048_PSS_SHA256, ID_MLDSA65_ECDSA_P256_SHA512, ID_MLDSA65_ECDSA_P384_SHA512,
    ID_MLDSA65_ED25519_SHA512, ID_MLDSA65_RSA3072_PSS_SHA512, ID_MLDSA65_RSA4096_PKCS15_SHA512,
    ID_MLDSA65_RSA4096_PSS_SHA512, ID_MLDSA87_ECDSA_P384_SHA512, ID_MLDSA87_ECDSA_P521_SHA512,
    ID_MLDSA87_ED448_SHAKE256, ID_MLDSA87_RSA3072_PSS_SHA512, ID_MLDSA87_RSA4096_PSS_SHA512,
};
use rsa::pkcs1::EncodeRsaPrivateKey;
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use signature::SignatureEncoding;
use spki::SubjectPublicKeyInfoOwned as SubjectPublicKeyInfo;

/// DER-encoded OID bytes for SHA-256: 2.16.840.1.101.3.4.2.1
const SHA256_OID_BYTES: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];
/// DER-encoded OID bytes for SHA-512: 2.16.840.1.101.3.4.2.3
const SHA512_OID_BYTES: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
];
/// DER-encoded OID bytes for SHAKE-128: 2.16.840.1.101.3.4.2.11
const SHAKE128_OID_BYTES: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B,
];
/// DER-encoded OID bytes for SHAKE-256: 2.16.840.1.101.3.4.2.12
const SHAKE256_OID_BYTES: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C,
];

lazy_static! {
    // CompositeAlgorithmSignatures2025
    static ref PREFIX: [u8; 32] =
        hex_literal::hex!("436F6D706F73697465416C676F726974686D5369676E61747572657332303235");
}

pub fn get_hash_alg(composite_oid: ObjectIdentifier) -> crate::error::Result<ObjectIdentifier> {
    if composite_oid == ID_MLDSA44_RSA2048_PKCS15_SHA256
        || composite_oid == ID_MLDSA44_RSA2048_PSS_SHA256
        || composite_oid == ID_MLDSA44_ECDSA_P256_SHA256
    {
        Ok(ID_SHA_256)
    } else if composite_oid == ID_MLDSA87_ED448_SHAKE256 {
        Ok(ID_SHAKE_256)
    } else {
        Ok(ID_SHA_512)
    }
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
pub struct PqcSigner {
    pub seed: Vec<u8>,
    pub keypair: PqcKeyPair,
    pub oid: ObjectIdentifier,
}

impl PqcSigner {
    pub(crate) fn new(seed: &[u8], keypair: PqcKeyPair) -> Self {
        let oid = Self::derive_oid(&keypair);
        PqcSigner {
            seed: seed.to_vec(),
            keypair,
            oid,
        }
    }

    pub(crate) fn new_with_oid(seed: &[u8], keypair: PqcKeyPair, oid: ObjectIdentifier) -> Self {
        PqcSigner {
            seed: seed.to_vec(),
            keypair,
            oid,
        }
    }

    pub(crate) fn oid(&self) -> ObjectIdentifier {
        self.oid
    }

    /// Returns the key algorithm OID derived from the keypair variant.
    /// Use this for SPKI encoding where the key algorithm (not the signature algorithm) is needed.
    pub(crate) fn spki_oid(&self) -> ObjectIdentifier {
        Self::derive_oid(&self.keypair)
    }

    fn derive_oid(keypair: &PqcKeyPair) -> ObjectIdentifier {
        match keypair {
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

    #[allow(clippy::unwrap_used)] // todo - fix me
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
                let ecdsa = sk.1.verifying_key().to_sec1_point(true);

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
                let ecdsa = sk.1.verifying_key().to_sec1_point(true);

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65EcdsaP384Sha512(sk) => {
                let mut mldsa = sk.0.verifying_key().encode().as_bytes().to_vec();
                let ecdsa = sk.1.verifying_key().to_sec1_point(true);

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
                let ecdsa = sk.1.verifying_key().to_sec1_point(true);

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
                let ecdsa = sk.1.verifying_key().to_sec1_point(true);

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
        }
    }
    #[allow(deprecated, clippy::unwrap_used)] // allow to_expanded, todo - fix unwrap_used
    pub(crate) fn private_key(&self) -> Vec<u8> {
        match &self.keypair {
            PqcKeyPair::MlDsa44(kp) => {
                let sk = kp.signing_key();
                sk.to_expanded().as_bytes().to_vec()
            }
            PqcKeyPair::MlDsa65(kp) => {
                let sk = kp.signing_key();
                sk.to_expanded().as_bytes().to_vec()
            }
            PqcKeyPair::MlDsa87(kp) => {
                let sk = kp.signing_key();
                sk.to_expanded().as_bytes().to_vec()
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
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa44Rsa2048Pkcs15Sha256(sk) => {
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa44Ed25519Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
                let ecdsa = sk.1.to_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa44EcdsaP256Sha256(sk) => {
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
                let ecdsa = sk.1.to_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65Rsa3072PssSha512(sk) => {
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65Rsa4096PssSha512(sk) => {
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65Rsa4096Pkcs15Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65EcdsaP256Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
                let ecdsa = sk.1.to_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65EcdsaP384Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
                let ecdsa = sk.1.to_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa65Ed25519Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
                let ecdsa = sk.1.to_bytes().to_vec();

                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut ecdsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa87EcdsaP384Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
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
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa87Rsa4096PssSha512(sk) => {
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
                let rsa = sk.1.to_pkcs1_der().unwrap();
                let mut retval = vec![];
                retval.append(&mut mldsa);
                retval.append(&mut rsa.as_bytes().to_vec());
                retval
            }
            PqcKeyPair::Mldsa87EcdsaP521Sha512(sk) => {
                let mut mldsa = sk.0.signing_key().to_expanded().as_bytes().to_vec();
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

    fn prepare_message_rep(
        &self,
        message_to_verify: &[u8],
    ) -> crate::error::Result<(Vec<u8>, Vec<u8>)> {
        let oid = self.oid();
        let domain = get_domain(oid)?;
        let ctx_len = [0x00];
        let hash = hash_message(oid, message_to_verify)?;

        // Prefix || Label || len(ctx) || ctx || PH( M )
        let mut message_rep = vec![];
        message_rep.append(&mut PREFIX.to_vec());
        message_rep.append(&mut domain.to_vec());
        message_rep.append(&mut ctx_len.to_vec());
        message_rep.append(&mut hash.to_vec());

        Ok((message_rep, domain))
    }

    fn hash_ml_dsa_sign(&self, msg: &[u8]) -> crate::error::Result<PqcSignature> {
        let hash = Sha512::digest(msg);
        let mut message_rep = vec![0x01, 0x00];
        message_rep.extend_from_slice(&SHA512_OID_BYTES);
        message_rep.extend_from_slice(&hash);

        let mut rng = rand::rng();
        let rnd: ml_dsa::B32 = crate::misc::gen_certs::rand(&mut rng);

        match &self.keypair {
            PqcKeyPair::MlDsa44(kp) => {
                let sig = kp.signing_key().sign_internal(&[&message_rep], &rnd);
                Ok(PqcSignature::MlDsa44(Box::new(sig)))
            }
            PqcKeyPair::MlDsa65(kp) => {
                let sig = kp.signing_key().sign_internal(&[&message_rep], &rnd);
                Ok(PqcSignature::MlDsa65(Box::new(sig)))
            }
            PqcKeyPair::MlDsa87(kp) => {
                let sig = kp.signing_key().sign_internal(&[&message_rep], &rnd);
                Ok(PqcSignature::MlDsa87(Box::new(sig)))
            }
            _ => Err(crate::error::Error::Unrecognized),
        }
    }

    fn hash_slh_dsa_sign(&self, msg: &[u8]) -> crate::error::Result<PqcSignature> {
        let oid = self.oid;
        let (hash_oid_bytes, hash) = if oid == ID_HASH_SLH_DSA_SHA_2_128_S_WITH_SHA_256
            || oid == ID_HASH_SLH_DSA_SHA_2_128_F_WITH_SHA_256
        {
            (SHA256_OID_BYTES.as_slice(), Sha256::digest(msg).to_vec())
        } else if oid == ID_HASH_SLH_DSA_SHA_2_192_S_WITH_SHA_512
            || oid == ID_HASH_SLH_DSA_SHA_2_192_F_WITH_SHA_512
            || oid == ID_HASH_SLH_DSA_SHA_2_256_S_WITH_SHA_512
            || oid == ID_HASH_SLH_DSA_SHA_2_256_F_WITH_SHA_512
        {
            (SHA512_OID_BYTES.as_slice(), Sha512::digest(msg).to_vec())
        } else if oid == ID_HASH_SLH_DSA_SHAKE_128_S_WITH_SHAKE_128
            || oid == ID_HASH_SLH_DSA_SHAKE_128_F_WITH_SHAKE_128
        {
            let mut hasher = sha3::Shake128::default();
            hasher.update(msg);
            let mut output = vec![0u8; 32];
            hasher.finalize_xof().read(&mut output);
            (SHAKE128_OID_BYTES.as_slice(), output)
        } else {
            // SHAKE-256 variants (192 and 256)
            let mut hasher = sha3::Shake256::default();
            hasher.update(msg);
            let mut output = vec![0u8; 64];
            hasher.finalize_xof().read(&mut output);
            (SHAKE256_OID_BYTES.as_slice(), output)
        };

        let mut message_rep = vec![0x01, 0x00];
        message_rep.extend_from_slice(hash_oid_bytes);
        message_rep.extend_from_slice(&hash);

        match &self.keypair {
            PqcKeyPair::Sha2_128s(sk) => Ok(PqcSignature::Sha2_128s(Box::new(
                sk.slh_sign_internal(&[&message_rep], None),
            ))),
            PqcKeyPair::Sha2_128f(sk) => Ok(PqcSignature::Sha2_128f(Box::new(
                sk.slh_sign_internal(&[&message_rep], None),
            ))),
            PqcKeyPair::Sha2_192s(sk) => Ok(PqcSignature::Sha2_192s(Box::new(
                sk.slh_sign_internal(&[&message_rep], None),
            ))),
            PqcKeyPair::Sha2_192f(sk) => Ok(PqcSignature::Sha2_192f(Box::new(
                sk.slh_sign_internal(&[&message_rep], None),
            ))),
            PqcKeyPair::Sha2_256s(sk) => Ok(PqcSignature::Sha2_256s(Box::new(
                sk.slh_sign_internal(&[&message_rep], None),
            ))),
            PqcKeyPair::Sha2_256f(sk) => Ok(PqcSignature::Sha2_256f(Box::new(
                sk.slh_sign_internal(&[&message_rep], None),
            ))),
            PqcKeyPair::Shake128s(sk) => Ok(PqcSignature::Shake128s(Box::new(
                sk.slh_sign_internal(&[&message_rep], None),
            ))),
            PqcKeyPair::Shake128f(sk) => Ok(PqcSignature::Shake128f(Box::new(
                sk.slh_sign_internal(&[&message_rep], None),
            ))),
            PqcKeyPair::Shake192s(sk) => Ok(PqcSignature::Shake192s(Box::new(
                sk.slh_sign_internal(&[&message_rep], None),
            ))),
            PqcKeyPair::Shake192f(sk) => Ok(PqcSignature::Shake192f(Box::new(
                sk.slh_sign_internal(&[&message_rep], None),
            ))),
            PqcKeyPair::Shake256s(sk) => Ok(PqcSignature::Shake256s(Box::new(
                sk.slh_sign_internal(&[&message_rep], None),
            ))),
            PqcKeyPair::Shake256f(sk) => Ok(PqcSignature::Shake256f(Box::new(
                sk.slh_sign_internal(&[&message_rep], None),
            ))),
            _ => Err(crate::error::Error::Unrecognized),
        }
    }

    fn is_hash_ml_dsa(&self) -> bool {
        self.oid == ID_HASH_ML_DSA_44_WITH_SHA_512
            || self.oid == ID_HASH_ML_DSA_65_WITH_SHA_512
            || self.oid == ID_HASH_ML_DSA_87_WITH_SHA_512
    }

    fn is_hash_slh_dsa(&self) -> bool {
        let oid = self.oid;
        oid == ID_HASH_SLH_DSA_SHA_2_128_S_WITH_SHA_256
            || oid == ID_HASH_SLH_DSA_SHA_2_128_F_WITH_SHA_256
            || oid == ID_HASH_SLH_DSA_SHA_2_192_S_WITH_SHA_512
            || oid == ID_HASH_SLH_DSA_SHA_2_192_F_WITH_SHA_512
            || oid == ID_HASH_SLH_DSA_SHA_2_256_S_WITH_SHA_512
            || oid == ID_HASH_SLH_DSA_SHA_2_256_F_WITH_SHA_512
            || oid == ID_HASH_SLH_DSA_SHAKE_128_S_WITH_SHAKE_128
            || oid == ID_HASH_SLH_DSA_SHAKE_128_F_WITH_SHAKE_128
            || oid == ID_HASH_SLH_DSA_SHAKE_192_S_WITH_SHAKE_256
            || oid == ID_HASH_SLH_DSA_SHAKE_192_F_WITH_SHAKE_256
            || oid == ID_HASH_SLH_DSA_SHAKE_256_S_WITH_SHAKE_256
            || oid == ID_HASH_SLH_DSA_SHAKE_256_F_WITH_SHAKE_256
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> crate::error::Result<PqcSignature> {
        if self.is_hash_ml_dsa() {
            return self.hash_ml_dsa_sign(msg);
        }
        if self.is_hash_slh_dsa() {
            return self.hash_slh_dsa_sign(msg);
        }

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
                let (msg_rep, label) = self.prepare_message_rep(msg)?;
                let mldsa =
                    sk.0.signing_key()
                        .sign_randomized(&msg_rep, &label, &mut rand::rng())
                        .map_err(|e| crate::error::Error::MlDsa(format!("{e:?}")))?;
                let rsa_sk = rsa::pss::SigningKey::<Sha256>::new_with_salt_len(sk.1.clone(), 32);
                let rsa = rsa_sk.sign_with_rng(&mut rand::rng(), &msg_rep).to_vec();
                Ok(PqcSignature::Mldsa44Rsa2048PssSha256(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa44Rsa2048Pkcs15Sha256(sk) => {
                let (msg_rep, label) = self.prepare_message_rep(msg)?;
                let mldsa =
                    sk.0.signing_key()
                        .sign_randomized(&msg_rep, &label, &mut rand::rng())
                        .map_err(|e| crate::error::Error::MlDsa(format!("{e:?}")))?;
                let rsa_sk = rsa::pkcs1v15::SigningKey::<Sha256>::new(sk.1.clone());
                let rsa = rsa_sk.sign(&msg_rep).to_vec();
                Ok(PqcSignature::Mldsa44Rsa2048Pkcs15Sha256(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa44Ed25519Sha512(_sk) => {
                todo!("restore when signature version conflict is resolved")
                // let msg_rep = self.prepare_message_rep(msg)?;
                // let mldsa = sk.0.signing_key().sign(&msg_rep);
                // let ecdsa = sk.1.sign(&msg_rep);
                // Ok(PqcSignature::Mldsa44Ed25519Sha512(Box::new((mldsa, ecdsa))))
            }
            PqcKeyPair::Mldsa44EcdsaP256Sha256(sk) => {
                let (msg_rep, label) = self.prepare_message_rep(msg)?;
                let mldsa =
                    sk.0.signing_key()
                        .sign_randomized(&msg_rep, &label, &mut rand::rng())
                        .map_err(|e| crate::error::Error::MlDsa(format!("{e:?}")))?;
                let ecdsa = sk.1.sign(&msg_rep);
                Ok(PqcSignature::Mldsa44EcdsaP256Sha256(Box::new((
                    mldsa, ecdsa,
                ))))
            }
            PqcKeyPair::Mldsa65Rsa3072PssSha512(sk) => {
                let (msg_rep, label) = self.prepare_message_rep(msg)?;
                let mldsa =
                    sk.0.signing_key()
                        .sign_randomized(&msg_rep, &label, &mut rand::rng())
                        .map_err(|e| crate::error::Error::MlDsa(format!("{e:?}")))?;
                let rsa_sk = rsa::pss::SigningKey::<Sha256>::new_with_salt_len(sk.1.clone(), 32);
                let rsa = rsa_sk.sign_with_rng(&mut rand::rng(), &msg_rep).to_vec();
                Ok(PqcSignature::Mldsa65Rsa3072PssSha512(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa65Rsa4096PssSha512(sk) => {
                let (msg_rep, label) = self.prepare_message_rep(msg)?;
                let mldsa =
                    sk.0.signing_key()
                        .sign_randomized(&msg_rep, &label, &mut rand::rng())
                        .map_err(|e| crate::error::Error::MlDsa(format!("{e:?}")))?;
                let rsa_sk = rsa::pss::SigningKey::<Sha384>::new_with_salt_len(sk.1.clone(), 48);
                let rsa = rsa_sk.sign_with_rng(&mut rand::rng(), &msg_rep).to_vec();
                Ok(PqcSignature::Mldsa65Rsa4096PssSha512(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa65Rsa4096Pkcs15Sha512(sk) => {
                let (msg_rep, label) = self.prepare_message_rep(msg)?;
                let mldsa =
                    sk.0.signing_key()
                        .sign_randomized(&msg_rep, &label, &mut rand::rng())
                        .map_err(|e| crate::error::Error::MlDsa(format!("{e:?}")))?;
                let rsa_sk = rsa::pkcs1v15::SigningKey::<Sha384>::new(sk.1.clone());
                let rsa = rsa_sk.sign(&msg_rep).to_vec();
                Ok(PqcSignature::Mldsa65Rsa4096Pkcs15Sha512(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa65EcdsaP256Sha512(sk) => {
                let (msg_rep, label) = self.prepare_message_rep(msg)?;
                let mldsa =
                    sk.0.signing_key()
                        .sign_randomized(&msg_rep, &label, &mut rand::rng())
                        .map_err(|e| crate::error::Error::MlDsa(format!("{e:?}")))?;
                let ecdsa = sk.1.sign(&msg_rep);
                Ok(PqcSignature::Mldsa65EcdsaP256Sha512(Box::new((
                    mldsa, ecdsa,
                ))))
            }
            PqcKeyPair::Mldsa65EcdsaP384Sha512(sk) => {
                let (msg_rep, label) = self.prepare_message_rep(msg)?;
                let mldsa =
                    sk.0.signing_key()
                        .sign_randomized(&msg_rep, &label, &mut rand::rng())
                        .map_err(|e| crate::error::Error::MlDsa(format!("{e:?}")))?;
                let ecdsa = sk.1.sign(&msg_rep);
                Ok(PqcSignature::Mldsa65EcdsaP384Sha512(Box::new((
                    mldsa, ecdsa,
                ))))
            }
            PqcKeyPair::Mldsa65Ed25519Sha512(_sk) => {
                todo!("restore when signature version conflict is resolved")
                // let msg_rep = self.prepare_message_rep(msg)?;
                // let mldsa = sk.0.signing_key().sign(&msg_rep);
                // let ecdsa = sk.1.sign(&msg_rep);
                // Ok(PqcSignature::Mldsa65Ed25519Sha512(Box::new((mldsa, ecdsa))))
            }
            PqcKeyPair::Mldsa87EcdsaP384Sha512(sk) => {
                let (msg_rep, label) = self.prepare_message_rep(msg)?;
                let mldsa =
                    sk.0.signing_key()
                        .sign_randomized(&msg_rep, &label, &mut rand::rng())
                        .map_err(|e| crate::error::Error::MlDsa(format!("{e:?}")))?;
                let ecdsa = sk.1.sign(&msg_rep);
                Ok(PqcSignature::Mldsa87EcdsaP384Sha512(Box::new((
                    mldsa, ecdsa,
                ))))
            }
            PqcKeyPair::Mldsa87Ed448Shake256(_) => {
                todo!("support signing with Mldsa87Ed448Shake256")
            }
            PqcKeyPair::Mldsa87Rsa3072PssSha512(sk) => {
                let (msg_rep, label) = self.prepare_message_rep(msg)?;
                let mldsa =
                    sk.0.signing_key()
                        .sign_randomized(&msg_rep, &label, &mut rand::rng())
                        .map_err(|e| crate::error::Error::MlDsa(format!("{e:?}")))?;
                let rsa_sk = rsa::pss::SigningKey::<Sha256>::new_with_salt_len(sk.1.clone(), 32);
                let rsa = rsa_sk.sign_with_rng(&mut rand::rng(), &msg_rep).to_vec();
                Ok(PqcSignature::Mldsa87Rsa3072PssSha512(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa87Rsa4096PssSha512(sk) => {
                let (msg_rep, label) = self.prepare_message_rep(msg)?;
                let mldsa =
                    sk.0.signing_key()
                        .sign_randomized(&msg_rep, &label, &mut rand::rng())
                        .map_err(|e| crate::error::Error::MlDsa(format!("{e:?}")))?;
                let rsa_sk = rsa::pss::SigningKey::<Sha384>::new_with_salt_len(sk.1.clone(), 48);
                let rsa = rsa_sk.sign_with_rng(&mut rand::rng(), &msg_rep).to_vec();
                Ok(PqcSignature::Mldsa87Rsa4096PssSha512(Box::new((
                    mldsa, rsa,
                ))))
            }
            PqcKeyPair::Mldsa87EcdsaP521Sha512(sk) => {
                let (msg_rep, label) = self.prepare_message_rep(msg)?;
                let mldsa =
                    sk.0.signing_key()
                        .sign_randomized(&msg_rep, &label, &mut rand::rng())
                        .map_err(|e| crate::error::Error::MlDsa(format!("{e:?}")))?;
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
            oid: self.spki_oid(),
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
