use ed448_goldilocks::Ed448;
use ml_dsa::{KeyPair, MlDsa44, MlDsa65, MlDsa87};
use rsa::RsaPrivateKey;
use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s, SigningKey,
};

#[allow(dead_code)]
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
