use der::asn1::BitString;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, Signature};
use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s,
};
use spki::SignatureBitStringEncoding;
use zerocopy::IntoBytes;

#[allow(dead_code)]
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
