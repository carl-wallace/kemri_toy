//! ECDH KEM implementation

use log::error;
use rand::rng;

use const_oid::{AssociatedOid, ObjectIdentifier};
use elliptic_curve::{
    Curve, CurveArithmetic, FieldBytesSize, PublicKey, SecretKey,
    ecdh::{EphemeralSecret, diffie_hellman},
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint, ValidatePublicKey},
};

use crate::error::Error;

pub struct EcdhKem<C>
where
    C: AssociatedOid + Curve + ValidatePublicKey,
    FieldBytesSize<C>: ModulusSize,
{
    sk: SecretKey<C>,
}

impl AssociatedOid for EcdhKem<p256::NistP256> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
}

impl AssociatedOid for EcdhKem<p384::NistP384> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
}
impl AssociatedOid for EcdhKem<p521::NistP521> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
}

impl<C> EcdhKem<C>
where
    C: AssociatedOid + Curve + CurveArithmetic + ValidatePublicKey,
    FieldBytesSize<C>: ModulusSize,
{
    pub fn new(der_sk: &[u8]) -> crate::error::Result<Self> {
        let sk = match SecretKey::<C>::from_slice(der_sk) {
            Ok(sk) => sk,
            Err(e) => {
                error!("Failed to decrypt ECDH secret key: {e}");
                return Err(Error::Unrecognized);
            }
        };
        Ok(Self { sk })
    }
    pub fn keygen() -> crate::error::Result<Self> {
        let mut rng = rng();
        let sk = SecretKey::<C>::random(&mut rng);
        Ok(Self { sk })
    }

    pub fn to_public_key(&self) -> PublicKey<C> {
        self.sk.public_key()
    }

    pub fn to_bytes(&self) -> crate::error::Result<Vec<u8>> {
        Ok(self.sk.to_bytes().to_vec())
    }

    pub fn encap(recip_pub_key_bytes: &[u8]) -> crate::error::Result<(Vec<u8>, Vec<u8>)>
    where
        <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
        <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
    {
        let mut rng = rng();
        let ephemeral_secret = EphemeralSecret::<C>::random(&mut rng);
        let recip_pk = PublicKey::<C>::from_sec1_bytes(recip_pub_key_bytes).unwrap();
        let ss = ephemeral_secret.diffie_hellman(&recip_pk);
        let ct = ephemeral_secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Ok((ss.raw_secret_bytes().to_vec(), ct))
    }
    pub fn decap(&self, ciphertext: &[u8]) -> crate::error::Result<Vec<u8>>
    where
        <C as CurveArithmetic>::AffinePoint: FromEncodedPoint<C>,
        <C as CurveArithmetic>::AffinePoint: ToEncodedPoint<C>,
    {
        let pk_e = PublicKey::<C>::from_sec1_bytes(ciphertext).unwrap();
        let ss = diffie_hellman(self.sk.to_nonzero_scalar(), pk_e.as_affine());
        Ok(ss.raw_secret_bytes().to_vec())
    }
}

#[test]
fn test_ecdh_kem() {
    let sender = EcdhKem::<p256::NistP256>::keygen().unwrap();
    let _sender_pub = sender.to_public_key();
    let recip = EcdhKem::<p256::NistP256>::keygen().unwrap();
    let recip_pub = recip.to_public_key();
    let recip_pub_key_bytes = recip_pub.to_encoded_point(false).as_bytes().to_vec();
    let (ss, ct) = EcdhKem::<p256::NistP256>::encap(&recip_pub_key_bytes).unwrap();
    let ss2 = recip.decap(&ct).unwrap();
    assert_eq!(ss, ss2);
}
