use const_oid::AssociatedOid;
use elliptic_curve::ecdh::{EphemeralSecret, diffie_hellman};
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::sec1::{ModulusSize, ValidatePublicKey};
use elliptic_curve::{Curve, CurveArithmetic, FieldBytesSize, PublicKey, SecretKey};
use rand::rng;

pub struct EcdhKem<C>
where
    C: AssociatedOid + Curve + ValidatePublicKey,
    FieldBytesSize<C>: ModulusSize,
{
    sk: SecretKey<C>,
}

impl<C> EcdhKem<C>
where
    C: AssociatedOid + Curve + CurveArithmetic + ValidatePublicKey,
    FieldBytesSize<C>: ModulusSize,
{
    pub fn new(der_sk: &[u8]) -> crate::Result<Self> {
        let sk = SecretKey::<C>::from_slice(der_sk).unwrap();
        Ok(Self { sk })
    }
    pub fn keygen() -> crate::Result<Self> {
        let mut rng = rng();
        let sk = SecretKey::<C>::random(&mut rng);
        Ok(Self { sk })
    }

    pub fn to_public_key(&self) -> PublicKey<C> {
        self.sk.public_key()
    }

    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        Ok(self.sk.to_bytes().to_vec())
    }

    pub fn encap(recip_pub_key_bytes: &[u8]) -> crate::Result<(Vec<u8>, Vec<u8>)>
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
    pub fn decap(&self, ciphertext: &[u8]) -> crate::Result<Vec<u8>>
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
    let sender_pub = sender.to_public_key();
    let recip = EcdhKem::<p256::NistP256>::keygen().unwrap();
    let recip_pub = recip.to_public_key();
    let recip_pub_key_bytes = recip_pub.to_encoded_point(false).as_bytes().to_vec();
    let (ss, ct) = EcdhKem::<p256::NistP256>::encap(&recip_pub_key_bytes).unwrap();
    let ss2 = recip.decap(&ct).unwrap();
    assert_eq!(ss, ss2);
}
