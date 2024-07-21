use crate::Result;
use rand_core::RngCore;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

pub fn oaep_encapsulate(pub_key: &RsaPublicKey) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut shared_secret = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut shared_secret);
    let padding = Oaep::new::<Sha256>();
    let enc = pub_key.encrypt(&mut rng, padding, &shared_secret[..])?;
    Ok((shared_secret.to_vec(), enc))
}

pub fn oaep_decapsulate(priv_key: &RsaPrivateKey, ct: &[u8]) -> Result<Vec<u8>> {
    let padding = Oaep::new::<Sha256>();
    let dec_data = priv_key.decrypt(padding, ct)?;
    Ok(dec_data)
}
