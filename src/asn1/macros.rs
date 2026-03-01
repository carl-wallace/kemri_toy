//! Macros supporting KEMRI usage

/// Macro for encrypting data using Aes128Wrap, Aes192Wrap or Aes256Wrap
macro_rules! encrypt_wrap {
    ($cek:expr, $alg:ty, $key:ident) => {{
        let kek: AesKw<$alg> = AesKw::new_from_slice($key.as_slice())
            .map_err(|e| cms::builder::Error::Builder(format!("Wrap failed: {e:?}")))?;
        let mut wrapped_key = vec![0u8; <$alg>::key_size() + 8];
        kek.wrap_key($cek, &mut wrapped_key)
            .map_err(|e| cms::builder::Error::Builder(format!("Wrap failed: {e:?}")))?;
        wrapped_key.to_vec()
    }};
}

//                 let (pqc_pk, trad_pk) = pk.split_at(1184);
//                 let pk = match <MlKem768 as Kem>::EncapsulationKey::new_from_slice(pqc_pk) {
//                     Ok(pk) => pk,
//                     Err(e) => {
//                         return Err(Error::Builder(format!("Encapsulate failed: {e:?}")))
//                     }
//                 };
//                 let ek = <MlKem768 as Kem>::EncapsulationKey::from(pk);
//                 let (mlkem_ct, mlkem_ss) = ek.encapsulate();
//                 let mut pqc_ct = mlkem_ct.to_vec();
//                 let pqc_ss = mlkem_ss.to_vec();
//                 let (trad_ss, mut trad_ct) = match RsaKem::encap(trad_pk) {
//                     Ok((trad_ss, trad_ct)) => (trad_ss, trad_ct.to_vec()),
//                     Err(e) => {
//                         return Err(Error::Builder(format!("RSA encapsulate failed: {e:?}")))
//                     }
//                 };
//
//                 let ss = match kem_combiner(&pqc_ss, &trad_ss, &trad_ct, &trad_pk, ID_MLKEM768_RSA2048_SHA3_256) {
//                     Ok(ss) => ss,
//                     Err(e) => {
//                         return Err(Error::Builder(format!("RSA encapsulate failed: {e:?}")))
//                     }
//                 };
//                 let mut ct = vec![];
//                 ct.append(&mut pqc_ct);
//                 ct.append(&mut trad_ct);
//                 (ss, ct, ID_MLKEM768_RSA2048_SHA3_256)

/// Prepare and return composite shared secret, composite ciphertext and OID.
#[macro_export]
macro_rules! comp_encap_rsa {
    ($pk:expr, $pqc_size:expr, $domain:expr, $params:ty) => {{
        let (pqc_pk, trad_pk) = $pk.split_at($pqc_size);
        let pk = match <$params as Kem>::EncapsulationKey::new_from_slice(pqc_pk) {
            Ok(pk) => pk,
            Err(e) => return Err(Error::Builder(format!("Encapsulate failed: {e:?}"))),
        };
        let ek = <$params as Kem>::EncapsulationKey::from(pk);
        let (mlkem_ct, mlkem_ss) = ek.encapsulate();
        let mut pqc_ct = mlkem_ct.to_vec();
        let pqc_ss = mlkem_ss.to_vec();
        let (trad_ss, mut trad_ct) = match RsaKem::encap(trad_pk) {
            Ok((trad_ss, trad_ct)) => (trad_ss, trad_ct.to_vec()),
            Err(e) => return Err(Error::Builder(format!("RSA encapsulate failed: {e:?}"))),
        };

        let ss = match kem_combiner(&pqc_ss, &trad_ss, &trad_ct, &trad_pk, $domain) {
            Ok(ss) => ss,
            Err(e) => return Err(Error::Builder(format!("RSA encapsulate failed: {e:?}"))),
        };
        let mut ct = vec![];
        ct.append(&mut pqc_ct);
        ct.append(&mut trad_ct);
        (ss, ct, $domain)
    }};
}

/// comp_encap_ecdh
#[macro_export]
macro_rules! comp_encap_ecdh {
    ($pk:expr, $pqc_size:expr, $domain:expr, $params:ty, $ec:ty) => {{
        let (pqc_pk, trad_pk) = $pk.split_at($pqc_size);
        let pk = match <$params as Kem>::EncapsulationKey::new_from_slice(pqc_pk) {
            Ok(pk) => pk,
            Err(e) => return Err(Error::Builder(format!("Encapsulate failed: {e:?}"))),
        };
        let ek = <$params as Kem>::EncapsulationKey::from(pk);
        let (mlkem_ct, mlkem_ss) = ek.encapsulate();
        let mut pqc_ct = mlkem_ct.to_vec();
        let pqc_ss = mlkem_ss.to_vec();
        let (trad_ss, trad_ct) = match EcdhKem::<$ec>::encap(trad_pk) {
            Ok((trad_ss, trad_ct)) => (trad_ss, trad_ct.to_vec()),
            Err(e) => return Err(Error::Builder(format!("RSA encapsulate failed: {e:?}"))),
        };

        let ss = match kem_combiner(&pqc_ss, &trad_ss, &trad_ct, &trad_pk, $domain) {
            Ok(ss) => ss,
            Err(e) => return Err(Error::Builder(format!("RSA encapsulate failed: {e:?}"))),
        };
        let mut ct = vec![];
        ct.append(&mut pqc_ct);
        ct.append(&mut trad_ct.to_vec());
        (ss, ct, $domain)
    }};
}
