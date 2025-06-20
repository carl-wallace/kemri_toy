//! Builder for `AuthEnvelopedData` with parts copied and adapted from `EnvelopedDataBuilder` in the cms crate

use log::debug;

use aes_gcm::{AeadCore, Aes128Gcm, Aes256Gcm, aead::AeadInOut};
use cipher::{Key, KeyInit, KeySizeUser};
use rand_core::CryptoRng;

use cms::{
    authenticated_data::MessageAuthenticationCode,
    builder::{Error, RecipientInfoBuilder},
    content_info::CmsVersion,
    enveloped_data::{EncryptedContentInfo, OriginatorInfo, RecipientInfo, RecipientInfos},
};
use der::{Any, Decode, Encode, asn1::OctetString, zeroize::Zeroize};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attributes;

use crate::{
    asn1::auth_env_data::{AuthEnvelopedData, GcmParameters},
    misc::{gen_certs::buffer_to_hex, utils::ContentEncryptionAlgorithmAead},
};

/// Result type with cms::builder::Error
type Result<T> = core::result::Result<T, Error>;

/// Builds CMS `AuthEnvelopedData` according to RFC 5083 § 2.1.
pub struct AuthEnvelopedDataBuilder<'c, R: ?Sized> {
    originator_info: Option<OriginatorInfo>,
    recipient_infos: Vec<Box<dyn RecipientInfoBuilder<Rng = R> + 'c>>,
    unencrypted_content: &'c [u8],
    // TODO bk Not good to offer both, `content_encryptor` and `content_encryption_algorithm`.
    // We should
    // (1) either derive `content_encryption_algorithm` from `content_encryptor` (but this is not
    //            yet supported by RustCrypto),
    // (2) or     pass `content_encryption_algorithm` and create an encryptor for it.
    // In the first case, we might need a new trait here, e.g. `DynEncryptionAlgorithmIdentifier` in
    // analogy to `DynSignatureAlgorithmIdentifier`.
    // Going for (2)
    //  content_encryptor: E,
    content_encryption_algorithm: ContentEncryptionAlgorithmAead,
    auth_attributes: Option<Attributes>,
    unauth_attributes: Option<Attributes>,
}

/// Macro for encrypting data using Aes128Gcm or Aes256Gcm
macro_rules! encrypt_gcm_mode {
    ($data:expr, $aead:ty, $key:expr, $aad:ident, $oid:expr) => {{
        let (key, nonce) = match $key {
            None => {
                let key = <$aead>::generate_key();
                // todo use rng parameter or something simliar to encrypt_block_mode to generate nonce and key
                let nonce = <$aead>::generate_nonce();
                (key.unwrap().to_vec(), nonce.unwrap().as_slice().to_vec())
            }
            Some(key) => {
                if key.len() != <$aead>::key_size() {
                    return Err(Error::Builder(String::from(
                        "Invalid key size for chosen algorithm",
                    )));
                }
                (
                    #[allow(deprecated)]
                    Key::<$aead>::from_slice(key).to_owned().to_vec(),
                    <$aead>::generate_nonce().unwrap().to_vec(),
                )
            }
        };
        debug!("CEK: {}", buffer_to_hex(&key));
        debug!("Nonce: {}", buffer_to_hex(&nonce.as_slice()));

        let cipher = <$aead>::new_from_slice(&key).unwrap();
        let mut buffer = vec![0u8; 0];
        buffer.extend_from_slice($data);
        let aad = $aad.unwrap_or("".as_bytes().to_vec());
        #[allow(deprecated)]
        let aead_nonce = aes_gcm::Nonce::from_slice(&nonce);
        match cipher.encrypt_in_place(&aead_nonce, &aad, &mut buffer) {
            Ok(_) => {
                let (ct, tag) = buffer.split_at(buffer.len() - 16);
                let gcm_params = GcmParameters {
                    nonce: OctetString::new(nonce.as_slice())?,
                    icv_len: 16,
                };
                let alg = AlgorithmIdentifierOwned {
                    oid: $oid,
                    parameters: Some(Any::from_der(&gcm_params.to_der()?)?),
                };
                Ok((ct.to_vec(), key.to_vec(), alg, Some(tag.to_vec())))
            }
            Err(_e) => Err(Error::Builder(
                "Failed to encrypt with AAD: {:e}".to_string(),
            )),
        }
    }};
}

/// Symmetrically encrypt data.
/// Returns encrypted content, content-encryption key and the used algorithm identifier (including
/// the used algorithm parameters).
///
/// TODO Which encryption algorithms shall also be supported?
/// TODO should the tag option be optional here, or just have this always be AEAD?
#[allow(clippy::type_complexity)]
fn encrypt_data<R>(
    data: &[u8],
    encryption_algorithm_identifier: &ContentEncryptionAlgorithmAead,
    key: Option<&[u8]>,
    aad: Option<Vec<u8>>,
    _rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>, AlgorithmIdentifierOwned, Option<Vec<u8>>)>
where
    R: CryptoRng + ?Sized,
{
    match encryption_algorithm_identifier {
        ContentEncryptionAlgorithmAead::Aes128Gcm => {
            encrypt_gcm_mode!(
                data,
                Aes128Gcm,
                key,
                aad,
                encryption_algorithm_identifier.oid()
            )
        }
        ContentEncryptionAlgorithmAead::Aes256Gcm => {
            encrypt_gcm_mode!(
                data,
                Aes256Gcm,
                key,
                aad,
                encryption_algorithm_identifier.oid()
            )
        }
    }
}
impl<'c, R> AuthEnvelopedDataBuilder<'c, R>
where
    R: CryptoRng + ?Sized,
{
    /// Create a new builder for `AuthEnvelopedData`
    pub fn new(
        originator_info: Option<OriginatorInfo>,
        unencrypted_content: &'c [u8],
        content_encryption_algorithm: ContentEncryptionAlgorithmAead,
        auth_attributes: Option<Attributes>,
        unauth_attributes: Option<Attributes>,
    ) -> Result<Self> {
        Ok(AuthEnvelopedDataBuilder {
            originator_info,
            recipient_infos: Vec::new(),
            unencrypted_content,
            content_encryption_algorithm,
            auth_attributes,
            unauth_attributes,
        })
    }

    /// Add recipient info. A builder is used, which generates a `RecipientInfo` according to
    /// RFC 5652 § 6.2, when `AuthEnvelopedData` is built.
    pub fn add_recipient_info(
        &mut self,
        recipient_info_builder: impl RecipientInfoBuilder<Rng = R> + 'c,
    ) -> Result<&mut Self> {
        self.recipient_infos.push(Box::new(recipient_info_builder));
        Ok(self)
    }

    /// Generate an `AuthEnvelopedData` object according to RFC 5083 § 2.2 using a provided
    /// random number generator.
    pub fn build_with_rng(&mut self, rng: &mut R) -> Result<AuthEnvelopedData> {
        // DER encode authenticated attributes, if any
        // Generate content encryption key
        // Encrypt content and capture authentication tag
        // Build recipient infos
        // Make sure, content encryption key is securely destroyed
        let aad = match &self.auth_attributes {
            Some(attrs) => Some(attrs.to_der()?),
            None => None,
        };

        let (encrypted_content, mut content_encryption_key, content_enc_alg, tag) = encrypt_data(
            self.unencrypted_content,
            &self.content_encryption_algorithm,
            None,
            aad,
            rng,
        )?;
        let encrypted_content_octetstring = OctetString::new(encrypted_content)?;
        let encrypted_content_info = EncryptedContentInfo {
            content_type: const_oid::db::rfc5911::ID_DATA, // TODO bk should this be configurable?
            content_enc_alg,
            encrypted_content: Some(encrypted_content_octetstring), // TODO bk `None` (external content) should also be possible
        };

        let recipient_infos_vec = self
            .recipient_infos
            .iter_mut()
            .map(|ri| ri.build_with_rng(&content_encryption_key, rng))
            .collect::<Result<Vec<RecipientInfo>>>()?;
        content_encryption_key.zeroize();
        let recip_infos = RecipientInfos::try_from(recipient_infos_vec)?;

        let mac = match tag {
            Some(mac) => MessageAuthenticationCode::new(mac)?,
            None => return Err(Error::Builder("Missing MAC".to_string())),
        };

        Ok(AuthEnvelopedData {
            version: self.calculate_version(),
            originator_info: self.originator_info.clone(),
            recip_infos,
            auth_encrypted_content: encrypted_content_info,
            auth_attrs: self.auth_attributes.clone(),
            mac,
            unauth_attrs: self.unauth_attributes.clone(),
        })
    }

    /// Calculate the `CMSVersion` of the `AuthEnvelopedData` according to RFC 5083 § 2.1, i.e., "MUST be set to 0"
    fn calculate_version(&self) -> CmsVersion {
        CmsVersion::V0
    }
}
