//! `AuthEnvelopedData`-related types

use cms::{
    authenticated_data::MessageAuthenticationCode,
    content_info::CmsVersion,
    enveloped_data::{EncryptedContentInfo, OriginatorInfo, RecipientInfos},
};
use der::{asn1::OctetString, Sequence};
use x509_cert::attr::Attributes;

/// The `AuthEnvelopedData` type is defined in [RFC 5083 Section 2.1].
///
/// ```text
///      AuthEnvelopedData ::= SEQUENCE {
///         version CMSVersion,
///         originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///         recipientInfos RecipientInfos,
///         authEncryptedContentInfo EncryptedContentInfo,
///         authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
///         mac MessageAuthenticationCode,
///         unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
/// ```
///
/// [RFC 5083 Section 2.1]: https://www.rfc-editor.org/rfc/rfc5083#section-2.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct AuthEnvelopedData {
    pub version: CmsVersion,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub originator_info: Option<OriginatorInfo>,
    pub recip_infos: RecipientInfos,
    pub auth_encrypted_content: EncryptedContentInfo,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub auth_attrs: Option<Attributes>,
    pub mac: MessageAuthenticationCode,
    #[asn1(
        context_specific = "2",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub unauth_attrs: Option<Attributes>,
}

/// The `GCMParameters` type is defined in [RFC 5084 Section 3.2].
///
/// ```text
///      GCMParameters ::= SEQUENCE {
///         aes-nonce        OCTET STRING, -- recommended size is 12 octets
///         aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
/// ```
///
/// [RFC 5084 Section 3.2]: https://www.rfc-editor.org/rfc/rfc5084.html#section-3.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct GcmParameters {
    ///         aes-nonce        OCTET STRING, -- recommended size is 12 octets
    pub nonce: OctetString,
    ///         aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }
    #[asn1(default = "default_twelve")]
    pub icv_len: i8,
}

/// Default value for icv_len field in GcmParameters.
fn default_twelve() -> i8 {
    12
}
