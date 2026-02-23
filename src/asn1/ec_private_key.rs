//! Temporary home for ECPrivateKey support (the sec1 crate was not playing well with current
//! pre-release stuff)

use const_oid::ObjectIdentifier;
use der::asn1::{BitString, OctetString};
use der::{Enumerated, Sequence};

#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum EcPrivateKeyVersion {
    /// Version 1 (default)
    V1 = 1,
}

//    ECPrivateKey ::= SEQUENCE {
//      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//      privateKey     OCTET STRING,
//      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
//      publicKey  [1] BIT STRING OPTIONAL
//    }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EcPrivateKey {
    pub version: EcPrivateKeyVersion,
    pub private_key: OctetString,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "false")]
    pub parameters: ObjectIdentifier, // Only supporting named curve here
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub public_key: Option<BitString>,
}
