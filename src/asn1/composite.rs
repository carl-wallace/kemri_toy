#![allow(dead_code)]

use der::asn1::{BitString, OctetString};
use der::Sequence;
use pqckeys::oak::OneAsymmetricKey;

/// ```text
/// CompositeKEMPublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
/// ```
// pub type CompositeKemPublicKey = [BitString;2];

/// ```text
/// CompositeKEMPublicKeyOs ::= OCTET STRING (CONTAINING
///                                 CompositeKEMPublicKey ENCODED BY der)
/// ```
pub type CompositeKemPublicKeyOs = OctetString;

/// ```text
/// CompositeKEMPublicKeyBs ::= BIT STRING (CONTAINING
///                                 CompositeKEMPublicKey ENCODED BY der)
/// ```
pub type CompositeKEMPublicKeyBs = OctetString;

/// ```text
/// CompositeKEMPrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
/// ```
pub type CompositeKemPrivateKey = [OneAsymmetricKey;2];

/// ```text
/// CompositeCiphertextValue ::= SEQUENCE SIZE (2) OF OCTET STRING
/// ```
pub type CompositeCiphertextValue = [OctetString;2];

/// ```text
///    RsaCompositeKemPublicKey ::= SEQUENCE {
/// 		firstPublicKey BIT STRING (ENCODED BY id-raw-key),
/// 		secondPublicKey BIT STRING (CONTAINING RSAPublicKey)
/// 	  }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct RsaCompositeKemPublicKey {
    pub first_public_key: BitString,
    pub second_public_key: BitString
}

pub enum CompositeKemPublicKey {
    Rsa(RsaCompositeKemPublicKey),
    Ecdsa(()) //todo
}

// --
// -- Composite KEM Algorithms
// --
//

// -- TODO: OID to be replaced by IANA
/// ```text
/// id-MLKEM512-RSA2048 OBJECT IDENTIFIER ::= {
///   joint-iso-itu-t(2) country(16) us(840) organization(1)
///   entrust(114027) algorithm(80) explicitcomposite(5) kem(2) 13 }
/// ```
pub const ML_KEM_512_RSA2048: crate::ObjectIdentifier =
    crate::ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.13");

// -- TODO: OID to be replaced by IANA
/// ```text
/// id-MLKEM512-RSA3072 OBJECT IDENTIFIER ::= {
///   joint-iso-itu-t(2) country(16) us(840) organization(1)
///   entrust(114027) algorithm(80) explicitcomposite(5) kem(2) 4 }
/// ```
pub const ML_KEM_512_RSA3072: crate::ObjectIdentifier =
    crate::ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.4");
