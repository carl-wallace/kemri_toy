//! This module defines constant values in support of composite KEM and composite signatures usage.
//! Definitions are from [draft-ietf-lamps-pq-composite-kem-07](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-07)
//! and [draft-ietf-lamps-pq-composite-sigs-06](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-06).

#![allow(dead_code)]
use der::asn1::{BitString, OctetString};

/// ```text
/// CompositeKEMPublicKey ::= BIT STRING
/// ```
pub type CompositeKemPublicKey = BitString;

/// ```text
/// CompositeKEMPrivateKey ::= OCTET STRING
/// ```
pub type CompositeKemPrivateKey = OctetString;

/// ```text
/// CompositeCiphertextValue ::= OCTET STRING
/// ```
pub type CompositeCiphertextValue = OctetString;
