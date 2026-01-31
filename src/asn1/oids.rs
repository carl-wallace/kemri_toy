use const_oid::ObjectIdentifier;

/// From [draft-ietf-lamps-cms-kemri-07 Section 3]
/// ```text
///   id-ori OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
///     rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) 13 }
///
///   id-ori-kem OBJECT IDENTIFIER ::= { id-ori 3 }
/// ```
/// [draft-ietf-lamps-cms-kemri-07 Section 3]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-kemri-07#section-3
pub const ID_ORI_KEM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.13.3");
/// From [RFC 8619 Section 2]
/// ```text
///   id-alg-hkdf-with-sha256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
///        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 28 }
/// ```
/// [RFC 8619 Section 2]: https://datatracker.ietf.org/doc/html/rfc8619#section-2
pub const ID_ALG_HKDF_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.28");
/// From [RFC 8619 Section 2]
/// ```text
///    id-alg-hkdf-with-sha384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
///        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 29 }
/// ```
/// [RFC 8619 Section 2]: https://datatracker.ietf.org/doc/html/rfc8619#section-2
pub const ID_ALG_HKDF_WITH_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.29");
/// From [RFC 8619 Section 2]
/// ```text
///    id-alg-hkdf-with-sha512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
///        us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) alg(3) 30 }
/// ```
/// [RFC 8619 Section 2]: https://datatracker.ietf.org/doc/html/rfc8619#section-2
pub const ID_ALG_HKDF_WITH_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.30");
/// From [draft-ietf-lamps-cms-sha3-hash Section 5.3]
/// ```text
///    hashAlgs OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16)
///        us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) 2 }
///
///    id-kmac128 OBJECT IDENTIFIER ::= { hashAlgs 21 }
/// ```
/// [draft-ietf-lamps-cms-sha3-hash Section 5.3]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sha3-hash-01#section-5.3
pub const ID_KMAC128: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.21");
/// From [draft-ietf-lamps-cms-sha3-hash Section 5.3]
/// ```text
///    hashAlgs OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16)
///        us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) 2 }
///
///    id-kmac256 OBJECT IDENTIFIER ::= { hashAlgs 22 }
/// ```
/// [draft-ietf-lamps-cms-sha3-hash Section 5.3]: https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-sha3-hash-01#section-5.3
pub const ID_KMAC256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.22");
