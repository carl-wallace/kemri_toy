// ML-KEM-1024-PrivateKey ::= CHOICE {
//      seed [0] OCTET STRING (SIZE (64)),
//      expandedKey OCTET STRING (SIZE (3168)),
//      both SEQUENCE {
//          seed OCTET STRING (SIZE (64)),
//          expandedKey OCTET STRING (SIZE (3168))
//          }
//      }

use der::{Choice, Sequence};
use der::asn1::OctetString;

pub type MlKemSeed = OctetString; //[u8; 64];

pub type MlKem512Expanded = OctetString; //[u8; 1632];
pub type MlKem768Expanded = OctetString; //[u8; 2400];
pub type MlKem1024Expanded = OctetString; //[u8; 3168];

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct MlKem512Both {
    pub seed: MlKemSeed,
    pub expanded_key: MlKem1024Expanded,
}

#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
#[allow(clippy::large_enum_variant)]
pub enum MlKem512PrivateKey {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Seed(MlKemSeed),
    ExpandedKey(MlKem512Expanded),
    Both(MlKem512Both),
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct MlKem768Both {
    pub seed: MlKemSeed,
    pub expanded_key: MlKem768Expanded,
}

#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
#[allow(clippy::large_enum_variant)]
pub enum MlKem768PrivateKey {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Seed(MlKemSeed),
    ExpandedKey(MlKem768Expanded),
    Both(MlKem768Both),
}
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct MlKem1024Both {
    pub seed: MlKemSeed,
    pub expanded_key: MlKem1024Expanded,
}

#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
#[allow(clippy::large_enum_variant)]
pub enum MlKem1024PrivateKey {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Seed(MlKemSeed),
    ExpandedKey(MlKem1024Expanded),
    Both(MlKem1024Both),
}

