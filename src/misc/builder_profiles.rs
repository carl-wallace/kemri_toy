use x509_cert::builder::profile::Profile;
use spki::SubjectPublicKeyInfoRef;
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, KeyUsage, KeyUsages, SubjectKeyIdentifier};
use x509_cert::name::Name;
use x509_cert::TbsCertificate;

/// KEM Certificate
pub struct KemCert {
    /// issuer   Name,
    /// represents the name signing the certificate
    pub issuer: Name,

    pub subject: Name,
}

impl Profile for KemCert {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions: Vec<Extension> = Vec::new();

        extensions.push(
            AuthorityKeyIdentifier::try_from(issuer_spk.clone())?
                .to_extension(&tbs.subject, &extensions)?,
        );

        let ski = SubjectKeyIdentifier::try_from(spk)?;
        extensions.push(ski.to_extension(&tbs.subject, &extensions)?);

        // ## keyUsage SHOULD
        let key_usage = KeyUsages::KeyEncipherment.into();
        extensions.push(KeyUsage(key_usage).to_extension(&tbs.subject, &extensions)?);

        Ok(extensions)
    }
}