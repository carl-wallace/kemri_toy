//! Result and Error types for kemri_toy

use std::array::TryFromSliceError;

use log::error;

/// Result type for kemri_toy
pub type Result<T> = core::result::Result<T, Error>;

/// Error type for kemri_toy
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum Error {
    Unrecognized,
    Asn1(der::Error),
    Builder(String),
    CertBuilder,
    Io,
    Slice,
    MlKem(String),
    MlDsa(String),
    SlhDsa(String),
    Rsa,
    Misc(String),
}

impl From<rsa::Error> for Error {
    fn from(err: rsa::Error) -> Error {
        error!("rsa::Error: {err:?}");
        Error::Rsa
    }
}

impl From<TryFromSliceError> for Error {
    fn from(err: TryFromSliceError) -> Error {
        error!("TryFromSliceError: {err:?}");
        Error::Slice
    }
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        error!("std::io::Error: {err:?}");
        Error::Io
    }
}

impl From<x509_cert::builder::Error> for Error {
    fn from(err: x509_cert::builder::Error) -> Error {
        error!("x509_cert::builder::Error: {err:?}");
        Error::CertBuilder
    }
}
