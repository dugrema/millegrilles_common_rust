use std::fmt;
use openssl::error::ErrorStack;

#[derive(Debug)]
pub enum Error {
    Str(&'static str),
    String(String),
    Openssl(ErrorStack),
    SerdeJson(serde_json::Error),
    Io(std::io::Error),
    Multibase(multibase::Error),
    Multihash(multihash::Error),
    Chacha20poly1350(chacha20poly1305::Error),
    Dryoc(dryoc::Error),
    MillegrillesCryptographie(millegrilles_cryptographie::error::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
}

impl From<ErrorStack> for Error {
    fn from(value: ErrorStack) -> Self {
        Self::Openssl(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self{ Self::Io(value) }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self{ Self::SerdeJson(value) }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

impl From<millegrilles_cryptographie::error::Error> for Error {
    fn from(value: millegrilles_cryptographie::error::Error) -> Self {
        Error::MillegrillesCryptographie(value)
    }
}