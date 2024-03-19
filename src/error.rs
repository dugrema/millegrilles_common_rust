use std::fmt;
use openssl::error::ErrorStack;

#[derive(Debug)]
pub enum Error {
    Str(&'static str),
    String(String),
    Openssl(ErrorStack)
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
