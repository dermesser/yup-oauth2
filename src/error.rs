//! Module containing various error types.

use std::borrow::Cow;
use std::error::Error as StdError;
use std::fmt;
use std::io;

use serde::Deserialize;

/// Error returned by the authorization server.
///
/// <https://tools.ietf.org/html/rfc6749#section-5.2>
/// <https://tools.ietf.org/html/rfc8628#section-3.5>
#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct AuthError {
    /// Error code from the server.
    pub error: AuthErrorCode,
    /// Human-readable text providing additional information.
    pub error_description: Option<String>,
    /// A URI identifying a human-readable web page with information about the error.
    pub error_uri: Option<String>,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.error.as_str())?;
        if let Some(desc) = &self.error_description {
            write!(f, ": {}", desc)?;
        }
        if let Some(uri) = &self.error_uri {
            write!(f, "; See {} for more info", uri)?;
        }
        Ok(())
    }
}
impl StdError for AuthError {}

/// The error code returned by the authorization server.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AuthErrorCode {
    /// invalid_request
    InvalidRequest,
    /// invalid_client
    InvalidClient,
    /// invalid_grant
    InvalidGrant,
    /// unauthorized_client
    UnauthorizedClient,
    /// unsupported_grant_type
    UnsupportedGrantType,
    /// invalid_scope
    InvalidScope,
    /// access_denied
    AccessDenied,
    /// expired_token
    ExpiredToken,
    /// other error
    Other(String),
}

impl AuthErrorCode {
    /// The error code as a &str
    pub fn as_str(&self) -> &str {
        match self {
            AuthErrorCode::InvalidRequest => "invalid_request",
            AuthErrorCode::InvalidClient => "invalid_client",
            AuthErrorCode::InvalidGrant => "invalid_grant",
            AuthErrorCode::UnauthorizedClient => "unauthorized_client",
            AuthErrorCode::UnsupportedGrantType => "unsupported_grant_type",
            AuthErrorCode::InvalidScope => "invalid_scope",
            AuthErrorCode::AccessDenied => "access_denied",
            AuthErrorCode::ExpiredToken => "expired_token",
            AuthErrorCode::Other(s) => s.as_str(),
        }
    }

    fn from_string<'a>(s: impl Into<Cow<'a, str>>) -> AuthErrorCode {
        let s = s.into();
        match s.as_ref() {
            "invalid_request" => AuthErrorCode::InvalidRequest,
            "invalid_client" => AuthErrorCode::InvalidClient,
            "invalid_grant" => AuthErrorCode::InvalidGrant,
            "unauthorized_client" => AuthErrorCode::UnauthorizedClient,
            "unsupported_grant_type" => AuthErrorCode::UnsupportedGrantType,
            "invalid_scope" => AuthErrorCode::InvalidScope,
            "access_denied" => AuthErrorCode::AccessDenied,
            "expired_token" => AuthErrorCode::ExpiredToken,
            _ => AuthErrorCode::Other(s.into_owned()),
        }
    }
}

impl From<String> for AuthErrorCode {
    fn from(s: String) -> Self {
        AuthErrorCode::from_string(s)
    }
}

impl<'a> From<&'a str> for AuthErrorCode {
    fn from(s: &str) -> Self {
        AuthErrorCode::from_string(s)
    }
}

impl<'de> Deserialize<'de> for AuthErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = AuthErrorCode;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("any string")
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(value.into())
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(value.into())
            }
        }
        deserializer.deserialize_string(V)
    }
}

/// A helper type to deserialize either an AuthError or another piece of data.
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum AuthErrorOr<T> {
    AuthError(AuthError),
    Data(T),
}

impl<T> AuthErrorOr<T> {
    pub(crate) fn into_result(self) -> Result<T, AuthError> {
        match self {
            AuthErrorOr::AuthError(err) => Result::Err(err),
            AuthErrorOr::Data(value) => Result::Ok(value),
        }
    }
}

/// Encapsulates all possible results of the `token(...)` operation
#[derive(Debug)]
pub enum Error {
    /// Indicates connection failure
    HttpError(hyper::Error),
    /// The server returned an error.
    AuthError(AuthError),
    /// Error while decoding a JSON response.
    JSONError(serde_json::Error),
    /// Error within user input.
    UserError(String),
    /// A lower level IO error.
    LowLevelError(io::Error),
    /// We required an access token, but received a response that didn't contain one.
    MissingAccessToken,
    /// We tried to read an environment variable, but failed.
    EnvError(std::env::VarError),
    /// Other errors produced by a storage provider
    OtherError(anyhow::Error),
}

impl From<hyper::Error> for Error {
    fn from(error: hyper::Error) -> Error {
        Error::HttpError(error)
    }
}

impl From<AuthError> for Error {
    fn from(value: AuthError) -> Error {
        Error::AuthError(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Error {
        Error::JSONError(value)
    }
}

impl From<std::env::VarError> for Error {
    fn from(value: std::env::VarError) -> Error {
        Error::EnvError(value)
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Error {
        Error::LowLevelError(value)
    }
}

impl From<anyhow::Error> for Error {
    fn from(value: anyhow::Error) -> Error {
        match value.downcast::<io::Error>() {
            Ok(io_error) => Error::LowLevelError(io_error),
            Err(err) => Error::OtherError(err),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::HttpError(ref err) => err.fmt(f),
            Error::AuthError(ref err) => err.fmt(f),
            Error::JSONError(ref e) => {
                write!(
                    f,
                    "JSON Error; this might be a bug with unexpected server responses! {}",
                    e
                )?;
                Ok(())
            }
            Error::UserError(ref s) => s.fmt(f),
            Error::EnvError(ref e) => e.fmt(f),
            Error::LowLevelError(ref e) => e.fmt(f),
            Error::MissingAccessToken => {
                write!(
                    f,
                    "Expected an access token, but received a response without one"
                )?;
                Ok(())
            }
            Error::OtherError(ref e) => e.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match *self {
            Error::HttpError(ref err) => Some(err),
            Error::AuthError(ref err) => Some(err),
            Error::JSONError(ref err) => Some(err),
            Error::LowLevelError(ref err) => Some(err),
            Error::EnvError(ref err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_error_code_deserialize() {
        assert_eq!(
            AuthErrorCode::InvalidRequest,
            serde_json::from_str(r#""invalid_request""#).unwrap()
        );
        assert_eq!(
            AuthErrorCode::InvalidClient,
            serde_json::from_str(r#""invalid_client""#).unwrap()
        );
        assert_eq!(
            AuthErrorCode::InvalidGrant,
            serde_json::from_str(r#""invalid_grant""#).unwrap()
        );
        assert_eq!(
            AuthErrorCode::UnauthorizedClient,
            serde_json::from_str(r#""unauthorized_client""#).unwrap()
        );
        assert_eq!(
            AuthErrorCode::UnsupportedGrantType,
            serde_json::from_str(r#""unsupported_grant_type""#).unwrap()
        );
        assert_eq!(
            AuthErrorCode::InvalidScope,
            serde_json::from_str(r#""invalid_scope""#).unwrap()
        );
        assert_eq!(
            AuthErrorCode::AccessDenied,
            serde_json::from_str(r#""access_denied""#).unwrap()
        );
        assert_eq!(
            AuthErrorCode::ExpiredToken,
            serde_json::from_str(r#""expired_token""#).unwrap()
        );
        assert_eq!(
            AuthErrorCode::Other("undefined".to_owned()),
            serde_json::from_str(r#""undefined""#).unwrap()
        );
    }
}
