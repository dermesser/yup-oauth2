//! Module containing various error types.

use std::borrow::Cow;
use std::error::Error as StdError;
use std::fmt;
use std::io;

use hyper::Error as HyperError;
use serde::Deserialize;
use thiserror::Error as ThisError;

pub use crate::client::SendError;
pub use crate::external_account::CredentialSourceError;
pub use crate::storage::TokenStorageError;

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

impl From<&str> for AuthErrorCode {
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
        impl serde::de::Visitor<'_> for V {
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
#[derive(Debug, ThisError)]
pub enum Error {
    /// Indicates connection failure
    #[error("Connection failure: {0}")]
    HttpError(#[from] HyperError),
    /// Indicates connection failure
    #[error("Connection failure: {0}")]
    HttpClientError(#[from] SendError),
    /// The server returned an error.
    #[error("Server error: {0}")]
    AuthError(#[from] AuthError),
    /// Error while decoding a JSON response.
    #[error("JSON Error; this might be a bug with unexpected server responses! {0}")]
    JSONError(#[from] serde_json::Error),
    /// Error within user input.
    #[error("Invalid user input: {0}")]
    UserError(String),
    /// A lower level IO error.
    #[error("Low level error: {0}")]
    LowLevelError(#[from] io::Error),
    /// We required an access token, but received a response that didn't contain one.
    #[error("Expected an access token, but received a response without one")]
    MissingAccessToken,
    /// Produced by storage provider
    #[error("Error while setting token in cache: {0}")]
    StorageError(#[from] TokenStorageError),
    /// Error while parsing credential source
    #[error("Credential source is invalid: {0}")]
    CredentialSourceError(CredentialSourceError),
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
