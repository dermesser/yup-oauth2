//! Module containing various error types.

use std::error::Error as StdError;
use std::fmt;
use std::io;

use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub(crate) struct JsonError {
    pub error: String,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
}

/// A helper type to deserialize either a JsonError or another piece of data.
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub(crate) enum JsonErrorOr<T> {
    Err(JsonError),
    Data(T),
}

impl<T> JsonErrorOr<T> {
    pub(crate) fn into_result(self) -> Result<T, JsonError> {
        match self {
            JsonErrorOr::Err(err) => Result::Err(err),
            JsonErrorOr::Data(value) => Result::Ok(value),
        }
    }
}

/// Encapsulates all possible results of a `poll_token(...)` operation in the Device flow.
#[derive(Debug)]
pub enum PollError {
    /// Connection failure - retry if you think it's worth it
    HttpError(hyper::Error),
    /// Indicates we are expired, including the expiration date
    Expired(DateTime<Utc>),
    /// Indicates that the user declined access. String is server response
    AccessDenied,
    /// Indicates that too many attempts failed.
    TimedOut,
    /// Other type of error.
    Other(String),
}

impl fmt::Display for PollError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            PollError::HttpError(ref err) => err.fmt(f),
            PollError::Expired(ref date) => writeln!(f, "Authentication expired at {}", date),
            PollError::AccessDenied => "Access denied by user".fmt(f),
            PollError::TimedOut => "Timed out waiting for token".fmt(f),
            PollError::Other(ref s) => format!("Unknown server error: {}", s).fmt(f),
        }
    }
}

impl StdError for PollError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match *self {
            PollError::HttpError(ref e) => Some(e),
            _ => None,
        }
    }
}

/// Encapsulates all possible results of the `token(...)` operation
#[derive(Debug)]
pub enum Error {
    /// Indicates connection failure
    ClientError(hyper::Error),
    /// The OAuth client was not found
    InvalidClient,
    /// Some requested scopes were invalid. String contains the scopes as part of
    /// the server error message
    InvalidScope(String),
    /// A 'catch-all' variant containing the server error and description
    /// First string is the error code, the second may be a more detailed description
    NegativeServerResponse(String, Option<String>),
    /// A malformed server response.
    BadServerResponse(String),
    /// Error while decoding a JSON response.
    JSONError(serde_json::Error),
    /// Error within user input.
    UserError(String),
    /// A lower level IO error.
    LowLevelError(io::Error),
    /// A poll error occurred in the DeviceFlow.
    Poll(PollError),
    /// An error occurred while refreshing tokens.
    Refresh(RefreshError),
    /// Error in token cache layer
    Cache(Box<dyn StdError + Send + Sync>),
}

impl From<hyper::Error> for Error {
    fn from(error: hyper::Error) -> Error {
        Error::ClientError(error)
    }
}

impl From<JsonError> for Error {
    fn from(value: JsonError) -> Error {
        match &*value.error {
            "invalid_client" => Error::InvalidClient,
            "invalid_scope" => Error::InvalidScope(
                value
                    .error_description
                    .unwrap_or_else(|| "no description provided".to_string()),
            ),
            _ => Error::NegativeServerResponse(value.error, value.error_description),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Error {
        Error::JSONError(value)
    }
}

impl From<RefreshError> for Error {
    fn from(value: RefreshError) -> Error {
        Error::Refresh(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::ClientError(ref err) => err.fmt(f),
            Error::InvalidClient => "Invalid Client".fmt(f),
            Error::InvalidScope(ref scope) => writeln!(f, "Invalid Scope: '{}'", scope),
            Error::NegativeServerResponse(ref error, ref desc) => {
                error.fmt(f)?;
                if let Some(ref desc) = *desc {
                    write!(f, ": {}", desc)?;
                }
                "\n".fmt(f)
            }
            Error::BadServerResponse(ref s) => s.fmt(f),
            Error::JSONError(ref e) => format!(
                "JSON Error; this might be a bug with unexpected server responses! {}",
                e
            )
            .fmt(f),
            Error::UserError(ref s) => s.fmt(f),
            Error::LowLevelError(ref e) => e.fmt(f),
            Error::Poll(ref pe) => pe.fmt(f),
            Error::Refresh(ref rr) => format!("{:?}", rr).fmt(f),
            Error::Cache(ref e) => e.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match *self {
            Error::ClientError(ref err) => Some(err),
            Error::LowLevelError(ref err) => Some(err),
            Error::JSONError(ref err) => Some(err),
            _ => None,
        }
    }
}

/// All possible outcomes of the refresh flow
#[derive(Debug)]
pub enum RefreshError {
    /// Indicates connection failure
    ConnectionError(hyper::Error),
    /// The server did not answer with a new token, providing the server message
    ServerError(String, Option<String>),
}

impl From<hyper::Error> for RefreshError {
    fn from(value: hyper::Error) -> Self {
        RefreshError::ConnectionError(value)
    }
}

impl From<JsonError> for RefreshError {
    fn from(value: JsonError) -> Self {
        RefreshError::ServerError(value.error, value.error_description)
    }
}

impl From<serde_json::Error> for RefreshError {
    fn from(_value: serde_json::Error) -> Self {
        RefreshError::ServerError(
            "failed to deserialize json token from refresh response".to_owned(),
            None,
        )
    }
}
