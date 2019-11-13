use std::error::Error;
use std::fmt;
use std::io;

use chrono::{DateTime, Utc};

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

/// Encapsulates all possible results of the `token(...)` operation
#[derive(Debug)]
pub enum RequestError {
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
    Cache(Box<dyn Error + Send + Sync>),
}

impl From<hyper::Error> for RequestError {
    fn from(error: hyper::Error) -> RequestError {
        RequestError::ClientError(error)
    }
}

impl From<JsonError> for RequestError {
    fn from(value: JsonError) -> RequestError {
        match &*value.error {
            "invalid_client" => RequestError::InvalidClient,
            "invalid_scope" => RequestError::InvalidScope(
                value
                    .error_description
                    .unwrap_or_else(|| "no description provided".to_string()),
            ),
            _ => RequestError::NegativeServerResponse(value.error, value.error_description),
        }
    }
}

impl From<serde_json::Error> for RequestError {
    fn from(value: serde_json::Error) -> RequestError {
        RequestError::JSONError(value)
    }
}

impl From<RefreshError> for RequestError {
    fn from(value: RefreshError) -> RequestError {
        RequestError::Refresh(value)
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            RequestError::ClientError(ref err) => err.fmt(f),
            RequestError::InvalidClient => "Invalid Client".fmt(f),
            RequestError::InvalidScope(ref scope) => writeln!(f, "Invalid Scope: '{}'", scope),
            RequestError::NegativeServerResponse(ref error, ref desc) => {
                error.fmt(f)?;
                if let Some(ref desc) = *desc {
                    write!(f, ": {}", desc)?;
                }
                "\n".fmt(f)
            }
            RequestError::BadServerResponse(ref s) => s.fmt(f),
            RequestError::JSONError(ref e) => format!(
                "JSON Error; this might be a bug with unexpected server responses! {}",
                e
            )
            .fmt(f),
            RequestError::UserError(ref s) => s.fmt(f),
            RequestError::LowLevelError(ref e) => e.fmt(f),
            RequestError::Poll(ref pe) => pe.fmt(f),
            RequestError::Refresh(ref rr) => format!("{:?}", rr).fmt(f),
            RequestError::Cache(ref e) => e.fmt(f),
        }
    }
}

impl Error for RequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            RequestError::ClientError(ref err) => Some(err),
            RequestError::LowLevelError(ref err) => Some(err),
            RequestError::JSONError(ref err) => Some(err),
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
