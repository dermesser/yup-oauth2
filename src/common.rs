use chrono::{DateTime, UTC};

/// Represents a token as returned by OAuth2 servers.
///
/// It is produced by all authentication flows.
/// It authenticates certain operations, and must be refreshed once 
/// it reached it's expirey date.
#[derive(Clone, PartialEq, Debug)]
pub struct Token {
    /// used when authenticating calls to oauth2 enabled services
    pub access_token: String,
    /// used to refresh an expired access_token
    pub refresh_token: String,
    /// The token type as string - usually 'Bearer'
    pub token_type: String,
    /// access_token is not valid for use after this date
    pub expires_at: DateTime<UTC>
}

/// All known authentication types, for suitable constants
pub enum AuthenticationType {
    /// [device authentication](https://developers.google.com/youtube/v3/guides/authentication#devices)
    Device,
}

impl Str for AuthenticationType {
    /// Converts itself into a URL string
    fn as_slice(&self) -> &'static str {
        match *self {
            AuthenticationType::Device => "https://accounts.google.com/o/oauth2/device/code",
        }
    }
}