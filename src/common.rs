use chrono::{DateTime, UTC, TimeZone};

/// Represents a token as returned by OAuth2 servers.
///
/// It is produced by all authentication flows.
/// It authenticates certain operations, and must be refreshed once 
/// it reached it's expiry date.
///
/// The type is tuned to be suitable for direct de-serialization from server
/// replies, as well as for serialization for later reuse. This is the reason
/// for the two fields dealing with expiry - once in relative in and once in 
/// absolute terms.
/// 
/// Utility methods make common queries easier, see `invalid()` or `expired()`.
#[derive(Clone, PartialEq, Debug, RustcDecodable, RustcEncodable)]
pub struct Token {
    /// used when authenticating calls to oauth2 enabled services.
    pub access_token: String,
    /// used to refresh an expired access_token.
    pub refresh_token: String,
    /// The token type as string - usually 'Bearer'.
    pub token_type: String,
    /// access_token will expire after this amount of time.
    /// Prefer using expiry_date()
    pub expires_in: Option<i64>,

    /// timestamp is seconds since epoch indicating when the token will expire in absolute terms.
    /// use expiry_date() to convert to DateTime.
    pub expires_in_timestamp: Option<i64>,
}

impl Token {

    /// Returns true if the access token is expired or unset.
    pub fn invalid(&self) -> bool {
        self.access_token.len() == 0
        || self.refresh_token.len() == 0
        || self.expired()
    }

    /// Returns true if we are expired.
    ///
    /// # Panics
    /// * if our access_token is unset
    pub fn expired(&self) -> bool {
        if self.access_token.len() == 0 || self.refresh_token.len() == 0 {
            panic!("called expired() on unset token");
        }
        self.expiry_date() <= UTC::now()
    }

    /// Returns a DateTime object representing our expiry date.
    pub fn expiry_date(&self) -> DateTime<UTC> {
        UTC.timestamp(self.expires_in_timestamp.unwrap(), 0)
    }

    /// Adjust our stored expiry format to be absolute, using the current time.
    pub fn set_expiry_absolute(&mut self) -> &mut Token {
        if self.expires_in_timestamp.is_some() {
            assert!(self.expires_in.is_none());
            return self
        }

        self.expires_in_timestamp = Some(UTC::now().timestamp() + self.expires_in.unwrap());
        self.expires_in = None;
        self
    }
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

/// Represents either 'installed' or 'web' applications in a json secrets file.
/// See `ConsoleApplicationSecret` for more information
#[derive(RustcDecodable, RustcEncodable)]
pub struct ApplicationSecret {
    /// The client ID.
    pub client_id: String,
    /// The client secret.
    pub client_secret: String,
    /// The token server endpoint URI.
    pub token_uri: String,
    /// The authorization server endpoint URI.
    pub auth_uri: String,
    pub redirect_uris: Vec<String>,

    /// The service account email associated with the client.
    pub client_email: Option<String>,
    /// The URL of the public x509 certificate, used to verify the signature on JWTs, such 
    /// as ID tokens, signed by the authentication provider.
    pub auth_provider_x509_cert_url: Option<String>,
    ///  The URL of the public x509 certificate, used to verify JWTs signed by the client.
    pub client_x509_cert_url: Option<String>
}

/// A type to facilitate reading and writing the json secret file
/// as returned by the [google developer console](https://code.google.com/apis/console)
#[derive(RustcDecodable, RustcEncodable)]
pub struct ConsoleApplicationSecret {
    web: Option<ApplicationSecret>,
    installed: Option<ApplicationSecret>
}


#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &'static str = "{\"installed\":{\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"client_secret\":\"UqkDJd5RFwnHoiG5x5Rub8SI\",\"token_uri\":\"https://accounts.google.com/o/oauth2/token\",\"client_email\":\"\",\"redirect_uris\":[\"urn:ietf:wg:oauth:2.0:oob\",\"oob\"],\"client_x509_cert_url\":\"\",\"client_id\":\"14070749909-vgip2f1okm7bkvajhi9jugan6126io9v.apps.googleusercontent.com\",\"auth_provider_x509_cert_url\":\"https://www.googleapis.com/oauth2/v1/certs\"}}";

    #[test]
    fn console_secret() {
        use rustc_serialize::json;
        match json::decode::<ConsoleApplicationSecret>(SECRET) {
            Ok(s) => assert!(s.installed.is_some() && s.web.is_none()),
            Err(err) => panic!(err),
        }
    }
}