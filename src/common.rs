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
            Ok(s) => assert!(s.installed.is_some()),
            Err(err) => panic!(err),
        }
    }
}