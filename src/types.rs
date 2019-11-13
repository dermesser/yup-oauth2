use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

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
/// Utility methods make common queries easier, see `expired()`.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct Token {
    /// used when authenticating calls to oauth2 enabled services.
    pub access_token: String,
    /// used to refresh an expired access_token.
    pub refresh_token: Option<String>,
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
    /// Returns true if we are expired.
    ///
    /// # Panics
    /// * if our access_token is unset
    pub fn expired(&self) -> bool {
        if self.access_token.is_empty() {
            panic!("called expired() on unset token");
        }
        if let Some(expiry_date) = self.expiry_date() {
            expiry_date - chrono::Duration::minutes(1) <= Utc::now()
        } else {
            false
        }
    }

    /// Returns a DateTime object representing our expiry date.
    pub fn expiry_date(&self) -> Option<DateTime<Utc>> {
        let expires_in_timestamp = self.expires_in_timestamp?;

        Utc.timestamp(expires_in_timestamp, 0).into()
    }

    /// Adjust our stored expiry format to be absolute, using the current time.
    pub fn set_expiry_absolute(&mut self) -> &mut Token {
        if self.expires_in_timestamp.is_some() {
            assert!(self.expires_in.is_none());
            return self;
        }

        if let Some(expires_in) = self.expires_in {
            self.expires_in_timestamp = Some(Utc::now().timestamp() + expires_in);
            self.expires_in = None;
        }

        self
    }
}

/// Represents either 'installed' or 'web' applications in a json secrets file.
/// See `ConsoleApplicationSecret` for more information
#[derive(Deserialize, Serialize, Clone, Default)]
pub struct ApplicationSecret {
    /// The client ID.
    pub client_id: String,
    /// The client secret.
    pub client_secret: String,
    /// The token server endpoint URI.
    pub token_uri: String,
    /// The authorization server endpoint URI.
    pub auth_uri: String,
    /// The redirect uris.
    pub redirect_uris: Vec<String>,
    /// Name of the google project the credentials are associated with
    pub project_id: Option<String>,
    /// The service account email associated with the client.
    pub client_email: Option<String>,
    /// The URL of the public x509 certificate, used to verify the signature on JWTs, such
    /// as ID tokens, signed by the authentication provider.
    pub auth_provider_x509_cert_url: Option<String>,
    ///  The URL of the public x509 certificate, used to verify JWTs signed by the client.
    pub client_x509_cert_url: Option<String>,
}

/// A type to facilitate reading and writing the json secret file
/// as returned by the [google developer console](https://code.google.com/apis/console)
#[derive(Deserialize, Serialize, Default)]
pub struct ConsoleApplicationSecret {
    /// web app secret
    pub web: Option<ApplicationSecret>,
    /// installed app secret
    pub installed: Option<ApplicationSecret>,
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const SECRET: &'static str =
        "{\"installed\":{\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\
         \"client_secret\":\"UqkDJd5RFwnHoiG5x5Rub8SI\",\"token_uri\":\"https://accounts.google.\
         com/o/oauth2/token\",\"client_email\":\"\",\"redirect_uris\":[\"urn:ietf:wg:oauth:2.0:\
         oob\",\"oob\"],\"client_x509_cert_url\":\"\",\"client_id\":\
         \"14070749909-vgip2f1okm7bkvajhi9jugan6126io9v.apps.googleusercontent.com\",\
         \"auth_provider_x509_cert_url\":\"https://www.googleapis.com/oauth2/v1/certs\"}}";

    #[test]
    fn console_secret() {
        use serde_json as json;
        match json::from_str::<ConsoleApplicationSecret>(SECRET) {
            Ok(s) => assert!(s.installed.is_some() && s.web.is_none()),
            Err(err) => panic!(err),
        }
    }
}
