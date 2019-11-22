use crate::error::{AuthErrorOr, Error};

use chrono::{DateTime, Utc};
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
    /// The time when the token expires.
    pub expires_at: Option<DateTime<Utc>>,
}

impl Token {
    pub(crate) fn from_json(json_data: &[u8]) -> Result<Token, Error> {
        #[derive(Deserialize)]
        struct RawToken {
            access_token: String,
            refresh_token: Option<String>,
            token_type: String,
            expires_in: Option<i64>,
        }

        let RawToken {
            access_token,
            refresh_token,
            token_type,
            expires_in,
        } = serde_json::from_slice::<AuthErrorOr<RawToken>>(json_data)?.into_result()?;

        let expires_at = expires_in
            .map(|seconds_from_now| Utc::now() + chrono::Duration::seconds(seconds_from_now));

        Ok(Token {
            access_token,
            refresh_token,
            token_type,
            expires_at,
        })
    }

    /// Returns true if we are expired.
    pub fn expired(&self) -> bool {
        self.expires_at
            .map(|expiration_time| expiration_time - chrono::Duration::minutes(1) <= Utc::now())
            .unwrap_or(false)
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
