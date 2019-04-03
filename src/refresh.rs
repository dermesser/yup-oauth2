use crate::types::{ApplicationSecret, FlowType, JsonError};

use super::Token;
use chrono::Utc;
use hyper;
use hyper::header::ContentType;
use serde_json as json;
use std::borrow::BorrowMut;
use std::io::Read;
use url::form_urlencoded;

/// Implements the [Outh2 Refresh Token Flow](https://developers.google.com/youtube/v3/guides/authentication#devices).
///
/// Refresh an expired access token, as obtained by any other authentication flow.
/// This flow is useful when your `Token` is expired and allows to obtain a new
/// and valid access token.
pub struct RefreshFlow<C> {
    client: C,
    result: RefreshResult,
}

/// All possible outcomes of the refresh flow
pub enum RefreshResult {
    /// Indicates connection failure
    Error(hyper::Error),
    /// The server did not answer with a new token, providing the server message
    RefreshError(String, Option<String>),
    /// The refresh operation finished successfully, providing a new `Token`
    Success(Token),
}

impl<C> RefreshFlow<C>
where
    C: BorrowMut<hyper::Client>,
{
    pub fn new(client: C) -> RefreshFlow<C> {
        RefreshFlow {
            client: client,
            result: RefreshResult::Error(hyper::Error::TooLarge),
        }
    }

    /// Attempt to refresh the given token, and obtain a new, valid one.
    /// If the `RefreshResult` is `RefreshResult::Error`, you may retry within an interval
    /// of your choice. If it is `RefreshResult:RefreshError`, your refresh token is invalid
    /// or your authorization was revoked. Therefore no further attempt shall be made,
    /// and you will have to re-authorize using the `DeviceFlow`
    ///
    /// # Arguments
    /// * `authentication_url` - URL matching the one used in the flow that obtained
    ///                          your refresh_token in the first place.
    /// * `client_id` & `client_secret` - as obtained when [registering your application](https://developers.google.com/youtube/registering_an_application)
    /// * `refresh_token` - obtained during previous call to `DeviceFlow::poll_token()` or equivalent
    ///
    /// # Examples
    /// Please see the crate landing page for an example.
    pub fn refresh_token(
        &mut self,
        flow_type: FlowType,
        client_secret: &ApplicationSecret,
        refresh_token: &str,
    ) -> &RefreshResult {
        let _ = flow_type;
        if let RefreshResult::Success(_) = self.result {
            return &self.result;
        }

        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", client_secret.client_id.as_ref()),
                ("client_secret", client_secret.client_secret.as_ref()),
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token"),
            ])
            .finish();

        let json_str: String = match self
            .client
            .borrow_mut()
            .post(&client_secret.token_uri)
            .header(ContentType(
                "application/x-www-form-urlencoded".parse().unwrap(),
            ))
            .body(&*req)
            .send()
        {
            Err(err) => {
                self.result = RefreshResult::Error(err);
                return &self.result;
            }
            Ok(mut res) => {
                let mut json_str = String::new();
                res.read_to_string(&mut json_str).unwrap();
                json_str
            }
        };

        #[derive(Deserialize)]
        struct JsonToken {
            access_token: String,
            token_type: String,
            expires_in: i64,
        }

        match json::from_str::<JsonError>(&json_str) {
            Err(_) => {}
            Ok(res) => {
                self.result = RefreshResult::RefreshError(res.error, res.error_description);
                return &self.result;
            }
        }

        let t: JsonToken = json::from_str(&json_str).unwrap();
        self.result = RefreshResult::Success(Token {
            access_token: t.access_token,
            token_type: t.token_type,
            refresh_token: refresh_token.to_string(),
            expires_in: None,
            expires_in_timestamp: Some(Utc::now().timestamp() + t.expires_in),
        });

        &self.result
    }
}

#[cfg(test)]
mod tests {
    use super::super::FlowType;
    use super::*;
    use crate::device::GOOGLE_DEVICE_CODE_URL;
    use crate::helper::parse_application_secret;
    use hyper;
    use std::default::Default;
    use yup_hyper_mock::{MockStream, SequentialConnector};

    struct MockGoogleRefresh(SequentialConnector);

    impl Default for MockGoogleRefresh {
        fn default() -> MockGoogleRefresh {
            let mut c = MockGoogleRefresh(Default::default());
            c.0.content.push(
                "HTTP/1.1 200 OK\r\n\
                 Server: BOGUS\r\n\
                 \r\n\
                 {\r\n\
                 \"access_token\":\"1/fFAGRNJru1FTz70BzhT3Zg\",\r\n\
                 \"expires_in\":3920,\r\n\
                 \"token_type\":\"Bearer\"\r\n\
                 }"
                .to_string(),
            );

            c
        }
    }

    impl hyper::net::NetworkConnector for MockGoogleRefresh {
        type Stream = MockStream;

        fn connect(&self, host: &str, port: u16, scheme: &str) -> ::hyper::Result<MockStream> {
            self.0.connect(host, port, scheme)
        }
    }

    const TEST_APP_SECRET: &'static str = r#"{"installed":{"client_id":"384278056379-tr5pbot1mil66749n639jo54i4840u77.apps.googleusercontent.com","project_id":"sanguine-rhythm-105020","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://accounts.google.com/o/oauth2/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"QeQUnhzsiO4t--ZGmj9muUAu","redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]}}"#;

    #[test]
    fn refresh_flow() {
        let appsecret = parse_application_secret(TEST_APP_SECRET).unwrap();

        let mut c = hyper::Client::with_connector(<MockGoogleRefresh as Default>::default());
        let mut flow = RefreshFlow::new(&mut c);

        match *flow.refresh_token(
            FlowType::Device(GOOGLE_DEVICE_CODE_URL.to_string()),
            &appsecret,
            "bogus_refresh_token",
        ) {
            RefreshResult::Success(ref t) => {
                assert_eq!(t.access_token, "1/fFAGRNJru1FTz70BzhT3Zg");
                assert!(!t.expired());
            }
            _ => unreachable!(),
        }
    }
}
