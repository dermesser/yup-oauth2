use common::AuthenticationType;

use chrono::UTC;
use hyper;
use hyper::header::ContentType;
use rustc_serialize::json;
use url::form_urlencoded;
use super::Token;

/// Implements the [Outh2 Refresh Token Flow](https://developers.google.com/youtube/v3/guides/authentication#devices).
/// 
/// Refresh an expired access token, as obtained by any other authentication flow.
/// This flow is useful when your `Token` is expired and allows to obtain a new
/// and valid access token.
pub struct RefreshFlow<NC> {
    client: hyper::Client<NC>,
    result: RefreshResult,
}


/// All possible outcomes of the refresh flow
pub enum RefreshResult {
    /// Indicates connection failure
    Error(hyper::HttpError),
    /// The server did not answer with a new token, providing the server message
    Refused(String),
    /// The refresh operation finished successfully, providing a new `Token`
    Success(Token),
}

impl<NC> RefreshFlow<NC>
    where NC: hyper::net::NetworkConnector {

    pub fn new(client: hyper::Client<NC>) -> RefreshFlow<NC> {
        RefreshFlow {
            client: client,
            result: RefreshResult::Error(hyper::HttpError::HttpStatusError),
        }
    }

    /// Attempt to refresh the given token, and obtain a new, valid one.
    /// If the `RefreshResult` is `RefreshResult::Error`, you may retry within an interval
    /// of your choice. If it is `RefreshResult::Refused`, your refresh token is invalid
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
    pub fn refresh_token(&mut self, auth_type: AuthenticationType, 
                                    client_id: &str, client_secret: &str, 
                                    refresh_token: &str) -> &RefreshResult {
        if let RefreshResult::Success(_) = self.result {
            return &self.result;
        }

        let req = form_urlencoded::serialize(
                                [("client_id", client_id),
                                 ("client_secret", client_secret),
                                 ("refresh_token", refresh_token),
                                 ("grant_type", "refresh_token")]
                                .iter().cloned());

        let json_str = 
            match self.client.post(auth_type.as_slice())
               .header(ContentType("application/x-www-form-urlencoded".parse().unwrap()))
               .body(req.as_slice())
               .send() {
            Err(err) => { 
                self.result = RefreshResult::Error(err);
                return &self.result;
            }
            Ok(mut res) => {
                String::from_utf8(res.read_to_end().unwrap()).unwrap()
            }
        };

        #[derive(RustcDecodable)]
        struct JsonError {
            error: String
        }

        #[derive(RustcDecodable)]
        struct JsonToken {
            access_token: String,
            token_type: String,
            expires_in: i64,
        }

        match json::decode::<JsonError>(&json_str) {
            Err(_) => {},
            Ok(res) => {
                self.result = RefreshResult::Refused(res.error);
                return &self.result;
            }
        }

        let t: JsonToken = json::decode(&json_str).unwrap();
        self.result = RefreshResult::Success(Token {
            access_token: t.access_token,
            token_type: t.token_type,
            refresh_token: refresh_token.to_string(),
            expires_in: None,
            expires_in_timestamp: Some(UTC::now().timestamp() + t.expires_in),
        });

        &self.result
    }
}



#[cfg(test)]
mod tests {
    use hyper;
    use std::default::Default;
    use super::*;
    use super::super::AuthenticationType;

    mock_connector_in_order!(MockGoogleRefresh { 
                                "HTTP/1.1 200 OK\r\n\
                                 Server: BOGUS\r\n\
                                 \r\n\
                                {\r\n\
                                  \"access_token\":\"1/fFAGRNJru1FTz70BzhT3Zg\",\r\n\
                                  \"expires_in\":3920,\r\n\
                                  \"token_type\":\"Bearer\"\r\n\
                                }"
                            });

    #[test]
    fn refresh_flow() {
        let mut flow = RefreshFlow::new(
                            hyper::Client::with_connector(
                                    <MockGoogleRefresh as Default>::default()));


        match *flow.refresh_token(AuthenticationType::Device, 
                                    "bogus", "secret", "bogus_refresh_token") {
            RefreshResult::Success(ref t) => {
                assert_eq!(t.access_token, "1/fFAGRNJru1FTz70BzhT3Zg");
                assert!(!t.expired() && !t.invalid());
            },
            _ => unreachable!()
        }
    }
}
