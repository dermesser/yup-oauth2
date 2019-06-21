use crate::types::{ApplicationSecret, JsonError};

use std::error::Error;

use super::Token;
use chrono::Utc;
use futures::stream::Stream;
use futures::Future;
use hyper;
use hyper::header;
use serde_json as json;
use url::form_urlencoded;

/// Implements the [Outh2 Refresh Token Flow](https://developers.google.com/youtube/v3/guides/authentication#devices).
///
/// Refresh an expired access token, as obtained by any other authentication flow.
/// This flow is useful when your `Token` is expired and allows to obtain a new
/// and valid access token.
pub struct RefreshFlow;

/// All possible outcomes of the refresh flow
#[derive(Debug)]
pub enum RefreshResult {
    /// Indicates connection failure
    Error(hyper::Error),
    /// The server did not answer with a new token, providing the server message
    RefreshError(String, Option<String>),
    /// The refresh operation finished successfully, providing a new `Token`
    Success(Token),
}

impl RefreshFlow {
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
    pub fn refresh_token<'a, C: 'static + hyper::client::connect::Connect>(
        client: hyper::Client<C>,
        client_secret: ApplicationSecret,
        refresh_token: String,
    ) -> impl 'a + Future<Item = RefreshResult, Error = Box<dyn 'static + Error + Send>> {
        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", client_secret.client_id.clone()),
                ("client_secret", client_secret.client_secret.clone()),
                ("refresh_token", refresh_token.to_string()),
                ("grant_type", "refresh_token".to_string()),
            ])
            .finish();

        let request = hyper::Request::post(client_secret.token_uri.clone())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(req))
            .unwrap(); // TODO: error handling

        client
            .request(request)
            .then(|r| {
                match r {
                    Err(err) => return Err(RefreshResult::Error(err)),
                    Ok(res) => {
                        Ok(res
                            .into_body()
                            .concat2()
                            .wait()
                            .map(|c| String::from_utf8(c.into_bytes().to_vec()).unwrap())
                            .unwrap()) // TODO: error handling
                    }
                }
            })
            .then(move |maybe_json_str: Result<String, RefreshResult>| {
                if let Err(e) = maybe_json_str {
                    return Ok(e);
                }
                let json_str = maybe_json_str.unwrap();
                #[derive(Deserialize)]
                struct JsonToken {
                    access_token: String,
                    token_type: String,
                    expires_in: i64,
                }

                match json::from_str::<JsonError>(&json_str) {
                    Err(_) => {}
                    Ok(res) => {
                        return Ok(RefreshResult::RefreshError(
                            res.error,
                            res.error_description,
                        ))
                    }
                }

                let t: JsonToken = json::from_str(&json_str).unwrap();
                Ok(RefreshResult::Success(Token {
                    access_token: t.access_token,
                    token_type: t.token_type,
                    refresh_token: refresh_token.to_string(),
                    expires_in: None,
                    expires_in_timestamp: Some(Utc::now().timestamp() + t.expires_in),
                }))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper;

    use hyper;
    use hyper_tls::HttpsConnector;
    use mockito;
    use tokio;

    #[test]
    fn test_refresh_end2end() {
        let server_url = mockito::server_url();

        let app_secret = r#"{"installed":{"client_id":"902216714886-k2v9uei3p1dk6h686jbsn9mo96tnbvto.apps.googleusercontent.com","project_id":"yup-test-243420","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"iuMPN6Ne1PD7cos29Tk9rlqH","redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]}}"#;
        let mut app_secret = helper::parse_application_secret(app_secret).unwrap();
        app_secret.token_uri = format!("{}/token", server_url);
        let refresh_token = "my-refresh-token".to_string();

        let https = HttpsConnector::new(1).unwrap();
        let client = hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(https);

        // Success
        {
            let _m = mockito::mock("POST", "/token")
                .match_body(
                    mockito::Matcher::Regex(".*client_id=902216714886-k2v9uei3p1dk6h686jbsn9mo96tnbvto.apps.googleusercontent.com.*refresh_token=my-refresh-token.*".to_string()))
                .with_status(200)
                .with_body(r#"{"access_token": "new-access-token", "token_type": "Bearer", "expires_in": 1234567}"#)
                .create();

            let fut = RefreshFlow::refresh_token(
                client.clone(),
                app_secret.clone(),
                refresh_token.clone(),
            )
            .then(|rr| {
                let rr = rr.unwrap();
                match rr {
                    RefreshResult::Success(tok) => {
                        assert_eq!("new-access-token", tok.access_token);
                        assert_eq!("Bearer", tok.token_type);
                    }
                    _ => panic!(format!("unexpected RefreshResult {:?}", rr)),
                }
                Ok(())
            });

            tokio::run(fut);
            _m.assert();
        }
        // Refresh error.
        {
            let _m = mockito::mock("POST", "/token")
                .match_body(
                    mockito::Matcher::Regex(".*client_id=902216714886-k2v9uei3p1dk6h686jbsn9mo96tnbvto.apps.googleusercontent.com.*refresh_token=my-refresh-token.*".to_string()))
                .with_status(400)
                .with_body(r#"{"error": "invalid_token"}"#)
                .create();

            let fut = RefreshFlow::refresh_token(client, app_secret, refresh_token).then(|rr| {
                let rr = rr.unwrap();
                match rr {
                    RefreshResult::RefreshError(e, None) => {
                        assert_eq!(e, "invalid_token");
                    }
                    _ => panic!(format!("unexpected RefreshResult {:?}", rr)),
                }
                Ok(())
            });

            tokio::run(fut);
            _m.assert();
        }
    }
}
