use crate::error::{JsonErrorOr, RefreshError};
use crate::types::ApplicationSecret;

use super::Token;
use chrono::Utc;
use futures_util::try_stream::TryStreamExt;
use hyper;
use hyper::header;
use url::form_urlencoded;

/// Implements the [OAuth2 Refresh Token Flow](https://developers.google.com/youtube/v3/guides/authentication#devices).
///
/// Refresh an expired access token, as obtained by any other authentication flow.
/// This flow is useful when your `Token` is expired and allows to obtain a new
/// and valid access token.
pub struct RefreshFlow;

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
    pub async fn refresh_token<C: hyper::client::connect::Connect + 'static>(
        client: &hyper::Client<C>,
        client_secret: &ApplicationSecret,
        refresh_token: &str,
    ) -> Result<Token, RefreshError> {
        // TODO: Does this function ever return RequestError? Maybe have it just return RefreshResult.
        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", client_secret.client_id.as_str()),
                ("client_secret", client_secret.client_secret.as_str()),
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token"),
            ])
            .finish();

        let request = hyper::Request::post(&client_secret.token_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(req))
            .unwrap(); // TODO: error handling

        let resp = client.request(request).await?;
        let body = resp.into_body().try_concat().await?;

        #[derive(Deserialize)]
        struct JsonToken {
            access_token: String,
            token_type: String,
            expires_in: i64,
        }

        let JsonToken {
            access_token,
            token_type,
            expires_in,
        } = serde_json::from_slice::<JsonErrorOr<_>>(&body)?.into_result()?;
        Ok(Token {
            access_token,
            token_type,
            refresh_token: Some(refresh_token.to_string()),
            expires_in: None,
            expires_in_timestamp: Some(Utc::now().timestamp() + expires_in),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper;

    use hyper;
    use hyper_rustls::HttpsConnector;
    use mockito;
    use tokio;

    #[test]
    fn test_refresh_end2end() {
        let server_url = mockito::server_url();

        let app_secret = r#"{"installed":{"client_id":"902216714886-k2v9uei3p1dk6h686jbsn9mo96tnbvto.apps.googleusercontent.com","project_id":"yup-test-243420","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"iuMPN6Ne1PD7cos29Tk9rlqH","redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]}}"#;
        let mut app_secret = helper::parse_application_secret(app_secret).unwrap();
        app_secret.token_uri = format!("{}/token", server_url);
        let refresh_token = "my-refresh-token";

        let https = HttpsConnector::new();
        let client = hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(https);

        let rt = tokio::runtime::Builder::new()
            .core_threads(1)
            .panic_handler(|e| std::panic::resume_unwind(e))
            .build()
            .unwrap();

        // Success
        {
            let _m = mockito::mock("POST", "/token")
                .match_body(
                    mockito::Matcher::Regex(".*client_id=902216714886-k2v9uei3p1dk6h686jbsn9mo96tnbvto.apps.googleusercontent.com.*refresh_token=my-refresh-token.*".to_string()))
                .with_status(200)
                .with_body(r#"{"access_token": "new-access-token", "token_type": "Bearer", "expires_in": 1234567}"#)
                .create();
            let fut = async {
                let token = RefreshFlow::refresh_token(&client, &app_secret, refresh_token)
                    .await
                    .unwrap();
                assert_eq!("new-access-token", token.access_token);
                assert_eq!("Bearer", token.token_type);
                Ok(()) as Result<(), ()>
            };

            rt.block_on(fut).expect("block_on");
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

            let fut = async {
                let rr = RefreshFlow::refresh_token(&client, &app_secret, refresh_token).await;
                match rr {
                    Err(RefreshError::ServerError(e, None)) => {
                        assert_eq!(e, "invalid_token");
                    }
                    _ => panic!(format!("unexpected RefreshResult {:?}", rr)),
                }
                Ok(()) as Result<(), ()>
            };

            rt.block_on(fut).expect("block_on");
            _m.assert();
        }
    }
}
