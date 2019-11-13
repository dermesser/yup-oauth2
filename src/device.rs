use std::borrow::Cow;
use std::time::Duration;

use ::log::error;
use chrono::{DateTime, Utc};
use futures::prelude::*;
use hyper;
use hyper::header;
use serde_json as json;
use url::form_urlencoded;

use crate::authenticator_delegate::{DefaultFlowDelegate, FlowDelegate, PollInformation, Retry};
use crate::error::{Error, JsonErrorOr, PollError};
use crate::types::{ApplicationSecret, Token};

pub const GOOGLE_DEVICE_CODE_URL: &str = "https://accounts.google.com/o/oauth2/device/code";

// https://developers.google.com/identity/protocols/OAuth2ForDevices#step-4:-poll-googles-authorization-server
pub const GOOGLE_GRANT_TYPE: &str = "http://oauth.net/grant_type/device/1.0";

/// Implements the [Oauth2 Device Flow](https://developers.google.com/youtube/v3/guides/authentication#devices)
/// It operates in two steps:
/// * obtain a code to show to the user
// * (repeatedly) poll for the user to authenticate your application
pub struct DeviceFlow {
    pub(crate) device_code_url: Cow<'static, str>,
    pub(crate) flow_delegate: Box<dyn FlowDelegate>,
    pub(crate) wait_duration: Duration,
    pub(crate) grant_type: Cow<'static, str>,
}

impl DeviceFlow {
    /// Create a new DeviceFlow. The default FlowDelegate will be used and the
    /// default wait time is 120 seconds.
    pub(crate) fn new() -> Self {
        DeviceFlow {
            device_code_url: GOOGLE_DEVICE_CODE_URL.into(),
            flow_delegate: Box::new(DefaultFlowDelegate),
            wait_duration: Duration::from_secs(120),
            grant_type: GOOGLE_GRANT_TYPE.into(),
        }
    }

    pub(crate) async fn token<C, T>(
        &self,
        hyper_client: &hyper::Client<C>,
        app_secret: &ApplicationSecret,
        scopes: &[T],
    ) -> Result<Token, Error>
    where
        T: AsRef<str>,
        C: hyper::client::connect::Connect + 'static,
    {
        let (pollinf, device_code) =
            Self::request_code(app_secret, hyper_client, &self.device_code_url, scopes).await?;
        self.flow_delegate.present_user_code(&pollinf);
        tokio::timer::Timeout::new(
            self.wait_for_device_token(
                hyper_client,
                app_secret,
                &pollinf,
                &device_code,
                &self.grant_type,
            ),
            self.wait_duration,
        )
        .await
        .map_err(|_| Error::Poll(PollError::TimedOut))?
    }

    async fn wait_for_device_token<C>(
        &self,
        hyper_client: &hyper::Client<C>,
        app_secret: &ApplicationSecret,
        pollinf: &PollInformation,
        device_code: &str,
        grant_type: &str,
    ) -> Result<Token, Error>
    where
        C: hyper::client::connect::Connect + 'static,
    {
        let mut interval = pollinf.interval;
        loop {
            tokio::timer::delay_for(interval).await;
            interval = match Self::poll_token(
                &app_secret,
                hyper_client,
                device_code,
                grant_type,
                pollinf.expires_at,
                &*self.flow_delegate as &dyn FlowDelegate,
            )
            .await
            {
                Ok(None) => match self.flow_delegate.pending(&pollinf) {
                    Retry::Abort | Retry::Skip => return Err(Error::Poll(PollError::TimedOut)),
                    Retry::After(d) => d,
                },
                Ok(Some(tok)) => return Ok(tok),
                Err(e @ PollError::AccessDenied)
                | Err(e @ PollError::TimedOut)
                | Err(e @ PollError::Expired(_)) => return Err(Error::Poll(e)),
                Err(ref e) => {
                    error!("Unknown error from poll token api: {}", e);
                    pollinf.interval
                }
            }
        }
    }

    /// The first step involves asking the server for a code that the user
    /// can type into a field at a specified URL. It is called only once, assuming
    /// there was no connection error. Otherwise, it may be called again until
    /// you receive an `Ok` result.
    /// # Arguments
    /// * `client_id` & `client_secret` - as obtained when [registering your application](https://developers.google.com/youtube/registering_an_application)
    /// * `scopes` - an iterator yielding String-like objects which are URLs defining what your
    ///              application is able to do. It is considered good behaviour to authenticate
    ///              only once, with all scopes you will ever require.
    ///              However, you can also manage multiple tokens for different scopes, if your
    ///              application is providing distinct read-only and write modes.
    /// # Panics
    /// * If called after a successful result was returned at least once.
    /// # Examples
    /// See test-cases in source code for a more complete example.
    async fn request_code<C, T>(
        application_secret: &ApplicationSecret,
        client: &hyper::Client<C>,
        device_code_url: &str,
        scopes: &[T],
    ) -> Result<(PollInformation, String), Error>
    where
        T: AsRef<str>,
        C: hyper::client::connect::Connect + 'static,
    {
        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", application_secret.client_id.as_str()),
                ("scope", crate::helper::join(scopes, " ").as_str()),
            ])
            .finish();

        // note: works around bug in rustlang
        // https://github.com/rust-lang/rust/issues/22252
        let req = hyper::Request::post(device_code_url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(req))
            .unwrap();
        let resp = client.request(req).await.map_err(Error::ClientError)?;
        // This return type is defined in https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15#section-3.2
        // The alias is present as Google use a non-standard name for verification_uri.
        // According to the standard interval is optional, however, all tested implementations provide it.
        // verification_uri_complete is optional in the standard but not provided in tested implementations.
        #[derive(Deserialize)]
        struct JsonData {
            device_code: String,
            user_code: String,
            #[serde(alias = "verification_url")]
            verification_uri: String,
            expires_in: Option<i64>,
            interval: i64,
        }

        let json_bytes = resp.into_body().try_concat().await?;
        let decoded: JsonData = json::from_slice::<JsonErrorOr<_>>(&json_bytes)?.into_result()?;
        let expires_in = decoded.expires_in.unwrap_or(60 * 60);
        let pi = PollInformation {
            user_code: decoded.user_code,
            verification_url: decoded.verification_uri,
            expires_at: Utc::now() + chrono::Duration::seconds(expires_in),
            interval: Duration::from_secs(i64::abs(decoded.interval) as u64),
        };
        Ok((pi, decoded.device_code))
    }

    /// If the first call is successful, this method may be called.
    /// As long as we are waiting for authentication, it will return `Ok(None)`.
    /// You should call it within the interval given the previously returned
    /// `PollInformation.interval` field.
    ///
    /// The operation was successful once you receive an Ok(Some(Token)) for the first time.
    /// Subsequent calls will return the previous result, which may also be an error state.
    ///
    /// Do not call after `PollError::Expired|PollError::AccessDenied` was among the
    /// `Err(PollError)` variants as the flow will not do anything anymore.
    /// Thus in any unsuccessful case which is not `PollError::HttpError`, you will have to start
    /// over the entire flow, which requires a new instance of this type.
    ///
    /// > ⚠️ **Warning**: We assume the caller doesn't call faster than `interval` and are not
    /// > protected against this kind of mis-use.
    ///
    /// # Examples
    /// See test-cases in source code for a more complete example.
    async fn poll_token<'a, C>(
        application_secret: &ApplicationSecret,
        client: &hyper::Client<C>,
        device_code: &str,
        grant_type: &str,
        expires_at: DateTime<Utc>,
        flow_delegate: &dyn FlowDelegate,
    ) -> Result<Option<Token>, PollError>
    where
        C: hyper::client::connect::Connect + 'static,
    {
        if expires_at <= Utc::now() {
            flow_delegate.expired(expires_at);
            return Err(PollError::Expired(expires_at));
        }

        // We should be ready for a new request
        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", application_secret.client_id.as_str()),
                ("client_secret", application_secret.client_secret.as_str()),
                ("code", device_code),
                ("grant_type", grant_type),
            ])
            .finish();

        let request = hyper::Request::post(&application_secret.token_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(req))
            .unwrap(); // TODO: Error checking
        let res = client
            .request(request)
            .await
            .map_err(PollError::HttpError)?;
        let body = res
            .into_body()
            .try_concat()
            .await
            .map_err(PollError::HttpError)?;
        #[derive(Deserialize)]
        struct JsonError {
            error: String,
        }

        match json::from_slice::<JsonError>(&body) {
            Err(_) => {} // ignore, move on, it's not an error
            Ok(res) => {
                match res.error.as_ref() {
                    "access_denied" => {
                        flow_delegate.denied();
                        return Err(PollError::AccessDenied);
                    }
                    "authorization_pending" => return Ok(None),
                    s => {
                        return Err(PollError::Other(format!(
                            "server message '{}' not understood",
                            s
                        )))
                    }
                };
            }
        }

        // yes, we expect that !
        let mut t: Token = json::from_slice(&body).unwrap();
        t.set_expiry_absolute();

        Ok(Some(t))
    }
}

#[cfg(test)]
mod tests {
    use hyper;
    use hyper_rustls::HttpsConnector;
    use mockito;
    use tokio;

    use super::*;
    use crate::helper::parse_application_secret;

    #[test]
    fn test_device_end2end() {
        #[derive(Clone)]
        struct FD;
        impl FlowDelegate for FD {
            fn present_user_code(&self, pi: &PollInformation) {
                assert_eq!("https://example.com/verify", pi.verification_url);
            }
        }

        let server_url = mockito::server_url();
        let app_secret = r#"{"installed":{"client_id":"902216714886-k2v9uei3p1dk6h686jbsn9mo96tnbvto.apps.googleusercontent.com","project_id":"yup-test-243420","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"iuMPN6Ne1PD7cos29Tk9rlqH","redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]}}"#;
        let mut app_secret = parse_application_secret(app_secret).unwrap();
        app_secret.token_uri = format!("{}/token", server_url);
        let device_code_url = format!("{}/code", server_url);

        let https = HttpsConnector::new();
        let client = hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(https);

        let flow = DeviceFlow {
            device_code_url: device_code_url.into(),
            flow_delegate: Box::new(FD),
            wait_duration: Duration::from_secs(5),
            grant_type: GOOGLE_GRANT_TYPE.into(),
        };

        let rt = tokio::runtime::Builder::new()
            .core_threads(1)
            .panic_handler(|e| std::panic::resume_unwind(e))
            .build()
            .unwrap();

        // Successful path
        {
            let code_response = r#"{"device_code": "devicecode", "user_code": "usercode", "verification_url": "https://example.com/verify", "expires_in": 1234567, "interval": 1}"#;
            let _m = mockito::mock("POST", "/code")
                .match_body(mockito::Matcher::Regex(
                    ".*client_id=902216714886.*".to_string(),
                ))
                .with_status(200)
                .with_body(code_response)
                .create();
            let token_response = r#"{"access_token": "accesstoken", "refresh_token": "refreshtoken", "token_type": "Bearer", "expires_in": 1234567}"#;
            let _m = mockito::mock("POST", "/token")
                .match_body(mockito::Matcher::Regex(
                    ".*client_secret=iuMPN6Ne1PD7cos29Tk9rlqH&code=devicecode.*".to_string(),
                ))
                .with_status(200)
                .with_body(token_response)
                .create();

            let fut = async {
                let token = flow
                    .token(
                        &client,
                        &app_secret,
                        &["https://www.googleapis.com/scope/1"],
                    )
                    .await
                    .unwrap();
                assert_eq!("accesstoken", token.access_token);
                Ok(()) as Result<(), ()>
            };
            rt.block_on(fut).expect("block_on");

            _m.assert();
        }
        // Code is not delivered.
        {
            let code_response =
                r#"{"error": "invalid_client_id", "error_description": "description"}"#;
            let _m = mockito::mock("POST", "/code")
                .match_body(mockito::Matcher::Regex(
                    ".*client_id=902216714886.*".to_string(),
                ))
                .with_status(400)
                .with_body(code_response)
                .create();
            let token_response = r#"{"access_token": "accesstoken", "refresh_token": "refreshtoken", "token_type": "Bearer", "expires_in": 1234567}"#;
            let _m = mockito::mock("POST", "/token")
                .match_body(mockito::Matcher::Regex(
                    ".*client_secret=iuMPN6Ne1PD7cos29Tk9rlqH&code=devicecode.*".to_string(),
                ))
                .with_status(200)
                .with_body(token_response)
                .expect(0) // Never called!
                .create();

            let fut = async {
                let res = flow
                    .token(
                        &client,
                        &app_secret,
                        &["https://www.googleapis.com/scope/1"],
                    )
                    .await;
                assert!(res.is_err());
                assert!(format!("{}", res.unwrap_err()).contains("invalid_client_id"));
                Ok(()) as Result<(), ()>
            };
            rt.block_on(fut).expect("block_on");

            _m.assert();
        }
        // Token is not delivered.
        {
            let code_response = r#"{"device_code": "devicecode", "user_code": "usercode", "verification_url": "https://example.com/verify", "expires_in": 1234567, "interval": 1}"#;
            let _m = mockito::mock("POST", "/code")
                .match_body(mockito::Matcher::Regex(
                    ".*client_id=902216714886.*".to_string(),
                ))
                .with_status(200)
                .with_body(code_response)
                .create();
            let token_response = r#"{"error": "access_denied"}"#;
            let _m = mockito::mock("POST", "/token")
                .match_body(mockito::Matcher::Regex(
                    ".*client_secret=iuMPN6Ne1PD7cos29Tk9rlqH&code=devicecode.*".to_string(),
                ))
                .with_status(400)
                .with_body(token_response)
                .expect(1)
                .create();

            let fut = async {
                let res = flow
                    .token(
                        &client,
                        &app_secret,
                        &["https://www.googleapis.com/scope/1"],
                    )
                    .await;
                assert!(res.is_err());
                assert!(format!("{}", res.unwrap_err()).contains("Access denied by user"));
                Ok(()) as Result<(), ()>
            };
            rt.block_on(fut).expect("block_on");

            _m.assert();
        }
    }
}
