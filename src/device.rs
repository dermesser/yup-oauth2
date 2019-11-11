use std::pin::Pin;
use std::time::Duration;

use ::log::{error, log};
use chrono::{DateTime, Utc};
use futures::prelude::*;
use hyper;
use hyper::header;
use serde_json as json;
use url::form_urlencoded;

use crate::authenticator_delegate::{DefaultFlowDelegate, FlowDelegate, PollInformation, Retry};
use crate::types::{ApplicationSecret, GetToken, JsonErrorOr, PollError, RequestError, Token};

pub const GOOGLE_DEVICE_CODE_URL: &str = "https://accounts.google.com/o/oauth2/device/code";

/// Implements the [Oauth2 Device Flow](https://developers.google.com/youtube/v3/guides/authentication#devices)
/// It operates in two steps:
/// * obtain a code to show to the user
// * (repeatedly) poll for the user to authenticate your application
#[derive(Clone)]
pub struct DeviceFlow<FD> {
    application_secret: ApplicationSecret,
    device_code_url: String,
    flow_delegate: FD,
    wait: Duration,
}

impl DeviceFlow<DefaultFlowDelegate> {
    /// Create a new DeviceFlow. The default FlowDelegate will be used and the
    /// default wait time is 120 seconds.
    pub fn new(secret: ApplicationSecret) -> DeviceFlow<DefaultFlowDelegate> {
        DeviceFlow {
            application_secret: secret,
            device_code_url: GOOGLE_DEVICE_CODE_URL.to_string(),
            flow_delegate: DefaultFlowDelegate,
            wait: Duration::from_secs(120),
        }
    }
}

impl<FD> DeviceFlow<FD> {
    /// Use the provided device code url.
    pub fn device_code_url(self, url: String) -> Self {
        DeviceFlow {
            device_code_url: url,
            ..self
        }
    }

    /// Use the provided FlowDelegate.
    pub fn delegate<NewFD>(self, delegate: NewFD) -> DeviceFlow<NewFD> {
        DeviceFlow {
            application_secret: self.application_secret,
            device_code_url: self.device_code_url,
            flow_delegate: delegate,
            wait: self.wait,
        }
    }

    /// Use the provided wait duration.
    pub fn wait_duration(self, duration: Duration) -> Self {
        DeviceFlow {
            wait: duration,
            ..self
        }
    }
}

impl<FD, C> crate::authenticator::AuthFlow<C> for DeviceFlow<FD>
where
    FD: FlowDelegate + 'static,
    C: hyper::client::connect::Connect + 'static,
{
    type TokenGetter = DeviceFlowImpl<FD, C>;

    fn build_token_getter(self, client: hyper::Client<C>) -> Self::TokenGetter {
        DeviceFlowImpl {
            client,
            application_secret: self.application_secret,
            device_code_url: self.device_code_url,
            fd: self.flow_delegate,
            wait: Duration::from_secs(1200),
        }
    }
}

/// The DeviceFlow implementation.
pub struct DeviceFlowImpl<FD, C> {
    client: hyper::Client<C, hyper::Body>,
    application_secret: ApplicationSecret,
    /// Usually GOOGLE_DEVICE_CODE_URL
    device_code_url: String,
    fd: FD,
    wait: Duration,
}

impl<FD, C> GetToken for DeviceFlowImpl<FD, C>
where
    FD: FlowDelegate + 'static,
    C: hyper::client::connect::Connect + 'static,
{
    fn token<'a, T>(
        &'a self,
        scopes: &'a [T],
    ) -> Pin<Box<dyn Future<Output = Result<Token, RequestError>> + Send + 'a>>
    where
        T: AsRef<str> + Sync,
    {
        Box::pin(self.retrieve_device_token(scopes))
    }
    fn api_key(&self) -> Option<String> {
        None
    }
    fn application_secret(&self) -> &ApplicationSecret {
        &self.application_secret
    }
}

impl<FD, C> DeviceFlowImpl<FD, C>
where
    C: hyper::client::connect::Connect + 'static,
    C::Transport: 'static,
    C::Future: 'static,
    FD: FlowDelegate + 'static,
{
    /// Essentially what `GetToken::token` does: Retrieve a token for the given scopes without
    /// caching.
    pub async fn retrieve_device_token<T>(&self, scopes: &[T]) -> Result<Token, RequestError>
    where
        T: AsRef<str>,
    {
        let application_secret = &self.application_secret;
        let client = self.client.clone();
        let wait = self.wait;
        let fd = &self.fd;
        let (pollinf, device_code) = Self::request_code(
            application_secret,
            client.clone(),
            &self.device_code_url,
            scopes,
        )
        .await?;
        fd.present_user_code(&pollinf);
        let maxn = wait.as_secs() / pollinf.interval.as_secs();
        for _ in 0..maxn {
            tokio::timer::delay_for(pollinf.interval).await;
            let r = Self::poll_token(
                application_secret,
                client.clone(),
                &device_code,
                pollinf.expires_at,
                fd,
            )
            .await;
            match r {
                Ok(None) => match fd.pending(&pollinf) {
                    Retry::Abort | Retry::Skip => {
                        return Err(RequestError::Poll(PollError::TimedOut))
                    }
                    Retry::After(d) => tokio::timer::delay_for(d).await,
                },
                Ok(Some(tok)) => return Ok(tok),
                Err(e @ PollError::AccessDenied)
                | Err(e @ PollError::TimedOut)
                | Err(e @ PollError::Expired(_)) => return Err(RequestError::Poll(e)),
                Err(ref e) => error!("Unknown error from poll token api: {}", e),
            }
        }
        error!("Too many poll attempts");
        Err(RequestError::Poll(PollError::TimedOut))
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
    async fn request_code<T>(
        application_secret: &ApplicationSecret,
        client: hyper::Client<C>,
        device_code_url: &str,
        scopes: &[T],
    ) -> Result<(PollInformation, String), RequestError>
    where
        T: AsRef<str>,
    {
        // note: cloned() shouldn't be needed, see issue
        // https://github.com/servo/rust-url/issues/81
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
        let resp = client
            .request(req)
            .await
            .map_err(RequestError::ClientError)?;
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
        match json::from_slice::<JsonErrorOr<JsonData>>(&json_bytes)? {
            JsonErrorOr::Err(e) => Err(e.into()),
            JsonErrorOr::Data(decoded) => {
                let expires_in = decoded.expires_in.unwrap_or(60 * 60);

                let pi = PollInformation {
                    user_code: decoded.user_code,
                    verification_url: decoded.verification_uri,
                    expires_at: Utc::now() + chrono::Duration::seconds(expires_in),
                    interval: Duration::from_secs(i64::abs(decoded.interval) as u64),
                };
                Ok((pi, decoded.device_code))
            }
        }
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
    async fn poll_token<'a>(
        application_secret: &ApplicationSecret,
        client: hyper::Client<C>,
        device_code: &str,
        expires_at: DateTime<Utc>,
        fd: &FD,
    ) -> Result<Option<Token>, PollError> {
        if expires_at <= Utc::now() {
            fd.expired(expires_at);
            return Err(PollError::Expired(expires_at));
        }

        // We should be ready for a new request
        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", application_secret.client_id.as_str()),
                ("client_secret", application_secret.client_secret.as_str()),
                ("code", device_code),
                ("grant_type", "http://oauth.net/grant_type/device/1.0"),
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
                        fd.denied();
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
    use crate::authenticator::AuthFlow;
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

        let flow = DeviceFlow::new(app_secret)
            .delegate(FD)
            .device_code_url(device_code_url)
            .build_token_getter(client);

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
                    .token(&["https://www.googleapis.com/scope/1"])
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
                let res = flow.token(&["https://www.googleapis.com/scope/1"]).await;
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
                let res = flow.token(&["https://www.googleapis.com/scope/1"]).await;
                assert!(res.is_err());
                assert!(format!("{}", res.unwrap_err()).contains("Access denied by user"));
                Ok(()) as Result<(), ()>
            };
            rt.block_on(fut).expect("block_on");

            _m.assert();
        }
    }
}
