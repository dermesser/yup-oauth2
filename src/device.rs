use std::iter::{FromIterator, IntoIterator};
use std::time::Duration;

use chrono::{self, Utc};
use futures::stream::Stream;
use futures::{future, prelude::*};
use http;
use hyper;
use hyper::header;
use itertools::Itertools;
use serde_json as json;
use tokio_timer;
use url::form_urlencoded;

use crate::authenticator_delegate::{FlowDelegate, PollInformation, Retry};
use crate::types::{
    ApplicationSecret, Flow, FlowType, GetToken, JsonError, PollError, RequestError, Token,
};

pub const GOOGLE_DEVICE_CODE_URL: &'static str = "https://accounts.google.com/o/oauth2/device/code";

/// Implements the [Oauth2 Device Flow](https://developers.google.com/youtube/v3/guides/authentication#devices)
/// It operates in two steps:
/// * obtain a code to show to the user
/// * (repeatedly) poll for the user to authenticate your application
pub struct DeviceFlow<FD, C> {
    client: hyper::Client<C, hyper::Body>,
    application_secret: ApplicationSecret,
    /// Usually GOOGLE_DEVICE_CODE_URL
    device_code_url: String,
    fd: FD,
    wait: Duration,
}

impl<FD, C> Flow for DeviceFlow<FD, C> {
    fn type_id() -> FlowType {
        FlowType::Device(String::new())
    }
}

impl<
        FD: FlowDelegate + Clone + Send + 'static,
        C: hyper::client::connect::Connect + Sync + 'static,
    > GetToken for DeviceFlow<FD, C>
{
    fn token<'b, I, T>(
        &mut self,
        scopes: I,
    ) -> Box<dyn Future<Item = Token, Error = RequestError> + Send>
    where
        T: AsRef<str> + Ord + 'b,
        I: Iterator<Item = &'b T>,
    {
        self.retrieve_device_token(Vec::from_iter(scopes.map(|s| s.as_ref().to_string())))
    }
    fn api_key(&mut self) -> Option<String> {
        None
    }
    fn application_secret(&self) -> ApplicationSecret {
        self.application_secret.clone()
    }
}

impl<FD, C> DeviceFlow<FD, C>
where
    C: hyper::client::connect::Connect + Sync + 'static,
    C::Transport: 'static,
    C::Future: 'static,
    FD: FlowDelegate + Clone + Send + 'static,
{
    pub fn new<S: 'static + AsRef<str>>(
        client: hyper::Client<C, hyper::Body>,
        secret: ApplicationSecret,
        fd: FD,
        device_code_url: Option<S>,
    ) -> DeviceFlow<FD, C> {
        DeviceFlow {
            client: client,
            application_secret: secret,
            device_code_url: device_code_url
                .as_ref()
                .map(|s| s.as_ref().to_string())
                .unwrap_or(GOOGLE_DEVICE_CODE_URL.to_string()),
            fd: fd,
            wait: Duration::from_secs(1200),
        }
    }

    /// Set the time to wait for the user to authorize us. The default is 120 seconds.
    pub fn set_wait_duration(&mut self, wait: Duration) {
        self.wait = wait;
    }

    /// Essentially what `GetToken::token` does: Retrieve a token for the given scopes without
    /// caching.
    pub fn retrieve_device_token<'a>(
        &mut self,
        scopes: Vec<String>,
    ) -> Box<dyn Future<Item = Token, Error = RequestError> + Send> {
        let application_secret = self.application_secret.clone();
        let client = self.client.clone();
        let wait = self.wait;
        let mut fd = self.fd.clone();
        let request_code = Self::request_code(
            application_secret.clone(),
            client.clone(),
            self.device_code_url.clone(),
            scopes,
        )
        .and_then(move |(pollinf, device_code)| {
            fd.present_user_code(&pollinf);
            Ok((pollinf, device_code))
        });
        let fd = self.fd.clone();
        Box::new(request_code.and_then(move |(pollinf, device_code)| {
            future::loop_fn(0, move |i| {
                // Make a copy of everything every time, because the loop function needs to be
                // repeatable, i.e. we can't move anything out.
                let pt = Self::poll_token(
                    application_secret.clone(),
                    client.clone(),
                    device_code.clone(),
                    pollinf.clone(),
                    fd.clone(),
                );
                let maxn = wait.as_secs() / pollinf.interval.as_secs();
                let mut fd = fd.clone();
                let pollinf = pollinf.clone();
                tokio_timer::sleep(pollinf.interval)
                    .then(|_| pt)
                    .then(move |r| match r {
                        Ok(None) if i < maxn => match fd.pending(&pollinf) {
                            Retry::Abort | Retry::Skip => {
                                Box::new(Err(RequestError::Poll(PollError::TimedOut)).into_future())
                            }
                            Retry::After(d) => Box::new(
                                tokio_timer::sleep(d)
                                    .then(move |_| Ok(future::Loop::Continue(i + 1))),
                            )
                                as Box<
                                    dyn Future<
                                            Item = future::Loop<Token, u64>,
                                            Error = RequestError,
                                        > + Send,
                                >,
                        },
                        Ok(Some(tok)) => Box::new(Ok(future::Loop::Break(tok)).into_future()),
                        Err(e @ PollError::AccessDenied)
                        | Err(e @ PollError::TimedOut)
                        | Err(e @ PollError::Expired(_)) => {
                            Box::new(Err(RequestError::Poll(e)).into_future())
                        }
                        Err(_) if i < maxn => {
                            Box::new(Ok(future::Loop::Continue(i + 1)).into_future())
                        }
                        // Too many attempts.
                        Ok(None) | Err(_) => {
                            Box::new(Err(RequestError::Poll(PollError::TimedOut)).into_future())
                        }
                    })
            })
        }))
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
    fn request_code(
        application_secret: ApplicationSecret,
        client: hyper::Client<C>,
        device_code_url: String,
        scopes: Vec<String>,
    ) -> impl Future<Item = (PollInformation, String), Error = RequestError> {
        // note: cloned() shouldn't be needed, see issue
        // https://github.com/servo/rust-url/issues/81
        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", application_secret.client_id.clone()),
                (
                    "scope",
                    scopes
                        .into_iter()
                        .intersperse(" ".to_string())
                        .collect::<String>(),
                ),
            ])
            .finish();

        // note: works around bug in rustlang
        // https://github.com/rust-lang/rust/issues/22252
        let request = hyper::Request::post(device_code_url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(req))
            .into_future();
        request
            .then(
                move |request: Result<hyper::Request<hyper::Body>, http::Error>| {
                    let request = request.unwrap();
                    client.request(request)
                },
            )
            .then(
                |r: Result<hyper::Response<hyper::Body>, hyper::error::Error>| {
                    match r {
                        Err(err) => {
                            return Err(RequestError::ClientError(err));
                        }
                        Ok(res) => {
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

                            let json_str: String = res
                                .into_body()
                                .concat2()
                                .wait()
                                .map(|c| String::from_utf8(c.into_bytes().to_vec()).unwrap())
                                .unwrap(); // TODO: error handling

                            // check for error
                            match json::from_str::<JsonError>(&json_str) {
                                Err(_) => {} // ignore, move on
                                Ok(res) => return Err(RequestError::from(res)),
                            }

                            let decoded: JsonData = json::from_str(&json_str).unwrap();

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
                },
            )
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
    fn poll_token<'a>(
        application_secret: ApplicationSecret,
        client: hyper::Client<C>,
        device_code: String,
        pi: PollInformation,
        mut fd: FD,
    ) -> impl Future<Item = Option<Token>, Error = PollError> {
        let expired = if pi.expires_at <= Utc::now() {
            fd.expired(&pi.expires_at);
            Err(PollError::Expired(pi.expires_at)).into_future()
        } else {
            Ok(()).into_future()
        };

        // We should be ready for a new request
        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", &application_secret.client_id[..]),
                ("client_secret", &application_secret.client_secret),
                ("code", &device_code),
                ("grant_type", "http://oauth.net/grant_type/device/1.0"),
            ])
            .finish();

        let request = hyper::Request::post(&application_secret.token_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(req))
            .unwrap(); // TODO: Error checking
        expired
            .and_then(move |_| client.request(request).map_err(|e| PollError::HttpError(e)))
            .map(|res| {
                res.into_body()
                    .concat2()
                    .wait()
                    .map(|c| String::from_utf8(c.into_bytes().to_vec()).unwrap())
                    .unwrap() // TODO: error handling
            })
            .and_then(move |json_str: String| {
                #[derive(Deserialize)]
                struct JsonError {
                    error: String,
                }

                match json::from_str::<JsonError>(&json_str) {
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
                let mut t: Token = json::from_str(&json_str).unwrap();
                t.set_expiry_absolute();

                Ok(Some(t.clone()))
            })
    }
}

#[cfg(test)]
mod tests {
    use hyper;
    use hyper_tls::HttpsConnector;
    use mockito;
    use tokio;

    use super::*;
    use crate::helper::parse_application_secret;

    #[test]
    fn test_device_end2end() {
        #[derive(Clone)]
        struct FD;
        impl FlowDelegate for FD {
            fn present_user_code(&mut self, pi: &PollInformation) {
                assert_eq!("https://example.com/verify", pi.verification_url);
            }
        }

        let server_url = mockito::server_url();
        let app_secret = r#"{"installed":{"client_id":"902216714886-k2v9uei3p1dk6h686jbsn9mo96tnbvto.apps.googleusercontent.com","project_id":"yup-test-243420","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"iuMPN6Ne1PD7cos29Tk9rlqH","redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]}}"#;
        let mut app_secret = parse_application_secret(app_secret).unwrap();
        app_secret.token_uri = format!("{}/token", server_url);
        let device_code_url = format!("{}/code", server_url);

        let https = HttpsConnector::new(1).expect("tls");
        let client = hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(https);

        let mut flow = DeviceFlow::new(client.clone(), app_secret, FD, Some(device_code_url));

        let mut rt = tokio::runtime::Builder::new()
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

            let fut = flow
                .token(vec!["https://www.googleapis.com/scope/1"].iter())
                .then(|token| {
                    let token = token.unwrap();
                    assert_eq!("accesstoken", token.access_token);
                    Ok(()) as Result<(), ()>
                });
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

            let fut = flow
                .token(vec!["https://www.googleapis.com/scope/1"].iter())
                .then(|token| {
                    assert!(token.is_err());
                    assert!(format!("{}", token.unwrap_err()).contains("invalid_client_id"));
                    Ok(()) as Result<(), ()>
                });
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

            let fut = flow
                .token(vec!["https://www.googleapis.com/scope/1"].iter())
                .then(|token| {
                    assert!(token.is_err());
                    assert!(format!("{}", token.unwrap_err()).contains("Access denied by user"));
                    Ok(()) as Result<(), ()>
                });
            rt.block_on(fut).expect("block_on");

            _m.assert();
        }
    }
}
