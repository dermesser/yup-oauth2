use std::error::Error;
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

use crate::authenticator_delegate::{FlowDelegate, PollError, PollInformation};
use crate::types::{ApplicationSecret, Flow, FlowType, GetToken, JsonError, RequestError, Token};

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
    ) -> Box<dyn Future<Item = Token, Error = Box<dyn Error + Send>> + Send>
    where
        T: AsRef<str> + Ord + 'b,
        I: Iterator<Item = &'b T>,
    {
        self.retrieve_device_token(Vec::from_iter(scopes.map(|s| s.as_ref().to_string())))
    }
    fn api_key(&mut self) -> Option<String> {
        None
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
            wait: Duration::from_secs(120),
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
    ) -> Box<dyn Future<Item = Token, Error = Box<dyn Error + Send>> + Send> {
        let mut fd = self.fd.clone();
        let application_secret = self.application_secret.clone();
        let client = self.client.clone();
        let wait = self.wait;
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
        Box::new(request_code.and_then(move |(pollinf, device_code)| {
            future::loop_fn(0, move |i| {
                // Make a copy of everything every time, because the loop function needs to be
                // repeatable, i.e. we can't move anything out.
                let pt = Self::poll_token(
                    application_secret.clone(),
                    client.clone(),
                    device_code.clone(),
                    pollinf.clone(),
                );
                let maxn = wait.as_secs() / pollinf.interval.as_secs();
                tokio_timer::sleep(pollinf.interval)
                    .then(|_| pt)
                    .then(move |r| match r {
                        Ok(None) if i < maxn => Ok(future::Loop::Continue(i + 1)),
                        Ok(Some(tok)) => Ok(future::Loop::Break(tok)),
                        Err(_) if i < maxn => Ok(future::Loop::Continue(i + 1)),
                        _ => Err(Box::new(PollError::TimedOut) as Box<dyn Error + Send>),
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
    ) -> impl Future<Item = (PollInformation, String), Error = Box<dyn 'static + Error + Send>>
    {
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
                            return Err(
                                Box::new(RequestError::ClientError(err)) as Box<dyn Error + Send>
                            );
                        }
                        Ok(res) => {
                            #[derive(Deserialize)]
                            struct JsonData {
                                device_code: String,
                                user_code: String,
                                verification_url: String,
                                expires_in: i64,
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
                                Ok(res) => {
                                    return Err(
                                        Box::new(RequestError::from(res)) as Box<dyn Error + Send>
                                    )
                                }
                            }

                            let decoded: JsonData = json::from_str(&json_str).unwrap();

                            let pi = PollInformation {
                                user_code: decoded.user_code,
                                verification_url: decoded.verification_url,
                                expires_at: Utc::now()
                                    + chrono::Duration::seconds(decoded.expires_in),
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
    /// Thus in any unsuccessful case which is not `PollError::HttpError`, you will have to start /// over the entire flow, which requires a new instance of this type.
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
    ) -> impl Future<Item = Option<Token>, Error = Box<dyn 'a + Error + Send>> {
        let expired = if pi.expires_at <= Utc::now() {
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
            .map_err(|e| Box::new(e) as Box<dyn Error + Send>)
            .and_then(move |_| {
                client
                    .request(request)
                    .map_err(|e| Box::new(e) as Box<dyn Error + Send>)
            })
            .map(|res| {
                res.into_body()
                    .concat2()
                    .wait()
                    .map(|c| String::from_utf8(c.into_bytes().to_vec()).unwrap())
                    .unwrap() // TODO: error handling
            })
            .and_then(|json_str: String| {
                #[derive(Deserialize)]
                struct JsonError {
                    error: String,
                }

                match json::from_str::<JsonError>(&json_str) {
                    Err(_) => {} // ignore, move on, it's not an error
                    Ok(res) => {
                        match res.error.as_ref() {
                            "access_denied" => {
                                return Err(
                                    Box::new(PollError::AccessDenied) as Box<dyn Error + Send>
                                );
                            }
                            "authorization_pending" => return Ok(None),
                            _ => panic!("server message '{}' not understood", res.error),
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
