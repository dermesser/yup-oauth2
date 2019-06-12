use std::error::Error;
use std::iter::IntoIterator;
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

use crate::authenticator_delegate::{AuthenticatorDelegate, PollError, PollInformation};
use crate::types::{ApplicationSecret, Flow, FlowType, JsonError, RequestError, Token};

pub const GOOGLE_DEVICE_CODE_URL: &'static str = "https://accounts.google.com/o/oauth2/device/code";

/// Implements the [Oauth2 Device Flow](https://developers.google.com/youtube/v3/guides/authentication#devices)
/// It operates in two steps:
/// * obtain a code to show to the user
/// * (repeatedly) poll for the user to authenticate your application
pub struct DeviceFlow<AD, C> {
    client: hyper::Client<C, hyper::Body>,
    application_secret: ApplicationSecret,
    /// Usually GOOGLE_DEVICE_CODE_URL
    device_code_url: String,
    ad: AD,
}

impl<AD, C> Flow for DeviceFlow<AD, C> {
    fn type_id() -> FlowType {
        FlowType::Device(String::new())
    }
}

impl<AD, C> DeviceFlow<AD, C>
where
    C: hyper::client::connect::Connect + Sync + 'static,
    C::Transport: 'static,
    C::Future: 'static,
    AD: AuthenticatorDelegate + Clone + Send + 'static,
{
    pub fn new<S: 'static + AsRef<str>>(
        client: hyper::Client<C, hyper::Body>,
        secret: ApplicationSecret,
        ad: AD,
        device_code_url: Option<S>,
    ) -> DeviceFlow<AD, C> {
        DeviceFlow {
            client: client,
            application_secret: secret,
            device_code_url: device_code_url
                .as_ref()
                .map(|s| s.as_ref().to_string())
                .unwrap_or(GOOGLE_DEVICE_CODE_URL.to_string()),
            ad: ad,
        }
    }

    pub fn retrieve_device_token<'a>(
        &mut self,
        scopes: Vec<String>,
    ) -> Box<dyn Future<Item = Option<Token>, Error = Box<dyn Error + Send>> + Send> {
        let mut ad = self.ad.clone();
        let application_secret = self.application_secret.clone();
        let client = self.client.clone();
        let request_code = Self::request_code(
            application_secret.clone(),
            client.clone(),
            self.device_code_url.clone(),
            scopes,
        )
        .and_then(move |(pollinf, device_code)| {
            println!("presenting, {}", device_code);
            ad.present_user_code(&pollinf);
            Ok((pollinf, device_code))
        });
        Box::new(request_code.and_then(|(pollinf, device_code)| {
            future::loop_fn(0, move |i| {
                // Make a copy of everything every time, because the loop function needs to be
                // repeatable, i.e. we can't move anything out.
                //
                let pt = Self::poll_token(
                    application_secret.clone(),
                    client.clone(),
                    device_code.clone(),
                    pollinf.clone(),
                );
                println!("waiting {:?}", pollinf.interval);
                tokio_timer::sleep(pollinf.interval)
                    .then(|_| pt)
                    .then(move |r| match r {
                        Ok(None) if i < 10 => Ok(future::Loop::Continue(i + 1)),
                        Ok(Some(tok)) => Ok(future::Loop::Break(Some(tok))),
                        Err(_) if i < 10 => Ok(future::Loop::Continue(i + 1)),
                        _ => Ok(future::Loop::Break(None)),
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
                    println!("request: {:?}", request);
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

#[cfg(test)]
pub mod tests {
    use super::*;

    mock_connector_in_order!(MockGoogleAuth {
            "HTTP/1.1 200 OK\r\n\
             Server: BOGUS\r\n\
             \r\n\
             {\r\n\
                 \"device_code\" : \"4/L9fTtLrhY96442SEuf1Rl3KLFg3y\",\r\n\
                 \"user_code\" : \"a9xfwk9c\",\r\n\
                 \"verification_url\" : \"http://www.google.com/device\",\r\n\
                 \"expires_in\" : 1800,\r\n\
                 \"interval\" : 0\r\n\
             }"
            "HTTP/1.1 200 OK\r\n\
             Server: BOGUS\r\n\
             \r\n\
             {\r\n\
                 \"error\" : \"authorization_pending\"\r\n\
             }"
            "HTTP/1.1 200 OK\r\nServer: \
             BOGUS\r\n\r\n{\r\n\"access_token\":\"1/fFAGRNJru1FTz70BzhT3Zg\",\
             \r\n\"expires_in\":3920,\r\n\"token_type\":\"Bearer\",\
             \r\n\"refresh_token\":\
             \"1/6BMfW9j53gdGImsixUH6kU5RsR4zwI9lUVX-tqf8JXQ\"\r\n}"
    });

    const TEST_APP_SECRET: &'static str = r#"{"installed":{"client_id":"384278056379-tr5pbot1mil66749n639jo54i4840u77.apps.googleusercontent.com","project_id":"sanguine-rhythm-105020","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://accounts.google.com/o/oauth2/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"QeQUnhzsiO4t--ZGmj9muUAu","redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]}}"#;

    #[test]
    fn working_flow() {
        use crate::helper::parse_application_secret;

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let appsecret = parse_application_secret(&TEST_APP_SECRET.to_string()).unwrap();
        let client = hyper::Client::builder()
            .executor(runtime.executor())
            .build(MockGoogleAuth::default());

        let mut flow = DeviceFlow::new(client, &appsecret, GOOGLE_DEVICE_CODE_URL);

        match flow.request_code(&["https://www.googleapis.com/auth/youtube.upload"]) {
            Ok(pi) => assert_eq!(pi.interval, Duration::from_secs(0)),
            Err(err) => assert!(false, "request_code failed: {}", err),
        }

        match flow.poll_token() {
            Ok(None) => {}
            _ => unreachable!(),
        }

        let t = match flow.poll_token() {
            Ok(Some(t)) => {
                assert_eq!(t.access_token, "1/fFAGRNJru1FTz70BzhT3Zg");
                t
            }
            _ => unreachable!(),
        };

        // from now on, all calls will yield the same result
        // As our mock has only 3 items, we would panic on this call
        assert_eq!(flow.poll_token().unwrap(), Some(t));
    }
}
