use std::default::Default;
use std::iter::IntoIterator;
use std::time::Duration;

use chrono::{self, Utc};
use futures::stream::Stream;
use futures::Future;
use hyper;
use hyper::header;
use itertools::Itertools;
use serde_json as json;
use url::form_urlencoded;

use crate::authenticator_delegate::{PollError, PollInformation};
use crate::types::{ApplicationSecret, Flow, FlowType, JsonError, RequestError, Token};

pub const GOOGLE_DEVICE_CODE_URL: &'static str = "https://accounts.google.com/o/oauth2/device/code";

/// Encapsulates all possible states of the Device Flow
enum DeviceFlowState {
    /// We failed to poll a result
    Error,
    /// We received poll information and will periodically poll for a token
    Pending(PollInformation),
    /// The flow finished successfully, providing token information
    Success(Token),
}

/// Implements the [Oauth2 Device Flow](https://developers.google.com/youtube/v3/guides/authentication#devices)
/// It operates in two steps:
/// * obtain a code to show to the user
/// * (repeatedly) poll for the user to authenticate your application
pub struct DeviceFlow<C> {
    client: hyper::Client<C, hyper::Body>,
    device_code: String,
    state: Option<DeviceFlowState>,
    error: Option<PollError>,
    application_secret: ApplicationSecret,
    device_code_url: String,
}

impl<C> Flow for DeviceFlow<C> {
    fn type_id() -> FlowType {
        FlowType::Device(String::new())
    }
}

impl<C> DeviceFlow<C>
where
    C: hyper::client::connect::Connect + Sync + 'static,
    C::Transport: 'static,
    C::Future: 'static,
{
    pub fn new<S: AsRef<str>>(
        client: hyper::Client<C, hyper::Body>,
        secret: &ApplicationSecret,
        device_code_url: S,
    ) -> DeviceFlow<C> {
        DeviceFlow {
            client: client,
            device_code: Default::default(),
            application_secret: secret.clone(),
            device_code_url: device_code_url.as_ref().to_string(),
            state: None,
            error: None,
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
    pub fn request_code<'b, T, I>(&mut self, scopes: I) -> Result<PollInformation, RequestError>
    where
        T: AsRef<str> + 'b,
        I: IntoIterator<Item = &'b T>,
    {
        if self.state.is_some() {
            panic!("Must not be called after we have obtained a token and have no error");
        }

        // note: cloned() shouldn't be needed, see issue
        // https://github.com/servo/rust-url/issues/81
        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", &self.application_secret.client_id),
                (
                    "scope",
                    &scopes
                        .into_iter()
                        .map(|s| s.as_ref())
                        .intersperse(" ")
                        .collect::<String>(),
                ),
            ])
            .finish();

        // note: works around bug in rustlang
        // https://github.com/rust-lang/rust/issues/22252
        let request = hyper::Request::post(&self.device_code_url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(req))?;

        // TODO: move the ? on request
        let ret = match self.client.request(request).wait() {
            Err(err) => {
                return Err(RequestError::ClientError(err)); // TODO: failed here
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
                    Ok(res) => return Err(RequestError::from(res)),
                }

                let decoded: JsonData = json::from_str(&json_str).unwrap();

                self.device_code = decoded.device_code;
                let pi = PollInformation {
                    user_code: decoded.user_code,
                    verification_url: decoded.verification_url,
                    expires_at: Utc::now() + chrono::Duration::seconds(decoded.expires_in),
                    interval: Duration::from_secs(i64::abs(decoded.interval) as u64),
                };
                self.state = Some(DeviceFlowState::Pending(pi.clone()));

                Ok(pi)
            }
        };

        ret
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
    pub fn poll_token(&mut self) -> Result<Option<Token>, &PollError> {
        // clone, as we may re-assign our state later
        let pi = match self.state {
            Some(ref s) => match *s {
                DeviceFlowState::Pending(ref pi) => pi.clone(),
                DeviceFlowState::Error => return Err(self.error.as_ref().unwrap()),
                DeviceFlowState::Success(ref t) => return Ok(Some(t.clone())),
            },
            _ => panic!("You have to call request_code() beforehand"),
        };

        if pi.expires_at <= Utc::now() {
            self.error = Some(PollError::Expired(pi.expires_at));
            self.state = Some(DeviceFlowState::Error);
            return Err(&self.error.as_ref().unwrap());
        }

        // We should be ready for a new request
        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", &self.application_secret.client_id[..]),
                ("client_secret", &self.application_secret.client_secret),
                ("code", &self.device_code),
                ("grant_type", "http://oauth.net/grant_type/device/1.0"),
            ])
            .finish();

        let request = hyper::Request::post(&self.application_secret.token_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(req))
            .unwrap(); // TODO: Error checking
        let json_str: String = match self.client.request(request).wait() {
            Err(err) => {
                self.error = Some(PollError::HttpError(err));
                return Err(self.error.as_ref().unwrap());
            }
            Ok(res) => {
                res.into_body()
                    .concat2()
                    .wait()
                    .map(|c| String::from_utf8(c.into_bytes().to_vec()).unwrap())
                    .unwrap() // TODO: error handling
            }
        };

        #[derive(Deserialize)]
        struct JsonError {
            error: String,
        }

        match json::from_str::<JsonError>(&json_str) {
            Err(_) => {} // ignore, move on, it's not an error
            Ok(res) => {
                match res.error.as_ref() {
                    "access_denied" => {
                        self.error = Some(PollError::AccessDenied);
                        self.state = Some(DeviceFlowState::Error);
                        return Err(self.error.as_ref().unwrap());
                    }
                    "authorization_pending" => return Ok(None),
                    _ => panic!("server message '{}' not understood", res.error),
                };
            }
        }

        // yes, we expect that !
        let mut t: Token = json::from_str(&json_str).unwrap();
        t.set_expiry_absolute();

        let res = Ok(Some(t.clone()));
        self.state = Some(DeviceFlowState::Success(t));
        return res;
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
