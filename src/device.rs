use std::iter::IntoIterator;
use time::Duration;
use std::default::Default;
use std::fmt;

use hyper;
use hyper::header::ContentType;
use url::form_urlencoded;
use itertools::Itertools;
use serde::json;
use chrono::{DateTime,UTC};
use std::borrow::BorrowMut;
use std::io::Read;

use common::{Token, FlowType, Flow, JsonError};

pub const GOOGLE_TOKEN_URL: &'static str = "https://accounts.google.com/o/oauth2/token";

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
    client: C,
    device_code: String,
    state: Option<DeviceFlowState>,
    error: Option<PollError>,
    secret: String,
    id: String,
}

impl<C> Flow for DeviceFlow<C> {
    fn type_id() -> FlowType {
        FlowType::Device
    }
}


/// Contains state of pending authentication requests
#[derive(Clone, Debug, PartialEq)]
pub struct PollInformation {
    /// Code the user must enter ...
    pub user_code: String,
    /// ... at the verification URL
    pub verification_url: String,

    /// The `user_code` expires at the given time
    /// It's the time the user has left to authenticate your application
    pub expires_at: DateTime<UTC>,
    /// The interval in which we may poll for a status change
    /// The server responds with errors of we poll too fast.
    pub interval: Duration,
}

impl fmt::Display for PollInformation {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "Proceed with polling until {}", self.expires_at)
    }
}

/// Encapsulates all possible results of the `request_token(...)` operation
pub enum RequestError {
    /// Indicates connection failure
    HttpError(hyper::Error),
    /// The OAuth client was not found
    InvalidClient,
    /// Some requested scopes were invalid. String contains the scopes as part of 
    /// the server error message
    InvalidScope(String),
    /// A 'catch-all' variant containing the server error and description
    /// First string is the error code, the second may be a more detailed description
    NegativeServerResponse(String, Option<String>),
}

impl From<JsonError> for RequestError {
    fn from(value: JsonError) -> RequestError {
        match &*value.error {
            "invalid_client" => RequestError::InvalidClient,
            "invalid_scope" => RequestError::InvalidScope(
                        value.error_description.unwrap_or("no description provided".to_string())
                               ),
            _ => RequestError::NegativeServerResponse(value.error, value.error_description),
        }
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            RequestError::HttpError(ref err) => err.fmt(f),
            RequestError::InvalidClient => "Invalid Client".fmt(f),
            RequestError::InvalidScope(ref scope) 
                => writeln!(f, "Invalid Scope: '{}'", scope),
            RequestError::NegativeServerResponse(ref error, ref desc) => {
                try!(error.fmt(f));
                if let &Some(ref desc) = desc {
                    try!(write!(f, ": {}", desc));
                }
                "\n".fmt(f)
            },
        }
    }
}

/// Encapsulates all possible results of a `poll_token(...)` operation
#[derive(Debug)]
pub enum PollError {
    /// Connection failure - retry if you think it's worth it
    HttpError(hyper::Error),
    /// indicates we are expired, including the expiration date
    Expired(DateTime<UTC>),
    /// Indicates that the user declined access. String is server response
    AccessDenied,
}

impl fmt::Display for PollError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            PollError::HttpError(ref err) => err.fmt(f),
            PollError::Expired(ref date)
                => writeln!(f, "Authentication expired at {}", date),
            PollError::AccessDenied => "Access denied by user".fmt(f),
        }
    }
}


impl<C> DeviceFlow<C> 
    where   C: BorrowMut<hyper::Client> {

    /// # Examples
    /// ```test_harness
    /// extern crate hyper;
    /// extern crate yup_oauth2 as oauth2;
    /// use oauth2::DeviceFlow;
    /// 
    /// # #[test] fn new() {
    /// let mut f = DeviceFlow::new(hyper::Client::new());
    /// # }
    /// ```
    pub fn new(client: C) -> DeviceFlow<C> {
        DeviceFlow {
            client: client,
            device_code: Default::default(),
            secret: Default::default(),
            id: Default::default(),
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
    pub fn request_code<'b, T, I>(&mut self, client_id: &str, client_secret: &str, scopes: I)
                                    -> Result<PollInformation, RequestError>
                                    where T: AsRef<str>,
                                          I: IntoIterator<Item=&'b T> {
        if self.state.is_some() {
            panic!("Must not be called after we have obtained a token and have no error");
        }

        // note: cloned() shouldn't be needed, see issue
        // https://github.com/servo/rust-url/issues/81
        let req = form_urlencoded::serialize(
                  &[("client_id", client_id),
                    ("scope", scopes.into_iter()
                                    .map(|s| s.as_ref())
                                    .intersperse(" ")
                                    .collect::<String>()
                                    .as_ref())]);

        // note: works around bug in rustlang
        // https://github.com/rust-lang/rust/issues/22252
        let ret = match self.client.borrow_mut().post(FlowType::Device.as_ref())
               .header(ContentType("application/x-www-form-urlencoded".parse().unwrap()))
               .body(&*req)
               .send() {
            Err(err) => {
                return Err(RequestError::HttpError(err));
            }
            Ok(mut res) => {


                #[derive(Deserialize)]
                struct JsonData {
                    device_code: String,
                    user_code: String,
                    verification_url: String,
                    expires_in: i64,
                    interval: i64,
                }

                let mut json_str = String::new();
                res.read_to_string(&mut json_str).unwrap();

                // check for error
                match json::from_str::<JsonError>(&json_str) {
                    Err(_) => {}, // ignore, move on
                    Ok(res) => {
                        return Err(RequestError::from(res))
                    }
                }

                let decoded: JsonData = json::from_str(&json_str).unwrap();

                self.device_code = decoded.device_code;
                let pi = PollInformation {
                    user_code: decoded.user_code,
                    verification_url: decoded.verification_url,
                    expires_at: UTC::now() + Duration::seconds(decoded.expires_in),
                    interval: Duration::seconds(decoded.interval),
                };
                self.state = Some(DeviceFlowState::Pending(pi.clone()));

                self.secret = client_secret.to_string();
                self.id = client_id.to_string();
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
            Some(ref s) => 
                match *s {
                    DeviceFlowState::Pending(ref pi) => pi.clone(),
                    DeviceFlowState::Error => return Err(self.error.as_ref().unwrap()),
                    DeviceFlowState::Success(ref t) => return Ok(Some(t.clone())),
                },
            _ => panic!("You have to call request_code() beforehand"),
        };

        if pi.expires_at <= UTC::now() {
            self.error = Some(PollError::Expired(pi.expires_at));
            self.state = Some(DeviceFlowState::Error);
            return Err(&self.error.as_ref().unwrap())
        }

        // We should be ready for a new request
        let req = form_urlencoded::serialize(
                       &[("client_id", &self.id[..]),
                         ("client_secret", &self.secret),
                         ("code", &self.device_code),
                         ("grant_type", "http://oauth.net/grant_type/device/1.0")]);

        let json_str = 
            match self.client.borrow_mut().post(GOOGLE_TOKEN_URL)
               .header(ContentType("application/x-www-form-urlencoded".parse().unwrap()))
               .body(&*req)
               .send() {
            Err(err) => {
                self.error = Some(PollError::HttpError(err));
                return Err(self.error.as_ref().unwrap());
            }
            Ok(mut res) => {
                let mut json_str = String::new();
                res.read_to_string(&mut json_str).unwrap();
                json_str
            }
        };

        #[derive(Deserialize)]
        struct JsonError {
            error: String
        }

        match json::from_str::<JsonError>(&json_str) {
            Err(_) => {}, // ignore, move on, it's not an error
            Ok(res) => {
                match res.error.as_ref() {
                    "access_denied" => {
                        self.error = Some(PollError::AccessDenied);
                        self.state = Some(DeviceFlowState::Error);
                        return Err(self.error.as_ref().unwrap())
                    },
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
        return res
    }
}


#[cfg(test)]
pub mod tests {
    use super::*;
    use std::default::Default;
    use time::Duration;
    use hyper;
    use yup_hyper_mock::{SequentialConnector, MockStream};

    pub struct MockGoogleAuth(SequentialConnector);

    impl Default for MockGoogleAuth {
        fn default() -> MockGoogleAuth {
            let mut c = MockGoogleAuth(Default::default());
            c.0.content.push("HTTP/1.1 200 OK\r\n\
                                 Server: BOGUS\r\n\
                                 \r\n\
                                {\r\n\
                                  \"device_code\" : \"4/L9fTtLrhY96442SEuf1Rl3KLFg3y\",\r\n\
                                  \"user_code\" : \"a9xfwk9c\",\r\n\
                                  \"verification_url\" : \"http://www.google.com/device\",\r\n\
                                  \"expires_in\" : 1800,\r\n\
                                  \"interval\" : 0\r\n\
                                }".to_string());

            c.0.content.push("HTTP/1.1 200 OK\r\n\
                             Server: BOGUS\r\n\
                             \r\n\
                            {\r\n\
                                \"error\" : \"authorization_pending\"\r\n\
                            }".to_string());

            c.0.content.push("HTTP/1.1 200 OK\r\n\
                             Server: BOGUS\r\n\
                             \r\n\
                            {\r\n\
                              \"access_token\":\"1/fFAGRNJru1FTz70BzhT3Zg\",\r\n\
                              \"expires_in\":3920,\r\n\
                              \"token_type\":\"Bearer\",\r\n\
                              \"refresh_token\":\"1/6BMfW9j53gdGImsixUH6kU5RsR4zwI9lUVX-tqf8JXQ\"\r\n\
                            }".to_string());
            c

        }
    }

    impl hyper::net::NetworkConnector for MockGoogleAuth {
        type Stream = MockStream;

        fn connect(&self, host: &str, port: u16, scheme: &str) -> ::hyper::Result<MockStream> {
            self.0.connect(host, port, scheme)
        }

        fn set_ssl_verifier(&mut self, _: hyper::net::ContextVerifier) {}
    }

    #[test]
    fn working_flow() {
        let mut flow = DeviceFlow::new(
                    hyper::Client::with_connector(<MockGoogleAuth as Default>::default()));

        match flow.request_code("bogus_client_id",
                                "bogus_secret",
                                &["https://www.googleapis.com/auth/youtube.upload"]) {
            Ok(pi) => assert_eq!(pi.interval, Duration::seconds(0)),
            _ => unreachable!(),
        }

        match flow.poll_token() {
            Ok(None) => {},
            _ => unreachable!(),
        }

        let t = 
            match flow.poll_token() {
                Ok(Some(t)) => {
                    assert_eq!(t.access_token, "1/fFAGRNJru1FTz70BzhT3Zg");
                    t
                },
                _ => unreachable!(),
            };

        // from now on, all calls will yield the same result
        // As our mock has only 3 items, we would panic on this call
        assert_eq!(flow.poll_token().unwrap(), Some(t));
    }
}
