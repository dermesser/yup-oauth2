use std::iter::IntoIterator;
use std::time::Duration;
use std::default::Default;
use std::rc::Rc;
use std::fmt;

use hyper;
use hyper::header::ContentType;
use url::form_urlencoded;
use itertools::Itertools;
use rustc_serialize::json;
use chrono::{DateTime,UTC};
use std::borrow::BorrowMut;
use std::io::Read;

use common::{Token, FlowType, Flow, JsonError};

pub const GOOGLE_TOKEN_URL: &'static str = "https://accounts.google.com/o/oauth2/token";

/// Implements the [Oauth2 Device Flow](https://developers.google.com/youtube/v3/guides/authentication#devices)
/// It operates in two steps:
/// * obtain a code to show to the user
/// * (repeatedly) poll for the user to authenticate your application
pub struct DeviceFlow<C> {
    client: C,
    device_code: String,
    state: PollResult,
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

    /// The message given by the server while polling it,
    /// usually not relevant to the user or the application
    pub server_message: String,
}

impl fmt::Display for PollInformation {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "Poll result was: '{}'", self.server_message)
    }
}

/// Encapsulates all possible results of the `request_token(...)` operation
#[derive(Clone)]
pub enum RequestResult {
    /// Indicates connection failure
    Error(Rc<hyper::HttpError>),
    /// The OAuth client was not found
    InvalidClient,
    /// Some requested scopes were invalid. String contains the scopes as part of 
    /// the server error message
    InvalidScope(String),
    /// A 'catch-all' variant containing the server error and description
    /// First string is the error code, the second may be a more detailed description
    NegativeServerResponse(String, Option<String>),
    /// Indicates we may enter the next phase
    ProceedWithPolling(PollInformation),
}

impl From<JsonError> for RequestResult {
    fn from(value: JsonError) -> RequestResult {
        match &*value.error {
            "invalid_client" => RequestResult::InvalidClient,
            "invalid_scope" => RequestResult::InvalidScope(
                        value.error_description.unwrap_or("no description provided".to_string())
                               ),
            _ => RequestResult::NegativeServerResponse(value.error, value.error_description),
        }
    }
}

impl fmt::Display for RequestResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            RequestResult::Error(ref err) => err.fmt(f),
            RequestResult::InvalidClient => "Invalid Client".fmt(f),
            RequestResult::InvalidScope(ref scope) 
                => writeln!(f, "Invalid Scope: '{}'", scope),
            RequestResult::NegativeServerResponse(ref error, ref desc) => {
                try!(error.fmt(f));
                if let &Some(ref desc) = desc {
                    try!(write!(f, ": {}", desc));
                }
                "\n".fmt(f)
            },
            RequestResult::ProceedWithPolling(ref pi) 
                => write!(f, "Proceed with polling: {}", pi),
        }
    }
}

/// Encapsulates all possible results of a `poll_token(...)` operation
#[derive(Clone, Debug)]
pub enum PollResult {
    /// Connection failure - retry if you think it's worth it
    Error(Rc<hyper::HttpError>),
    /// See `PollInformation`
    AuthorizationPending(PollInformation),
    /// indicates we are expired, including the expiration date
    Expired(DateTime<UTC>),
    /// Indicates that the user declined access. String is server response
    AccessDenied,
    /// Indicates that access is granted, and you are done
    AccessGranted(Token),
}

impl fmt::Display for PollResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            PollResult::Error(ref err) => err.fmt(f),
            PollResult::AuthorizationPending(ref pi) => pi.fmt(f),
            PollResult::Expired(ref date)
                => writeln!(f, "Authentication expired at {}", date),
            PollResult::AccessDenied => "Access denied by user".fmt(f),
            PollResult::AccessGranted(ref token) 
                => writeln!(f, "Access granted by user, expires at {}", token.expiry_date()),
        }
    }
}

impl Default for PollResult {
    fn default() -> PollResult {
        PollResult::Error(Rc::new(hyper::HttpError::HttpStatusError))
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
            state: Default::default(),
        }
    }

    /// The first step involves asking the server for a code that the user
    /// can type into a field at a specified URL. It is called only once, assuming
    /// there was no connection error. Otherwise, it may be called again until 
    /// the state changes to `PollResult::AuthorizationPending`.
    /// # Arguments
    /// * `client_id` & `client_secret` - as obtained when [registering your application](https://developers.google.com/youtube/registering_an_application)
    /// * `scopes` - an iterator yielding String-like objects which are URLs defining what your 
    ///              application is able to do. It is considered good behaviour to authenticate
    ///              only once, with all scopes you will ever require.
    ///              However, you can also manage multiple tokens for different scopes, if your 
    ///              application is providing distinct read-only and write modes.
    /// # Handling the `PollResult`
    /// * will panic if called while our state is not `PollResult::Error` 
    ///   or `PollResult::NeedToken`
    /// # Examples
    /// See test-cases in source code for a more complete example.
    pub fn request_code<'b, T, I>(&mut self, client_id: &str, client_secret: &str, scopes: I)
                                    -> RequestResult
                                    where T: AsRef<str>,
                                          I: IntoIterator<Item=&'b T> {
        if self.device_code.len() > 0 {
            panic!("Must not be called after we have obtained a token and have no error");
        }

        // note: cloned() shouldn't be needed, see issue
        // https://github.com/servo/rust-url/issues/81
        let req = form_urlencoded::serialize(
                  [("client_id", client_id),
                   ("scope", scopes.into_iter()
                                   .map(|s| s.as_ref())
                                   .intersperse(" ")
                                   .collect::<String>()
                                   .as_ref())].iter().cloned());

        match self.client.borrow_mut().post(FlowType::Device.as_ref())
               .header(ContentType("application/x-www-form-urlencoded".parse().unwrap()))
               .body(&*req)
               .send() {
            Err(err) => {
                return RequestResult::Error(Rc::new(err));
            }
            Ok(mut res) => {


                #[derive(RustcDecodable)]
                struct JsonData {
                    device_code: String,
                    user_code: String,
                    verification_url: String,
                    expires_in: i64,
                    interval: i64,
                }

                // This will work once hyper uses std::io::Reader
                // let decoded: JsonData = rustc_serialize::Decodable::decode(
                //                     &mut json::Decoder::new(
                //                         json::Json::from_reader(&mut res)
                //                                     .ok()
                //                                     .expect("decode must work!"))).unwrap();
                let mut json_str = String::new();
                res.read_to_string(&mut json_str).ok().expect("string decode must work");

                // check for error
                match json::decode::<JsonError>(&json_str) {
                    Err(_) => {}, // ignore, move on
                    Ok(res) => {
                        return RequestResult::from(res)
                    }
                }

                let decoded: JsonData = json::decode(&json_str).ok().expect("valid reply thanks to valid client_id and client_secret");

                self.device_code = decoded.device_code;
                let pi = PollInformation {
                    user_code: decoded.user_code,
                    verification_url: decoded.verification_url,
                    expires_at: UTC::now() + Duration::seconds(decoded.expires_in),
                    interval: Duration::seconds(decoded.interval),
                    server_message: Default::default(),
                };
                self.state = PollResult::AuthorizationPending(pi.clone());

                self.secret = client_secret.to_string();
                self.id = client_id.to_string();
                RequestResult::ProceedWithPolling(pi)
            }
        }
    }

    /// If the first call is successful, which is expected unless there is a network problem,
    /// the returned `PollResult::AuthorizationPending` variant contains enough information to 
    /// poll within a given `interval` to at some point obtain a result which is 
    /// not `PollResult::AuthorizationPending`.
    /// # Handling the `PollResult`
    /// * call within `PollResult::AuthorizationPending.interval` until the variant changes. 
    ///   Keep calling as desired, even after `PollResult::Error`.
    /// * Do not call after `PollResult::Expired`, `PollResult::AccessDenied` 
    ///   or `PollResult::AccessGranted` as the flow will do nothing anymore.
    ///   Thus in any unsuccessful case, you will have to start over the entire flow, which
    ///   requires a new instance of this type.
    /// 
    /// > ⚠️ **Warning**: We assume the caller doesn't call faster than `interval` and are not
    /// > protected against this kind of mis-use. The latter will be indicated in
    /// > `PollResult::AuthorizationPending.server_message`
    ///
    /// # Examples
    /// See test-cases in source code for a more complete example.
    pub fn poll_token(&mut self) -> PollResult {
        // clone, as we may re-assign our state later
        let state = self.state.clone();
        match state {
            PollResult::AuthorizationPending(mut pi) => {
                if pi.expires_at <= UTC::now() {
                    self.state = PollResult::Expired(pi.expires_at);
                    return self.state.clone();
                }

                // We should be ready for a new request
                let req = form_urlencoded::serialize(
                                [("client_id", &self.id[..]),
                                 ("client_secret", &self.secret),
                                 ("code", &self.device_code),
                                 ("grant_type", "http://oauth.net/grant_type/device/1.0")]
                                .iter().cloned());

                let json_str = 
                    match self.client.borrow_mut().post(GOOGLE_TOKEN_URL)
                       .header(ContentType("application/x-www-form-urlencoded".parse().unwrap()))
                       .body(&*req)
                       .send() {
                    Err(err) => { 
                        return PollResult::Error(Rc::new(err));
                    }
                    Ok(mut res) => {
                        let mut json_str = String::new();
                        res.read_to_string(&mut json_str).ok().expect("string decode must work");
                        json_str
                    }
                };

                #[derive(RustcDecodable)]
                struct JsonError {
                    error: String
                }

                match json::decode::<JsonError>(&json_str) {
                    Err(_) => {}, // ignore, move on, it's not an error
                    Ok(res) => {
                        pi.server_message = res.error;
                        self.state = match pi.server_message.as_ref() {
                            "access_denied" => PollResult::AccessDenied,
                            "authorization_pending" => PollResult::AuthorizationPending(pi),
                            _ => panic!("server message '{}' not understood", pi.server_message),
                        };
                        return self.state.clone();
                    }
                }

                // yes, we expect that !
                let mut t: Token = json::decode(&json_str).unwrap();
                t.set_expiry_absolute();
                self.state = PollResult::AccessGranted(t);
            },
            // In any other state, we will bail out and do nothing
            _ => {}
        }

        self.state.clone()
    }
}


#[cfg(test)]
pub mod tests {
    use super::*;
    use std::default::Default;
    use hyper;

    mock_connector_in_order!(MockGoogleAuth { 
                                "HTTP/1.1 200 OK\r\n\
                                 Server: BOGUS\r\n\
                                 \r\n\
                                {\r\n\
                                  \"device_code\" : \"4/L9fTtLrhY96442SEuf1Rl3KLFg3y\",\r\n\
                                  \"user_code\" : \"a9xfwk9c\",\r\n\
                                  \"verification_url\" : \"http://www.google.com/device\",\r\n\
                                  \"expires_in\" : \"1800\",\r\n\
                                  \"interval\" : 0\r\n\
                                }"
                                "HTTP/1.1 200 OK\r\n\
                                 Server: BOGUS\r\n\
                                 \r\n\
                                {\r\n\
                                    \"error\" : \"authorization_pending\"\r\n\
                                }"
                                "HTTP/1.1 200 OK\r\n\
                                 Server: BOGUS\r\n\
                                 \r\n\
                                {\r\n\
                                  \"access_token\":\"1/fFAGRNJru1FTz70BzhT3Zg\",\r\n\
                                  \"expires_in\":3920,\r\n\
                                  \"token_type\":\"Bearer\",\r\n\
                                  \"refresh_token\":\"1/6BMfW9j53gdGImsixUH6kU5RsR4zwI9lUVX-tqf8JXQ\"\r\n\
                                }"
                                 });

    #[test]
    fn working_flow() {
        let mut flow = DeviceFlow::new(
                    hyper::Client::with_connector(<MockGoogleAuth as Default>::default()));

        match flow.request_code("bogus_client_id",
                                    "bogus_secret",
                                    &["https://www.googleapis.com/auth/youtube.upload"]) {
                RequestResult::ProceedWithPolling(_) => {},
                _ => unreachable!(),
            };

        match flow.poll_token() {
            PollResult::AuthorizationPending(ref pi) => {
                assert_eq!(pi.server_message, "authorization_pending");
            },
            _ => unreachable!(),
        }

        match flow.poll_token() {
            PollResult::AccessGranted(ref t) => {
                assert_eq!(t.access_token, "1/fFAGRNJru1FTz70BzhT3Zg");
            },
            _ => unreachable!(),
        }

        // from now on, all calls will yield the same result
        // As our mock has only 3 items, we would panic on this call
        flow.poll_token();
    }
}