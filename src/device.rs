use std::iter::IntoIterator;
use std::time::Duration;
use std::default::Default;
use std::cmp::min;
use std::old_io::timer;

use hyper;
use hyper::header::ContentType;
use url::form_urlencoded;
use itertools::Itertools;
use rustc_serialize::json;
use chrono::{DateTime,UTC};
use std::borrow::BorrowMut;
use std::marker::PhantomData;

use common::{Token, AuthenticationType, Flow};

pub const GOOGLE_TOKEN_URL: &'static str = "https://accounts.google.com/o/oauth2/token";

/// Implements the [Oauth2 Device Flow](https://developers.google.com/youtube/v3/guides/authentication#devices)
/// It operates in two steps:
/// * obtain a code to show to the user
/// * (repeatedly) poll for the user to authenticate your application
pub struct DeviceFlow<C, NC> {
    client: C,
    device_code: String,
    state: PollResult,
    secret: String,
    id: String,

    _m: PhantomData<NC>,
}

impl<C, NC> Flow for DeviceFlow<C, NC> {
    fn type_id() -> AuthenticationType {
        AuthenticationType::Device
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

/// Encapsulates all possible results of the `request_token(...)` operation
#[derive(Clone)]
pub enum RequestResult {
    /// Indicates connection failure
    Error(hyper::HttpError),
    /// The OAuth client was not found
    InvalidClient,
    /// Some requested scopes were invalid. String contains the scopes as part of 
    /// the server error message
    InvalidScope(String),
    /// Indicates we may enter the next phase
    ProceedWithPolling(PollInformation),
}

impl RequestResult {
    fn from_server_message(msg: &str, desc: &str) -> RequestResult {
        match msg {
            "invalid_client" => RequestResult::InvalidClient,
            "invalid_scope" => RequestResult::InvalidScope(desc.to_string()),
            _ => panic!("'{}' not understood", msg)
        }
    }
}

/// Encapsulates all possible results of a `poll_token(...)` operation
#[derive(Clone)]
pub enum PollResult {
    /// Connection failure - retry if you think it's worth it
    Error(hyper::HttpError),
    /// See `PollInformation`
    AuthorizationPending(PollInformation),
    /// indicates we are expired, including the expiration date
    Expired(DateTime<UTC>),
    /// Indicates that the user declined access. String is server response
    AccessDenied,
    /// Indicates that access is granted, and you are done
    AccessGranted(Token),
}

impl Default for PollResult {
    fn default() -> PollResult {
        PollResult::Error(hyper::HttpError::HttpStatusError)
    }
}

impl<C, NC> DeviceFlow<C, NC> 
    where   C: BorrowMut<hyper::Client<NC>>,
            NC: hyper::net::NetworkConnector {

    /// # Examples
    /// ```test_harness
    /// extern crate hyper;
    /// extern crate "yup-oauth2" as oauth2;
    /// use oauth2::DeviceFlow;
    /// 
    /// # #[test] fn new() {
    /// let mut f = DeviceFlow::new(hyper::Client::new());
    /// # }
    /// ```
    pub fn new(client: C) -> DeviceFlow<C, NC> {
        DeviceFlow {
            client: client,
            device_code: Default::default(),
            secret: Default::default(),
            id: Default::default(),
            state: Default::default(),
            _m: PhantomData,
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
                                    where T: Str,
                                          I: IntoIterator<Item=&'b T> {
        if self.device_code.len() > 0 {
            panic!("Must not be called after we have obtained a token and have no error");
        }

        // note: cloned() shouldn't be needed, see issue
        // https://github.com/servo/rust-url/issues/81
        let req = form_urlencoded::serialize(
                  [("client_id", client_id),
                   ("scope", scopes.into_iter()
                                   .map(|s| s.as_slice())
                                   .intersperse(" ")
                                   .collect::<String>()
                                   .as_slice())].iter().cloned());

        match self.client.borrow_mut().post(AuthenticationType::Device.as_slice())
               .header(ContentType("application/x-www-form-urlencoded".parse().unwrap()))
               .body(req.as_slice())
               .send() {
            Err(err) => {
                return RequestResult::Error(err);
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


                #[derive(RustcDecodable)]
                struct JsonError {
                    error: String,
                    error_description: String
                }

                // This will work once hyper uses std::io::Reader
                // let decoded: JsonData = rustc_serialize::Decodable::decode(
                //                     &mut json::Decoder::new(
                //                         json::Json::from_reader(&mut res)
                //                                     .ok()
                //                                     .expect("decode must work!"))).unwrap();
                let json_str = String::from_utf8(res.read_to_end().unwrap()).unwrap();

                // check for error
                match json::decode::<JsonError>(&json_str) {
                    Err(_) => {}, // ignore, move on
                    Ok(res) => {
                        return RequestResult::from_server_message(&res.error, 
                                                                  &res.error_description)
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
                                [("client_id", self.id.as_slice()),
                                 ("client_secret", &self.secret),
                                 ("code", &self.device_code),
                                 ("grant_type", "http://oauth.net/grant_type/device/1.0")]
                                .iter().cloned());

                let json_str = 
                    match self.client.borrow_mut().post(GOOGLE_TOKEN_URL)
                       .header(ContentType("application/x-www-form-urlencoded".parse().unwrap()))
                       .body(req.as_slice())
                       .send() {
                    Err(err) => { 
                        return PollResult::Error(err);
                    }
                    Ok(mut res) => {
                        String::from_utf8(res.read_to_end().unwrap()).unwrap()
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
                        self.state = match pi.server_message.as_slice() {
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

/// A utility type to help executing the `DeviceFlow` correctly.
///
/// This involves polling the authentication server in the given intervals
/// until there is a definitive result.
///
/// These results will be passed the `DeviceFlowHelperDelegate` implementation to deal with
/// * presenting the user code
/// * inform the user about the progress or errors
/// * abort the operation
/// 
pub struct DeviceFlowHelper<'a> {
    delegate: &'a mut (DeviceFlowHelperDelegate + 'a),
}

impl<'a> DeviceFlowHelper<'a> {

    /// Initialize a new instance with the given delegate
    pub fn new(delegate: &'a mut DeviceFlowHelperDelegate) -> DeviceFlowHelper<'a> {
        DeviceFlowHelper {
            delegate: delegate,
        }
    }

    /// Blocks until a token was retrieved from the server, or the delegate 
    /// decided to abort the attempt, or the user decided not to authorize 
    /// the application.
    pub fn retrieve_token<'b, C, NC, T, I>(&mut self,
                                    client: C, 
                                    client_id: &str, client_secret: &str, scopes: I) 
                                    -> Option<Token>
                                    where T: Str,
                                          I: IntoIterator<Item=&'b T> + Clone,
                                          NC: hyper::net::NetworkConnector,
                                          C: BorrowMut<hyper::Client<NC>>  {
        let mut flow = DeviceFlow::new(client);

        // PHASE 1: REQUEST CODE
        loop {
            let res = flow.request_code(client_id, client_secret, scopes.clone());
            match res {
                RequestResult::Error(err) => {
                    match self.delegate.connection_error(err) {
                        Retry::Abort => return None,
                        Retry::After(d) => timer::sleep(d),
                    }
                },
                RequestResult::InvalidClient
                |RequestResult::InvalidScope(_) => {
                    self.delegate.request_failure(res);
                    return None
                }
                RequestResult::ProceedWithPolling(pi) => {
                    self.delegate.present_user_code(pi);
                    break
                }
            }
        }

        // PHASE 1: POLL TOKEN
        loop {
            match flow.poll_token() {
                PollResult::Error(err) => {
                    match self.delegate.connection_error(err) {
                        Retry::Abort => return None,
                        Retry::After(d) => timer::sleep(d),
                    }
                },
                PollResult::Expired(t) => {
                    self.delegate.expired(t);
                    return None
                },
                PollResult::AccessDenied => {
                    self.delegate.denied();
                    return None
                },
                PollResult::AuthorizationPending(pi) => {
                    match self.delegate.pending(&pi) {
                        Retry::Abort => return None,
                        Retry::After(d) => timer::sleep(min(d, pi.interval)),
                    }
                },
                PollResult::AccessGranted(token) => {
                    return Some(token)
                },
            }
        }
    }
}

/// A utility type to indicate how operations DeviceFlowHelper operations should be retried
pub enum Retry {
    /// Signal you don't want to retry
    Abort,
    /// Signals you want to retry after the given duration
    After(Duration)
}

/// A partially implemented trait to interact with the `DeviceFlowHelper`
/// 
/// The only method that needs to be implemented manually is `present_user_code(...)`,
/// as no assumptions are made on how this presentation should happen.
pub trait DeviceFlowHelperDelegate {

    /// Called whenever there is an HttpError, usually if there are network problems.
    /// 
    /// Return retry information.
    fn connection_error(&mut self, hyper::HttpError) -> Retry {
        Retry::Abort
    }

    /// The server denied the attempt to obtain a request code
    fn request_failure(&mut self, RequestResult) {}

    /// The server has returned a `user_code` which must be shown to the user,
    /// along with the `verification_url`.
    /// Will be called exactly once, provided we didn't abort during `request_code` phase.
    fn present_user_code(&mut self, PollInformation);

    /// Called if the request code is expired. You will have to start over in this case.
    /// This will be the last call the delegate receives.
    fn expired(&mut self, DateTime<UTC>) {}

    /// Called if the user denied access. You would have to start over. 
    /// This will be the last call the delegate receives.
    fn denied(&mut self) {}

    /// Called as long as we are waiting for the user to authorize us.
    /// Can be used to print progress information, or decide to time-out.
    /// 
    /// If the returned `Retry` variant is a duration, it will only be used if it
    /// is larger than the interval desired by the server.
    fn pending(&mut self,  &PollInformation) -> Retry {
        Retry::After(Duration::seconds(5))
    }
}


#[cfg(test)]
mod tests {
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

    #[test]
    fn authenticator() {
        struct TestHandler;
        impl DeviceFlowHelperDelegate for TestHandler {
            fn present_user_code(&mut self, pi: PollInformation) {
                println!("{:?}", pi);
            }
        }
        if let Some(t) = DeviceFlowHelper::new(&mut TestHandler)
                        .retrieve_token(hyper::Client::with_connector(
                                            <MockGoogleAuth as Default>::default()),
                                         "bogus_client_id",
                                         "bogus_secret",
                                         &["https://www.googleapis.com/auth/youtube.upload"]) {
            assert_eq!(t.access_token, "1/fFAGRNJru1FTz70BzhT3Zg")
        } else {
            panic!("Expected to retrieve token in one go");
        }
    }
}