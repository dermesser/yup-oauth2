use std::iter::IntoIterator;
use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::hash::{SipHasher, Hash, Hasher};
use std::thread::sleep;
use std::cmp::min;
use std::error::Error;
use std::fmt;
use std::convert::From;

use common::{Token, FlowType, ApplicationSecret};
use device::{PollInformation, RequestResult, DeviceFlow, PollResult};
use refresh::{RefreshResult, RefreshFlow};
use chrono::{DateTime, UTC, Duration, Local};
use hyper;


/// Implements a specialized storage to set and retrieve `Token` instances.
/// The `scope_hash` represents the signature of the scopes for which the given token
/// should be stored or retrieved.
/// For completeness, the underlying, sorted scopes are provided as well. They might be
/// useful for presentation to the user.
pub trait TokenStorage {
    type Error: 'static + Error;

    /// If `token` is None, it is invalid or revoked and should be removed from storage.
    fn set(&mut self, scope_hash: u64, scopes: &Vec<&str>, token: Option<Token>) -> Option<Self::Error>;
    /// A `None` result indicates that there is no token for the given scope_hash.
    fn get(&self, scope_hash: u64, scopes: &Vec<&str>) -> Result<Option<Token>, Self::Error>;
}

/// A storage that remembers nothing.
#[derive(Default)]
pub struct NullStorage;
#[derive(Debug)]
pub struct NullError;

impl Error for NullError {
    fn description(&self) -> &str {
        "NULL"
    }
}

impl fmt::Display for NullError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        "NULL-ERROR".fmt(f)
    }
}

impl TokenStorage for NullStorage {
    type Error = NullError;
    fn set(&mut self, _: u64, _: &Vec<&str>, _: Option<Token>) -> Option<NullError> { None }
    fn get(&self, _: u64, _: &Vec<&str>) -> Result<Option<Token>, NullError> { Ok(None) }
}

/// A storage that remembers values for one session only.
#[derive(Default)]
pub struct MemoryStorage {
    pub tokens: HashMap<u64, Token>
}

impl TokenStorage for MemoryStorage {
    type Error = NullError;

    fn set(&mut self, scope_hash: u64, _: &Vec<&str>, token: Option<Token>) -> Option<NullError> {
        match token {
            Some(t) => self.tokens.insert(scope_hash, t),
            None => self.tokens.remove(&scope_hash),
        };
        None
    }

    fn get(&self, scope_hash: u64, _: &Vec<&str>) -> Result<Option<Token>, NullError> {
        match self.tokens.get(&scope_hash) {
            Some(t) => Ok(Some(t.clone())),
            None => Ok(None),
        }
    }
}

/// A generalized authenticator which will keep tokens valid and store them. 
///
/// It is the go-to helper to deal with any kind of supported authentication flow,
/// which will be kept valid and usable.
///
/// # Device Flow
/// This involves polling the authentication server in the given intervals
/// until there is a definitive result.
///
/// These results will be passed the `DeviceFlowHelperDelegate` implementation to deal with
/// * presenting the user code
/// * inform the user about the progress or errors
/// * abort the operation
/// 
/// # Usage
/// Please have a look at the library's landing page.
pub struct Authenticator<D, S, C> {
    flow_type: FlowType,
    delegate: D,
    storage: S,
    client: C,
    secret: ApplicationSecret,
}

#[derive(Debug)]
struct StringError {
    error: String,
}

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.description().fmt(f)
    }
}

impl StringError {
    fn new(error: String, desc: Option<&String>) -> StringError {
        let mut error = error;
        if let Some(d) = desc {
            error.push_str(": ");
            error.push_str(&*d);
        }

        StringError {
            error: error,
        }
    }
}

impl<'a> From<&'a Error> for StringError {
    fn from(err: &'a Error) -> StringError {
        StringError::new(err.description().to_string(), None)
    }
}

impl From<String> for StringError {
    fn from(value: String) -> StringError {
        StringError::new(value, None)
    }
}

impl Error for StringError {
    fn description(&self) -> &str {
        &self.error
    }
}

/// A provider for authorization tokens, yielding tokens valid for a given scope.
/// The `api_key()` method is an alternative in case there are no scopes or
/// if no user is involved.
pub trait GetToken {
    fn token<'b, I, T>(&mut self, scopes: I) -> Result<Token, Box<Error>>
        where   T: AsRef<str> + Ord,
                I: IntoIterator<Item=&'b T>;

    fn api_key(&mut self) -> Option<String>;
}

impl<D, S, C> Authenticator<D, S, C>
    where  D: AuthenticatorDelegate,
           S: TokenStorage,
           C: BorrowMut<hyper::Client> {

    
    /// Returns a new `Authenticator` instance
    ///
    /// # Arguments
    /// * `secret` - usually obtained from a client secret file produced by the 
    ///              [developer console][dev-con]
    /// * `delegate` - Used to further refine the flow of the authentication.
    /// * `client` - used for all authentication https requests
    /// * `storage` - used to cache authorization tokens tokens permanently. However,
    ///               the implementation doesn't have any particular semantic requirement, which
    ///               is why `NullStorage` and `MemoryStorage` can be used as well.
    /// * `flow_type` - the kind of authentication to use to obtain a token for the 
    ///                 required scopes. If unset, it will be derived from the secret.
    /// [dev-con]: https://console.developers.google.com
    pub fn new(secret: &ApplicationSecret, 
               delegate: D, client: C, storage: S, flow_type: Option<FlowType>)
                                                     -> Authenticator<D, S, C> {
        Authenticator {
            flow_type: flow_type.unwrap_or(FlowType::Device),
            delegate: delegate,
            storage: storage,
            client: client,
            secret: secret.clone(),
        }
    }

    fn retrieve_device_token(&mut self, scopes: &Vec<&str>) -> Result<Token, Box<Error>> {
        let mut flow = DeviceFlow::new(self.client.borrow_mut());

        // PHASE 1: REQUEST CODE
        loop {
            let res = flow.request_code(&self.secret.client_id, 
                                        &self.secret.client_secret, scopes.iter());
            match res {
                RequestResult::Error(err) => {
                    match self.delegate.connection_error(&*err) {
                        Retry::Abort|Retry::Skip => return Err(Box::new(StringError::from(&*err as &Error))),
                        Retry::After(d) => sleep(d),
                    }
                },
                RequestResult::InvalidClient
                |RequestResult::NegativeServerResponse(_, _)
                |RequestResult::InvalidScope(_) => {
                    let serr = StringError::from(res.to_string());
                    self.delegate.request_failure(res);
                    return Err(Box::new(serr))
                }
                RequestResult::ProceedWithPolling(pi) => {
                    self.delegate.present_user_code(pi);
                    break
                }
            }
        }

        // PHASE 1: POLL TOKEN
        loop {
            let pt = flow.poll_token();
            let pts = pt.to_string();
            match pt {
                PollResult::Error(err) => {
                    match self.delegate.connection_error(&*err) {
                        Retry::Abort|Retry::Skip => return Err(Box::new(StringError::from(&*err as &Error))),
                        Retry::After(d) => sleep(d),
                    }
                },
                PollResult::Expired(t) => {
                    self.delegate.expired(t);
                    return  Err(Box::new(StringError::from(pts)))
                },
                PollResult::AccessDenied => {
                    self.delegate.denied();
                    return Err(Box::new(StringError::from(pts)))
                },
                PollResult::AuthorizationPending(pi) => {
                    match self.delegate.pending(&pi) {
                        Retry::Abort|Retry::Skip => return Err(Box::new(StringError::new(pts, None))),
                        Retry::After(d) => sleep(min(d, pi.interval)),
                    }
                },
                PollResult::AccessGranted(token) => {
                    return Ok(token)
                },
            }
        }
    }
}

impl<D, S, C> GetToken for Authenticator<D, S, C>
    where  D: AuthenticatorDelegate,
           S: TokenStorage,
           C: BorrowMut<hyper::Client> {

    /// Blocks until a token was retrieved from storage, from the server, or until the delegate 
    /// decided to abort the attempt, or the user decided not to authorize the application.
    /// In any failure case, the delegate will be provided with additional information, and 
    /// the caller will be informed about storage related errors.
    /// Otherwise it is guaranteed to be valid for the given scopes.
    fn token<'b, I, T>(&mut self, scopes: I) -> Result<Token, Box<Error>>
        where   T: AsRef<str> + Ord,
                I: IntoIterator<Item=&'b T> {
        let (scope_key, scopes) = {
            let mut sv: Vec<&str> = scopes.into_iter()
                                  .map(|s|s.as_ref())
                                  .collect::<Vec<&str>>();
            sv.sort();
            let mut sh = SipHasher::new();
            &sv.hash(&mut sh);
            let sv = sv;
            (sh.finish(), sv)
        };

        // Get cached token. Yes, let's do an explicit return
        loop {
            return match self.storage.get(scope_key, &scopes) {
                Ok(Some(mut t)) => {
                    // t needs refresh ?
                    if t.expired() {
                        let mut rf = RefreshFlow::new(self.client.borrow_mut());
                        loop {
                            match *rf.refresh_token(self.flow_type,
                                                   &self.secret.client_id, 
                                                   &self.secret.client_secret, 
                                                   &t.refresh_token,
                                                   scopes.iter()) {
                                RefreshResult::Error(ref err) => {
                                    match self.delegate.connection_error(err) {
                                        Retry::Abort|Retry::Skip => 
                                            return Err(Box::new(StringError::new(
                                                                    err.description().to_string(),
                                                                    None))),
                                        Retry::After(d) => sleep(d),
                                    }
                                },
                                RefreshResult::RefreshError(ref err_str, ref err_description) => {
                                    self.delegate.token_refresh_failed(&err_str, &err_description);
                                    return Err(Box::new(
                                        StringError::new(err_str.clone(), err_description.as_ref())))
                                },
                                RefreshResult::Success(ref new_t) => {
                                    t = new_t.clone();
                                    loop {
                                        if let Some(err) = self.storage.set(scope_key, &scopes, Some(t.clone())) {
                                            match self.delegate.token_storage_failure(true, &err) {
                                                Retry::Skip => break,
                                                Retry::Abort => return Err(Box::new(err)),
                                                Retry::After(d) => {
                                                    sleep(d);
                                                    continue;
                                                }
                                            }
                                        }
                                        break; // .set()
                                    }
                                    break; // refresh_token loop
                                }
                            }// RefreshResult handling
                        }// refresh loop
                    }// handle expiration
                    Ok(t)
                }
                Ok(None) => {
                    // Nothing was in storage - get a new token
                    // get new token. The respective sub-routine will do all the logic.
                    match 
                        match self.flow_type {
                            FlowType::Device => self.retrieve_device_token(&scopes),
                        }
                    {
                        Ok(token) => {
                            loop {
                                if let Some(err) = self.storage.set(scope_key, &scopes, Some(token.clone())) {
                                    match self.delegate.token_storage_failure(true, &err) {
                                        Retry::Skip => break,
                                        Retry::Abort => return Err(Box::new(err)),
                                        Retry::After(d) => {
                                            sleep(d);
                                            continue;
                                        }
                                    }
                                }
                                break;
                            }// end attempt to save
                            Ok(token)
                        },
                        Err(err) => Err(err),
                    }// end match token retrieve result
                },
                Err(err) => {
                    match self.delegate.token_storage_failure(false, &err) {
                        Retry::Abort|Retry::Skip => Err(Box::new(err)),
                        Retry::After(d) => {
                            sleep(d);
                            continue
                        }
                    }
                },
            }// end match
        }// end loop
    }

    fn api_key(&mut self) -> Option<String> {
        if self.secret.client_id.len() == 0 {
            return None
        }
        Some(self.secret.client_id.clone())
    }
}



/// A partially implemented trait to interact with the `Authenticator`
/// 
/// The only method that needs to be implemented manually is `present_user_code(...)`,
/// as no assumptions are made on how this presentation should happen.
pub trait AuthenticatorDelegate {

    /// Called whenever there is an HttpError, usually if there are network problems.
    /// 
    /// Return retry information.
    fn connection_error(&mut self, &hyper::HttpError) -> Retry {
        Retry::Abort
    }

    /// Called whenever we failed to retrieve a token or set a token due to a storage error.
    /// You may use it to either ignore the incident or retry.
    /// This can be useful if the underlying `TokenStorage` may fail occasionally.
    /// if `is_set` is true, the failure resulted from `TokenStorage.set(...)`. Otherwise, 
    /// it was `TokenStorage.get(...)`
    fn token_storage_failure(&mut self, is_set: bool, _: &Error) -> Retry {
        let _ = is_set;
        Retry::Abort
    }

    /// The server denied the attempt to obtain a request code
    fn request_failure(&mut self, RequestResult) {}

    /// Called if the request code is expired. You will have to start over in this case.
    /// This will be the last call the delegate receives.
    /// Given `DateTime` is the expiration date
    fn expired(&mut self, DateTime<UTC>) {}

    /// Called if the user denied access. You would have to start over. 
    /// This will be the last call the delegate receives.
    fn denied(&mut self) {}

    /// Called if we could not acquire a refresh token for a reason possibly specified 
    /// by the server.
    /// This call is made for the delegate's information only.
    fn token_refresh_failed(&mut self, error: &String, error_description: &Option<String>) {
        { let _ = error; }
        { let _ = error_description; }
    }

    /// Called as long as we are waiting for the user to authorize us.
    /// Can be used to print progress information, or decide to time-out.
    /// 
    /// If the returned `Retry` variant is a duration.
    /// # Notes
    /// * Only used in `DeviceFlow`. Return value will only be used if it
    /// is larger than the interval desired by the server.
    fn pending(&mut self,  &PollInformation) -> Retry {
        Retry::After(Duration::seconds(5))
    }

    /// The server has returned a `user_code` which must be shown to the user,
    /// along with the `verification_url`.
    /// # Notes
    /// * Will be called exactly once, provided we didn't abort during `request_code` phase.
    /// * Will only be called if the Authenticator's flow_type is `FlowType::Device`.
    fn present_user_code(&mut self, pi: PollInformation) {
        println!{"Please enter {} at {} and grant access to this application", 
                  pi.user_code, pi.verification_url}
        println!("Do not close this application until you either denied or granted access.");
        println!("You have time until {}.", pi.expires_at.with_timezone(&Local));
    }
}

/// Uses all default implementations by AuthenticatorDelegate, and makes the trait's
/// implementation usable in the first place.
pub struct DefaultAuthenticatorDelegate;
impl AuthenticatorDelegate for DefaultAuthenticatorDelegate {}

/// A utility type to indicate how operations DeviceFlowHelper operations should be retried
pub enum Retry {
    /// Signal you don't want to retry
    Abort,
    /// Signals you want to retry after the given duration
    After(Duration),
    /// Instruct the caller to attempt to keep going, or choose an alternate path.
    /// If this is not supported, it will have the same effect as `Abort`
    Skip,
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::device::tests::MockGoogleAuth;
    use super::super::common::tests::SECRET;
    use super::super::common::{ConsoleApplicationSecret};
    use std::default::Default;
    use hyper;

    #[test]
    fn flow() {
        use rustc_serialize::json;

        let secret = json::decode::<ConsoleApplicationSecret>(SECRET).unwrap().installed.unwrap();
        let res = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
                        hyper::Client::with_connector(<MockGoogleAuth as Default>::default()),
                        <MemoryStorage as Default>::default(), None)
                        .token(&["https://www.googleapis.com/auth/youtube.upload"]);

        match res {
            Ok(t) => assert_eq!(t.access_token, "1/fFAGRNJru1FTz70BzhT3Zg"),
            _ => panic!("Expected to retrieve token in one go"),
        }
    }
}