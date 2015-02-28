use std::iter::IntoIterator;
use std::borrow::{Borrow, BorrowMut};
use std::marker::PhantomData;
use std::collections::HashMap;
use std::hash::{SipHasher, Hash, Hasher};
use std::old_io::timer::sleep;
use std::cmp::min;

use common::{Token, FlowType, ApplicationSecret};
use device::{PollInformation, RequestResult, DeviceFlow, PollResult};
use refresh::{RefreshResult, RefreshFlow};
use chrono::{DateTime, UTC, Duration};
use hyper;


/// Implements a specialised storage to set and retrieve `Token` instances.
/// The `scope_hash` represents the signature of the scopes for which the given token
/// should be stored or retrieved.
pub trait TokenStorage {
    /// If `token` is None, it is invalid or revoked and should be removed from storage.
    fn set(&mut self, scope_hash: u64, token: Option<Token>);
    /// A `None` result indicates that there is no token for the given scope_hash.
    fn get(&self, scope_hash: u64) -> Option<Token>;
}

/// A storage that remembers nothing.
#[derive(Default)]
pub struct NullStorage;

impl TokenStorage for NullStorage {
    fn set(&mut self, _: u64, _: Option<Token>) {}
    fn get(&self, _: u64) -> Option<Token> { None }
}

/// A storage that remembers values for one session only.
#[derive(Default)]
pub struct MemoryStorage {
    pub tokens: HashMap<u64, Token>
}

impl TokenStorage for MemoryStorage {
    fn set(&mut self, scope_hash: u64, token: Option<Token>) {
        match token {
            Some(t) => self.tokens.insert(scope_hash, t),
            None => self.tokens.remove(&scope_hash),
        };
    }

    fn get(&self, scope_hash: u64) -> Option<Token> {
        match self.tokens.get(&scope_hash) {
            Some(t) => Some(t.clone()),
            None => None,
        }
    }
}

/// A generalized authenticator which will keep tokens valid and store them. 
///
/// It is the go-to helper to deal with any kind of supported authentication flow,
/// which will be kept valid and usable.
pub struct Authenticator<D, S, C, NC> {
    flow_type: FlowType,
    delegate: D,
    storage: S,
    client: C,
    secret: ApplicationSecret,

    _m: PhantomData<NC>
}

impl<D, S, C, NC> Authenticator<D, S, C, NC>
    where  D: AuthenticatorDelegate,
           S: TokenStorage,
          NC: hyper::net::NetworkConnector,
           C: BorrowMut<hyper::Client<NC>> {

    
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
                                                     -> Authenticator<D, S, C, NC> {
        Authenticator {
            flow_type: flow_type.unwrap_or(FlowType::Device),
            delegate: delegate,
            storage: storage,
            client: client,
            secret: secret.clone(),
            _m: PhantomData
        }
    }

    /// Blocks until a token was retrieved from storage, from the server, or until the delegate 
    /// decided to abort the attempt, or the user decided not to authorize the application.
    /// In any failure case, the returned token will be None, otherwise it is guaranteed to be 
    /// valid for the given scopes.
    pub fn token<'b, I, T>(&mut self, scopes: I) -> Option<Token>
        where   T: Str + Ord,
                I: IntoIterator<Item=&'b T> {
        let (scope_key, scope, scopes) = {
            let mut sv: Vec<&str> = scopes.into_iter()
                                  .map(|s|s.as_slice())
                                  .collect::<Vec<&str>>();
            sv.sort();
            let s = sv.connect(" ");

            let mut sh = SipHasher::new();
            s.hash(&mut sh);
            let sv = sv;
            (sh.finish(), s, sv)
        };

        // Get cached token. Yes, let's do an explicit return
        return match self.storage.get(scope_key) {
            Some(mut t) => {
                // t needs refresh ?
                if t.expired() {
                    let mut rf = RefreshFlow::new(self.client.borrow_mut());
                    loop {
                        match *rf.refresh_token(self.flow_type,
                                               &self.secret.client_id, 
                                               &self.secret.client_secret, 
                                               &t.refresh_token) {
                            RefreshResult::Error(ref err) => {
                                match self.delegate.connection_error(err.clone()) {
                                    Retry::Abort => return None,
                                    Retry::After(d) => sleep(d),
                                }
                            },
                            RefreshResult::Refused(_) => {
                                self.delegate.denied();
                                return None
                            },
                            RefreshResult::Success(ref new_t) => {
                                t = new_t.clone();
                                self.storage.set(scope_key, Some(t.clone()));
                            }
                        }// RefreshResult handling
                    }// refresh loop
                }// handle expiration
                Some(t)
            }
            None => {
                // get new token. The respective sub-routine will do all the logic.
                let ot = match self.flow_type {
                    FlowType::Device => self.retrieve_device_token(&scopes),
                };
                // store it, no matter what. If tokens have become invalid, it's ok
                // to indicate that to the storage.
                self.storage.set(scope_key, ot.clone());
                ot
            },
        }
    }

    fn retrieve_device_token(&mut self, scopes: &Vec<&str>) -> Option<Token> {
        let mut flow = DeviceFlow::new(self.client.borrow_mut());

        // PHASE 1: REQUEST CODE
        loop {
            let res = flow.request_code(&self.secret.client_id, 
                                        &self.secret.client_secret, scopes.iter());
            match res {
                RequestResult::Error(err) => {
                    match self.delegate.connection_error(err) {
                        Retry::Abort => return None,
                        Retry::After(d) => sleep(d),
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
                        Retry::After(d) => sleep(d),
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
                        Retry::After(d) => sleep(min(d, pi.interval)),
                    }
                },
                PollResult::AccessGranted(token) => {
                    return Some(token)
                },
            }
        }
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
    fn connection_error(&mut self, hyper::HttpError) -> Retry {
        Retry::Abort
    }

    /// The server denied the attempt to obtain a request code
    fn request_failure(&mut self, RequestResult) {}

    /// Called if the request code is expired. You will have to start over in this case.
    /// This will be the last call the delegate receives.
    fn expired(&mut self, DateTime<UTC>) {}

    /// Called if the user denied access. You would have to start over. 
    /// This will be the last call the delegate receives.
    fn denied(&mut self) {}

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
    fn present_user_code(&mut self, PollInformation);
}

/// A utility type to indicate how operations DeviceFlowHelper operations should be retried
pub enum Retry {
    /// Signal you don't want to retry
    Abort,
    /// Signals you want to retry after the given duration
    After(Duration)
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::device::tests::MockGoogleAuth;
    use super::super::common::tests::SECRET;
    use super::super::common::{ConsoleApplicationSecret, Token};
    use super::super::device::PollInformation;
    use std::default::Default;
    use hyper;

    #[test]
    fn flow() {
        use rustc_serialize::json;

        struct TestHandler;
        impl AuthenticatorDelegate for TestHandler {
            fn present_user_code(&mut self, pi: PollInformation) {
                println!("{:?}", pi);
            }
        }
        let secret = json::decode::<ConsoleApplicationSecret>(SECRET).unwrap().installed.unwrap();
        let res = Authenticator::new(&secret, TestHandler,
                        hyper::Client::with_connector(<MockGoogleAuth as Default>::default()),
                        <MemoryStorage as Default>::default(), None)
                        .token(&["https://www.googleapis.com/auth/youtube.upload"]);

        match res {
            Some(t) => assert_eq!(t.access_token, "1/fFAGRNJru1FTz70BzhT3Zg"),
            _ => panic!("Expected to retrieve token in one go"),
        }
    }
}