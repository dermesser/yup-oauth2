use std::iter::IntoIterator;
use std::borrow::BorrowMut;
use std::hash::{SipHasher, Hash, Hasher};
use std::thread::sleep;
use std::cmp::min;
use std::error::Error;
use std::fmt;
use std::convert::From;

use authenticator_delegate::{AuthenticatorDelegate, PollError, PollInformation};
use common::{RequestError, Token, FlowType, ApplicationSecret};
use device::DeviceFlow;
use installed::{InstalledFlow, InstalledFlowReturnMethod};
use refresh::{RefreshResult, RefreshFlow};
use storage::TokenStorage;
use std::time::Duration;
use hyper;


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

        StringError { error: error }
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
        where T: AsRef<str> + Ord + 'b,
              I: IntoIterator<Item = &'b T>;

    fn api_key(&mut self) -> Option<String>;
}

impl<D, S, C> Authenticator<D, S, C>
    where D: AuthenticatorDelegate,
          S: TokenStorage,
          C: BorrowMut<hyper::Client>
{
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
               delegate: D,
               client: C,
               storage: S,
               flow_type: Option<FlowType>)
               -> Authenticator<D, S, C> {
        Authenticator {
            flow_type: flow_type.unwrap_or(FlowType::Device),
            delegate: delegate,
            storage: storage,
            client: client,
            secret: secret.clone(),
        }
    }


    fn do_installed_flow(&mut self, scopes: &Vec<&str>) -> Result<Token, Box<Error>> {
        let installed_type;

        match self.flow_type {
            FlowType::InstalledInteractive => {
                installed_type = Some(InstalledFlowReturnMethod::Interactive)
            }
            FlowType::InstalledRedirect(port) => {
                installed_type = Some(InstalledFlowReturnMethod::HTTPRedirect(port))
            }
            _ => installed_type = None,
        }

        let mut flow = InstalledFlow::new(self.client.borrow_mut(), installed_type);
        flow.obtain_token(&mut self.delegate, &self.secret, scopes.iter())
    }

    fn retrieve_device_token(&mut self, scopes: &Vec<&str>) -> Result<Token, Box<Error>> {
        let mut flow = DeviceFlow::new(self.client.borrow_mut());

        // PHASE 1: REQUEST CODE
        let pi: PollInformation;
        loop {
            let res = flow.request_code(&self.secret.client_id,
                                        &self.secret.client_secret,
                                        scopes.iter());

            pi = match res {
                Err(res_err) => {
                    match res_err {
                        RequestError::HttpError(err) => {
                            match self.delegate.connection_error(&err) {
                                Retry::Abort | Retry::Skip => {
                                    return Err(Box::new(StringError::from(&err as &Error)))
                                }
                                Retry::After(d) => sleep(d),
                            }
                        }
                        RequestError::InvalidClient |
                        RequestError::NegativeServerResponse(_, _) |
                        RequestError::InvalidScope(_) => {
                            let serr = StringError::from(res_err.to_string());
                            self.delegate.request_failure(res_err);
                            return Err(Box::new(serr));
                        }
                    };
                    continue;
                }
                Ok(pi) => {
                    self.delegate.present_user_code(&pi);
                    pi
                }
            };
            break;
        }

        // PHASE 1: POLL TOKEN
        loop {
            match flow.poll_token() {
                Err(ref poll_err) => {
                    let pts = poll_err.to_string();
                    match poll_err {
                        &&PollError::HttpError(ref err) => {
                            match self.delegate.connection_error(err) {
                                Retry::Abort | Retry::Skip => {
                                    return Err(Box::new(StringError::from(err as &Error)))
                                }
                                Retry::After(d) => sleep(d),
                            }
                        }
                        &&PollError::Expired(ref t) => {
                            self.delegate.expired(t);
                            return Err(Box::new(StringError::from(pts)));
                        }
                        &&PollError::AccessDenied => {
                            self.delegate.denied();
                            return Err(Box::new(StringError::from(pts)));
                        }
                    }; // end match poll_err
                }
                Ok(None) => {
                    match self.delegate.pending(&pi) {
                        Retry::Abort | Retry::Skip => {
                            return Err(Box::new(StringError::new("Pending authentication aborted"
                                                                     .to_string(),
                                                                 None)))
                        }
                        Retry::After(d) => sleep(min(d, pi.interval)),
                    }
                }
                Ok(Some(token)) => return Ok(token),
            }
        }
    }
}

impl<D, S, C> GetToken for Authenticator<D, S, C>
    where D: AuthenticatorDelegate,
          S: TokenStorage,
          C: BorrowMut<hyper::Client>
{
    /// Blocks until a token was retrieved from storage, from the server, or until the delegate
    /// decided to abort the attempt, or the user decided not to authorize the application.
    /// In any failure case, the delegate will be provided with additional information, and
    /// the caller will be informed about storage related errors.
    /// Otherwise it is guaranteed to be valid for the given scopes.
    fn token<'b, I, T>(&mut self, scopes: I) -> Result<Token, Box<Error>>
        where T: AsRef<str> + Ord + 'b,
              I: IntoIterator<Item = &'b T>
    {
        let (scope_key, scopes) = {
            let mut sv: Vec<&str> = scopes.into_iter()
                .map(|s| s.as_ref())
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
                                                    &t.refresh_token) {
                                RefreshResult::Error(ref err) => {
                                    match self.delegate.connection_error(err) {
                                        Retry::Abort|Retry::Skip =>
                                            return Err(Box::new(StringError::new(
                                                                    err.description().to_string(),
                                                                    None))),
                                        Retry::After(d) => sleep(d),
                                    }
                                }
                                RefreshResult::RefreshError(ref err_str, ref err_description) => {
                                    self.delegate.token_refresh_failed(&err_str, &err_description);
                                    let storage_err = match self.storage
                                        .set(scope_key, &scopes, None) {
                                        Ok(_) => String::new(),
                                        Err(err) => err.to_string(),
                                    };
                                    return Err(Box::new(StringError::new(storage_err + err_str,
                                                                         err_description.as_ref())));
                                }
                                RefreshResult::Success(ref new_t) => {
                                    t = new_t.clone();
                                    loop {
                                        if let Err(err) = self.storage
                                            .set(scope_key, &scopes, Some(t.clone())) {
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
                    match match self.flow_type {
                        FlowType::Device => self.retrieve_device_token(&scopes),
                        FlowType::InstalledInteractive => self.do_installed_flow(&scopes),
                        FlowType::InstalledRedirect(_) => self.do_installed_flow(&scopes),
                    } {
                        Ok(token) => {
                            loop {
                                if let Err(err) = self.storage
                                    .set(scope_key, &scopes, Some(token.clone())) {
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
                        }
                        Err(err) => Err(err),
                    }// end match token retrieve result
                }
                Err(err) => {
                    match self.delegate.token_storage_failure(false, &err) {
                        Retry::Abort | Retry::Skip => Err(Box::new(err)),
                        Retry::After(d) => {
                            sleep(d);
                            continue;
                        }
                    }
                }
            };// end match
        }// end loop
    }

    fn api_key(&mut self) -> Option<String> {
        if self.secret.client_id.len() == 0 {
            return None;
        }
        Some(self.secret.client_id.clone())
    }
}


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
    use super::super::common::ConsoleApplicationSecret;
    use storage::MemoryStorage;
    use std::default::Default;
    use hyper;

    #[test]
    fn flow() {
        use serde_json as json;

        let secret = json::from_str::<ConsoleApplicationSecret>(SECRET).unwrap().installed.unwrap();
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
