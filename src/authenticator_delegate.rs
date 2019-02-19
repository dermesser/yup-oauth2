use hyper;

use std::error::Error;
use std::fmt;
use std::io;

use crate::authenticator::Retry;
use crate::types::RequestError;

use chrono::{DateTime, Local, Utc};
use std::time::Duration;

/// Contains state of pending authentication requests
#[derive(Clone, Debug, PartialEq)]
pub struct PollInformation {
    /// Code the user must enter ...
    pub user_code: String,
    /// ... at the verification URL
    pub verification_url: String,

    /// The `user_code` expires at the given time
    /// It's the time the user has left to authenticate your application
    pub expires_at: DateTime<Utc>,
    /// The interval in which we may poll for a status change
    /// The server responds with errors of we poll too fast.
    pub interval: Duration,
}

impl fmt::Display for PollInformation {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "Proceed with polling until {}", self.expires_at)
    }
}

/// Encapsulates all possible results of a `poll_token(...)` operation
#[derive(Debug)]
pub enum PollError {
    /// Connection failure - retry if you think it's worth it
    HttpError(hyper::Error),
    /// indicates we are expired, including the expiration date
    Expired(DateTime<Utc>),
    /// Indicates that the user declined access. String is server response
    AccessDenied,
}

impl fmt::Display for PollError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            PollError::HttpError(ref err) => err.fmt(f),
            PollError::Expired(ref date) => writeln!(f, "Authentication expired at {}", date),
            PollError::AccessDenied => "Access denied by user".fmt(f),
        }
    }
}

/// A partially implemented trait to interact with the `Authenticator`
///
/// The only method that needs to be implemented manually is `present_user_code(...)`,
/// as no assumptions are made on how this presentation should happen.
pub trait AuthenticatorDelegate {
    /// Called whenever there is an client, usually if there are network problems.
    ///
    /// Return retry information.
    fn client_error(&mut self, _: &hyper::Error) -> Retry {
        Retry::Abort
    }

    /// Called whenever there is an HttpError, usually if there are network problems.
    ///
    /// Return retry information.
    fn connection_error(&mut self, _: &hyper::http::Error) -> Retry {
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
    fn request_failure(&mut self, _: RequestError) {}

    /// Called if the request code is expired. You will have to start over in this case.
    /// This will be the last call the delegate receives.
    /// Given `DateTime` is the expiration date
    fn expired(&mut self, _: &DateTime<Utc>) {}

    /// Called if the user denied access. You would have to start over.
    /// This will be the last call the delegate receives.
    fn denied(&mut self) {}

    /// Called if we could not acquire a refresh token for a reason possibly specified
    /// by the server.
    /// This call is made for the delegate's information only.
    fn token_refresh_failed(&mut self, error: &String, error_description: &Option<String>) {
        {
            let _ = error;
        }
        {
            let _ = error_description;
        }
    }

    /// Called as long as we are waiting for the user to authorize us.
    /// Can be used to print progress information, or decide to time-out.
    ///
    /// If the returned `Retry` variant is a duration.
    /// # Notes
    /// * Only used in `DeviceFlow`. Return value will only be used if it
    /// is larger than the interval desired by the server.
    fn pending(&mut self, _: &PollInformation) -> Retry {
        Retry::After(Duration::from_secs(5))
    }

    /// Configure a custom redirect uri if needed.
    fn redirect_uri(&self) -> Option<String> {
        None
    }

    /// The server has returned a `user_code` which must be shown to the user,
    /// along with the `verification_url`.
    /// # Notes
    /// * Will be called exactly once, provided we didn't abort during `request_code` phase.
    /// * Will only be called if the Authenticator's flow_type is `FlowType::Device`.
    fn present_user_code(&mut self, pi: &PollInformation) {
        println!(
            "Please enter {} at {} and grant access to this application",
            pi.user_code, pi.verification_url
        );
        println!("Do not close this application until you either denied or granted access.");
        println!(
            "You have time until {}.",
            pi.expires_at.with_timezone(&Local)
        );
    }

    /// This method is used by the InstalledFlow.
    /// We need the user to navigate to a URL using their browser and potentially paste back a code
    /// (or maybe not). Whether they have to enter a code depends on the InstalledFlowReturnMethod
    /// used.
    fn present_user_url(&mut self, url: &String, need_code: bool) -> Option<String> {
        if need_code {
            println!(
                "Please direct your browser to {}, follow the instructions and enter the \
                 code displayed here: ",
                url
            );

            let mut code = String::new();
            io::stdin().read_line(&mut code).ok().map(|_| {
                // Remove newline
                code.pop();
                code
            })
        } else {
            println!(
                "Please direct your browser to {} and follow the instructions displayed \
                 there.",
                url
            );
            None
        }
    }
}

/// Uses all default implementations by AuthenticatorDelegate, and makes the trait's
/// implementation usable in the first place.
pub struct DefaultAuthenticatorDelegate;
impl AuthenticatorDelegate for DefaultAuthenticatorDelegate {}
