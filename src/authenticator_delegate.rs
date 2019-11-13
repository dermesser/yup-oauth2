use hyper;

use std::error::Error;
use std::fmt;
use std::pin::Pin;

use crate::types::{PollError, RequestError};

use chrono::{DateTime, Local, Utc};
use std::time::Duration;

use futures::prelude::*;
use tio::AsyncBufReadExt;
use tokio::io as tio;

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

impl fmt::Display for PollError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            PollError::HttpError(ref err) => err.fmt(f),
            PollError::Expired(ref date) => writeln!(f, "Authentication expired at {}", date),
            PollError::AccessDenied => "Access denied by user".fmt(f),
            PollError::TimedOut => "Timed out waiting for token".fmt(f),
            PollError::Other(ref s) => format!("Unknown server error: {}", s).fmt(f),
        }
    }
}

impl Error for PollError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            PollError::HttpError(ref e) => Some(e),
            _ => None,
        }
    }
}

/// A partially implemented trait to interact with the `Authenticator`
///
/// The only method that needs to be implemented manually is `present_user_code(...)`,
/// as no assumptions are made on how this presentation should happen.
pub trait AuthenticatorDelegate: Send + Sync {
    /// Called whenever there is an client, usually if there are network problems.
    ///
    /// Return retry information.
    fn client_error(&self, _: &hyper::Error) -> Retry {
        Retry::Abort
    }

    /// The server denied the attempt to obtain a request code
    fn request_failure(&self, _: RequestError) {}

    /// Called if we could not acquire a refresh token for a reason possibly specified
    /// by the server.
    /// This call is made for the delegate's information only.
    fn token_refresh_failed(&self, error: &str, error_description: Option<&str>) {
        {
            let _ = error;
        }
        {
            let _ = error_description;
        }
    }
}

/// FlowDelegate methods are called when an OAuth flow needs to ask the application what to do in
/// certain cases.
pub trait FlowDelegate: Send + Sync {
    /// Called if the request code is expired. You will have to start over in this case.
    /// This will be the last call the delegate receives.
    /// Given `DateTime` is the expiration date
    fn expired(&self, _: DateTime<Utc>) {}

    /// Called if the user denied access. You would have to start over.
    /// This will be the last call the delegate receives.
    fn denied(&self) {}

    /// Called as long as we are waiting for the user to authorize us.
    /// Can be used to print progress information, or decide to time-out.
    ///
    /// If the returned `Retry` variant is a duration.
    /// # Notes
    /// * Only used in `DeviceFlow`. Return value will only be used if it
    /// is larger than the interval desired by the server.
    fn pending(&self, _: &PollInformation) -> Retry {
        Retry::After(Duration::from_secs(5))
    }

    /// Configure a custom redirect uri if needed.
    fn redirect_uri(&self) -> Option<&str> {
        None
    }
    /// The server has returned a `user_code` which must be shown to the user,
    /// along with the `verification_url`.
    /// # Notes
    /// * Will be called exactly once, provided we didn't abort during `request_code` phase.
    /// * Will only be called if the Authenticator's flow_type is `DeviceFlow`.
    fn present_user_code(&self, pi: &PollInformation) {
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
    fn present_user_url<'a>(
        &'a self,
        url: &'a str,
        need_code: bool,
    ) -> Pin<Box<dyn Future<Output = Result<String, Box<dyn Error + Send + Sync>>> + Send + 'a>>
    {
        Box::pin(present_user_url(url, need_code))
    }
}

async fn present_user_url(
    url: &str,
    need_code: bool,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    if need_code {
        println!(
            "Please direct your browser to {}, follow the instructions and enter the \
             code displayed here: ",
            url
        );
        let mut user_input = String::new();
        match tio::BufReader::new(tio::stdin())
            .read_line(&mut user_input)
            .await
        {
            Err(err) => {
                println!("{:?}", err);
                Err(Box::new(err) as Box<dyn Error + Send + Sync>)
            }
            Ok(_) => Ok(user_input),
        }
    } else {
        println!(
            "Please direct your browser to {} and follow the instructions displayed \
             there.",
            url
        );
        Ok(String::new())
    }
}

/// Uses all default implementations by AuthenticatorDelegate, and makes the trait's
/// implementation usable in the first place.
#[derive(Clone)]
pub struct DefaultAuthenticatorDelegate;
impl AuthenticatorDelegate for DefaultAuthenticatorDelegate {}

/// Uses all default implementations in the FlowDelegate trait.
#[derive(Clone)]
pub struct DefaultFlowDelegate;
impl FlowDelegate for DefaultFlowDelegate {}
