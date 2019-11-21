//! Module containing types related to delegates.

use crate::error::RefreshError;

use std::fmt;
use std::pin::Pin;
use std::time::Duration;

use chrono::{DateTime, Local, Utc};
use futures::prelude::*;

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

/// A partially implemented trait to interact with the `Authenticator`
///
/// The only method that needs to be implemented manually is `present_user_code(...)`,
/// as no assumptions are made on how this presentation should happen.
pub trait AuthenticatorDelegate: Send + Sync {
    /// Called if we could not acquire a refresh token for a reason possibly specified
    /// by the server.
    /// This call is made for the delegate's information only.
    fn token_refresh_failed(&self, _: &RefreshError) {}
}

/// DeviceFlowDelegate methods are called when a device flow needs to ask the
/// application what to do in certain cases.
pub trait DeviceFlowDelegate: Send + Sync {
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
    fn pending(&self, _: &PollInformation) -> Retry {
        Retry::After(Duration::from_secs(5))
    }

    /// The server has returned a `user_code` which must be shown to the user,
    /// along with the `verification_url`.
    /// # Notes
    /// * Will be called exactly once, provided we didn't abort during `request_code` phase.
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
}

/// InstalledFlowDelegate methods are called when an installed flow needs to ask
/// the application what to do in certain cases.
pub trait InstalledFlowDelegate: Send + Sync {
    /// Configure a custom redirect uri if needed.
    fn redirect_uri(&self) -> Option<&str> {
        None
    }

    /// We need the user to navigate to a URL using their browser and potentially paste back a code
    /// (or maybe not). Whether they have to enter a code depends on the InstalledFlowReturnMethod
    /// used.
    fn present_user_url<'a>(
        &'a self,
        url: &'a str,
        need_code: bool,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(present_user_url(url, need_code))
    }
}

async fn present_user_url(url: &str, need_code: bool) -> Result<String, String> {
    use tokio::io::AsyncBufReadExt;
    if need_code {
        println!(
            "Please direct your browser to {}, follow the instructions and enter the \
             code displayed here: ",
            url
        );
        let mut user_input = String::new();
        tokio::io::BufReader::new(tokio::io::stdin())
            .read_line(&mut user_input)
            .await
            .map_err(|e| format!("couldn't read code: {}", e))?;
        // remove trailing whitespace.
        user_input.truncate(user_input.trim_end().len());
        Ok(user_input)
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
#[derive(Copy, Clone)]
pub struct DefaultAuthenticatorDelegate;
impl AuthenticatorDelegate for DefaultAuthenticatorDelegate {}

/// Uses all default implementations in the DeviceFlowDelegate trait.
#[derive(Copy, Clone)]
pub struct DefaultDeviceFlowDelegate;
impl DeviceFlowDelegate for DefaultDeviceFlowDelegate {}

/// Uses all default implementations in the DeviceFlowDelegate trait.
#[derive(Copy, Clone)]
pub struct DefaultInstalledFlowDelegate;
impl InstalledFlowDelegate for DefaultInstalledFlowDelegate {}
