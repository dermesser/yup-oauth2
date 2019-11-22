//! Module containing types related to delegates.

use std::pin::Pin;
use std::time::Duration;

use chrono::{DateTime, Local, Utc};
use futures::prelude::*;

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

/// DeviceFlowDelegate methods are called when a device flow needs to ask the
/// application what to do in certain cases.
pub trait DeviceFlowDelegate: Send + Sync {
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

/// Uses all default implementations in the DeviceFlowDelegate trait.
#[derive(Copy, Clone)]
pub struct DefaultDeviceFlowDelegate;
impl DeviceFlowDelegate for DefaultDeviceFlowDelegate {}

/// Uses all default implementations in the DeviceFlowDelegate trait.
#[derive(Copy, Clone)]
pub struct DefaultInstalledFlowDelegate;
impl InstalledFlowDelegate for DefaultInstalledFlowDelegate {}
