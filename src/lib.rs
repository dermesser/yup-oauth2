//! This library can be used to acquire oauth2.0 authentication for services.
//!
//! For your application to use this library, you will have to obtain an application
//! id and secret by
//! [following this guide](https://developers.google.com/youtube/registering_an_application) (for
//! Google services) respectively the documentation of the API provider you want to connect to.
//!
//! # Device Flow Usage
//! As the `DeviceFlow` involves polling, the `DeviceFlowHelper` should be used
//! as means to adhere to the protocol, and remain resilient to all kinds of errors
//! that can occour on the way.
//!
//! # Service account "flow"
//! When using service account credentials, no user interaction is required. The access token
//! can be obtained automatically using the private key of the client (which you can download
//! from the API provider). See `examples/service_account/` for an example on how to use service
//! account credentials. See
//! [developers.google.com](https://developers.google.com/identity/protocols/OAuth2ServiceAccount)
//! for a detailed description of the protocol. This crate implements OAuth for Service Accounts
//! based on the Google APIs; it may or may not work with other providers.
//!
//! # Installed Flow Usage
//! The `InstalledFlow` involves showing a URL to the user (or opening it in a browser)
//! and then either prompting the user to enter a displayed code, or make the authorizing
//! website redirect to a web server spun up by this library and running on localhost.
//!
//! In order to use the interactive method, use the `InstalledInteractive` `FlowType`;
//! for the redirect method, use `InstalledRedirect`, with the port number to let the
//! server listen on.
//!
//! You can implement your own `AuthenticatorDelegate` in order to customize the flow;
//! the `InstalledFlow` uses the `present_user_url` method.
//!
//! The returned `Token` is stored permanently in the given token storage in order to
//! authorize future API requests to the same scopes.
//!
//! ```test_harness,no_run
//! // TODO: Rewrite example here once new authenticator works.
//! ```
//!
#[macro_use]
extern crate serde_derive;

#[cfg(test)]
#[macro_use]
extern crate yup_hyper_mock as hyper_mock;

mod authenticator;
mod authenticator_delegate;
mod device;
mod helper;
mod installed;
mod refresh;
mod service_account;
mod storage;
mod types;

pub use crate::authenticator::Authenticator;
pub use crate::authenticator_delegate::{
    AuthenticatorDelegate, DefaultAuthenticatorDelegate, DefaultFlowDelegate, FlowDelegate,
    PollError, PollInformation,
};
pub use crate::device::{DeviceFlow, GOOGLE_DEVICE_CODE_URL};
pub use crate::helper::*;
pub use crate::installed::{InstalledFlow, InstalledFlowReturnMethod};
pub use crate::refresh::{RefreshFlow, RefreshResult};
pub use crate::service_account::*;
pub use crate::storage::{DiskTokenStorage, MemoryStorage, NullStorage, TokenStorage};
pub use crate::types::{
    ApplicationSecret, ConsoleApplicationSecret, FlowType, GetToken, Scheme, Token, TokenType,
};
