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
//! The following example, which is derived from the (actual and runnable) example in
//! `examples/test-installed/`, shows the basics of using this crate:
//!
//! ```test_harness,no_run
//! use futures::prelude::*;
//! use yup_oauth2::GetToken;
//! use yup_oauth2::{Authenticator, InstalledFlow};
//!
//! use hyper::client::Client;
//! use hyper_tls::HttpsConnector;
//!
//! use std::path::Path;
//!
//! fn main() {
//!     // Boilerplate: Set up hyper HTTP client and TLS.
//!     let https = HttpsConnector::new(1).expect("tls");
//!     let client = Client::builder()
//!         .keep_alive(false)
//!         .build::<_, hyper::Body>(https);
//!
//!     // Read application secret from a file. Sometimes it's easier to compile it directly into
//!     // the binary. The clientsecret file contains JSON like `{"installed":{"client_id": ... }}`
//!     let secret = yup_oauth2::read_application_secret(Path::new("clientsecret.json"))
//!         .expect("clientsecret.json");
//!
//!     // There are two types of delegates; FlowDelegate and AuthenticatorDelegate. See the
//!     // respective documentation; all you need to know here is that they determine how the user
//!     // is asked to visit the OAuth flow URL or how to read back the provided code.
//!     let ad = yup_oauth2::DefaultFlowDelegate;
//!
//!     // InstalledFlow handles OAuth flows of that type. They are usually the ones where a user
//!     // grants access to their personal account (think Google Drive, Github API, etc.).
//!     let inf = InstalledFlow::new(
//!         client.clone(),
//!         ad,
//!         secret,
//!         yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect(8081),
//!     );
//!     // You could already use InstalledFlow by itself, but usually you want to cache tokens and
//!     // refresh them, rather than ask the user every time to log in again. Authenticator wraps
//!     // other flows and handles these.
//!     // This type of authenticator caches tokens in a JSON file on disk.
//!     let mut auth = Authenticator::new_disk(
//!         client,
//!         inf,
//!         yup_oauth2::DefaultAuthenticatorDelegate,
//!         "tokencache.json",
//!     )
//!     .unwrap();
//!     let s = "https://www.googleapis.com/auth/drive.file".to_string();
//!     let scopes = vec![s];
//!
//!     // token(<scopes>) is the one important function of this crate; it does everything to
//!     // obtain a token that can be sent e.g. as Bearer token.
//!     let tok = auth.token(scopes.iter());
//!     // Finally we print the token.
//!     let fut = tok.map_err(|e| println!("error: {:?}", e)).and_then(|t| {
//!         println!("The token is {:?}", t);
//!         Ok(())
//!     });
//!
//!     tokio::run(fut)
//! }
//! ```
//!
#[macro_use]
extern crate serde_derive;

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
    PollInformation,
};
pub use crate::device::{DeviceFlow, GOOGLE_DEVICE_CODE_URL};
pub use crate::helper::*;
pub use crate::installed::{InstalledFlow, InstalledFlowReturnMethod};
pub use crate::service_account::*;
pub use crate::storage::{DiskTokenStorage, MemoryStorage, NullStorage, TokenStorage};
pub use crate::types::{
    ApplicationSecret, ConsoleApplicationSecret, FlowType, GetToken, PollError, RefreshResult,
    RequestError, Scheme, Token, TokenType,
};
