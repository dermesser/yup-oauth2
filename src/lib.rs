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
//! #[macro_use]
//! extern crate serde_derive;
//! 
//! extern crate hyper;
//! extern crate yup_oauth2 as oauth2;
//! extern crate serde;
//! extern crate serde_json;
//!
//! use oauth2::{Authenticator, DefaultAuthenticatorDelegate, PollInformation, ConsoleApplicationSecret, MemoryStorage, GetToken};
//! use serde_json as json;
//! use std::default::Default;
//! # const SECRET: &'static str = "{\"installed\":{\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"client_secret\":\"UqkDJd5RFwnHoiG5x5Rub8SI\",\"token_uri\":\"https://accounts.google.com/o/oauth2/token\",\"client_email\":\"\",\"redirect_uris\":[\"urn:ietf:wg:oauth:2.0:oob\",\"oob\"],\"client_x509_cert_url\":\"\",\"client_id\":\"14070749909-vgip2f1okm7bkvajhi9jugan6126io9v.apps.googleusercontent.com\",\"auth_provider_x509_cert_url\":\"https://www.googleapis.com/oauth2/v1/certs\"}}";
//!
//! # #[test] fn device() {
//! let secret = json::from_str::<ConsoleApplicationSecret>(SECRET).unwrap().installed.unwrap();
//! let res = Authenticator::new(&secret, DefaultAuthenticatorDelegate,
//!                         hyper::Client::new(),
//!                         <MemoryStorage as Default>::default(), None)
//!                         .token(&["https://www.googleapis.com/auth/youtube.upload"]);
//! match res {
//!     Ok(t) => {
//!     // now you can use t.access_token to authenticate API calls within your
//!     // given scopes. It will not be valid forever, but Authenticator will automatically
//!     // refresh the token for you.
//!     },
//!     Err(err) => println!("Failed to acquire token: {}", err),
//! }
//! # }
//! ```
//!
#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;

extern crate base64;
extern crate chrono;
extern crate openssl;
extern crate hyper;
#[cfg(test)]
extern crate log;
#[cfg(test)]
extern crate yup_hyper_mock;
extern crate url;
extern crate itertools;

mod authenticator;
mod authenticator_delegate;
mod device;
mod helper;
mod installed;
mod refresh;
mod service_account;
mod storage;
mod types;

pub use device::{GOOGLE_DEVICE_CODE_URL, DeviceFlow};
pub use refresh::{RefreshFlow, RefreshResult};
pub use types::{Token, FlowType, ApplicationSecret, ConsoleApplicationSecret, Scheme, TokenType};
pub use installed::{InstalledFlow, InstalledFlowReturnMethod};
pub use storage::{TokenStorage, NullStorage, MemoryStorage, DiskTokenStorage};
pub use authenticator::{Authenticator, Retry, GetToken};
pub use authenticator_delegate::{AuthenticatorDelegate, DefaultAuthenticatorDelegate, PollError,
                                 PollInformation};
pub use helper::*;
pub use service_account::*;

