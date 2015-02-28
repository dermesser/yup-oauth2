#![feature(old_io, std_misc, core)]
//! This library can be used to acquire oauth2.0 authentication for services.
//! At the time of writing, only one way of doing so is implemented, the [device flow](https://developers.google.com/youtube/v3/guides/authentication#devices), along with a flow 
//! for [refreshing tokens](https://developers.google.com/youtube/v3/guides/authentication#devices)
//! 
//! For your application to use this library, you will have to obtain an application
//! id and secret by [following this guide](https://developers.google.com/youtube/registering_an_application).
//! 
//! # Device Flow Usage
//! As the `DeviceFlow` involves polling, the `DeviceFlowHelper` should be used
//! as means to adhere to the protocol, and remain resilient to all kinds of errors
//! that can occour on the way.
//!
//! The returned `Token` should be stored permanently to authorize future API requests.
//!
//! ```test_harness,no_run
//! extern crate hyper;
//! extern crate "yup-oauth2" as oauth2;
//! use oauth2::{DeviceFlowHelper, DeviceFlowHelperDelegate, PollInformation};
//!
//! # #[test] fn device() {
//! struct PrintHandler;
//! impl DeviceFlowHelperDelegate for PrintHandler {
//!     fn present_user_code(&mut self, pi: PollInformation) {
//!          println!{"Please enter {} at {} and grant access to this application", 
//!                    pi.user_code, pi.verification_url}
//!          println!("Do not close this application until you either denied or granted access");
//!     }
//! }
//! if let Some(t) = DeviceFlowHelper::new(&mut PrintHandler)
//!                  .retrieve_token(hyper::Client::new(),
//!                                  "your_client_id",
//!                                  "your_secret",
//!                                  &["https://www.googleapis.com/auth/youtube.upload"]) {
//!     // now you can use t.access_token to authenticate API calls within your
//!     // given scopes. It will not be valid forever, which is when you have to 
//!     // refresh it using the `RefreshFlow`
//! } else {
//!     println!("user declined");
//! }
//! # }
//! ```
//!
//! # Refresh Flow Usage
//! As the `Token` you retrieved previously will only be valid for a certain time, you will have
//! to use the information from the `Token.refresh_token` field to get a new `access_token`.
//!
//! ```test_harness,no_run
//! extern crate hyper;
//! extern crate "yup-oauth2" as oauth2;
//! use oauth2::{RefreshFlow, FlowType, RefreshResult};
//!
//! # #[test] fn refresh() {
//! let mut f = RefreshFlow::new(hyper::Client::new());
//! let new_token = match *f.refresh_token(FlowType::Device,
//!                                        "my_client_id", "my_secret",
//!                                        "my_refresh_token") {
//!                        RefreshResult::Success(ref t) => t,
//!                        _ => panic!("bad luck ;)")
//!                };
//! # }
//! ```

extern crate chrono;

#[macro_use]
extern crate hyper;
#[macro_use]
extern crate log;
#[cfg(test)] #[macro_use]
extern crate "yup-hyper-mock" as hyper_mock;
extern crate mime;
extern crate url;
extern crate itertools;
extern crate "rustc-serialize" as rustc_serialize;


mod device;
mod refresh;
mod common;
mod helper;

pub use device::{DeviceFlow, PollInformation, PollResult, DeviceFlowHelper, 
                 DeviceFlowHelperDelegate, Retry};
pub use refresh::{RefreshFlow, RefreshResult};
pub use common::{Token, FlowType, ApplicationSecret, ConsoleApplicationSecret};
