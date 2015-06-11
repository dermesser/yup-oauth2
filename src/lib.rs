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
//! #![feature(custom_derive, plugin)]
//! #![plugin(serde_macros)]
//! extern crate hyper;
//! extern crate yup_oauth2 as oauth2;
//! extern crate serde;
//! 
//! use oauth2::{Authenticator, DefaultAuthenticatorDelegate, PollInformation, ConsoleApplicationSecret, MemoryStorage, GetToken};
//! use serde::json;
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
//!     // given scopes. It will not be valid forever, which is when you have to 
//!     // refresh it using the `RefreshFlow`
//!     },
//!     Err(err) => println!("Failed to acquire token: {}", err),
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
//! extern crate yup_oauth2 as oauth2;
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
#![cfg_attr(feature = "nightly", feature(custom_derive))]

#[cfg(feature = "nightly")]
include!("lib.rs.in");

#[cfg(feature = "with_syntex")]
include!(concat!(env!("OUT_DIR"), "/lib.rs"));