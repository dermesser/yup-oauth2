[![Build
Status](https://travis-ci.org/dermesser/yup-oauth2.svg)](https://travis-ci.org/dermesser/yup-oauth2)
[![Coverage
Status](https://coveralls.io/repos/github/dermesser/yup-oauth2/badge.svg?branch=master)](https://coveralls.io/github/dermesser/yup-oauth2?branch=master)
[![crates.io](https://img.shields.io/crates/v/yup-oauth2.svg)](https://crates.io/crates/yup-oauth2)

**yup-oauth2** is a utility library which implements several OAuth 2.0 flows. It's mainly used by
[google-apis-rs](https://github.com/Byron/google-apis-rs), to authenticate against Google services.
(However, you're able to use it with raw HTTP requests as well; the flows are implemented as token
sources yielding HTTP Bearer tokens).

### Supported authorization types

* Device flow (user enters code on authorization page)
* Installed application flow (user visits URL, copies code to application, application uses
  code to obtain token). Used for services like GMail, Drive, ...
* Service account flow: Non-interactive for server-to-server communication based on public key
  cryptography. Used for services like Cloud Pubsub, Cloud Storage, ...

### Usage

Please have a look at the [API landing page][API-docs] for all the examples you will ever need.

A simple commandline program which authenticates any scope and prints token information can be found
in [the examples directory][examples].

The video below shows the *auth* example in action. It's meant to be used as utility to record all
server communication and improve protocol compliance.

![usage][auth-usage]

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
         http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.


[API-docs]: https://docs.rs/yup-oauth2/
[examples]: https://github.com/dermesser/yup-oauth2/tree/master/examples
[auth-usage]: https://raw.githubusercontent.com/dermesser/yup-oauth2/master/examples/auth.rs-usage.gif

