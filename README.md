[![Build Status](https://travis-ci.org/Byron/yup-oauth2.svg)](https://travis-ci.org/Byron/yup-oauth2)

**yup-oauth2** is a utility library which will implement [oauthv2 device authentication](https://developers.google.com/youtube/v3/guides/authentication#devices) suitable for [**yup**](https://github.com/Byron/yup) to work.

It is implemented such that it makes no assumptions about the front-end, allowing more uses than just in yup.

Architecturally, it may never be implementing more than device authentication, yet is set up not to constrain itself.

### Usage

Please have a look at the [API landing page][API-docs] for all the examples you will ever need.

A simple commandline program which authenticates any scope and prints token information can be found in [the examples directory][examples].

The video below shows the *auth* example in action. It's meant to be used as utility to record all server communication and improve protocol compliance.

![usage][auth-usage]


[API-docs]: http://byron.github.io/yup-oauth2
[examples]: https://github.com/Byron/yup-oauth2/tree/master/examples
[auth-usage]: https://raw.githubusercontent.com/Byron/yup-oauth2/master/examples/auth.rs-usage.gif

