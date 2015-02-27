[![Build Status](https://travis-ci.org/Byron/yup-oauth2.svg)](https://travis-ci.org/Byron/yup-oauth2)

**yup-oauth2** is a utility library which will implement [oauthv2 device authentication](https://developers.google.com/youtube/v3/guides/authentication#devices) suitable for [**yup**](https://github.com/Byron/yup) to work.

It is implemented such that it makes no assumptions about the front-end, allowing more uses than just in yup.

Architecturally, it may never be implementing more than device authentication, yet is set up not to constrain itself.