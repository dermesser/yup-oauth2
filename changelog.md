<a name="v0.5.4"></a>
### v0.5.4 (2016-02-07)


#### Bug Fixes

* **secret:**  allow project_id field ([c039db56](https://github.com/Byron/yup-oauth2/commit/c039db56cdda527e51e83e3f65033b94aca11a68))

#### Improvements

* **duration:**  use std::time::Duration everywhere ([c18ae07b](https://github.com/Byron/yup-oauth2/commit/c18ae07bbb6855230ba64806967456ee681e8f4a))



<a name="v0.5.2"></a>
## v0.5.2 (2015-08-08)


#### Bug Fixes

* **tests**  assure tests actually work ([ad0bde30](https://github.com/Byron/yup-oauth2/commit/ad0bde3092499e26c819a871065f70d0d8519e0b))



<a name="v0.5.1"></a>
## v0.5.1 (2015-08-08)

* compatibility with serde 0.5.x

<a name="v0.5.0"></a>
## v0.5.0 (2015-06-18)

This release essentially make yup-oauth2 work on rustc *stable*.

#### Features

* **syntex**  basic infrastructure ([9b2f9e77](https://github.com/Byron/yup-oauth2/commit/9b2f9e77be8189e6cc9ef196f49e764011ca9519))

#### Bug Fixes

* **lib**
  *  remove macro usage to work on stable ([6a5915d7](https://github.com/Byron/yup-oauth2/commit/6a5915d7d64820ecaf6aed30c92f2f7fbe28d72f))
  *  setup nightly crate meta data correctly ([a260b138](https://github.com/Byron/yup-oauth2/commit/a260b13868aaf667ef5379e4223ec0c94b78e26b))
* **syntex**  cleanup, build works on stable ([0901497d](https://github.com/Byron/yup-oauth2/commit/0901497d8984ac5cd02aa1a0c21d463dce9a1edf))



<a name="v0.4.5"></a>
## v0.4.5 (2015-05-11)


#### Bug Fixes

* **rustup**  workaround rustlang bug ([47b68cf4](https://github.com/Byron/yup-oauth2/commit/47b68cf4010974b1ea834b292d9b9101d15a6c46))


<a name="v0.4.4"></a>
## v0.4.4 (2015-05-08)


#### Features

* **testing**  use travis-cargo ([dd711b6e](https://github.com/Byron/yup-oauth2/commit/dd711b6e8065bb699aa244cd6a51f21bdb4e05e9))

#### Bug Fixes

* **hyper**  update to hyper v0.4.0 ([7383f5ef](https://github.com/Byron/yup-oauth2/commit/7383f5efb60fabdb797a71cc5288068b3095c294))



<a name="v0.4.3"></a>
## v0.4.3 (2015-05-02)


#### Bug Fixes

* **JsonError**  make `error` field non-optional ([a395fe89](https://github.com/Byron/yup-oauth2/commit/a395fe892c9893360305f93de60b61cbc64162f9), closes [#6](https://github.com/Byron/yup-oauth2/issues/6))



<a name="v0.4.2"></a>
## v0.4.2 (2015-05-02)


#### Bug Fixes

* **json**  assure we understand json errors ([b08b239e](https://github.com/Byron/yup-oauth2/commit/b08b239e88815f83034eadd751d64b25d9650798))



<a name="v0.4.1"></a>
## v0.4.1 (2015-05-02)


#### Bug Fixes

* **TokenStorage**  `set()` returns `Result<(), _>` ([f95bb816](https://github.com/Byron/yup-oauth2/commit/f95bb816f7346ae5d1b04e946f09da372e9c0a37), closes [#5](https://github.com/Byron/yup-oauth2/issues/5))



<a name="v0.4.0"></a>
## v0.4.0 (2015-05-02)


#### Features

* **serde**  use serde instead of rustc_serialize ([e05e5553](https://github.com/Byron/yup-oauth2/commit/e05e5553e3bbfb0b8bebf3da785f4d1a16e353f3), closes [#2](https://github.com/Byron/yup-oauth2/issues/2))



<a name="v0.3.10"></a>
## v0.3.10 (2015-05-02)


#### Bug Fixes

* **rustup**  1.1.0-nightly (97d4e76c2 2015-04-27) ([3ca51ccf](https://github.com/Byron/yup-oauth2/commit/3ca51ccfe2c410349002279ddd925edf245da1e6))



<a name="v0.3.9"></a>
## v0.3.9 (2015-05-02)


#### Bug Fixes

* **rustup**  replace sleep with sleep_ms ([727c1d80](https://github.com/Byron/yup-oauth2/commit/727c1d801b4ae8f7b7cb80050139926bbcb9bf48))



<a name="v0.3.8"></a>
## v0.3.8 (2015-05-02)


#### Bug Fixes

* **common**  remove obsolete marker trait ([2a1247ba](https://github.com/Byron/yup-oauth2/commit/2a1247bae0b7a5fd0195b8dca8cda2a2cf1b2132))



<a name="v0.3.7"></a>
## v0.3.7 (2015-05-02)


#### Bug Fixes

* **helper**  unset stored token on refresh failure ([690bcdb6](https://github.com/Byron/yup-oauth2/commit/690bcdb627ed8dc9e033bc8823997fcfb69ccd89))



<a name="v0.3.6"></a>
## v0.3.6 (2015-05-02)


#### Bug Fixes

* **refresh**  use correct URL for refresh flow ([1ce4147d](https://github.com/Byron/yup-oauth2/commit/1ce4147d545a3a22d60180e9ae0473c8d039784d))



<a name="v0.3.5"></a>
## v0.3.5 (2015-05-02)


#### Bug Fixes

* **rustup**  (abf0548b5 2015-04-15) (built 2015-04-15) ([84454d17](https://github.com/Byron/yup-oauth2/commit/84454d1736fb3a4b5448a678b3fb26495bd64a69))
* **API**
  *  review Result types and adapt code ([2481c75c](https://github.com/Byron/yup-oauth2/commit/2481c75c3148e262419a969feb49aa0a8141f836), closes [#4](https://github.com/Byron/yup-oauth2/issues/4))
  *  overall improved error handling ([2cdf8bbf](https://github.com/Byron/yup-oauth2/commit/2cdf8bbf76976c47b9052d2e675aa0ced16f726b))



<a name="v0.3.3"></a>
## v0.3.3 (2015-05-02)


#### Bug Fixes

* **version-up**  v0.3.3 ([0222a19e](https://github.com/Byron/yup-oauth2/commit/0222a19e9df3fa7b90ee429b02a053cc2210d9ea), closes [#3](https://github.com/Byron/yup-oauth2/issues/3))



<a name="v0.3.2"></a>
## v0.3.2 (2015-05-02)


#### Bug Fixes

* **update-dependencies**  rustup + dep-up ([2489b813](https://github.com/Byron/yup-oauth2/commit/2489b81383dae08b9ddf5809286ceee08d091fcc))
* **common**
  *  Default trait for ApplicationSecret ([445675db](https://github.com/Byron/yup-oauth2/commit/445675db7f3b34f01a794732a9f254889d1f16b6))
  *  AuthenticationType implements Str ([aa030e89](https://github.com/Byron/yup-oauth2/commit/aa030e8987760720f3d616cb0dad18c531bc7a45))
* **example-auth**  convert UTC to local time ([b23bb245](https://github.com/Byron/yup-oauth2/commit/b23bb2459b282ebc0cc4b9667a576d9a427710d5))
* **device**  DeviceFlowHelper fails by default ... ([646a94ac](https://github.com/Byron/yup-oauth2/commit/646a94ac11c06d456cf05ae80954e6ca7e3bc47a))
* **cargo**
  *  version bump ([fda2d62f](https://github.com/Byron/yup-oauth2/commit/fda2d62fa221cd0b8150af41a09706f6e78f9cfb))
  *  added keywords ([aef1a4a2](https://github.com/Byron/yup-oauth2/commit/aef1a4a28cdae083c3098dd8f7973fec0b7b3de8))
  *  fix repo link and description ([20a7fd83](https://github.com/Byron/yup-oauth2/commit/20a7fd83dc2f482508d3764dacdb4981e03a44d9))
  *  yup-hyper-mock pulled from crates ([2b269e08](https://github.com/Byron/yup-oauth2/commit/2b269e084d2016d93f07e48f8b31e73677492ef7))
* **rustup**
  *  update to latest rustc ([3d1678da](https://github.com/Byron/yup-oauth2/commit/3d1678daead26705b876ec7f1ad7305479c0225c))
  *  switch to using io where possible ([437a6095](https://github.com/Byron/yup-oauth2/commit/437a60959b15aae657ad9285fa5ab33580ccd221))
* **refresh**  BorrowMut for & and owned Client ([88d4bf8c](https://github.com/Byron/yup-oauth2/commit/88d4bf8c28ea10db0730e072986303f71bdbfed3))

#### Features

* **header**  Authorization Scheme for Oauth ([feba2d0e](https://github.com/Byron/yup-oauth2/commit/feba2d0e5afe01171bb6ba1289dcf68644c00354))
* **auth**
  *  Authenticator support GetToken trait ([fb0c3ff5](https://github.com/Byron/yup-oauth2/commit/fb0c3ff506a70431112c46f4c4d79f6a9559dd58))
  *  open verification url automatically ([515e128c](https://github.com/Byron/yup-oauth2/commit/515e128cac42569b5009108fa0eb008b412631ca))
* **common**
  *  Token type serialization support ([1f655b4e](https://github.com/Byron/yup-oauth2/commit/1f655b4eff499457d4ee9554aaa3b0eb99465b42))
  *  ConsoleApplicationSecret ([aedc9b66](https://github.com/Byron/yup-oauth2/commit/aedc9b6696c2880808705eb0cb130137ccdaf481))
* **refresh**  &mut Client instead of Client ([4486bd59](https://github.com/Byron/yup-oauth2/commit/4486bd595fc4a3e6fecafbc5323fc0d6398a9ff9))
* **api_key**  GetToken.api_key() ([0710d310](https://github.com/Byron/yup-oauth2/commit/0710d310f821662ea8cdf449d192e671ecfa9f69))
* **helper**  full implementation of Authenticator ([c227c161](https://github.com/Byron/yup-oauth2/commit/c227c161fd7233d236c1ee5e700dd56298922f08))
* **util**  new MemoryStorage and NullStorage ([091f1c07](https://github.com/Byron/yup-oauth2/commit/091f1c07592808656735cb8800f0a809329e58d9))
* **device**  BorrowMut for client ([3f965c8f](https://github.com/Byron/yup-oauth2/commit/3f965c8fea1f341809be97364cbaa570b986f2c4))



