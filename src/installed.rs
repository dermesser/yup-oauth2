// Copyright (c) 2016 Google Inc (lewinb@google.com).
//
// Refer to the project root for licensing information.
//
use std::convert::AsRef;
use std::sync::{Arc, Mutex};

use futures::prelude::*;
use futures::stream::Stream;
use futures::sync::oneshot;
use hyper;
use hyper::{header, StatusCode, Uri};
use url::form_urlencoded;
use url::percent_encoding::{percent_encode, QUERY_ENCODE_SET};

use crate::authenticator_delegate::FlowDelegate;
use crate::types::{ApplicationSecret, GetToken, RequestError, Token};

const OOB_REDIRECT_URI: &'static str = "urn:ietf:wg:oauth:2.0:oob";

/// Assembles a URL to request an authorization token (with user interaction).
/// Note that the redirect_uri here has to be either None or some variation of
/// http://localhost:{port}, or the authorization won't work (error "redirect_uri_mismatch")
fn build_authentication_request_url<'a, T, I>(
    auth_uri: &str,
    client_id: &str,
    scopes: I,
    redirect_uri: Option<String>,
) -> String
where
    T: AsRef<str> + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut url = String::new();
    let mut scopes_string = scopes.into_iter().fold(String::new(), |mut acc, sc| {
        acc.push_str(sc.as_ref());
        acc.push_str(" ");
        acc
    });
    // Remove last space
    scopes_string.pop();

    url.push_str(auth_uri);
    vec![
        format!("?scope={}", scopes_string),
        format!("&access_type=offline"),
        format!(
            "&redirect_uri={}",
            redirect_uri.unwrap_or(OOB_REDIRECT_URI.to_string())
        ),
        format!("&response_type=code"),
        format!("&client_id={}", client_id),
    ]
    .into_iter()
    .fold(url, |mut u, param| {
        u.push_str(&percent_encode(param.as_ref(), QUERY_ENCODE_SET).to_string());
        u
    })
}

impl<FD: FlowDelegate + 'static + Send + Clone, C: hyper::client::connect::Connect + 'static>
    GetToken for InstalledFlow<FD, C>
{
    fn token<'b, I, T>(
        &mut self,
        scopes: I,
    ) -> Box<dyn Future<Item = Token, Error = RequestError> + Send>
    where
        T: AsRef<str> + Ord + 'b,
        I: Iterator<Item = &'b T>,
    {
        Box::new(self.obtain_token(scopes.into_iter().map(|s| s.as_ref().to_string()).collect()))
    }
    fn api_key(&mut self) -> Option<String> {
        None
    }
    fn application_secret(&self) -> ApplicationSecret {
        self.appsecret.clone()
    }
}

/// InstalledFlow provides tokens for services that follow the "Installed" OAuth flow. (See
/// https://www.oauth.com/oauth2-servers/authorization/,
/// https://developers.google.com/identity/protocols/OAuth2InstalledApp). You should use it wrapped
/// inside an `Authenticator` to benefit from refreshing tokens and caching previously obtained
/// authorization.
pub struct InstalledFlow<FD: FlowDelegate, C: hyper::client::connect::Connect + 'static> {
    method: InstalledFlowReturnMethod,
    client: hyper::client::Client<C, hyper::Body>,
    fd: FD,
    appsecret: ApplicationSecret,
}

/// cf. https://developers.google.com/identity/protocols/OAuth2InstalledApp#choosingredirecturi
pub enum InstalledFlowReturnMethod {
    /// Involves showing a URL to the user and asking to copy a code from their browser
    /// (default)
    Interactive,
    /// Involves spinning up a local HTTP server and Google redirecting the browser to
    /// the server with a URL containing the code (preferred, but not as reliable). The
    /// parameter is the port to listen on.
    HTTPRedirect(u16),
}

impl<'c, FD: 'static + FlowDelegate + Clone + Send, C: 'c + hyper::client::connect::Connect>
    InstalledFlow<FD, C>
{
    /// Starts a new Installed App auth flow.
    /// If HTTPRedirect is chosen as method and the server can't be started, the flow falls
    /// back to Interactive.
    pub fn new(
        client: hyper::client::Client<C, hyper::Body>,
        fd: FD,
        secret: ApplicationSecret,
        method: InstalledFlowReturnMethod,
    ) -> InstalledFlow<FD, C> {
        InstalledFlow {
            method: method,
            fd: fd,
            appsecret: secret,
            client: client,
        }
    }

    /// Handles the token request flow; it consists of the following steps:
    /// . Obtain a authorization code with user cooperation or internal redirect.
    /// . Obtain a token and refresh token using that code.
    /// . Return that token
    ///
    /// It's recommended not to use the DefaultFlowDelegate, but a specialized one.
    pub fn obtain_token<'a>(
        &mut self,
        scopes: Vec<String>, // Note: I haven't found a better way to give a list of strings here, due to ownership issues with futures.
    ) -> impl 'a + Future<Item = Token, Error = RequestError> + Send {
        let rduri = self.fd.redirect_uri();
        // Start server on localhost to accept auth code.
        let server = if let InstalledFlowReturnMethod::HTTPRedirect(port) = self.method {
            match InstalledFlowServer::new(port) {
                Result::Err(e) => Err(RequestError::ClientError(e)),
                Result::Ok(server) => Ok(Some(server)),
            }
        } else {
            Ok(None)
        };
        let port = if let Ok(Some(ref srv)) = server {
            Some(srv.port)
        } else {
            None
        };
        let client = self.client.clone();
        let (appsecclone, appsecclone2) = (self.appsecret.clone(), self.appsecret.clone());
        let auth_delegate = self.fd.clone();
        server
            .into_future()
            // First: Obtain authorization code from user.
            .and_then(move |server| {
                Self::ask_authorization_code(server, auth_delegate, &appsecclone, scopes.iter())
            })
            // Exchange the authorization code provided by Google/the provider for a refresh and an
            // access token.
            .and_then(move |authcode| {
                let request = Self::request_token(appsecclone2, authcode, rduri, port);
                let result = client.request(request);
                // Handle result here, it makes ownership tracking easier.
                result
                    .and_then(move |r| {
                        r.into_body()
                            .concat2()
                            .map(|c| String::from_utf8(c.into_bytes().to_vec()).unwrap()) // TODO: error handling
                    })
                    .then(|body_or| {
                        let resp = match body_or {
                            Err(e) => return Err(RequestError::ClientError(e)),
                            Ok(s) => s,
                        };

                        let token_resp: Result<JSONTokenResponse, serde_json::Error> =
                            serde_json::from_str(&resp);

                        match token_resp {
                            Err(e) => {
                                return Err(RequestError::JSONError(e));
                            }
                            Ok(tok) => {
                                if tok.error.is_some() {
                                    Err(RequestError::NegativeServerResponse(
                                        tok.error.unwrap(),
                                        tok.error_description,
                                    ))
                                } else {
                                    Ok(tok)
                                }
                            }
                        }
                    })
            })
            // Return the combined token.
            .and_then(|tokens| {
                // Successful response
                if tokens.access_token.is_some() {
                    let mut token = Token {
                        access_token: tokens.access_token.unwrap(),
                        refresh_token: tokens.refresh_token.unwrap(),
                        token_type: tokens.token_type.unwrap(),
                        expires_in: tokens.expires_in,
                        expires_in_timestamp: None,
                    };

                    token.set_expiry_absolute();
                    Ok(token)
                } else {
                    Err(RequestError::NegativeServerResponse(
                        tokens.error.unwrap(),
                        tokens.error_description,
                    ))
                }
            })
    }

    fn ask_authorization_code<'a, S, T>(
        server: Option<InstalledFlowServer>,
        mut auth_delegate: FD,
        appsecret: &ApplicationSecret,
        scopes: S,
    ) -> Box<dyn Future<Item = String, Error = RequestError> + Send>
    where
        T: AsRef<str> + 'a,
        S: Iterator<Item = &'a T>,
    {
        if server.is_none() {
            let url = build_authentication_request_url(
                &appsecret.auth_uri,
                &appsecret.client_id,
                scopes,
                auth_delegate.redirect_uri(),
            );
            Box::new(
                auth_delegate
                    .present_user_url(&url, true /* need_code */)
                    .then(|r| {
                        match r {
                            Ok(Some(mut code)) => {
                                // Partial backwards compatibility in case an implementation adds a new line
                                // due to previous behaviour.
                                let ends_with_newline =
                                    code.chars().last().map(|c| c == '\n').unwrap_or(false);
                                if ends_with_newline {
                                    code.pop();
                                }
                                Ok(code)
                            }
                            _ => Err(RequestError::UserError("couldn't read code".to_string())),
                        }
                    }),
            )
        } else {
            let mut server = server.unwrap();
            // The redirect URI must be this very localhost URL, otherwise authorization is refused
            // by certain providers.
            let url = build_authentication_request_url(
                &appsecret.auth_uri,
                &appsecret.client_id,
                scopes,
                auth_delegate
                    .redirect_uri()
                    .or_else(|| Some(format!("http://localhost:{}", server.port))),
            );
            Box::new(
                auth_delegate
                    .present_user_url(&url, false /* need_code */)
                    .then(move |_| server.block_till_auth())
                    .map_err(|e| {
                        RequestError::UserError(format!(
                            "could not obtain token via redirect: {}",
                            e
                        ))
                    }),
            )
        }
    }

    /// Sends the authorization code to the provider in order to obtain access and refresh tokens.
    fn request_token<'a>(
        appsecret: ApplicationSecret,
        authcode: String,
        custom_redirect_uri: Option<String>,
        port: Option<u16>,
    ) -> hyper::Request<hyper::Body> {
        let redirect_uri = custom_redirect_uri.unwrap_or_else(|| match port {
            None => OOB_REDIRECT_URI.to_string(),
            Some(port) => format!("http://localhost:{}", port),
        });

        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(vec![
                ("code".to_string(), authcode.to_string()),
                ("client_id".to_string(), appsecret.client_id.clone()),
                ("client_secret".to_string(), appsecret.client_secret.clone()),
                ("redirect_uri".to_string(), redirect_uri),
                ("grant_type".to_string(), "authorization_code".to_string()),
            ])
            .finish();

        let request = hyper::Request::post(appsecret.token_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(body))
            .unwrap(); // TODO: error check
        request
    }
}

#[derive(Deserialize)]
struct JSONTokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<i64>,

    error: Option<String>,
    error_description: Option<String>,
}

struct InstalledFlowServer {
    port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
    auth_code_rx: Option<oneshot::Receiver<String>>,
    threadpool: Option<tokio_threadpool::ThreadPool>,
}

impl InstalledFlowServer {
    fn new(port: u16) -> Result<InstalledFlowServer, hyper::error::Error> {
        let (auth_code_tx, auth_code_rx) = oneshot::channel::<String>();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let threadpool = tokio_threadpool::Builder::new()
            .pool_size(1)
            .name_prefix("InstalledFlowServer-")
            .build();
        let service_maker = InstalledFlowServiceMaker::new(auth_code_tx);

        let addr = format!("127.0.0.1:{}", port);
        let builder = hyper::server::Server::try_bind(&addr.parse().unwrap())?;
        let server = builder.http1_only(true).serve(service_maker);
        let port = server.local_addr().port();
        let server_future = server
            .with_graceful_shutdown(shutdown_rx)
            .map_err(|err| panic!("Failed badly: {}", err));

        threadpool.spawn(server_future);

        Result::Ok(InstalledFlowServer {
            port: port,
            shutdown_tx: Some(shutdown_tx),
            auth_code_rx: Some(auth_code_rx),
            threadpool: Some(threadpool),
        })
    }

    fn block_till_auth(&mut self) -> Result<String, oneshot::Canceled> {
        match self.auth_code_rx.take() {
            Some(auth_code_rx) => auth_code_rx.wait(),
            None => Result::Err(oneshot::Canceled),
        }
    }
}

impl std::ops::Drop for InstalledFlowServer {
    fn drop(&mut self) {
        self.shutdown_tx.take().map(|tx| tx.send(()));
        self.auth_code_rx.take().map(|mut rx| rx.close());
        self.threadpool.take();
    }
}

pub struct InstalledFlowHandlerResponseFuture {
    inner: Box<
        dyn futures::Future<Item = hyper::Response<hyper::Body>, Error = hyper::http::Error> + Send,
    >,
}

impl InstalledFlowHandlerResponseFuture {
    fn new(
        fut: Box<
            dyn futures::Future<Item = hyper::Response<hyper::Body>, Error = hyper::http::Error>
                + Send,
        >,
    ) -> Self {
        Self { inner: fut }
    }
}

impl futures::Future for InstalledFlowHandlerResponseFuture {
    type Item = hyper::Response<hyper::Body>;
    type Error = hyper::http::Error;

    fn poll(&mut self) -> futures::Poll<Self::Item, Self::Error> {
        self.inner.poll()
    }
}

/// Creates InstalledFlowService on demand
struct InstalledFlowServiceMaker {
    auth_code_tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
}

impl InstalledFlowServiceMaker {
    fn new(auth_code_tx: oneshot::Sender<String>) -> InstalledFlowServiceMaker {
        let auth_code_tx = Arc::new(Mutex::new(Option::Some(auth_code_tx)));
        InstalledFlowServiceMaker { auth_code_tx }
    }
}

impl<Ctx> hyper::service::MakeService<Ctx> for InstalledFlowServiceMaker {
    type ReqBody = hyper::Body;
    type ResBody = hyper::Body;
    type Error = hyper::http::Error;
    type Service = InstalledFlowService;
    type Future = futures::future::FutureResult<Self::Service, Self::Error>;
    type MakeError = hyper::http::Error;

    fn make_service(&mut self, _ctx: Ctx) -> Self::Future {
        let service = InstalledFlowService {
            auth_code_tx: self.auth_code_tx.clone(),
        };
        futures::future::ok(service)
    }
}

/// HTTP service handling the redirect from the provider.
struct InstalledFlowService {
    auth_code_tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
}

impl hyper::service::Service for InstalledFlowService {
    type ReqBody = hyper::Body;
    type ResBody = hyper::Body;
    type Error = hyper::http::Error;
    type Future = InstalledFlowHandlerResponseFuture;

    fn call(&mut self, req: hyper::Request<Self::ReqBody>) -> Self::Future {
        match req.uri().path_and_query() {
            Some(path_and_query) => {
                // We use a fake URL because the redirect goes to a URL, meaning we
                // can't use the url form decode (because there's slashes and hashes and stuff in
                // it).
                let url = Uri::builder()
                    .scheme("http")
                    .authority("example.com")
                    .path_and_query(path_and_query.clone())
                    .build();

                if url.is_err() {
                    let response = hyper::Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(hyper::Body::from("Unparseable URL"));

                    match response {
                        Ok(response) => InstalledFlowHandlerResponseFuture::new(Box::new(
                            futures::future::ok(response),
                        )),
                        Err(err) => InstalledFlowHandlerResponseFuture::new(Box::new(
                            futures::future::err(err),
                        )),
                    }
                } else {
                    self.handle_url(url.unwrap());
                    let response =
                        hyper::Response::builder()
                            .status(StatusCode::OK)
                            .body(hyper::Body::from(
                                "<html><head><title>Success</title></head><body>You may now \
                                 close this window.</body></html>",
                            ));

                    match response {
                        Ok(response) => InstalledFlowHandlerResponseFuture::new(Box::new(
                            futures::future::ok(response),
                        )),
                        Err(err) => InstalledFlowHandlerResponseFuture::new(Box::new(
                            futures::future::err(err),
                        )),
                    }
                }
            }
            None => {
                let response = hyper::Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(hyper::Body::from("Invalid Request!"));

                match response {
                    Ok(response) => InstalledFlowHandlerResponseFuture::new(Box::new(
                        futures::future::ok(response),
                    )),
                    Err(err) => {
                        InstalledFlowHandlerResponseFuture::new(Box::new(futures::future::err(err)))
                    }
                }
            }
        }
    }
}

impl InstalledFlowService {
    fn handle_url(&mut self, url: hyper::Uri) {
        // The provider redirects to the specified localhost URL, appending the authorization
        // code, like this: http://localhost:8080/xyz/?code=4/731fJ3BheyCouCniPufAd280GHNV5Ju35yYcGs
        // We take that code and send it to the ask_authorization_code() function that
        // waits for it.
        for (param, val) in form_urlencoded::parse(url.query().unwrap_or("").as_bytes()) {
            if param == "code".to_string() {
                let mut auth_code_tx = self.auth_code_tx.lock().unwrap();
                match auth_code_tx.take() {
                    Some(auth_code_tx) => {
                        let _ = auth_code_tx.send(val.to_owned().to_string());
                    }
                    None => {
                        // call to the server after a previous call. Each server is only designed
                        // to receive a single request.
                    }
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fmt;
    use std::str::FromStr;

    use hyper;
    use hyper::client::connect::HttpConnector;
    use hyper_tls::HttpsConnector;
    use mockito::{self, mock};
    use tokio;

    use super::*;
    use crate::authenticator_delegate::FlowDelegate;
    use crate::helper::*;
    use crate::types::StringError;

    #[test]
    fn test_end2end() {
        #[derive(Clone)]
        struct FD(
            String,
            hyper::Client<HttpsConnector<HttpConnector>, hyper::Body>,
        );
        impl FlowDelegate for FD {
            /// Depending on need_code, return the pre-set code or send the code to the server at
            /// the redirect_uri given in the url.
            fn present_user_url<S: AsRef<str> + fmt::Display>(
                &mut self,
                url: S,
                need_code: bool,
            ) -> Box<dyn Future<Item = Option<String>, Error = Box<dyn Error + Send>> + Send>
            {
                if need_code {
                    Box::new(Ok(Some(self.0.clone())).into_future())
                } else {
                    // Parse presented url to obtain redirect_uri with location of local
                    // code-accepting server.
                    let uri = Uri::from_str(url.as_ref()).unwrap();
                    let query = uri.query().unwrap();
                    let parsed = form_urlencoded::parse(query.as_bytes()).into_owned();
                    let mut rduri = None;
                    for (k, v) in parsed {
                        if k == "redirect_uri" {
                            rduri = Some(v);
                            break;
                        }
                    }
                    if rduri.is_none() {
                        return Box::new(
                            Err(Box::new(StringError::new("no redirect uri!", None))
                                as Box<dyn Error + Send>)
                            .into_future(),
                        );
                    }
                    let mut rduri = rduri.unwrap();
                    rduri.push_str(&format!("?code={}", self.0));
                    let rduri = Uri::from_str(rduri.as_ref()).unwrap();
                    // Hit server.
                    return Box::new(
                        self.1
                            .get(rduri)
                            .map_err(|e| Box::new(e) as Box<dyn Error + Send>)
                            .map(|_| None),
                    );
                }
            }
        }

        let server_url = mockito::server_url();
        let app_secret = r#"{"installed":{"client_id":"902216714886-k2v9uei3p1dk6h686jbsn9mo96tnbvto.apps.googleusercontent.com","project_id":"yup-test-243420","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"iuMPN6Ne1PD7cos29Tk9rlqH","redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]}}"#;
        let mut app_secret = parse_application_secret(app_secret).unwrap();
        app_secret.token_uri = format!("{}/token", server_url);

        let https = HttpsConnector::new(1).expect("tls");
        let client = hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(https);

        let fd = FD("authorizationcode".to_string(), client.clone());
        let mut inf = InstalledFlow::new(
            client.clone(),
            fd,
            app_secret.clone(),
            InstalledFlowReturnMethod::Interactive,
        );

        let mut rt = tokio::runtime::Builder::new()
            .core_threads(1)
            .panic_handler(|e| std::panic::resume_unwind(e))
            .build()
            .unwrap();

        // Successful path.
        {
            let _m = mock("POST", "/token")
            .match_body(mockito::Matcher::Regex(".*code=authorizationcode.*client_id=9022167.*".to_string()))
            .with_body(r#"{"access_token": "accesstoken", "refresh_token": "refreshtoken", "token_type": "Bearer", "expires_in": 12345678}"#)
            .expect(1)
            .create();

            let fut = inf
                .token(vec!["https://googleapis.com/some/scope"].iter())
                .and_then(|tok| {
                    assert_eq!("accesstoken", tok.access_token);
                    assert_eq!("refreshtoken", tok.refresh_token);
                    assert_eq!("Bearer", tok.token_type);
                    Ok(())
                });
            rt.block_on(fut).expect("block on");
            _m.assert();
        }
        // Successful path with HTTP redirect.
        {
            let mut inf = InstalledFlow::new(
                client.clone(),
                FD(
                    "authorizationcodefromlocalserver".to_string(),
                    client.clone(),
                ),
                app_secret,
                InstalledFlowReturnMethod::HTTPRedirect(8081),
            );
            let _m = mock("POST", "/token")
            .match_body(mockito::Matcher::Regex(".*code=authorizationcodefromlocalserver.*client_id=9022167.*".to_string()))
            .with_body(r#"{"access_token": "accesstoken", "refresh_token": "refreshtoken", "token_type": "Bearer", "expires_in": 12345678}"#)
            .expect(1)
            .create();

            let fut = inf
                .token(vec!["https://googleapis.com/some/scope"].iter())
                .and_then(|tok| {
                    assert_eq!("accesstoken", tok.access_token);
                    assert_eq!("refreshtoken", tok.refresh_token);
                    assert_eq!("Bearer", tok.token_type);
                    Ok(())
                });
            rt.block_on(fut).expect("block on");
            _m.assert();
        }
        // Error from server.
        {
            let _m = mock("POST", "/token")
                .match_body(mockito::Matcher::Regex(
                    ".*code=authorizationcode.*client_id=9022167.*".to_string(),
                ))
                .with_status(400)
                .with_body(r#"{"error": "invalid_code"}"#)
                .expect(1)
                .create();

            let fut = inf
                .token(vec!["https://googleapis.com/some/scope"].iter())
                .then(|tokr| {
                    assert!(tokr.is_err());
                    assert!(format!("{}", tokr.unwrap_err()).contains("invalid_code"));
                    Ok(()) as Result<(), ()>
                });
            rt.block_on(fut).expect("block on");
            _m.assert();
        }
        rt.shutdown_on_idle().wait().expect("shutdown");
    }

    #[test]
    fn test_request_url_builder() {
        assert_eq!(
            "https://accounts.google.\
             com/o/oauth2/auth?scope=email%20profile&access_type=offline&redirect_uri=urn:ietf:wg:oauth:2.0:\
             oob&response_type=code&client_id=812741506391-h38jh0j4fv0ce1krdkiq0hfvt6n5amr\
             f.apps.googleusercontent.com",
            build_authentication_request_url(
                "https://accounts.google.com/o/oauth2/auth",
                "812741506391-h38jh0j4fv0ce1krdkiq0hfvt6n5am\
                 rf.apps.googleusercontent.com",
                vec![&"email".to_string(), &"profile".to_string()],
                None
            )
        );
    }

    #[test]
    fn test_server_random_local_port() {
        let addr1 = InstalledFlowServer::new(0).unwrap();
        let addr2 = InstalledFlowServer::new(0).unwrap();
        assert_ne!(addr1.port, addr2.port);
    }

    #[test]
    fn test_http_handle_url() {
        let (tx, rx) = oneshot::channel();
        let mut handler = InstalledFlowService {
            auth_code_tx: Arc::new(Mutex::new(Option::Some(tx))),
        };
        // URLs are usually a bit botched
        let url: Uri = "http://example.com:1234/?code=ab/c%2Fd#".parse().unwrap();
        handler.handle_url(url);
        assert_eq!(rx.wait().unwrap(), "ab/c/d".to_string());
    }

    #[test]
    fn test_server() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let client: hyper::Client<hyper::client::HttpConnector, hyper::Body> =
            hyper::Client::builder()
                .executor(runtime.executor())
                .build_http();
        let mut server = InstalledFlowServer::new(0).unwrap();

        let response = client
            .get(
                format!("http://127.0.0.1:{}/", server.port)
                    .parse()
                    .unwrap(),
            )
            .wait();
        match response {
            Result::Ok(response) => {
                assert!(response.status().is_success());
            }
            Result::Err(err) => {
                assert!(false, "Failed to request from local server: {:?}", err);
            }
        }

        let response = client
            .get(
                format!("http://127.0.0.1:{}/?code=ab/c%2Fd#", server.port)
                    .parse()
                    .unwrap(),
            )
            .wait();
        match response {
            Result::Ok(response) => {
                assert!(response.status().is_success());
            }
            Result::Err(err) => {
                assert!(false, "Failed to request from local server: {:?}", err);
            }
        }

        match server.block_till_auth() {
            Result::Ok(response) => {
                assert_eq!(response, "ab/c/d".to_string());
            }
            Result::Err(err) => {
                assert!(false, "Server failed to pass on the message: {:?}", err);
            }
        }
    }
}
