// Copyright (c) 2016 Google Inc (lewinb@google.com).
//
// Refer to the project root for licensing information.
//
use std::convert::AsRef;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures::future::FutureExt;
use futures_util::try_stream::TryStreamExt;
use hyper;
use hyper::header;
use tokio::sync::oneshot;
use url::form_urlencoded;
use url::percent_encoding::{percent_encode, QUERY_ENCODE_SET};

use crate::authenticator_delegate::{DefaultFlowDelegate, FlowDelegate};
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

impl<FD, C> GetToken for InstalledFlowImpl<FD, C>
where
    FD: FlowDelegate + 'static,
    C: hyper::client::connect::Connect + 'static,
{
    fn token<'a, T>(
        &'a self,
        scopes: &'a [T],
    ) -> Pin<Box<dyn Future<Output = Result<Token, RequestError>> + Send + 'a>>
    where
        T: AsRef<str> + Sync,
    {
        Box::pin(self.obtain_token(scopes))
    }
    fn api_key(&self) -> Option<String> {
        None
    }
    fn application_secret(&self) -> ApplicationSecret {
        self.appsecret.clone()
    }
}

/// The InstalledFlow implementation.
pub struct InstalledFlowImpl<FD, C>
where
    FD: FlowDelegate + 'static,
    C: hyper::client::connect::Connect + 'static,
{
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
    /// the server with a URL containing the code (preferred, but not as reliable).
    HTTPRedirectEphemeral,
    /// Involves spinning up a local HTTP server and Google redirecting the browser to
    /// the server with a URL containing the code (preferred, but not as reliable). The
    /// parameter is the port to listen on.
    HTTPRedirect(u16),
}

/// InstalledFlowImpl provides tokens for services that follow the "Installed" OAuth flow. (See
/// https://www.oauth.com/oauth2-servers/authorization/,
/// https://developers.google.com/identity/protocols/OAuth2InstalledApp).
pub struct InstalledFlow<FD: FlowDelegate + 'static> {
    method: InstalledFlowReturnMethod,
    flow_delegate: FD,
    appsecret: ApplicationSecret,
}

impl InstalledFlow<DefaultFlowDelegate> {
    /// Create a new InstalledFlow with the provided secret and method.
    pub fn new(
        secret: ApplicationSecret,
        method: InstalledFlowReturnMethod,
    ) -> InstalledFlow<DefaultFlowDelegate> {
        InstalledFlow {
            method,
            flow_delegate: DefaultFlowDelegate,
            appsecret: secret,
        }
    }
}

impl<FD> InstalledFlow<FD>
where
    FD: FlowDelegate,
{
    /// Use the provided FlowDelegate.
    pub fn delegate<NewFD: FlowDelegate>(self, delegate: NewFD) -> InstalledFlow<NewFD> {
        InstalledFlow {
            method: self.method,
            flow_delegate: delegate,
            appsecret: self.appsecret,
        }
    }
}

impl<FD, C> crate::authenticator::AuthFlow<C> for InstalledFlow<FD>
where
    FD: FlowDelegate + 'static,
    C: hyper::client::connect::Connect + 'static,
{
    type TokenGetter = InstalledFlowImpl<FD, C>;

    fn build_token_getter(self, client: hyper::Client<C>) -> Self::TokenGetter {
        InstalledFlowImpl {
            method: self.method,
            fd: self.flow_delegate,
            appsecret: self.appsecret,
            client,
        }
    }
}

impl<FD, C> InstalledFlowImpl<FD, C>
where
    FD: FlowDelegate + 'static,
    C: hyper::client::connect::Connect + 'static,
{
    /// Handles the token request flow; it consists of the following steps:
    /// . Obtain a authorization code with user cooperation or internal redirect.
    /// . Obtain a token and refresh token using that code.
    /// . Return that token
    ///
    /// It's recommended not to use the DefaultFlowDelegate, but a specialized one.
    async fn obtain_token<T>(
        &self,
        scopes: &[T],
    ) -> Result<Token, RequestError>
    where
        T: AsRef<str>,
    {
        match self.method {
            InstalledFlowReturnMethod::HTTPRedirect(port) => {
                self.ask_auth_code_via_http(scopes, port).await
            }
            InstalledFlowReturnMethod::HTTPRedirectEphemeral => {
                self.ask_auth_code_via_http(scopes, 0).await
            }
            InstalledFlowReturnMethod::Interactive => {
                self.ask_auth_code_interactively(scopes).await
            }
        }
    }

    async fn ask_auth_code_interactively<T>(&self, scopes: &[T]) -> Result<Token, RequestError>
    where
        T: AsRef<str>,
    {
        let auth_delegate = &self.fd;
        let appsecret = &self.appsecret;
        let url = build_authentication_request_url(
            &appsecret.auth_uri,
            &appsecret.client_id,
            scopes,
            auth_delegate.redirect_uri(),
        );
        let authcode = match auth_delegate
            .present_user_url(&url, true /* need code */)
            .await
        {
            Ok(mut code) => {
                // Partial backwards compatibility in case an implementation adds a new line
                // due to previous behaviour.
                let ends_with_newline = code.chars().last().map(|c| c == '\n').unwrap_or(false);
                if ends_with_newline {
                    code.pop();
                }
                code
            }
            _ => return Err(RequestError::UserError("couldn't read code".to_string())),
        };
        self.exchange_auth_code(authcode, None).await
    }

    async fn ask_auth_code_via_http<T>(
        &self,
        scopes: &[T],
        desired_port: u16,
    ) -> Result<Token, RequestError>
    where
        T: AsRef<str>,
    {
        let auth_delegate = &self.fd;
        let appsecret = &self.appsecret;
        let server = InstalledFlowServer::run(desired_port)?;
        let bound_port = server.local_addr().port();

        // Present url to user.
        // The redirect URI must be this very localhost URL, otherwise authorization is refused
        // by certain providers.
        let url = build_authentication_request_url(
            &appsecret.auth_uri,
            &appsecret.client_id,
            scopes,
            auth_delegate
                .redirect_uri()
                .or_else(|| Some(format!("http://localhost:{}", bound_port))),
        );
        let _ = auth_delegate
            .present_user_url(&url, false /* need code */)
            .await;

        let auth_code = server.wait_for_auth_code().await;
        self.exchange_auth_code(auth_code, Some(bound_port)).await
    }

    async fn exchange_auth_code(
        &self,
        authcode: String,
        port: Option<u16>,
    ) -> Result<Token, RequestError> {
        let appsec = &self.appsecret;
        let redirect_uri = &self.fd.redirect_uri();
        let request = Self::request_token(appsec.clone(), authcode, redirect_uri.clone(), port);
        let resp = self
            .client
            .request(request)
            .await
            .map_err(|e| RequestError::ClientError(e))?;
        let body = resp
            .into_body()
            .try_concat()
            .await
            .map_err(|e| RequestError::ClientError(e))?;
        let tokens: JSONTokenResponse =
            serde_json::from_slice(&body).map_err(|e| RequestError::JSONError(e))?;
        match tokens {
            JSONTokenResponse {
                error: Some(err),
                error_description,
                ..
            } => Err(RequestError::NegativeServerResponse(err, error_description)),
            JSONTokenResponse {
                access_token: Some(access_token),
                refresh_token,
                token_type: Some(token_type),
                expires_in,
                ..
            } => {
                let mut token = Token {
                    access_token,
                    refresh_token,
                    token_type,
                    expires_in,
                    expires_in_timestamp: None,
                };
                token.set_expiry_absolute();
                Ok(token)
            }
            JSONTokenResponse {
                error_description, ..
            } => Err(RequestError::NegativeServerResponse(
                "".to_owned(),
                error_description,
            )),
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

fn spawn_with_handle<F>(f: F) -> impl Future<Output = ()>
where
    F: Future<Output = ()> + 'static + Send,
{
    let (tx, rx) = oneshot::channel();
    tokio::spawn(f.map(move |_| tx.send(()).unwrap()));
    async {
        let _ = rx.await;
    }
}

struct InstalledFlowServer {
    addr: SocketAddr,
    auth_code_rx: oneshot::Receiver<String>,
    trigger_shutdown_tx: oneshot::Sender<()>,
    shutdown_complete: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl InstalledFlowServer {
    fn run(desired_port: u16) -> Result<Self, RequestError> {
        use hyper::service::{make_service_fn, service_fn};
        let (auth_code_tx, auth_code_rx) = oneshot::channel::<String>();
        let (trigger_shutdown_tx, trigger_shutdown_rx) = oneshot::channel::<()>();
        let auth_code_tx = Arc::new(Mutex::new(Some(auth_code_tx)));

        let service = make_service_fn(move |_| {
            let auth_code_tx = auth_code_tx.clone();
            async move {
                use std::convert::Infallible;
                Ok::<_, Infallible>(service_fn(move |req| {
                    installed_flow_server::handle_req(req, auth_code_tx.clone())
                }))
            }
        });
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], desired_port).into();
        let server = hyper::server::Server::try_bind(&addr)?;
        let server = server.http1_only(true).serve(service);
        let addr = server.local_addr();
        let shutdown_complete = spawn_with_handle(async {
            let _ = server
                .with_graceful_shutdown(async move {
                    let _ = trigger_shutdown_rx.await;
                })
                .await;
        });
        Ok(InstalledFlowServer {
            addr,
            auth_code_rx,
            trigger_shutdown_tx,
            shutdown_complete: Box::pin(shutdown_complete),
        })
    }

    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    async fn wait_for_auth_code(self) -> String {
        // Wait for the auth code from the server.
        let auth_code = self
            .auth_code_rx
            .await
            .expect("server shutdown while waiting for auth_code");
        // auth code received. shutdown the server
        let _ = self.trigger_shutdown_tx.send(());
        self.shutdown_complete.await;
        auth_code
    }
}

mod installed_flow_server {
    use hyper::{Body, Request, Response, StatusCode, Uri};
    use std::sync::{Arc, Mutex};
    use tokio::sync::oneshot;
    use url::form_urlencoded;

    pub(super) async fn handle_req(
        req: Request<Body>,
        auth_code_tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
    ) -> Result<Response<Body>, http::Error> {
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

                match url {
                    Err(_) => hyper::Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(hyper::Body::from("Unparseable URL")),
                    Ok(url) => match auth_code_from_url(url) {
                        Some(auth_code) => {
                            if let Some(sender) = auth_code_tx.lock().unwrap().take() {
                                let _ = sender.send(auth_code);
                            }
                            hyper::Response::builder().status(StatusCode::OK).body(
                                hyper::Body::from(
                                    "<html><head><title>Success</title></head><body>You may now \
                                     close this window.</body></html>",
                                ),
                            )
                        }
                        None => hyper::Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(hyper::Body::from("No `code` in URL")),
                    },
                }
            }
            None => hyper::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(hyper::Body::from("Invalid Request!")),
        }
    }

    fn auth_code_from_url(url: hyper::Uri) -> Option<String> {
        // The provider redirects to the specified localhost URL, appending the authorization
        // code, like this: http://localhost:8080/xyz/?code=4/731fJ3BheyCouCniPufAd280GHNV5Ju35yYcGs
        form_urlencoded::parse(url.query().unwrap_or("").as_bytes()).find_map(|(param, val)| {
            if param == "code" {
                Some(val.into_owned())
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fmt;
    use std::str::FromStr;

    use hyper::Uri;
    use hyper::client::connect::HttpConnector;
    use hyper_rustls::HttpsConnector;
    use mockito::{self, mock};
    use tokio;

    use super::*;
    use crate::authenticator::AuthFlow;
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
            fn present_user_url<'a, S: AsRef<str> + fmt::Display + Send + Sync + 'a>(
                &'a self,
                url: S,
                need_code: bool,
            ) -> Pin<
                Box<dyn Future<Output = Result<String, Box<dyn Error + Send + Sync>>> + Send + 'a>,
            > {
                Box::pin(async move {
                    if need_code {
                        Ok(self.0.clone())
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
                            return Err(Box::new(StringError::new("no redirect uri!", None))
                                as Box<dyn Error + Send + Sync>);
                        }
                        let mut rduri = rduri.unwrap();
                        rduri.push_str(&format!("?code={}", self.0));
                        let rduri = Uri::from_str(rduri.as_ref()).unwrap();
                        // Hit server.
                        self.1
                            .get(rduri)
                            .await
                            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)
                            .map(|_| "".to_string())
                    }
                })
            }
        }

        let server_url = mockito::server_url();
        let app_secret = r#"{"installed":{"client_id":"902216714886-k2v9uei3p1dk6h686jbsn9mo96tnbvto.apps.googleusercontent.com","project_id":"yup-test-243420","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"iuMPN6Ne1PD7cos29Tk9rlqH","redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]}}"#;
        let mut app_secret = parse_application_secret(app_secret).unwrap();
        app_secret.token_uri = format!("{}/token", server_url);

        let https = HttpsConnector::new();
        let client = hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(https);

        let fd = FD("authorizationcode".to_string(), client.clone());
        let inf =
            InstalledFlow::new(app_secret.clone(), InstalledFlowReturnMethod::Interactive)
                .delegate(fd)
                .build_token_getter(client.clone());

        let rt = tokio::runtime::Builder::new()
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

            let fut = || {
                async {
                    let tok = inf
                        .token(&["https://googleapis.com/some/scope"])
                        .await
                        .map_err(|_| ())?;
                    assert_eq!("accesstoken", tok.access_token);
                    assert_eq!("refreshtoken", tok.refresh_token.unwrap());
                    assert_eq!("Bearer", tok.token_type);
                    Ok(()) as Result<(), ()>
                }
            };
            rt.block_on(fut()).expect("block on");
            _m.assert();
        }
        // Successful path with HTTP redirect.
        {
            let inf =
                InstalledFlow::new(app_secret, InstalledFlowReturnMethod::HTTPRedirect(8081))
                    .delegate(FD(
                        "authorizationcodefromlocalserver".to_string(),
                        client.clone(),
                    ))
                    .build_token_getter(client.clone());
            let _m = mock("POST", "/token")
            .match_body(mockito::Matcher::Regex(".*code=authorizationcodefromlocalserver.*client_id=9022167.*".to_string()))
            .with_body(r#"{"access_token": "accesstoken", "refresh_token": "refreshtoken", "token_type": "Bearer", "expires_in": 12345678}"#)
            .expect(1)
            .create();

            let fut = async {
                let tok = inf
                    .token(&["https://googleapis.com/some/scope"])
                    .await
                    .map_err(|_| ())?;
                assert_eq!("accesstoken", tok.access_token);
                assert_eq!("refreshtoken", tok.refresh_token.unwrap());
                assert_eq!("Bearer", tok.token_type);
                Ok(()) as Result<(), ()>
            };
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

            let fut = async {
                let tokr = inf.token(&["https://googleapis.com/some/scope"]).await;
                assert!(tokr.is_err());
                assert!(format!("{}", tokr.unwrap_err()).contains("invalid_code"));
                Ok(()) as Result<(), ()>
            };
            rt.block_on(fut).expect("block on");
            _m.assert();
        }
        rt.shutdown_on_idle();
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

    #[tokio::test]
    async fn test_server_random_local_port() {
        let addr1 = InstalledFlowServer::run(0).unwrap().local_addr();
        let addr2 = InstalledFlowServer::run(0).unwrap().local_addr();
        assert_ne!(addr1.port(), addr2.port());
    }

    #[tokio::test]
    async fn test_http_handle_url() {
        let (tx, rx) = oneshot::channel();
        // URLs are usually a bit botched
        let url: Uri = "http://example.com:1234/?code=ab/c%2Fd#".parse().unwrap();
        let req = hyper::Request::get(url)
            .body(hyper::body::Body::empty())
            .unwrap();
        installed_flow_server::handle_req(req, Arc::new(Mutex::new(Some(tx))))
            .await
            .unwrap();
        assert_eq!(rx.await.unwrap().as_str(), "ab/c/d");
    }

    #[tokio::test]
    async fn test_server() {
        let client: hyper::Client<hyper::client::HttpConnector, hyper::Body> =
            hyper::Client::builder().build_http();
        let server = InstalledFlowServer::run(0).unwrap();

        let response = client
            .get(format!("http://{}/", server.local_addr()).parse().unwrap())
            .await;
        match response {
            Result::Ok(_response) => {
                // TODO: Do we really want this to assert success?
                //assert!(response.status().is_success());
            }
            Result::Err(err) => {
                assert!(false, "Failed to request from local server: {:?}", err);
            }
        }

        let response = client
            .get(
                format!("http://{}/?code=ab/c%2Fd#", server.local_addr())
                    .parse()
                    .unwrap(),
            )
            .await;
        match response {
            Result::Ok(response) => {
                assert!(response.status().is_success());
            }
            Result::Err(err) => {
                assert!(false, "Failed to request from local server: {:?}", err);
            }
        }

        assert_eq!(server.wait_for_auth_code().await.as_str(), "ab/c/d");
    }
}
