// Copyright (c) 2016 Google Inc (lewinb@google.com).
//
// Refer to the project root for licensing information.
//
use crate::authenticator_delegate::{DefaultInstalledFlowDelegate, InstalledFlowDelegate};
use crate::error::Error;
use crate::types::{ApplicationSecret, TokenInfo};

use futures::lock::Mutex;
use http_body_util::BodyExt;
use std::convert::AsRef;
use std::net::SocketAddr;
use std::sync::Arc;

use http::header;
use hyper_util::client::legacy::connect::Connect;
use percent_encoding::{percent_encode, AsciiSet, CONTROLS};
use tokio::sync::oneshot;
use url::form_urlencoded;

const QUERY_SET: AsciiSet = CONTROLS.add(b' ').add(b'"').add(b'#').add(b'<').add(b'>');

const OOB_REDIRECT_URI: &str = "urn:ietf:wg:oauth:2.0:oob";

/// Assembles a URL to request an authorization token (with user interaction).
/// Note that the redirect_uri here has to be either None or some variation of
/// http://localhost:{port}, or the authorization won't work (error "redirect_uri_mismatch")
fn build_authentication_request_url<T>(
    auth_uri: &str,
    client_id: &str,
    scopes: &[T],
    redirect_uri: Option<&str>,
    force_account_selection: bool,
) -> String
where
    T: AsRef<str>,
{
    let mut url = String::new();
    let scopes_string = crate::helper::join(scopes, " ");

    url.push_str(auth_uri);

    if !url.contains('?') {
        url.push('?');
    } else {
        match url.chars().last() {
            Some('?') | None => {}
            Some(_) => url.push('&'),
        }
    }

    let mut params = vec![
        format!("scope={}", scopes_string),
        "&access_type=offline".to_string(),
        format!("&redirect_uri={}", redirect_uri.unwrap_or(OOB_REDIRECT_URI)),
        "&response_type=code".to_string(),
        format!("&client_id={}", client_id),
    ];
    if force_account_selection {
        params.push("&prompt=select_account+consent".to_string());
    }
    params.into_iter().fold(url, |mut u, param| {
        u.push_str(&percent_encode(param.as_ref(), &QUERY_SET).to_string());
        u
    })
}

/// Method by which the user agent return token to this application.
///
/// cf. <https://developers.google.com/identity/protocols/OAuth2InstalledApp#choosingredirecturi>
pub enum InstalledFlowReturnMethod {
    /// Involves showing a URL to the user and asking to copy a code from their browser
    /// (default)
    Interactive,
    /// Involves spinning up a local HTTP server and Google redirecting the browser to
    /// the server with a URL containing the code (preferred, but not as reliable).
    HTTPRedirect,
    /// Identical to [Self::HTTPRedirect], but allows a port to be specified for the
    /// server, instead of choosing a port randomly.
    HTTPPortRedirect(u16),
}

/// InstalledFlowImpl provides tokens for services that follow the "Installed" OAuth flow. (See
/// <https://www.oauth.com/oauth2-servers/authorization/>,
/// <https://developers.google.com/identity/protocols/OAuth2InstalledApp>).
pub struct InstalledFlow {
    pub(crate) app_secret: ApplicationSecret,
    pub(crate) method: InstalledFlowReturnMethod,
    pub(crate) flow_delegate: Box<dyn InstalledFlowDelegate>,
    pub(crate) force_account_selection: bool,
}

impl InstalledFlow {
    /// Create a new InstalledFlow with the provided secret and method.
    ///
    /// In order to specify the redirect URL to use (in the case of `HTTPRedirect` or
    /// `HTTPPortRedirect` as method), either implement the `InstalledFlowDelegate` trait, or
    /// use the `DefaultInstalledFlowDelegateWithRedirectURI`, which presents the URL on stdout.
    /// The redirect URL to use is configured with the OAuth provider, and possible options are
    /// given in the `ApplicationSecret.redirect_uris` field.
    ///
    /// The `InstalledFlowDelegate` implementation should be assigned to the `flow_delegate` field
    /// of the `InstalledFlow` struct.
    pub(crate) fn new(
        app_secret: ApplicationSecret,
        method: InstalledFlowReturnMethod,
    ) -> InstalledFlow {
        InstalledFlow {
            app_secret,
            method,
            flow_delegate: Box::new(DefaultInstalledFlowDelegate),
            force_account_selection: false,
        }
    }

    /// Handles the token request flow; it consists of the following steps:
    /// . Obtain a authorization code with user cooperation or internal redirect.
    /// . Obtain a token and refresh token using that code.
    /// . Return that token
    ///
    /// It's recommended not to use the DefaultInstalledFlowDelegate, but a specialized one.
    pub(crate) async fn token<C, T>(
        &self,
        hyper_client: &hyper_util::client::legacy::Client<C, String>,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        C: Connect + Clone + Send + Sync + 'static,
    {
        match self.method {
            InstalledFlowReturnMethod::HTTPRedirect => {
                self.ask_auth_code_via_http(hyper_client, None, &self.app_secret, scopes)
                    .await
            }
            InstalledFlowReturnMethod::HTTPPortRedirect(port) => {
                self.ask_auth_code_via_http(hyper_client, Some(port), &self.app_secret, scopes)
                    .await
            }
            InstalledFlowReturnMethod::Interactive => {
                self.ask_auth_code_interactively(hyper_client, &self.app_secret, scopes)
                    .await
            }
        }
    }

    async fn ask_auth_code_interactively<C, T>(
        &self,
        hyper_client: &hyper_util::client::legacy::Client<C, String>,
        app_secret: &ApplicationSecret,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        C: Connect + Clone + Send + Sync + 'static,
    {
        let url = build_authentication_request_url(
            &app_secret.auth_uri,
            &app_secret.client_id,
            scopes,
            self.flow_delegate.redirect_uri(),
            self.force_account_selection,
        );
        log::debug!("Presenting auth url to user: {}", url);
        let auth_code = self
            .flow_delegate
            .present_user_url(&url, true /* need code */)
            .await
            .map_err(Error::UserError)?;
        log::debug!("Received auth code: {}", auth_code);
        self.exchange_auth_code(&auth_code, hyper_client, app_secret, None)
            .await
    }

    async fn ask_auth_code_via_http<C, T>(
        &self,
        hyper_client: &hyper_util::client::legacy::Client<C, String>,
        port: Option<u16>,
        app_secret: &ApplicationSecret,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        C: Connect + Clone + Send + Sync + 'static,
    {
        use std::borrow::Cow;
        let server = InstalledFlowServer::run(port)?;
        let server_addr = server.local_addr();

        // Present url to user.
        // The redirect URI must be this very localhost URL, otherwise authorization is refused
        // by certain providers.
        let redirect_uri: Cow<str> = match self.flow_delegate.redirect_uri() {
            Some(uri) => uri.into(),
            None => format!("http://{}", server_addr).into(),
        };
        let url = build_authentication_request_url(
            &app_secret.auth_uri,
            &app_secret.client_id,
            scopes,
            Some(redirect_uri.as_ref()),
            self.force_account_selection,
        );
        log::debug!("Presenting auth url to user: {}", url);
        let _ = self
            .flow_delegate
            .present_user_url(&url, false /* need code */)
            .await;
        let auth_code = server.wait_for_auth_code().await;
        self.exchange_auth_code(&auth_code, hyper_client, app_secret, Some(server_addr))
            .await
    }

    async fn exchange_auth_code<C>(
        &self,
        authcode: &str,
        hyper_client: &hyper_util::client::legacy::Client<C, String>,
        app_secret: &ApplicationSecret,
        server_addr: Option<SocketAddr>,
    ) -> Result<TokenInfo, Error>
    where
        C: Connect + Clone + Send + Sync + 'static,
    {
        let redirect_uri = self.flow_delegate.redirect_uri();
        let request = Self::request_token(app_secret, authcode, redirect_uri, server_addr);
        log::debug!("Sending request: {:?}", request);
        let (head, body) = hyper_client.request(request).await?.into_parts();
        let body = body.collect().await?.to_bytes();
        log::debug!("Received response; head: {:?} body: {:?}", head, body);
        TokenInfo::from_json(&body)
    }

    /// Sends the authorization code to the provider in order to obtain access and refresh tokens.
    fn request_token(
        app_secret: &ApplicationSecret,
        authcode: &str,
        custom_redirect_uri: Option<&str>,
        server_addr: Option<SocketAddr>,
    ) -> http::Request<String> {
        use std::borrow::Cow;
        let redirect_uri: Cow<str> = match (custom_redirect_uri, server_addr) {
            (Some(uri), _) => uri.into(),
            (None, Some(addr)) => format!("http://{}", addr).into(),
            (None, None) => OOB_REDIRECT_URI.into(),
        };

        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(vec![
                ("code", authcode),
                ("client_id", app_secret.client_id.as_str()),
                ("client_secret", app_secret.client_secret.as_str()),
                ("redirect_uri", redirect_uri.as_ref()),
                ("grant_type", "authorization_code"),
            ])
            .finish();

        http::Request::post(&app_secret.token_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .unwrap() // TODO: error check
    }
}

struct InstalledFlowServer {
    addr: SocketAddr,
    auth_code_rx: oneshot::Receiver<String>,
    trigger_shutdown_tx: oneshot::Sender<()>,
    shutdown_complete: tokio::task::JoinHandle<()>,
}

impl InstalledFlowServer {
    fn run(port: Option<u16>) -> Result<Self, Error> {
        let (auth_code_tx, auth_code_rx) = oneshot::channel::<String>();
        let (trigger_shutdown_tx, mut trigger_shutdown_rx) = oneshot::channel::<()>();
        let auth_code_tx = Arc::new(Mutex::new(Some(auth_code_tx)));

        let service = hyper::service::service_fn(move |req| {
            installed_flow_server::handle_req(req, auth_code_tx.clone())
        });

        let addr: std::net::SocketAddr = match port {
            Some(port) => ([127, 0, 0, 1], port).into(),
            None => ([127, 0, 0, 1], 0).into(),
        };

        let server =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .http1_only();
        let graceful = hyper_util::server::graceful::GracefulShutdown::new();

        let std_listener = std::net::TcpListener::bind(addr)?;
        std_listener.set_nonblocking(true)?;
        let addr = std_listener.local_addr()?;
        let tcp_server = tokio::net::TcpListener::from_std(std_listener)?;

        log::debug!("HTTP server listening on {}", addr);

        let shutdown_complete = tokio::spawn(async move {
            loop {
                let conn = tokio::select! {
                    Ok((conn,_)) = tcp_server.accept() => conn,
                    _ = &mut trigger_shutdown_rx => break,
                    else => break,
                };

                let conn = server
                    .serve_connection(hyper_util::rt::TokioIo::new(conn), service.clone())
                    .into_owned();

                let conn = graceful.watch(conn);

                tokio::spawn(async move {
                    if let Err(err) = conn.await {
                        log::debug!("connection error: {err}");
                    }
                });
            }

            tokio::select! {
                _ = graceful.shutdown() => {
                     log::debug!("Gracefully shutdown!");
                },
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                     log::debug!("Waited 10 seconds for graceful shutdown, aborting...");
                }
            }
        });

        Ok(InstalledFlowServer {
            addr,
            auth_code_rx,
            trigger_shutdown_tx,
            shutdown_complete,
        })
    }

    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    async fn wait_for_auth_code(self) -> String {
        log::debug!("Waiting for HTTP server to receive auth code");
        // Wait for the auth code from the server.
        let auth_code = self
            .auth_code_rx
            .await
            .expect("server shutdown while waiting for auth_code");
        log::debug!("HTTP server received auth code: {}", auth_code);
        log::debug!("Shutting down HTTP server");
        // auth code received. shutdown the server
        let _ = self.trigger_shutdown_tx.send(());
        let _ = self.shutdown_complete.await;
        auth_code
    }
}

mod installed_flow_server {
    use futures::lock::Mutex;
    use http::{Request, Response, StatusCode, Uri};
    use std::sync::Arc;
    use tokio::sync::oneshot;
    use url::form_urlencoded;

    pub(super) async fn handle_req<B: hyper::body::Body>(
        req: Request<B>,
        auth_code_tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
    ) -> Result<Response<String>, http::Error> {
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
                    Err(_) => http::Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(String::from("Unparseable URL")),
                    Ok(url) => match auth_code_from_url(url) {
                        Some(auth_code) => {
                            if let Some(sender) = auth_code_tx.lock().await.take() {
                                let _ = sender.send(auth_code);
                            }
                            http::Response::builder()
                                .status(StatusCode::OK)
                                .body(String::from(
                                    "<html><head><title>Success</title></head><body>You may now \
                                     close this window.</body></html>",
                                ))
                        }
                        None => http::Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(String::from("No `code` in URL")),
                    },
                }
            }
            None => http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(String::from("Invalid Request!")),
        }
    }

    fn auth_code_from_url(url: http::Uri) -> Option<String> {
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
    use super::*;
    use http::Uri;

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
                &["email", "profile"],
                None,
                false
            )
        );
    }

    #[test]
    fn test_request_url_builder_appends_queries() {
        assert_eq!(
            "https://accounts.google.\
             com/o/oauth2/auth?unknown=testing&scope=email%20profile&access_type=offline&redirect_uri=urn:ietf:wg:oauth:2.0:\
             oob&response_type=code&client_id=812741506391-h38jh0j4fv0ce1krdkiq0hfvt6n5amr\
             f.apps.googleusercontent.com",
            build_authentication_request_url(
                "https://accounts.google.com/o/oauth2/auth?unknown=testing",
                "812741506391-h38jh0j4fv0ce1krdkiq0hfvt6n5am\
                 rf.apps.googleusercontent.com",
                &["email", "profile"],
                None,
                false
            )
        );
    }

    #[tokio::test]
    async fn test_server_random_local_port() {
        let addr1 = InstalledFlowServer::run(None).unwrap().local_addr();
        let addr2 = InstalledFlowServer::run(None).unwrap().local_addr();
        assert_ne!(addr1.port(), addr2.port());
    }

    #[tokio::test]
    async fn test_http_handle_url() {
        let (tx, rx) = oneshot::channel();
        // URLs are usually a bit botched
        let url: Uri = "http://example.com:1234/?code=ab/c%2Fd#".parse().unwrap();
        let req = http::Request::get(url).body(String::new()).unwrap();
        installed_flow_server::handle_req(req, Arc::new(Mutex::new(Some(tx))))
            .await
            .unwrap();
        assert_eq!(rx.await.unwrap().as_str(), "ab/c/d");
    }

    #[tokio::test]
    async fn test_server() {
        let client: hyper_util::client::legacy::Client<
            hyper_util::client::legacy::connect::HttpConnector,
            String,
        > = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
        let server = InstalledFlowServer::run(None).unwrap();

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
