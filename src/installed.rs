// Copyright (c) 2016 Google Inc (lewinb@google.com).
//
// Refer to the project root for licensing information.
//
use crate::authenticator_delegate::{DefaultInstalledFlowDelegate, InstalledFlowDelegate};
use crate::error::Error;
use crate::types::{ApplicationSecret, TokenInfo};

use std::convert::AsRef;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures::future::FutureExt;
use futures_util::try_stream::TryStreamExt;
use hyper::header;
use tokio::sync::oneshot;
use url::form_urlencoded;
use url::percent_encoding::{percent_encode, QUERY_ENCODE_SET};

const OOB_REDIRECT_URI: &str = "urn:ietf:wg:oauth:2.0:oob";

/// Assembles a URL to request an authorization token (with user interaction).
/// Note that the redirect_uri here has to be either None or some variation of
/// http://localhost:{port}, or the authorization won't work (error "redirect_uri_mismatch")
fn build_authentication_request_url<T>(
    auth_uri: &str,
    client_id: &str,
    scopes: &[T],
    redirect_uri: Option<&str>,
) -> String
where
    T: AsRef<str>,
{
    let mut url = String::new();
    let scopes_string = crate::helper::join(scopes, " ");

    url.push_str(auth_uri);
    vec![
        format!("?scope={}", scopes_string),
        "&access_type=offline".to_string(),
        format!("&redirect_uri={}", redirect_uri.unwrap_or(OOB_REDIRECT_URI)),
        "&response_type=code".to_string(),
        format!("&client_id={}", client_id),
    ]
    .into_iter()
    .fold(url, |mut u, param| {
        u.push_str(&percent_encode(param.as_ref(), QUERY_ENCODE_SET).to_string());
        u
    })
}

/// cf. https://developers.google.com/identity/protocols/OAuth2InstalledApp#choosingredirecturi
pub enum InstalledFlowReturnMethod {
    /// Involves showing a URL to the user and asking to copy a code from their browser
    /// (default)
    Interactive,
    /// Involves spinning up a local HTTP server and Google redirecting the browser to
    /// the server with a URL containing the code (preferred, but not as reliable).
    HTTPRedirect,
}

/// InstalledFlowImpl provides tokens for services that follow the "Installed" OAuth flow. (See
/// https://www.oauth.com/oauth2-servers/authorization/,
/// https://developers.google.com/identity/protocols/OAuth2InstalledApp).
pub struct InstalledFlow {
    pub(crate) app_secret: ApplicationSecret,
    pub(crate) method: InstalledFlowReturnMethod,
    pub(crate) flow_delegate: Box<dyn InstalledFlowDelegate>,
}

impl InstalledFlow {
    /// Create a new InstalledFlow with the provided secret and method.
    pub(crate) fn new(
        app_secret: ApplicationSecret,
        method: InstalledFlowReturnMethod,
    ) -> InstalledFlow {
        InstalledFlow {
            app_secret,
            method,
            flow_delegate: Box::new(DefaultInstalledFlowDelegate),
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
        hyper_client: &hyper::Client<C>,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        C: hyper::client::connect::Connect + 'static,
    {
        match self.method {
            InstalledFlowReturnMethod::HTTPRedirect => {
                self.ask_auth_code_via_http(hyper_client, &self.app_secret, scopes)
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
        hyper_client: &hyper::Client<C>,
        app_secret: &ApplicationSecret,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        C: hyper::client::connect::Connect + 'static,
    {
        let url = build_authentication_request_url(
            &app_secret.auth_uri,
            &app_secret.client_id,
            scopes,
            self.flow_delegate.redirect_uri(),
        );
        let authcode = self
            .flow_delegate
            .present_user_url(&url, true /* need code */)
            .await
            .map_err(Error::UserError)?;
        self.exchange_auth_code(&authcode, hyper_client, app_secret, None)
            .await
    }

    async fn ask_auth_code_via_http<C, T>(
        &self,
        hyper_client: &hyper::Client<C>,
        app_secret: &ApplicationSecret,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        C: hyper::client::connect::Connect + 'static,
    {
        use std::borrow::Cow;
        let server = InstalledFlowServer::run()?;
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
        );
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
        hyper_client: &hyper::Client<C>,
        app_secret: &ApplicationSecret,
        server_addr: Option<SocketAddr>,
    ) -> Result<TokenInfo, Error>
    where
        C: hyper::client::connect::Connect + 'static,
    {
        let redirect_uri = self.flow_delegate.redirect_uri();
        let request = Self::request_token(app_secret, authcode, redirect_uri, server_addr);
        let resp = hyper_client.request(request).await?;
        let body = resp.into_body().try_concat().await?;
        TokenInfo::from_json(&body)
    }

    /// Sends the authorization code to the provider in order to obtain access and refresh tokens.
    fn request_token(
        app_secret: &ApplicationSecret,
        authcode: &str,
        custom_redirect_uri: Option<&str>,
        server_addr: Option<SocketAddr>,
    ) -> hyper::Request<hyper::Body> {
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

        hyper::Request::post(&app_secret.token_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(body))
            .unwrap() // TODO: error check
    }
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
    fn run() -> Result<Self, Error> {
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
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], 0).into();
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
    use super::*;
    use hyper::Uri;

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
                None
            )
        );
    }

    #[tokio::test]
    async fn test_server_random_local_port() {
        let addr1 = InstalledFlowServer::run().unwrap().local_addr();
        let addr2 = InstalledFlowServer::run().unwrap().local_addr();
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
        let server = InstalledFlowServer::run().unwrap();

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
