// Copyright (c) 2016 Google Inc (lewinb@google.com).
//
// Refer to the project root for licensing information.
//
extern crate serde_json;
extern crate url;

use std::borrow::BorrowMut;
use std::convert::AsRef;
use std::error::Error;
use std::io;
use std::io::Read;
use std::sync::Mutex;
use std::sync::mpsc::{channel, Receiver, Sender};

use hyper;
use hyper::{client, header, server, status, uri};
use serde_json::error;
use url::form_urlencoded;
use url::percent_encoding::{percent_encode, QUERY_ENCODE_SET};

use crate::types::{ApplicationSecret, Token};
use crate::authenticator_delegate::AuthenticatorDelegate;

const OOB_REDIRECT_URI: &'static str = "urn:ietf:wg:oauth:2.0:oob";

/// Assembles a URL to request an authorization token (with user interaction).
/// Note that the redirect_uri here has to be either None or some variation of
/// http://localhost:{port}, or the authorization won't work (error "redirect_uri_mismatch")
fn build_authentication_request_url<'a, T, I>(auth_uri: &str,
                                              client_id: &str,
                                              scopes: I,
                                              redirect_uri: Option<String>)
                                              -> String
    where T: AsRef<str> + 'a,
          I: IntoIterator<Item = &'a T>
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
    vec![format!("?scope={}", scopes_string),
         format!("&redirect_uri={}",
                 redirect_uri.unwrap_or(OOB_REDIRECT_URI.to_string())),
         format!("&response_type=code"),
         format!("&client_id={}", client_id)]
        .into_iter()
        .fold(url, |mut u, param| {
            u.push_str(&percent_encode(param.as_ref(), QUERY_ENCODE_SET).to_string());
            u
        })
}

pub struct InstalledFlow<C> {
    client: C,
    server: Option<server::Listening>,
    port: Option<u32>,

    auth_code_rcv: Option<Receiver<String>>,
}

/// cf. https://developers.google.com/identity/protocols/OAuth2InstalledApp#choosingredirecturi
pub enum InstalledFlowReturnMethod {
    /// Involves showing a URL to the user and asking to copy a code from their browser
    /// (default)
    Interactive,
    /// Involves spinning up a local HTTP server and Google redirecting the browser to
    /// the server with a URL containing the code (preferred, but not as reliable). The
    /// parameter is the port to listen on.
    HTTPRedirect(u32),
}

impl<C> InstalledFlow<C>
    where C: BorrowMut<hyper::Client>
{
    /// Starts a new Installed App auth flow.
    /// If HTTPRedirect is chosen as method and the server can't be started, the flow falls
    /// back to Interactive.
    pub fn new(client: C, method: Option<InstalledFlowReturnMethod>) -> InstalledFlow<C> {
        let default = InstalledFlow {
            client: client,
            server: None,
            port: None,
            auth_code_rcv: None,
        };
        match method {
            None => default,
            Some(InstalledFlowReturnMethod::Interactive) => default,
            // Start server on localhost to accept auth code.
            Some(InstalledFlowReturnMethod::HTTPRedirect(port)) => {
                let server = server::Server::http(format!("127.0.0.1:{}", port).as_str());

                match server {
                    Result::Err(_) => default,
                    Result::Ok(server) => {
                        let (tx, rx) = channel();
                        let listening =
                            server.handle(InstalledFlowHandler { auth_code_snd: Mutex::new(tx) });

                        match listening {
                            Result::Err(_) => default,
                            Result::Ok(listening) => {
                                InstalledFlow {
                                    client: default.client,
                                    server: Some(listening),
                                    port: Some(port),
                                    auth_code_rcv: Some(rx),
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Handles the token request flow; it consists of the following steps:
    /// . Obtain a auhorization code with user cooperation or internal redirect.
    /// . Obtain a token and refresh token using that code.
    /// . Return that token
    ///
    /// It's recommended not to use the DefaultAuthenticatorDelegate, but a specialized one.
    pub fn obtain_token<'a, AD: AuthenticatorDelegate, S, T>(&mut self,
                                                             auth_delegate: &mut AD,
                                                             appsecret: &ApplicationSecret,
                                                             scopes: S)
                                                             -> Result<Token, Box<Error>>
        where T: AsRef<str> + 'a,
              S: Iterator<Item = &'a T>
    {
        let authcode = self.get_authorization_code(auth_delegate, &appsecret, scopes)?;
        let tokens = self.request_token(&appsecret, &authcode)?;

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
            Result::Ok(token)
        } else {
            let err = io::Error::new(io::ErrorKind::Other,
                                     format!("Token API error: {} {}",
                                             tokens.error.unwrap_or("<unknown err>".to_string()),
                                             tokens.error_description
                                                 .unwrap_or("".to_string()))
                                         .as_str());
            Result::Err(Box::new(err))
        }
    }

    /// Obtains an authorization code either interactively or via HTTP redirect (see
    /// InstalledFlowReturnMethod).
    fn get_authorization_code<'a, AD: AuthenticatorDelegate, S, T>(&mut self,
                                                                   auth_delegate: &mut AD,
                                                                   appsecret: &ApplicationSecret,
                                                                   scopes: S)
                                                                   -> Result<String, Box<Error>>
        where T: AsRef<str> + 'a,
              S: Iterator<Item = &'a T>
    {
        let result: Result<String, Box<Error>> = match self.server {
            None => {
                let url = build_authentication_request_url(&appsecret.auth_uri,
                                                           &appsecret.client_id,
                                                           scopes,
                                                           None);
                match auth_delegate.present_user_url(&url, true /* need_code */) {
                    None => {
                        Result::Err(Box::new(io::Error::new(io::ErrorKind::UnexpectedEof,
                                                            "couldn't read code")))
                    }
                    Some(mut code) => {
                        // Partial backwards compatibilty in case an implementation adds a new line
                        // due to previous behaviour.
                        let ends_with_newline =
                            code.chars().last().map(|c| c == '\n').unwrap_or(false);
                        if ends_with_newline {
                            code.pop();
                        }
                        Result::Ok(code)
                    }
                }
            }
            Some(_) => {
                // The redirect URI must be this very localhost URL, otherwise Google refuses
                // authorization.
                let url = build_authentication_request_url(&appsecret.auth_uri,
                                                           &appsecret.client_id,
                                                           scopes,
                                                           Some(format!("http://localhost:{}",
                                                                        self.port
                                                                            .unwrap_or(8080))));
                auth_delegate.present_user_url(&url, false /* need_code */);

                match self.auth_code_rcv.as_ref().unwrap().recv() {
                    Result::Err(e) => Result::Err(Box::new(e)),
                    Result::Ok(s) => Result::Ok(s),
                }
            }
        };
        self.server.as_mut().map(|l| l.close()).is_some();
        result
    }

    /// Sends the authorization code to the provider in order to obtain access and refresh tokens.
    fn request_token(&mut self,
                     appsecret: &ApplicationSecret,
                     authcode: &str)
                     -> Result<JSONTokenResponse, Box<Error>> {
        let redirect_uri;

        match self.port {
            None => redirect_uri = OOB_REDIRECT_URI.to_string(),
            Some(p) => redirect_uri = format!("http://localhost:{}", p),
        }

        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(vec![("code".to_string(), authcode.to_string()),
                               ("client_id".to_string(), appsecret.client_id.clone()),
                               ("client_secret".to_string(), appsecret.client_secret.clone()),
                               ("redirect_uri".to_string(), redirect_uri),
                               ("grant_type".to_string(), "authorization_code".to_string())])
            .finish();

        let result: Result<client::Response, hyper::Error> = self.client
            .borrow_mut()
            .post(&appsecret.token_uri)
            .body(&body)
            .header(header::ContentType("application/x-www-form-urlencoded".parse().unwrap()))
            .send();

        let mut resp = String::new();

        match result {
            Result::Err(e) => return Result::Err(Box::new(e)),
            Result::Ok(mut response) => {
                let result = response.read_to_string(&mut resp);

                match result {
                    Result::Err(e) => return Result::Err(Box::new(e)),
                    Result::Ok(_) => (),
                }
            }
        }

        let token_resp: Result<JSONTokenResponse, error::Error> = serde_json::from_str(&resp);

        match token_resp {
            Result::Err(e) => return Result::Err(Box::new(e)),
            Result::Ok(tok) => Result::Ok(tok) as Result<JSONTokenResponse, Box<Error>>,
        }
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

/// HTTP handler handling the redirect from the provider.
struct InstalledFlowHandler {
    auth_code_snd: Mutex<Sender<String>>,
}

impl server::Handler for InstalledFlowHandler {
    fn handle(&self, rq: server::Request, mut rp: server::Response) {
        match rq.uri {
            uri::RequestUri::AbsolutePath(path) => {
                // We use a fake URL because the redirect goes to a URL, meaning we
                // can't use the url form decode (because there's slashes and hashes and stuff in
                // it).
                let url = hyper::Url::parse(&format!("http://example.com{}", path));

                if url.is_err() {
                    *rp.status_mut() = status::StatusCode::BadRequest;
                    let _ = rp.send("Unparseable URL".as_ref());
                } else {
                    self.handle_url(url.unwrap());
                    *rp.status_mut() = status::StatusCode::Ok;
                    let _ =
                        rp.send("<html><head><title>Success</title></head><body>You may now \
                                 close this window.</body></html>"
                            .as_ref());
                }
            }
            _ => {
                *rp.status_mut() = status::StatusCode::BadRequest;
                let _ = rp.send("Invalid Request!".as_ref());
            }
        }
    }
}

impl InstalledFlowHandler {
    fn handle_url(&self, url: hyper::Url) {
        // Google redirects to the specified localhost URL, appending the authorization
        // code, like this: http://localhost:8080/xyz/?code=4/731fJ3BheyCouCniPufAd280GHNV5Ju35yYcGs
        // We take that code and send it to the get_authorization_code() function that
        // waits for it.
        for (param, val) in url.query_pairs().into_owned() {
            if param == "code".to_string() {
                let _ = self.auth_code_snd.lock().unwrap().send(val);
            }
        }

    }
}

#[cfg(test)]
mod tests {
    use super::build_authentication_request_url;
    use super::InstalledFlowHandler;

    use std::sync::Mutex;
    use std::sync::mpsc::channel;

    use hyper::Url;

    #[test]
    fn test_request_url_builder() {
        assert_eq!("https://accounts.google.\
                    com/o/oauth2/auth?scope=email%20profile&redirect_uri=urn:ietf:wg:oauth:2.0:\
                    oob&response_type=code&client_id=812741506391-h38jh0j4fv0ce1krdkiq0hfvt6n5amr\
                    f.apps.googleusercontent.com",
                   build_authentication_request_url("https://accounts.google.com/o/oauth2/auth",
                                                    "812741506391-h38jh0j4fv0ce1krdkiq0hfvt6n5am\
                                                     rf.apps.googleusercontent.com",
                                                    vec![&"email".to_string(),
                                                         &"profile".to_string()],
                                                    None));
    }

    #[test]
    fn test_http_handle_url() {
        let (tx, rx) = channel();
        let handler = InstalledFlowHandler { auth_code_snd: Mutex::new(tx) };
        // URLs are usually a bit botched
        let url = Url::parse("http://example.com:1234/?code=ab/c%2Fd#").unwrap();
        handler.handle_url(url);
        assert_eq!(rx.recv().unwrap(), "ab/c/d".to_string());
    }
}
