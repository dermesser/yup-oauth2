//! This module provides a token source (`GetToken`) that obtains tokens for service accounts.
//! Service accounts are usually used by software (i.e., non-human actors) to get access to
//! resources. Currently, this module only works with RS256 JWTs, which makes it at least suitable for
//! authentication with Google services.
//!
//! Resources:
//! - [Using OAuth 2.0 for Server to Server
//! Applications](https://developers.google.com/identity/protocols/OAuth2ServiceAccount)
//! - [JSON Web Tokens](https://jwt.io/)
//!
//! Copyright (c) 2016 Google Inc (lewinb@google.com).
//!

use std::default::Default;
use std::error;
use std::sync::{Arc, Mutex};

use crate::storage::{hash_scopes, MemoryStorage, TokenStorage};
use crate::types::{GetToken, StringError, Token};

use futures::stream::Stream;
use futures::{future, prelude::*};
use hyper::header;
use url::form_urlencoded;

use rustls::{
    self,
    internal::pemfile,
    sign::{self, SigningKey},
    PrivateKey,
};
use std::io;

use base64;
use chrono;
use hyper;
use serde_json;

const GRANT_TYPE: &'static str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const GOOGLE_RS256_HEAD: &'static str = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";

/// Encodes s as Base64
fn encode_base64<T: AsRef<[u8]>>(s: T) -> String {
    base64::encode_config(s.as_ref(), base64::URL_SAFE)
}

/// Decode a PKCS8 formatted RSA key.
fn decode_rsa_key(pem_pkcs8: &str) -> Result<PrivateKey, Box<dyn error::Error + Send>> {
    let private = pem_pkcs8.to_string().replace("\\n", "\n").into_bytes();
    let mut private_reader: &[u8] = private.as_ref();
    let private_keys = pemfile::pkcs8_private_keys(&mut private_reader);

    if let Ok(pk) = private_keys {
        if pk.len() > 0 {
            Ok(pk[0].clone())
        } else {
            Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Not enough private keys in PEM",
            )))
        }
    } else {
        Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Error reading key from PEM",
        )))
    }
}

/// JSON schema of secret service account key. You can obtain the key from
/// the Cloud Console at https://console.cloud.google.com/.
///
/// You can use `helpers::service_account_key_from_file()` as a quick way to read a JSON client
/// secret into a ServiceAccountKey.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServiceAccountKey {
    #[serde(rename = "type")]
    pub key_type: Option<String>,
    pub project_id: Option<String>,
    pub private_key_id: Option<String>,
    pub private_key: Option<String>,
    pub client_email: Option<String>,
    pub client_id: Option<String>,
    pub auth_uri: Option<String>,
    pub token_uri: Option<String>,
    pub auth_provider_x509_cert_url: Option<String>,
    pub client_x509_cert_url: Option<String>,
}

/// Permissions requested for a JWT.
/// See https://developers.google.com/identity/protocols/OAuth2ServiceAccount#authorizingrequests.
#[derive(Serialize, Debug)]
struct Claims {
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    sub: Option<String>,
    scope: String,
}

/// A JSON Web Token ready for signing.
struct JWT {
    /// The value of GOOGLE_RS256_HEAD.
    header: String,
    /// A Claims struct, expressing the set of desired permissions etc.
    claims: Claims,
}

impl JWT {
    /// Create a new JWT from claims.
    fn new(claims: Claims) -> JWT {
        JWT {
            header: GOOGLE_RS256_HEAD.to_string(),
            claims: claims,
        }
    }

    /// Encodes the first two parts (header and claims) to base64 and assembles them into a form
    /// ready to be signed.
    fn encode_claims(&self) -> String {
        let mut head = encode_base64(&self.header);
        let claims = encode_base64(serde_json::to_string(&self.claims).unwrap());

        head.push_str(".");
        head.push_str(&claims);
        head
    }

    /// Sign a JWT base string with `private_key`, which is a PKCS8 string.
    fn sign(&self, private_key: &str) -> Result<String, Box<dyn error::Error + Send>> {
        let mut jwt_head = self.encode_claims();
        let key = decode_rsa_key(private_key)?;
        let signing_key = sign::RSASigningKey::new(&key).map_err(|_| {
            Box::new(io::Error::new(
                io::ErrorKind::Other,
                "Couldn't initialize signer",
            )) as Box<dyn error::Error + Send>
        })?;
        let signer = signing_key
            .choose_scheme(&[rustls::SignatureScheme::RSA_PKCS1_SHA256])
            .ok_or(Box::new(io::Error::new(
                io::ErrorKind::Other,
                "Couldn't choose signing scheme",
            )) as Box<dyn error::Error + Send>)?;
        let signature = signer
            .sign(jwt_head.as_bytes())
            .map_err(|e| Box::new(e) as Box<dyn error::Error + Send>)?;
        let signature_b64 = encode_base64(signature);

        jwt_head.push_str(".");
        jwt_head.push_str(&signature_b64);

        Ok(jwt_head)
    }
}

/// Set `iss`, `aud`, `exp`, `iat`, `scope` field in the returned `Claims`. `scopes` is an iterator
/// yielding strings with OAuth scopes.
fn init_claims_from_key<'a, I, T>(key: &ServiceAccountKey, scopes: I) -> Claims
where
    T: AsRef<str> + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let iat = chrono::Utc::now().timestamp();
    let expiry = iat + 3600 - 5; // Max validity is 1h.

    let mut scopes_string = scopes.into_iter().fold(String::new(), |mut acc, sc| {
        acc.push_str(sc.as_ref());
        acc.push_str(" ");
        acc
    });
    scopes_string.pop();

    Claims {
        iss: key.client_email.clone().unwrap(),
        aud: key.token_uri.clone().unwrap(),
        exp: expiry,
        iat: iat,
        sub: None,
        scope: scopes_string,
    }
}

/// A token source (`GetToken`) yielding OAuth tokens for services that use ServiceAccount authorization.
/// This token source caches token and automatically renews expired ones.
pub struct ServiceAccountAccess<C> {
    client: hyper::Client<C, hyper::Body>,
    key: ServiceAccountKey,
    cache: Arc<Mutex<MemoryStorage>>,
    sub: Option<String>,
}

/// This is the schema of the server's response.
#[derive(Deserialize, Debug)]
struct TokenResponse {
    access_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<i64>,
}

impl TokenResponse {
    fn to_oauth_token(self) -> Token {
        let expires_ts = chrono::Utc::now().timestamp() + self.expires_in.unwrap_or(0);

        Token {
            access_token: self.access_token.unwrap(),
            token_type: self.token_type.unwrap(),
            refresh_token: String::new(),
            expires_in: self.expires_in,
            expires_in_timestamp: Some(expires_ts),
        }
    }
}

impl<'a, C: 'static + hyper::client::connect::Connect> ServiceAccountAccess<C> {
    /// Returns a new `ServiceAccountAccess` token source.
    #[allow(dead_code)]
    pub fn new(
        key: ServiceAccountKey,
        client: hyper::Client<C, hyper::Body>,
    ) -> ServiceAccountAccess<C> {
        ServiceAccountAccess {
            client: client,
            key: key,
            cache: Arc::new(Mutex::new(MemoryStorage::default())),
            sub: None,
        }
    }

    /// Set `sub` claim in new `ServiceAccountKey` (see
    /// https://developers.google.com/identity/protocols/OAuth2ServiceAccount#authorizingrequests).
    pub fn with_sub(
        key: ServiceAccountKey,
        client: hyper::Client<C, hyper::Body>,
        sub: String,
    ) -> ServiceAccountAccess<C> {
        ServiceAccountAccess {
            client: client,
            key: key,
            cache: Arc::new(Mutex::new(MemoryStorage::default())),
            sub: Some(sub),
        }
    }

    ///
    fn request_token(
        client: hyper::client::Client<C>,
        sub: Option<String>,
        key: ServiceAccountKey,
        scopes: Vec<String>,
    ) -> impl Future<Item = Token, Error = Box<dyn 'static + error::Error + Send>> {
        let mut claims = init_claims_from_key(&key, &scopes);
        claims.sub = sub.clone();
        let signed = JWT::new(claims)
            .sign(key.private_key.as_ref().unwrap())
            .into_future();
        signed
            .map(|signed| {
                form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(vec![
                        ("grant_type".to_string(), GRANT_TYPE.to_string()),
                        ("assertion".to_string(), signed),
                    ])
                    .finish()
            })
            .map(|rqbody| {
                hyper::Request::post(key.token_uri.unwrap())
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(hyper::Body::from(rqbody))
                    .unwrap()
            })
            .and_then(move |request| {
                client
                    .request(request)
                    .map_err(|e| Box::new(e) as Box<dyn error::Error + Send>)
            })
            .and_then(|response| {
                response
                    .into_body()
                    .concat2()
                    .map_err(|e| Box::new(e) as Box<dyn error::Error + Send>)
            })
            .map(|c| String::from_utf8(c.into_bytes().to_vec()).unwrap())
            .and_then(|s| {
                serde_json::from_str(&s).map_err(|e| Box::new(e) as Box<dyn error::Error + Send>)
            })
            .then(
                |token: Result<TokenResponse, Box<dyn error::Error + Send>>| match token {
                    Err(e) => return Err(e),
                    Ok(token) => {
                        if token.access_token.is_none()
                            || token.token_type.is_none()
                            || token.expires_in.is_none()
                        {
                            Err(Box::new(StringError::new(
                                "Token response lacks fields".to_string(),
                                Some(&format!("{:?}", token)),
                            ))
                                as Box<dyn error::Error + Send>)
                        } else {
                            Ok(token.to_oauth_token())
                        }
                    }
                },
            )
    }
}

impl<C: 'static> GetToken for ServiceAccountAccess<C>
where
    C: hyper::client::connect::Connect,
{
    fn token<'b, I, T>(
        &mut self,
        scopes: I,
    ) -> Box<dyn Future<Item = Token, Error = Box<dyn error::Error + Send>> + Send>
    where
        T: AsRef<str> + Ord + 'b,
        I: Iterator<Item = &'b T>,
    {
        let (hash, scps) = hash_scopes(scopes);

        match self
            .cache
            .lock()
            .unwrap()
            .get(hash, &scps.iter().map(|s| s.as_str()).collect())
        {
            Ok(Some(token)) => {
                if !token.expired() {
                    return Box::new(future::ok(token));
                }
            }
            Err(e) => return Box::new(future::err(Box::new(e) as Box<dyn error::Error + Send>)),
            _ => {}
        }

        let cache = self.cache.clone();
        Box::new(
            Self::request_token(
                self.client.clone(),
                self.sub.clone(),
                self.key.clone(),
                scps.iter().map(|s| s.to_string()).collect(),
            )
            .then(move |r| match r {
                Ok(token) => {
                    let _ = cache.lock().unwrap().set(
                        hash,
                        &scps.iter().map(|s| s.as_str()).collect(),
                        Some(token.clone()),
                    );
                    Box::new(future::ok(token))
                }
                Err(e) => Box::new(future::err(e)),
            }),
        )
    }

    fn api_key(&mut self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::service_account_key_from_file;
    use crate::types::GetToken;
    use hyper;
    use hyper_tls::HttpsConnector;

    // This is a valid but deactivated key.
    const TEST_PRIVATE_KEY_PATH: &'static str = "examples/Sanguine-69411a0c0eea.json";

    // Uncomment this test to verify that we can successfully obtain tokens.
    //#[test]
    #[allow(dead_code)]
    fn test_service_account_e2e() {
        let key = service_account_key_from_file(&TEST_PRIVATE_KEY_PATH.to_string()).unwrap();
        let https = HttpsConnector::new(4).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let client = hyper::Client::builder()
            .executor(runtime.executor())
            .build(https);
        let mut acc = ServiceAccountAccess::new(key, client);
        println!(
            "{:?}",
            acc.token(vec!["https://www.googleapis.com/auth/pubsub"].iter())
                .wait()
        );
    }

    #[test]
    fn test_jwt_initialize_claims() {
        let key = service_account_key_from_file(TEST_PRIVATE_KEY_PATH).unwrap();
        let scopes = vec!["scope1", "scope2", "scope3"];
        let claims = super::init_claims_from_key(&key, &scopes);

        assert_eq!(
            claims.iss,
            "oauth2-public-test@sanguine-rhythm-105020.iam.gserviceaccount.com".to_string()
        );
        assert_eq!(claims.scope, "scope1 scope2 scope3".to_string());
        assert_eq!(
            claims.aud,
            "https://accounts.google.com/o/oauth2/token".to_string()
        );
        assert!(claims.exp > 1000000000);
        assert!(claims.iat < claims.exp);
        assert_eq!(claims.exp - claims.iat, 3595);
    }

    #[test]
    fn test_jwt_sign() {
        let key = service_account_key_from_file(TEST_PRIVATE_KEY_PATH).unwrap();
        let scopes = vec!["scope1", "scope2", "scope3"];
        let claims = super::init_claims_from_key(&key, &scopes);
        let jwt = super::JWT::new(claims);
        let signature = jwt.sign(key.private_key.as_ref().unwrap());

        assert!(signature.is_ok());

        let signature = signature.unwrap();
        assert_eq!(
            signature.split(".").nth(0).unwrap(),
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        );
    }
}
