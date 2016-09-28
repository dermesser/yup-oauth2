//! This module provides a token source (`GetToken`) that obtains tokens for service accounts.
//! Service accounts are usually used by software (i.e., non-human actors) to get access to
//! resources. Currently, this module only works with RS256 JWTs, and uses the Google request URL
//! by default (this can be amended by a patch).
//!
//! Resources:
//! - [Using OAuth 2.0 for Server to Server
//! Applications](https://developers.google.com/identity/protocols/OAuth2ServiceAccount)
//! - [JSON Web Tokens](https://jwt.io/)
//!
//! Copyright (c) 2016 Google Inc (lewinb@google.com).
//!

use std::borrow::BorrowMut;
use std::default::Default;
use std::error;
use std::io::{Read, Write};
use std::result;

use authenticator::GetToken;
use types::{StringError, Token};
use storage::{hash_scopes, MemoryStorage, TokenStorage};

use hyper::header;
use url::form_urlencoded;

use base64;
use chrono;
use hyper;
use openssl;
use serde_json;

const GRANT_TYPE: &'static str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const GOOGLE_RS256_HEAD: &'static str = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";

// Encodes s as Base64
fn encode_base64<T: AsRef<[u8]>>(s: T) -> String {
    base64::encode_mode(s.as_ref(), base64::Base64Mode::UrlSafe)
}

// Calculates the SHA256 hash.
fn hash_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = openssl::crypto::hash::Hasher::new(openssl::crypto::hash::Type::SHA256);
    let _ = hasher.write(data);
    hasher.finish()
}

// Signs the hash with key.
fn sign_rsa(key: &openssl::crypto::rsa::RSA, hash: &[u8]) -> String {
    let signature = key.sign(openssl::crypto::hash::Type::SHA256, hash).unwrap();
    let b64_signature = encode_base64(signature);

    b64_signature
}

// Reads an RSA key from pem_pkcs8 (the format of the 'private_key' field in the service account
// key).
fn decode_rsa_key(pem_pkcs8: &str) -> Result<openssl::crypto::rsa::RSA, Box<error::Error>> {
    let private_key = pem_pkcs8.to_string().replace("\\n", "\n");
    let privkey = openssl::crypto::rsa::RSA::private_key_from_pem(&mut private_key.as_bytes());

    match privkey {
        Err(e) => Err(Box::new(e)),
        Ok(key) => Ok(key),
    }
}

/// JSON schema of secret service account key. You can obtain the key from
/// the Cloud Console at https://console.cloud.google.com/.
///
/// You can use `helpers::service_account_key_from_file()` as a quick way to read a JSON client
/// secret into a ServiceAccountKey.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServiceAccountKey {
    #[serde(rename="type")]
    pub key_type: Option<String>,
    pub project_id: Option<String>,
    pub private_key_id: Option<String>,
    pub private_key: Option<String>,
    pub client_email: Option<String>,
    pub client_id: Option<String>,
    pub auth_uri: Option<String>,
    pub token_uri: Option<String>,
    pub auth_provier_x509_cert_url: Option<String>,
    pub client_x509_cert_url: Option<String>,
}

#[derive(Serialize, Debug)]
struct Claims {
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    sub: Option<String>,
    scope: String,
}

struct JWT {
    header: String,
    claims: Claims,
}

impl JWT {
    fn new(claims: Claims) -> JWT {
        JWT {
            header: GOOGLE_RS256_HEAD.to_string(),
            claims: claims,
        }
    }
    // Encodes the first two parts (header and claims) to base64 and assembles them into a form
    // ready to be signed.
    fn encode_claims(&self) -> String {
        let mut head = encode_base64(&self.header);
        let claims = encode_base64(serde_json::to_string(&self.claims).unwrap());

        head.push_str(".");
        head.push_str(&claims);
        head
    }

    fn sign(&self, private_key: &str) -> Result<String, Box<error::Error>> {
        let mut jwt_head = self.encode_claims();

        let key = try!(decode_rsa_key(private_key));
        let hash = hash_sha256(&jwt_head.as_bytes());
        let signature = sign_rsa(&key, &hash);

        jwt_head.push_str(".");
        jwt_head.push_str(&signature);

        Ok(jwt_head)
    }
}

fn init_claims_from_key<'a, I, T>(key: &ServiceAccountKey, scopes: I) -> Claims
    where T: AsRef<str> + 'a,
          I: IntoIterator<Item = &'a T>
{
    let iat = chrono::UTC::now().timestamp();
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

/// See "Additional claims" at https://developers.google.com/identity/protocols/OAuth2ServiceAccount
#[allow(dead_code)]
fn set_sub_claim(mut claims: Claims, sub: String) -> Claims {
    claims.sub = Some(sub);
    claims
}

/// A token source (`GetToken`) yielding OAuth tokens for services that use ServiceAccount authorization.
/// This token source caches token and automatically renews expired ones.
pub struct ServiceAccountAccess<C> {
    client: C,
    key: ServiceAccountKey,
    cache: MemoryStorage,
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
        let expires_ts = chrono::UTC::now().timestamp() + self.expires_in.unwrap_or(0);

        Token {
            access_token: self.access_token.unwrap(),
            token_type: self.token_type.unwrap(),
            refresh_token: String::new(),
            expires_in: self.expires_in,
            expires_in_timestamp: Some(expires_ts),
        }
    }
}

impl<'a, C> ServiceAccountAccess<C>
    where C: BorrowMut<hyper::Client>
{
    /// Returns a new `ServiceAccountAccess` token source.
    #[allow(dead_code)]
    pub fn new(key: ServiceAccountKey, client: C) -> ServiceAccountAccess<C> {
        ServiceAccountAccess {
            client: client,
            key: key,
            cache: MemoryStorage::default(),
        }
    }

    fn request_token(&mut self, scopes: &Vec<&str>) -> result::Result<Token, Box<error::Error>> {
        let signed = try!(JWT::new(init_claims_from_key(&self.key, scopes))
            .sign(self.key.private_key.as_ref().unwrap()));

        let body = form_urlencoded::serialize(vec![("grant_type".to_string(),
                                                    GRANT_TYPE.to_string()),
                                                   ("assertion".to_string(), signed)]);

        let mut response = String::new();
        let mut result = try!(self.client
            .borrow_mut()
            .post(self.key.token_uri.as_ref().unwrap())
            .body(&body)
            .header(header::ContentType("application/x-www-form-urlencoded".parse().unwrap()))
            .send());

        try!(result.read_to_string(&mut response));

        let token: Result<TokenResponse, serde_json::error::Error> =
            serde_json::from_str(&response);

        match token {
            Err(e) => return Err(Box::new(e)),
            Ok(token) => {
                if token.access_token.is_none() || token.token_type.is_none() ||
                   token.expires_in.is_none() {
                    Err(Box::new(StringError::new("Token response lacks fields".to_string(),
                                                  Some(&format!("{:?}", token)))))
                } else {
                    Ok(token.to_oauth_token())
                }
            }
        }
    }
}

impl<C: BorrowMut<hyper::Client>> GetToken for ServiceAccountAccess<C> {
    fn token<'b, I, T>(&mut self, scopes: I) -> result::Result<Token, Box<error::Error>>
        where T: AsRef<str> + Ord + 'b,
              I: IntoIterator<Item = &'b T>
    {
        let (hash, scps) = hash_scopes(scopes);

        if let Some(token) = try!(self.cache.get(hash, &scps)) {
            if !token.expired() {
                return Ok(token);
            }
        }

        let token = try!(self.request_token(&scps));
        let _ = self.cache.set(hash, &scps, Some(token.clone()));

        Ok(token)
    }

    fn api_key(&mut self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helper::service_account_key_from_file;
    use hyper;
    use authenticator::GetToken;

    // This is a valid but deactivated key.
    const TEST_PRIVATE_KEY_PATH: &'static str = "examples/Sanguine-69411a0c0eea.json";

    // Uncomment this test to verify that we can successfully obtain tokens.
    // #[test]
    #[allow(dead_code)]
    fn test_service_account_e2e() {
        let key = service_account_key_from_file(&TEST_PRIVATE_KEY_PATH.to_string()).unwrap();
        let mut acc = ServiceAccountAccess::new(key, hyper::client::Client::new());
        println!("{:?}",
                 acc.token(vec![&"https://www.googleapis.com/auth/pubsub"]).unwrap());
    }

    #[test]
    fn test_jwt_initialize_claims() {
        let key = service_account_key_from_file(&TEST_PRIVATE_KEY_PATH.to_string()).unwrap();
        let scopes = vec!["scope1", "scope2", "scope3"];
        let claims = super::init_claims_from_key(&key, &scopes);

        assert_eq!(claims.iss,
                   "oauth2-public-test@sanguine-rhythm-105020.iam.gserviceaccount.com".to_string());
        assert_eq!(claims.scope, "scope1 scope2 scope3".to_string());
        assert_eq!(claims.aud,
                   "https://accounts.google.com/o/oauth2/token".to_string());
        assert!(claims.exp > 1000000000);
        assert!(claims.iat < claims.exp);
        assert_eq!(claims.exp - claims.iat, 3595);
    }

    #[test]
    fn test_jwt_sign() {
        let key = service_account_key_from_file(&TEST_PRIVATE_KEY_PATH.to_string()).unwrap();
        let scopes = vec!["scope1", "scope2", "scope3"];
        let claims = super::init_claims_from_key(&key, &scopes);
        let jwt = super::JWT::new(claims);
        let signature = jwt.sign(key.private_key.as_ref().unwrap());

        assert!(signature.is_ok());

        let signature = signature.unwrap();
        assert_eq!(signature.split(".").nth(0).unwrap(),
                   "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9");
    }
}
