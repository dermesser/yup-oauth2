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

use crate::error::Error;
use crate::types::Token;

use std::io;

use futures::prelude::*;
use hyper::header;
use rustls::{
    self,
    internal::pemfile,
    sign::{self, SigningKey},
    PrivateKey,
};
use serde::{Deserialize, Serialize};
use url::form_urlencoded;

const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const GOOGLE_RS256_HEAD: &str = r#"{"alg":"RS256","typ":"JWT"}"#;

/// Encodes s as Base64
fn append_base64<T: AsRef<[u8]> + ?Sized>(s: &T, out: &mut String) {
    base64::encode_config_buf(s, base64::URL_SAFE, out)
}

/// Decode a PKCS8 formatted RSA key.
fn decode_rsa_key(pem_pkcs8: &str) -> Result<PrivateKey, io::Error> {
    let private_keys = pemfile::pkcs8_private_keys(&mut pem_pkcs8.as_bytes());

    match private_keys {
        Ok(mut keys) if !keys.is_empty() => {
            keys.truncate(1);
            Ok(keys.remove(0))
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Not enough private keys in PEM",
        )),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Error reading key from PEM",
        )),
    }
}

/// JSON schema of secret service account key. You can obtain the key from
/// the Cloud Console at https://console.cloud.google.com/.
///
/// You can use `helpers::read_service_account_key()` as a quick way to read a JSON client
/// secret into a ServiceAccountKey.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServiceAccountKey {
    #[serde(rename = "type")]
    /// key_type
    pub key_type: Option<String>,
    /// project_id
    pub project_id: Option<String>,
    /// private_key_id
    pub private_key_id: Option<String>,
    /// private_key
    pub private_key: String,
    /// client_email
    pub client_email: String,
    /// client_id
    pub client_id: Option<String>,
    /// auth_uri
    pub auth_uri: Option<String>,
    /// token_uri
    pub token_uri: String,
    /// auth_provider_x509_cert_url
    pub auth_provider_x509_cert_url: Option<String>,
    /// client_x509_cert_url
    pub client_x509_cert_url: Option<String>,
}

/// Permissions requested for a JWT.
/// See https://developers.google.com/identity/protocols/OAuth2ServiceAccount#authorizingrequests.
#[derive(Serialize, Debug)]
struct Claims<'a> {
    iss: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    subject: Option<&'a str>,
    scope: String,
}

impl<'a> Claims<'a> {
    fn new<T>(key: &'a ServiceAccountKey, scopes: &[T], subject: Option<&'a str>) -> Self
    where
        T: AsRef<str>,
    {
        let iat = chrono::Utc::now().timestamp();
        let expiry = iat + 3600 - 5; // Max validity is 1h.

        let scope = crate::helper::join(scopes, " ");
        Claims {
            iss: &key.client_email,
            aud: &key.token_uri,
            exp: expiry,
            iat,
            subject,
            scope,
        }
    }
}

/// A JSON Web Token ready for signing.
pub(crate) struct JWTSigner {
    signer: Box<dyn rustls::sign::Signer>,
}

impl JWTSigner {
    fn new(private_key: &str) -> Result<Self, io::Error> {
        let key = decode_rsa_key(private_key)?;
        let signing_key = sign::RSASigningKey::new(&key)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Couldn't initialize signer"))?;
        let signer = signing_key
            .choose_scheme(&[rustls::SignatureScheme::RSA_PKCS1_SHA256])
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "Couldn't choose signing scheme")
            })?;
        Ok(JWTSigner { signer })
    }

    fn sign_claims(&self, claims: &Claims) -> Result<String, rustls::TLSError> {
        let mut jwt_head = Self::encode_claims(claims);
        let signature = self.signer.sign(jwt_head.as_bytes())?;
        jwt_head.push_str(".");
        append_base64(&signature, &mut jwt_head);
        Ok(jwt_head)
    }

    /// Encodes the first two parts (header and claims) to base64 and assembles them into a form
    /// ready to be signed.
    fn encode_claims(claims: &Claims) -> String {
        let mut head = String::new();
        append_base64(GOOGLE_RS256_HEAD, &mut head);
        head.push_str(".");
        append_base64(&serde_json::to_string(&claims).unwrap(), &mut head);
        head
    }
}

pub struct ServiceAccountFlowOpts {
    pub(crate) key: ServiceAccountKey,
    pub(crate) subject: Option<String>,
}

/// ServiceAccountFlow can fetch oauth tokens using a service account.
pub struct ServiceAccountFlow {
    key: ServiceAccountKey,
    subject: Option<String>,
    signer: JWTSigner,
}

impl ServiceAccountFlow {
    pub(crate) fn new(opts: ServiceAccountFlowOpts) -> Result<Self, io::Error> {
        let signer = JWTSigner::new(&opts.key.private_key)?;
        Ok(ServiceAccountFlow {
            key: opts.key,
            subject: opts.subject,
            signer,
        })
    }

    /// Send a request for a new Bearer token to the OAuth provider.
    pub(crate) async fn token<C, T>(
        &self,
        hyper_client: &hyper::Client<C>,
        scopes: &[T],
    ) -> Result<Token, Error>
    where
        T: AsRef<str>,
        C: hyper::client::connect::Connect + 'static,
    {
        let claims = Claims::new(&self.key, scopes, self.subject.as_ref().map(|x| x.as_str()));
        let signed = self.signer.sign_claims(&claims).map_err(|_| {
            Error::LowLevelError(io::Error::new(
                io::ErrorKind::Other,
                "unable to sign claims",
            ))
        })?;
        let rqbody = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[("grant_type", GRANT_TYPE), ("assertion", signed.as_str())])
            .finish();
        let request = hyper::Request::post(&self.key.token_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(rqbody))
            .unwrap();
        let response = hyper_client.request(request).await?;
        let body = response.into_body().try_concat().await?;
        Token::from_json(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::read_service_account_key;
    use crate::parse_json;
    use chrono::Utc;
    use hyper_rustls::HttpsConnector;

    use mockito::mock;

    #[tokio::test]
    async fn test_mocked_http() {
        env_logger::try_init().unwrap();
        let https = HttpsConnector::new();
        let client = hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(https);
        let server_url = &mockito::server_url();
        let key: ServiceAccountKey = parse_json!({
          "type": "service_account",
          "project_id": "yup-test-243420",
          "private_key_id": "26de294916614a5ebdf7a065307ed3ea9941902b",
          "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDemmylrvp1KcOn\n9yTAVVKPpnpYznvBvcAU8Qjwr2fSKylpn7FQI54wCk5VJVom0jHpAmhxDmNiP8yv\nHaqsef+87Oc0n1yZ71/IbeRcHZc2OBB33/LCFqf272kThyJo3qspEqhuAw0e8neg\nLQb4jpm9PsqR8IjOoAtXQSu3j0zkXemMYFy93PWHjVpPEUX16NGfsWH7oxspBHOk\n9JPGJL8VJdbiAoDSDgF0y9RjJY5I52UeHNhMsAkTYs6mIG4kKXt2+T9tAyHw8aho\nwmuytQAfydTflTfTG8abRtliF3nil2taAc5VB07dP1b4dVYy/9r6M8Z0z4XM7aP+\nNdn2TKm3AgMBAAECggEAWi54nqTlXcr2M5l535uRb5Xz0f+Q/pv3ceR2iT+ekXQf\n+mUSShOr9e1u76rKu5iDVNE/a7H3DGopa7ZamzZvp2PYhSacttZV2RbAIZtxU6th\n7JajPAM+t9klGh6wj4jKEcE30B3XVnbHhPJI9TCcUyFZoscuPXt0LLy/z8Uz0v4B\nd5JARwyxDMb53VXwukQ8nNY2jP7WtUig6zwE5lWBPFMbi8GwGkeGZOruAK5sPPwY\nGBAlfofKANI7xKx9UXhRwisB4+/XI1L0Q6xJySv9P+IAhDUI6z6kxR+WkyT/YpG3\nX9gSZJc7qEaxTIuDjtep9GTaoEqiGntjaFBRKoe+VQKBgQDzM1+Ii+REQqrGlUJo\nx7KiVNAIY/zggu866VyziU6h5wjpsoW+2Npv6Dv7nWvsvFodrwe50Y3IzKtquIal\nVd8aa50E72JNImtK/o5Nx6xK0VySjHX6cyKENxHRDnBmNfbALRM+vbD9zMD0lz2q\nmns/RwRGq3/98EqxP+nHgHSr9QKBgQDqUYsFAAfvfT4I75Glc9svRv8IsaemOm07\nW1LCwPnj1MWOhsTxpNF23YmCBupZGZPSBFQobgmHVjQ3AIo6I2ioV6A+G2Xq/JCF\nmzfbvZfqtbbd+nVgF9Jr1Ic5T4thQhAvDHGUN77BpjEqZCQLAnUWJx9x7e2xvuBl\n1A6XDwH/ewKBgQDv4hVyNyIR3nxaYjFd7tQZYHTOQenVffEAd9wzTtVbxuo4sRlR\nNM7JIRXBSvaATQzKSLHjLHqgvJi8LITLIlds1QbNLl4U3UVddJbiy3f7WGTqPFfG\nkLhUF4mgXpCpkMLxrcRU14Bz5vnQiDmQRM4ajS7/kfwue00BZpxuZxst3QKBgQCI\nRI3FhaQXyc0m4zPfdYYVc4NjqfVmfXoC1/REYHey4I1XetbT9Nb/+ow6ew0UbgSC\nUZQjwwJ1m1NYXU8FyovVwsfk9ogJ5YGiwYb1msfbbnv/keVq0c/Ed9+AG9th30qM\nIf93hAfClITpMz2mzXIMRQpLdmQSR4A2l+E4RjkSOwKBgQCB78AyIdIHSkDAnCxz\nupJjhxEhtQ88uoADxRoEga7H/2OFmmPsqfytU4+TWIdal4K+nBCBWRvAX1cU47vH\nJOlSOZI0gRKe0O4bRBQc8GXJn/ubhYSxI02IgkdGrIKpOb5GG10m85ZvqsXw3bKn\nRVHMD0ObF5iORjZUqD0yRitAdg==\n-----END PRIVATE KEY-----\n",
          "client_email": "yup-test-sa-1@yup-test-243420.iam.gserviceaccount.com",
          "client_id": "102851967901799660408",
          "auth_uri": "https://accounts.google.com/o/oauth2/auth",
          "token_uri": format!("{}/token", server_url),
          "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
          "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/yup-test-sa-1%40yup-test-243420.iam.gserviceaccount.com"
        });

        let json_response = serde_json::json!({
          "access_token": "ya29.c.ElouBywiys0LyNaZoLPJcp1Fdi2KjFMxzvYKLXkTdvM-rDfqKlvEq6PiMhGoGHx97t5FAvz3eb_ahdwlBjSStxHtDVQB4ZPRJQ_EOi-iS7PnayahU2S9Jp8S6rk",
          "expires_in": 3600,
          "token_type": "Bearer"
        });
        let bad_json_response = serde_json::json!({
          "error": "access_denied",
        });

        // Successful path.
        {
            let _m = mock("POST", "/token")
                .with_status(200)
                .with_header("content-type", "text/json")
                .with_body(json_response.to_string())
                .expect(1)
                .create();
            let acc = ServiceAccountFlow::new(ServiceAccountFlowOpts {
                key: key.clone(),
                subject: None,
            })
            .unwrap();
            let tok = acc
                .token(&client, &["https://www.googleapis.com/auth/pubsub"])
                .await
                .expect("token failed");
            assert!(tok.access_token.contains("ya29.c.ElouBywiys0Ly"));
            assert!(Utc::now() + chrono::Duration::seconds(3600) >= tok.expires_at.unwrap());
            _m.assert();
        }
        // Malformed response.
        {
            let _m = mock("POST", "/token")
                .with_status(200)
                .with_header("content-type", "text/json")
                .with_body(bad_json_response.to_string())
                .create();
            let acc = ServiceAccountFlow::new(ServiceAccountFlowOpts {
                key: key.clone(),
                subject: None,
            })
            .unwrap();
            let result = acc
                .token(&client, &["https://www.googleapis.com/auth/pubsub"])
                .await;
            assert!(result.is_err());
            _m.assert();
        }
    }

    // Valid but deactivated key.
    const TEST_PRIVATE_KEY_PATH: &'static str = "examples/Sanguine-69411a0c0eea.json";

    // Uncomment this test to verify that we can successfully obtain tokens.
    //#[tokio::test]
    #[allow(dead_code)]
    async fn test_service_account_e2e() {
        let key = read_service_account_key(TEST_PRIVATE_KEY_PATH)
            .await
            .unwrap();
        let acc = ServiceAccountFlow::new(ServiceAccountFlowOpts { key, subject: None }).unwrap();
        let https = HttpsConnector::new();
        let client = hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(https);
        println!(
            "{:?}",
            acc.token(&client, &["https://www.googleapis.com/auth/pubsub"])
                .await
        );
    }

    #[tokio::test]
    async fn test_jwt_initialize_claims() {
        let key = read_service_account_key(TEST_PRIVATE_KEY_PATH)
            .await
            .unwrap();
        let scopes = vec!["scope1", "scope2", "scope3"];
        let claims = Claims::new(&key, &scopes, None);

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

    #[tokio::test]
    async fn test_jwt_sign() {
        let key = read_service_account_key(TEST_PRIVATE_KEY_PATH)
            .await
            .unwrap();
        let scopes = vec!["scope1", "scope2", "scope3"];
        let signer = JWTSigner::new(&key.private_key).unwrap();
        let claims = Claims::new(&key, &scopes, None);
        let signature = signer.sign_claims(&claims);

        assert!(signature.is_ok());

        let signature = signature.unwrap();
        assert_eq!(
            signature.split(".").nth(0).unwrap(),
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        );
    }
}
