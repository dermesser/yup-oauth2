//! This module provides an authenticator that uses authorized user secrets
//! to generate impersonated service account tokens.
//!
//! Resources:
//! - [service account impersonation](https://cloud.google.com/iam/docs/create-short-lived-credentials-direct#sa-credentials-oauth)

use http::header;
use http_body_util::BodyExt;
use hyper_util::client::legacy::connect::Connect;
use serde::Serialize;

use crate::{
    authorized_user::{AuthorizedUserFlow, AuthorizedUserSecret},
    storage::TokenInfo,
    Error,
};

const IAM_CREDENTIALS_ENDPOINT: &str = "https://iamcredentials.googleapis.com";

fn uri(email: &str) -> String {
    format!(
        "{}/v1/projects/-/serviceAccounts/{}:generateAccessToken",
        IAM_CREDENTIALS_ENDPOINT, email
    )
}

fn id_uri(email: &str) -> String {
    format!(
        "{}/v1/projects/-/serviceAccounts/{}:generateIdToken",
        IAM_CREDENTIALS_ENDPOINT, email
    )
}

#[derive(Serialize)]
struct Request<'a> {
    scope: &'a [&'a str],
    lifetime: &'a str,
}

#[derive(Serialize)]
struct IdRequest<'a> {
    audience: &'a str,
    #[serde(rename = "includeEmail")]
    include_email: bool,
}

// The response to our impersonation request. (Note that the naming is
// different from `types::AccessToken` even though the data is equivalent.)
#[derive(serde::Deserialize, Debug)]
struct TokenResponse {
    /// The actual token
    #[serde(rename = "accessToken")]
    access_token: String,
    /// The time until the token expires and a new one needs to be requested.
    /// In RFC3339 format.
    #[serde(rename = "expireTime")]
    expires_time: String,
}

impl From<TokenResponse> for TokenInfo {
    fn from(resp: TokenResponse) -> TokenInfo {
        let expires_at = time::OffsetDateTime::parse(
            &resp.expires_time,
            &time::format_description::well_known::Rfc3339,
        )
        .ok();
        TokenInfo {
            access_token: Some(resp.access_token),
            refresh_token: None,
            expires_at,
            id_token: None,
        }
    }
}

// The response to a request for impersonating an ID token.
#[derive(serde::Deserialize, Debug)]
struct IdTokenResponse {
    token: String,
}

impl From<IdTokenResponse> for TokenInfo {
    fn from(resp: IdTokenResponse) -> TokenInfo {
        // The response doesn't include an expiry field, but according to the docs [1]
        // the tokens are always valid for 1 hour.
        //
        // [1] https://cloud.google.com/iam/docs/create-short-lived-credentials-direct#sa-credentials-oidc
        let expires_at = time::OffsetDateTime::now_utc() + time::Duration::HOUR;
        TokenInfo {
            id_token: Some(resp.token),
            refresh_token: None,
            access_token: None,
            expires_at: Some(expires_at),
        }
    }
}

/// ServiceAccountImpersonationFlow uses user credentials to impersonate a service
/// account.
pub struct ServiceAccountImpersonationFlow {
    // If true, we request an impersonated access token. If false, we request an
    // impersonated ID token.
    pub(crate) access_token: bool,
    pub(crate) inner_flow: AuthorizedUserFlow,
    pub(crate) service_account_email: String,
}

impl ServiceAccountImpersonationFlow {
    pub(crate) fn new(
        user_secret: AuthorizedUserSecret,
        service_account_email: &str,
    ) -> ServiceAccountImpersonationFlow {
        ServiceAccountImpersonationFlow {
            access_token: true,
            inner_flow: AuthorizedUserFlow {
                secret: user_secret,
            },
            service_account_email: service_account_email.to_string(),
        }
    }

    pub(crate) async fn token<C, T>(
        &self,
        hyper_client: &hyper_util::client::legacy::Client<C, String>,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        C: Connect + Clone + Send + Sync + 'static,
    {
        let inner_token = self
            .inner_flow
            .token(hyper_client, scopes)
            .await?
            .access_token
            .ok_or(Error::MissingAccessToken)?;
        token_impl(
            hyper_client,
            &if self.access_token {
                uri(&self.service_account_email)
            } else {
                id_uri(&self.service_account_email)
            },
            self.access_token,
            &inner_token,
            scopes,
        )
        .await
    }
}

fn access_request(
    uri: &str,
    inner_token: &str,
    scopes: &[&str],
) -> Result<http::Request<String>, Error> {
    let req_body = Request {
        scope: scopes,
        // Max validity is 1h.
        lifetime: "3600s",
    };
    let req_body = serde_json::to_string(&req_body)?;
    Ok(http::Request::post(uri)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::CONTENT_LENGTH, req_body.len())
        .header(header::AUTHORIZATION, format!("Bearer {}", inner_token))
        .body(req_body)
        .unwrap())
}

fn id_request(
    uri: &str,
    inner_token: &str,
    scopes: &[&str],
) -> Result<http::Request<String>, Error> {
    // Only one audience is supported.
    let audience = scopes.first().unwrap_or(&"");
    let req_body = IdRequest {
        audience,
        include_email: true,
    };
    let req_body = serde_json::to_string(&req_body)?;
    Ok(http::Request::post(uri)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::CONTENT_LENGTH, req_body.len())
        .header(header::AUTHORIZATION, format!("Bearer {}", inner_token))
        .body(req_body)
        .unwrap())
}

pub(crate) async fn token_impl<C, T>(
    hyper_client: &hyper_util::client::legacy::Client<C, String>,
    uri: &str,
    access_token: bool,
    inner_token: &str,
    scopes: &[T],
) -> Result<TokenInfo, Error>
where
    T: AsRef<str>,
    C: Connect + Clone + Send + Sync + 'static,
{
    let scopes: Vec<_> = scopes.iter().map(|s| s.as_ref()).collect();
    let request = if access_token {
        access_request(uri, inner_token, &scopes)?
    } else {
        id_request(uri, inner_token, &scopes)?
    };

    log::debug!("requesting impersonated token {:?}", request);
    let (head, body) = hyper_client.request(request).await?.into_parts();
    let body = body.collect().await?.to_bytes();
    log::debug!("received response; head: {:?}, body: {:?}", head, body);

    if access_token {
        let response: TokenResponse = serde_json::from_slice(&body)?;
        Ok(response.into())
    } else {
        let response: IdTokenResponse = serde_json::from_slice(&body)?;
        Ok(response.into())
    }
}
