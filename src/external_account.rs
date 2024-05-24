//! This module provides a token source (`GetToken`) that obtains tokens using workload identity federation
//! for use by software (i.e., non-human actors) to get access to Google services.
//!
//! Resources:
//! - [Workload identity federation](https://cloud.google.com/iam/docs/workload-identity-federation)
//! - [External Account Credentials (Workload Identity Federation)](https://google.aip.dev/auth/4117)
//!
use crate::error::Error;
use crate::types::TokenInfo;
use http::Uri;
use hyper::client::connect::Connection;
use hyper::header;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error as StdError;
use tokio::io::{AsyncRead, AsyncWrite};
use tower_service::Service;
use url::form_urlencoded;

/// JSON schema of external account secret.
///
/// You can use `helpers::read_external_account_secret()` to read a JSON file
/// into a `ExternalAccountSecret`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExternalAccountSecret {
    /// audience
    pub audience: String,
    /// subject_token_type
    pub subject_token_type: String,
    /// service_account_impersonation_url
    pub service_account_impersonation_url: Option<String>,
    /// token_url
    pub token_url: String,
    // TODO: support service_account_impersonation.
    /// credential_source
    pub credential_source: CredentialSource,
    #[serde(rename = "type")]
    /// key_type
    pub key_type: String,
}

/// JSON schema of credential source.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum CredentialSource {
    /// file-sourced credentials
    File {
        /// file
        file: String,
    },
    /// Microsoft Azure and URL-sourced credentials
    Url {
        /// url
        url: String,
        /// headers
        headers: Option<HashMap<String, String>>,
        /// format
        format: UrlCredentialSourceFormat,
    },
    // TODO: executable-sourced credentials
}

/// JSON schema of URL-sourced credentials' format.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum UrlCredentialSourceFormat {
    /// text
    #[serde(rename = "text")]
    Text,
    /// json
    #[serde(rename = "json")]
    Json {
        /// subject_token_field_name
        subject_token_field_name: String,
    },
}

/// ExternalAccountFlow can fetch oauth tokens using an external account secret.
pub struct ExternalAccountFlow {
    pub(crate) secret: ExternalAccountSecret,
}

impl ExternalAccountFlow {
    /// Send a request for a new Bearer token to the OAuth provider.
    pub(crate) async fn token<S, T>(
        &self,
        hyper_client: &hyper::Client<S>,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        S: Service<Uri> + Clone + Send + Sync + 'static,
        S::Response: Connection + AsyncRead + AsyncWrite + Send + Unpin + 'static,
        S::Future: Send + Unpin + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let subject_token = match &self.secret.credential_source {
            CredentialSource::File { file } => tokio::fs::read_to_string(file).await?,
            CredentialSource::Url {
                url,
                headers,
                format,
            } => {
                let request = headers
                    .iter()
                    .flatten()
                    .fold(hyper::Request::get(url), |builder, (name, value)| {
                        builder.header(name, value)
                    })
                    .body(hyper::Body::empty())
                    .unwrap();

                log::debug!("requesting credential from url: {:?}", request);
                let (head, body) = hyper_client.request(request).await?.into_parts();
                let body = hyper::body::to_bytes(body).await?;
                log::debug!("received response; head: {:?}, body: {:?}", head, body);

                match format {
                    UrlCredentialSourceFormat::Text => {
                        String::from_utf8(body.to_vec()).map_err(anyhow::Error::from)?
                    }
                    UrlCredentialSourceFormat::Json {
                        subject_token_field_name,
                    } => serde_json::from_slice::<HashMap<String, serde_json::Value>>(&body)?
                        .remove(subject_token_field_name)
                        .ok_or_else(|| anyhow::format_err!("missing {subject_token_field_name}"))?
                        .as_str()
                        .ok_or_else(|| anyhow::format_err!("invalid type"))?
                        .to_string(),
                }
            }
        };

        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("audience", self.secret.audience.as_str()),
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                (
                    "requested_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                (
                    "subject_token_type",
                    self.secret.subject_token_type.as_str(),
                ),
                ("subject_token", subject_token.as_str()),
                (
                    "scope",
                    if self.secret.service_account_impersonation_url.is_some() {
                        "https://www.googleapis.com/auth/cloud-platform".to_owned()
                    } else {
                        crate::helper::join(scopes, " ")
                    }
                    .as_str(),
                ),
            ])
            .finish();

        let request = hyper::Request::post(&self.secret.token_url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(req))
            .unwrap();

        log::debug!("requesting token from external account: {:?}", request);
        let (head, body) = hyper_client.request(request).await?.into_parts();
        let body = hyper::body::to_bytes(body).await?;
        log::debug!("received response; head: {:?}, body: {:?}", head, body);

        let token_info = TokenInfo::from_json(&body)?;

        if let Some(service_account_impersonation_url) =
            &self.secret.service_account_impersonation_url
        {
            crate::service_account_impersonator::token_impl(
                hyper_client,
                service_account_impersonation_url,
                true,
                &token_info.access_token.ok_or(Error::MissingAccessToken)?,
                scopes,
            )
            .await
        } else {
            Ok(token_info)
        }
    }
}
