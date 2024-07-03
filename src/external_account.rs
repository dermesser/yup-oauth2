//! This module provides a token source (`GetToken`) that obtains tokens using workload identity federation
//! for use by software (i.e., non-human actors) to get access to Google services.
//!
//! Resources:
//! - [Workload identity federation](https://cloud.google.com/iam/docs/workload-identity-federation)
//! - [External Account Credentials (Workload Identity Federation)](https://google.aip.dev/auth/4117)
//!
use crate::client::SendRequest;
use crate::error::Error;
use crate::types::TokenInfo;
use http::header;
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
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
        /// File name of a file containing a subject token.
        file: String,
    },

    /// [Microsoft Azure and URL-sourced credentials](https://google.aip.dev/auth/4117#determining-the-subject-token-in-microsoft-azure-and-url-sourced-credentials)
    Url {
        /// This defines the local metadata server to retrieve the external credentials from. For
        /// Azure, this should be the Azure Instance Metadata Service (IMDS) URL used to retrieve
        /// the Azure AD access token.
        url: String,
        /// This defines the headers to append to the GET request to credential_source.url.
        headers: Option<HashMap<String, String>>,
        /// See struct documentation.
        format: UrlCredentialSourceFormat,
    },
    // TODO: executable-sourced credentials
}

/// JSON schema of URL-sourced credentials' format.
/// This indicates the format of the URL response. This can be either "text" or "json". The default should be "text".
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum UrlCredentialSourceFormat {
    /// Response is text.
    #[serde(rename = "text")]
    Text,
    /// Response is JSON.
    #[serde(rename = "json")]
    Json {
        /// Required for JSON URL responses. This indicates the JSON field name where the subject_token should be stored.
        subject_token_field_name: String,
    },
}

#[derive(Debug, Error)]
/// Errors that can happen when parsing a Credential source
pub enum CredentialSourceError {
    /// Parsing credential text source failed
    #[error("Failed to parse credential text source: {0}")]
    CredentialSourceTextInvalid(std::string::FromUtf8Error),
    /// Failed to parse JSON
    #[error("JSON credential source is invalid: {0}")]
    JsonInvalid(#[source] serde_json::Error),
    /// JSON is missing this field
    #[error("JSON credential source is missing field {0}")]
    MissingJsonField(String),
    /// This field of JSON is invalid
    #[error("JSON credential source could not convert field {0} to string")]
    InvalidJsonField(String),
}

/// An ExternalAccountFlow can fetch OAuth tokens using an external account secret.
pub struct ExternalAccountFlow {
    pub(crate) secret: ExternalAccountSecret,
}

impl ExternalAccountFlow {
    /// Send a request for a new Bearer token to the OAuth provider.
    pub(crate) async fn token<T>(
        &self,
        hyper_client: &impl SendRequest,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
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
                    .body(String::new())
                    .unwrap();

                log::debug!("requesting credential from url: {:?}", request);
                let (head, body) = hyper_client.request(request).await?.into_parts();
                let body = body.collect().await?.to_bytes();
                log::debug!("received response; head: {:?}, body: {:?}", head, body);

                match format {
                    UrlCredentialSourceFormat::Text => {
                        String::from_utf8(body.to_vec()).map_err(|e| {
                            Error::CredentialSourceError(
                                CredentialSourceError::CredentialSourceTextInvalid(e),
                            )
                        })?
                    }
                    UrlCredentialSourceFormat::Json {
                        subject_token_field_name,
                    } => serde_json::from_slice::<HashMap<String, serde_json::Value>>(&body)
                        .map_err(|e| {
                            Error::CredentialSourceError(CredentialSourceError::JsonInvalid(e))
                        })?
                        .remove(subject_token_field_name)
                        .ok_or_else(|| {
                            Error::CredentialSourceError(CredentialSourceError::MissingJsonField(
                                subject_token_field_name.to_owned(),
                            ))
                        })?
                        .as_str()
                        .ok_or_else(|| {
                            Error::CredentialSourceError(CredentialSourceError::InvalidJsonField(
                                subject_token_field_name.to_owned(),
                            ))
                        })?
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

        let request = http::Request::post(&self.secret.token_url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(req)
            .unwrap();

        log::debug!("requesting token from external account: {:?}", request);
        let (head, body) = hyper_client.request(request).await?.into_parts();
        let body = body.collect().await?.to_bytes();
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
