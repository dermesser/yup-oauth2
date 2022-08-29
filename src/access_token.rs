//! pseudo authenticator for use with plain access tokens
use crate::error::Error;
use crate::types::TokenInfo;
use hyper::client::connect::Connection;
// use hyper::header;
use http::Uri;
// use serde::{Deserialize, Serialize};
use std::error::Error as StdError;
use tokio::io::{AsyncRead, AsyncWrite};
use tower_service::Service;
// use url::form_urlencoded;

/// the flow for the access token authenticator
pub struct AccessTokenFlow {
    pub(crate) access_token: String,
}

impl AccessTokenFlow {
    /// just return the access token
    pub(crate) async fn token<S, T>(
        &self,
        _hyper_client: &hyper::Client<S>,
        _scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        S: Service<Uri> + Clone + Send + Sync + 'static,
        S::Response: Connection + AsyncRead + AsyncWrite + Send + Unpin + 'static,
        S::Future: Send + Unpin + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        Ok(TokenInfo {
            access_token: self.access_token.clone(),
            refresh_token: None,
            expires_at: None,
            id_token: None,
        })
    }
}
