//! pseudo authenticator for use with plain access tokens.
//! If you use a specialized service to manage your
//! OAuth2-tokens you may get just the fresh generated
//! access token from your service.
//! The intention behind this is that if two services using the
//! same refresh token then each service will invalitate the
//! access token of the other service by generating a new token.
use crate::error::Error;
use crate::types::TokenInfo;
use hyper_util::client::legacy::connect::Connect;

/// the flow for the access token authenticator
pub struct AccessTokenFlow {
    pub(crate) access_token: String,
}

impl AccessTokenFlow {
    /// just return the access token
    pub(crate) async fn token<C, B, T>(
        &self,
        _hyper_client: &hyper_util::client::legacy::Client<C, B>,
        _scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        C: Connect + Clone + Send + Sync + 'static,
    {
        Ok(TokenInfo {
            access_token: Some(self.access_token.clone()),
            refresh_token: None,
            expires_at: None,
            id_token: None,
        })
    }
}
