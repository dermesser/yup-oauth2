//! Module containing functionality for serializing tokens and using them at a later point for
//! non-interactive services.
use crate::client::SendRequest;
use crate::error::Error;
use crate::refresh::RefreshFlow;
use crate::types::{ApplicationSecret, TokenInfo};

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Default, Debug)]
struct Entry {
    scopes: Vec<String>,
    refresh_token: String,
}

impl Entry {
    fn is_subset<T>(&self, scopes: &[T]) -> bool
    where
        T: AsRef<str>,
    {
        scopes
            .iter()
            .all(|scope| self.scopes.iter().any(|s| s.as_str() == scope.as_ref()))
    }
}

/// These tokens are meant to be constructed interactively using another flow, and then can be
/// serialized to be deserialized and used non-interactively later on.  Since access tokens are
/// typically short-lived, this authenticator assumes it will be expired and only stores the
/// refresh token.
#[derive(Deserialize, Serialize, Clone, Default, Debug)]
pub struct NoninteractiveTokens {
    app_secret: ApplicationSecret,
    refresh_tokens: Vec<Entry>,
}

impl NoninteractiveTokens {
    fn entry_for_scopes<T>(&self, scopes: &[T]) -> Option<&Entry>
    where
        T: AsRef<str>,
    {
        self.refresh_tokens
            .iter()
            .find(|entry| entry.is_subset(scopes))
    }
}

/// A flow that uses a `NoninteractiveTokens` instance to provide access tokens.
pub struct NoninteractiveFlow(pub(crate) NoninteractiveTokens);

impl NoninteractiveFlow {
    pub(crate) fn app_secret(&self) -> &ApplicationSecret {
        &self.0.app_secret
    }

    pub(crate) async fn token<T>(
        &self,
        hyper_client: &impl SendRequest,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>
    {
        let refresh_token = (match self.0.entry_for_scopes(scopes) {
            None => Err(Error::UserError(format!(
                "No matching token found for scopes {:?}",
                scopes
                    .iter()
                    .map(|x| x.as_ref().to_string())
                    .collect::<Vec<_>>()
            ))),
            Some(entry) => Ok(&entry.refresh_token),
        })?;

        RefreshFlow::refresh_token(hyper_client, self.app_secret(), refresh_token.as_str()).await
    }
}
