//! Module containing functionality for serializing tokens and using them at a later point for
//! non-interactive services.
use crate::authenticator::Authenticator;
use crate::client::SendRequest;
use crate::error::Error;
use crate::refresh::RefreshFlow;
use crate::types::{ApplicationSecret, TokenInfo};

use hyper_util::client::legacy::connect::Connect;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Default, Debug)]
struct Entry {
    scopes: Vec<String>,
    refresh_token: String,
}

impl Entry {
    fn create<T>(scopes: &[T], refresh_token: String) -> Self
    where
        T: AsRef<str>,
    {
        Entry {
            scopes: (scopes.iter().map(|x| x.as_ref().to_string()).collect()),
            refresh_token,
        }
    }

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

    /// Create a builder using an existing authenticator to get tokens interactively, which can be
    /// saved and used later non-interactively..
    pub fn builder<'a, C>(
        authenticator: &'a Authenticator<C>,
    ) -> Result<NoninteractiveTokensBuilder<'a, C>, Error>
    where
        C: Connect + Clone + Send + Sync + 'static,
    {
        let app_secret = (match authenticator.app_secret() {
            Some(secret) => Ok(secret.clone()),
            None => Err(Error::UserError(
                "No application secret present in authenticator".into(),
            )),
        })?;

        Ok(NoninteractiveTokensBuilder {
            authenticator,
            tokens: NoninteractiveTokens {
                app_secret,
                refresh_tokens: vec![],
            },
        })
    }
}

/// A builder to construct `NoninteractiveTokens` using an existing authenticator.
#[derive(Clone)]
pub struct NoninteractiveTokensBuilder<'a, C>
where C: Connect + Clone + Send + Sync + 'static {
    authenticator: &'a Authenticator<C>,
    tokens: NoninteractiveTokens,
}

impl<'a, C> NoninteractiveTokensBuilder<'a, C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    /// Finalize the `NoninteractiveTokens`.
    pub fn build(self) -> NoninteractiveTokens {
        self.tokens
    }

    /// Add a cached refresh token for a given set of scopes.
    pub async fn add_token_for<T>(
        mut self,
        scopes: &[T],
        force_refresh: bool,
    ) -> Result<NoninteractiveTokensBuilder<'a, C>, Error>
    where
        T: AsRef<str>,
    {
        let info = self.authenticator.find_token_info(scopes, force_refresh).await?;
        match info.refresh_token {
            Some(token) => {
                self.tokens
                    .refresh_tokens
                    .push(Entry::create(scopes, token.clone()));
                Ok(self)
            }
            None => Err(Error::UserError(
                "Returned token doesn't contain a refresh token".into(),
            )),
        }
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
