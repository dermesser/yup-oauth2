use crate::authenticator_delegate::{AuthenticatorDelegate, DefaultAuthenticatorDelegate};
use crate::refresh::RefreshFlow;
use crate::storage::{self, Storage};
use crate::types::{ApplicationSecret, GetToken, RefreshResult, RequestError, Token};

use futures::prelude::*;

use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Mutex;

/// Authenticator abstracts different `GetToken` implementations behind one type and handles
/// caching received tokens. It's important to use it (instead of the flows directly) because
/// otherwise the user needs to be asked for new authorization every time a token is generated.
///
/// `ServiceAccountAccess` does not need (and does not work) with `Authenticator`, given that it
/// does not require interaction and implements its own caching. Use it directly.
///
/// NOTE: It is recommended to use a client constructed like this in order to prevent functions
/// like `hyper::run()` from hanging: `let client = hyper::Client::builder().keep_alive(false);`.
/// Due to token requests being rare, this should not result in a too bad performance problem.
struct AuthenticatorImpl<T: GetToken, AD: AuthenticatorDelegate, C: hyper::client::connect::Connect>
{
    client: hyper::Client<C>,
    inner: T,
    store: Storage,
    delegate: AD,
}

/// A trait implemented for any hyper::Client as well as teh DefaultHyperClient.
pub trait HyperClientBuilder {
    type Connector: hyper::client::connect::Connect + 'static;

    fn build_hyper_client(self) -> hyper::Client<Self::Connector>;
}

/// The builder value used when the default hyper client should be used.
pub struct DefaultHyperClient;
impl HyperClientBuilder for DefaultHyperClient {
    type Connector = hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>;

    fn build_hyper_client(self) -> hyper::Client<Self::Connector> {
        hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(hyper_rustls::HttpsConnector::new())
    }
}

impl<C> HyperClientBuilder for hyper::Client<C>
where
    C: hyper::client::connect::Connect + 'static,
{
    type Connector = C;

    fn build_hyper_client(self) -> hyper::Client<C> {
        self
    }
}

/// An internal trait implemented by flows to be used by an authenticator.
pub trait AuthFlow<C> {
    type TokenGetter: GetToken;

    fn build_token_getter(self, client: hyper::Client<C>) -> Self::TokenGetter;
}

enum StorageType {
    Memory,
    Disk(PathBuf),
}

/// An authenticator can be used with `InstalledFlow`'s or `DeviceFlow`'s and
/// will refresh tokens as they expire as well as optionally persist tokens to
/// disk.
pub struct Authenticator<T, AD, C> {
    client: C,
    token_getter: T,
    storage_type: StorageType,
    delegate: AD,
}

impl<T> Authenticator<T, DefaultAuthenticatorDelegate, DefaultHyperClient>
where
    T: AuthFlow<<DefaultHyperClient as HyperClientBuilder>::Connector>,
{
    /// Create a new authenticator with the provided flow. By default a new
    /// hyper::Client will be created the default authenticator delegate will be
    /// used, and tokens will not be persisted to disk.
    /// Accepted flow types are DeviceFlow and InstalledFlow.
    ///
    /// Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    /// use std::path::Path;
    /// use yup_oauth2::{ApplicationSecret, Authenticator, DeviceFlow};
    /// let creds = ApplicationSecret::default();
    /// let auth = Authenticator::new(DeviceFlow::new(creds)).build().await.unwrap();
    /// # }
    /// ```
    pub fn new(flow: T) -> Authenticator<T, DefaultAuthenticatorDelegate, DefaultHyperClient> {
        Authenticator {
            client: DefaultHyperClient,
            token_getter: flow,
            storage_type: StorageType::Memory,
            delegate: DefaultAuthenticatorDelegate,
        }
    }
}

impl<T, AD, C> Authenticator<T, AD, C>
where
    T: AuthFlow<C::Connector>,
    AD: AuthenticatorDelegate,
    C: HyperClientBuilder,
{
    /// Use the provided hyper client.
    pub fn hyper_client<NewC>(
        self,
        hyper_client: hyper::Client<NewC>,
    ) -> Authenticator<T, AD, hyper::Client<NewC>>
    where
        NewC: hyper::client::connect::Connect + 'static,
        T: AuthFlow<NewC>,
    {
        Authenticator {
            client: hyper_client,
            token_getter: self.token_getter,
            storage_type: self.storage_type,
            delegate: self.delegate,
        }
    }

    /// Persist tokens to disk in the provided filename.
    pub fn persist_tokens_to_disk<P: Into<PathBuf>>(self, path: P) -> Authenticator<T, AD, C> {
        Authenticator {
            client: self.client,
            token_getter: self.token_getter,
            storage_type: StorageType::Disk(path.into()),
            delegate: self.delegate,
        }
    }

    /// Use the provided authenticator delegate.
    pub fn delegate<NewAD: AuthenticatorDelegate>(
        self,
        delegate: NewAD,
    ) -> Authenticator<T, NewAD, C> {
        Authenticator {
            client: self.client,
            token_getter: self.token_getter,
            storage_type: self.storage_type,
            delegate,
        }
    }

    /// Create the authenticator.
    pub async fn build(self) -> io::Result<impl GetToken>
    where
        T::TokenGetter: GetToken,
        C::Connector: hyper::client::connect::Connect + 'static,
    {
        let client = self.client.build_hyper_client();
        let inner = self.token_getter.build_token_getter(client.clone());
        let store = match self.storage_type {
            StorageType::Memory => Storage::Memory {
                tokens: Mutex::new(storage::JSONTokens::new()),
            },
            StorageType::Disk(path) => Storage::Disk(storage::DiskStorage::new(path).await?),
        };

        Ok(AuthenticatorImpl {
            client,
            inner,
            store,
            delegate: self.delegate,
        })
    }
}

impl<GT, AD, C> AuthenticatorImpl<GT, AD, C>
where
    GT: GetToken,
    AD: AuthenticatorDelegate,
    C: hyper::client::connect::Connect + 'static,
{
    async fn get_token<T>(&self, scopes: &[T]) -> Result<Token, RequestError>
    where
        T: AsRef<str> + Sync,
    {
        let scope_key = storage::ScopeHash::new(scopes);
        let store = &self.store;
        let delegate = &self.delegate;
        let client = &self.client;
        let gettoken = &self.inner;
        let appsecret = gettoken.application_secret();
        match store.get(scope_key, scopes) {
            Some(t) if !t.expired() => {
                // unexpired token found
                Ok(t)
            }
            Some(Token {
                refresh_token: Some(refresh_token),
                ..
            }) => {
                // token is expired but has a refresh token.
                let rr = RefreshFlow::refresh_token(client, appsecret, &refresh_token).await?;
                match rr {
                    RefreshResult::Error(ref e) => {
                        delegate.token_refresh_failed(
                            e.description(),
                            Some("the request has likely timed out"),
                        );
                        Err(RequestError::Refresh(rr))
                    }
                    RefreshResult::RefreshError(ref s, ref ss) => {
                        delegate.token_refresh_failed(
                            &format!("{}{}", s, ss.as_ref().map(|s| format!(" ({})", s)).unwrap_or_else(String::new)),
                            Some("the refresh token is likely invalid and your authorization has been revoked"),
                            );
                        Err(RequestError::Refresh(rr))
                    }
                    RefreshResult::Success(t) => {
                        store.set(scope_key, scopes, Some(t.clone())).await;
                        Ok(t)
                    }
                }
            }
            None
            | Some(Token {
                refresh_token: None,
                ..
            }) => {
                // no token in the cache or the token returned does not contain a refresh token.
                let t = gettoken.token(scopes).await?;
                store.set(scope_key, scopes, Some(t.clone())).await;
                Ok(t)
            }
        }
    }
}

impl<GT, AD, C> GetToken for AuthenticatorImpl<GT, AD, C>
where
    GT: GetToken,
    AD: AuthenticatorDelegate,
    C: hyper::client::connect::Connect + 'static,
{
    /// Returns the API Key of the inner flow.
    fn api_key(&self) -> Option<String> {
        self.inner.api_key()
    }
    /// Returns the application secret of the inner flow.
    fn application_secret(&self) -> &ApplicationSecret {
        self.inner.application_secret()
    }

    fn token<'a, T>(
        &'a self,
        scopes: &'a [T],
    ) -> Pin<Box<dyn Future<Output = Result<Token, RequestError>> + Send + 'a>>
    where
        T: AsRef<str> + Sync,
    {
        Box::pin(self.get_token(scopes))
    }
}
