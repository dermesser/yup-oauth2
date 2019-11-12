use crate::authenticator_delegate::{AuthenticatorDelegate, DefaultAuthenticatorDelegate, Retry};
use crate::refresh::RefreshFlow;
use crate::storage::{hash_scopes, DiskTokenStorage, MemoryStorage, TokenStorage};
use crate::types::{ApplicationSecret, GetToken, RefreshResult, RequestError, Token};

use futures::{future, prelude::*};
use tokio_timer;

use std::error::Error;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

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
struct AuthenticatorImpl<
    T: GetToken,
    S: TokenStorage,
    AD: AuthenticatorDelegate,
    C: hyper::client::connect::Connect,
> {
    client: hyper::Client<C>,
    inner: Arc<Mutex<T>>,
    store: Arc<Mutex<S>>,
    delegate: AD,
}

/// A trait implemented for any hyper::Client as well as teh DefaultHyperClient.
pub trait HyperClientBuilder {
    type Connector: hyper::client::connect::Connect;

    fn build_hyper_client(self) -> hyper::Client<Self::Connector>;
}

/// The builder value used when the default hyper client should be used.
pub struct DefaultHyperClient;
impl HyperClientBuilder for DefaultHyperClient {
    type Connector = hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>;

    fn build_hyper_client(self) -> hyper::Client<Self::Connector> {
        hyper::Client::builder()
            .keep_alive(false)
            .build::<_, hyper::Body>(hyper_rustls::HttpsConnector::new(1))
    }
}

impl<C> HyperClientBuilder for hyper::Client<C>
where
    C: hyper::client::connect::Connect,
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

/// An authenticator can be used with `InstalledFlow`'s or `DeviceFlow`'s and
/// will refresh tokens as they expire as well as optionally persist tokens to
/// disk.
pub struct Authenticator<
    T: AuthFlow<C::Connector>,
    S: TokenStorage,
    AD: AuthenticatorDelegate,
    C: HyperClientBuilder,
> {
    client: C,
    token_getter: T,
    store: io::Result<S>,
    delegate: AD,
}

impl<T> Authenticator<T, MemoryStorage, DefaultAuthenticatorDelegate, DefaultHyperClient>
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
    /// use std::path::Path;
    /// use yup_oauth2::{ApplicationSecret, Authenticator, DeviceFlow};
    /// let creds = ApplicationSecret::default();
    /// let auth = Authenticator::new(DeviceFlow::new(creds)).build().unwrap();
    /// ```
    pub fn new(
        flow: T,
    ) -> Authenticator<T, MemoryStorage, DefaultAuthenticatorDelegate, DefaultHyperClient> {
        Authenticator {
            client: DefaultHyperClient,
            token_getter: flow,
            store: Ok(MemoryStorage::new()),
            delegate: DefaultAuthenticatorDelegate,
        }
    }
}

impl<T, S, AD, C> Authenticator<T, S, AD, C>
where
    T: AuthFlow<C::Connector>,
    S: TokenStorage,
    AD: AuthenticatorDelegate,
    C: HyperClientBuilder,
{
    /// Use the provided hyper client.
    pub fn hyper_client<NewC>(
        self,
        hyper_client: hyper::Client<NewC>,
    ) -> Authenticator<T, S, AD, hyper::Client<NewC>>
    where
        NewC: hyper::client::connect::Connect,
        T: AuthFlow<NewC>,
    {
        Authenticator {
            client: hyper_client,
            token_getter: self.token_getter,
            store: self.store,
            delegate: self.delegate,
        }
    }

    /// Persist tokens to disk in the provided filename.
    pub fn persist_tokens_to_disk<P: AsRef<Path>>(
        self,
        path: P,
    ) -> Authenticator<T, DiskTokenStorage, AD, C> {
        let disk_storage = DiskTokenStorage::new(path.as_ref().to_str().unwrap());
        Authenticator {
            client: self.client,
            token_getter: self.token_getter,
            store: disk_storage,
            delegate: self.delegate,
        }
    }

    /// Use the provided authenticator delegate.
    pub fn delegate<NewAD: AuthenticatorDelegate>(
        self,
        delegate: NewAD,
    ) -> Authenticator<T, S, NewAD, C> {
        Authenticator {
            client: self.client,
            token_getter: self.token_getter,
            store: self.store,
            delegate: delegate,
        }
    }

    /// Create the authenticator.
    pub fn build(self) -> io::Result<impl GetToken>
    where
        T::TokenGetter: 'static + GetToken + Send,
        S: 'static + Send,
        AD: 'static + Send,
        C::Connector: 'static + Clone + Send,
    {
        let client = self.client.build_hyper_client();
        let store = Arc::new(Mutex::new(self.store?));
        let inner = Arc::new(Mutex::new(
            self.token_getter.build_token_getter(client.clone()),
        ));

        Ok(AuthenticatorImpl {
            client,
            inner,
            store,
            delegate: self.delegate,
        })
    }
}

impl<
        GT: 'static + GetToken + Send,
        S: 'static + TokenStorage + Send,
        AD: 'static + AuthenticatorDelegate + Send,
        C: 'static + hyper::client::connect::Connect + Clone + Send,
    > GetToken for AuthenticatorImpl<GT, S, AD, C>
{
    /// Returns the API Key of the inner flow.
    fn api_key(&mut self) -> Option<String> {
        self.inner.lock().unwrap().api_key()
    }
    /// Returns the application secret of the inner flow.
    fn application_secret(&self) -> ApplicationSecret {
        self.inner.lock().unwrap().application_secret()
    }

    fn token<I, T>(
        &mut self,
        scopes: I,
    ) -> Box<dyn Future<Item = Token, Error = RequestError> + Send>
    where
        T: Into<String>,
        I: IntoIterator<Item = T>,
    {
        let (scope_key, scopes) = hash_scopes(scopes);
        let store = self.store.clone();
        let mut delegate = self.delegate.clone();
        let client = self.client.clone();
        let appsecret = self.inner.lock().unwrap().application_secret();
        let gettoken = self.inner.clone();
        let loopfn = move |()| -> Box<
            dyn Future<Item = future::Loop<Token, ()>, Error = RequestError> + Send,
        > {
            // How well does this work with tokio?
            match store.lock().unwrap().get(
                scope_key.clone(),
                &scopes.iter().map(|s| s.as_str()).collect(),
            ) {
                Ok(Some(t)) => {
                    if !t.expired() {
                        return Box::new(Ok(future::Loop::Break(t)).into_future());
                    }
                    // Implement refresh flow.
                    let refresh_token = t.refresh_token.clone();
                    let mut delegate = delegate.clone();
                    let store = store.clone();
                    let scopes = scopes.clone();
                    let refresh_fut = RefreshFlow::refresh_token(
                        client.clone(),
                        appsecret.clone(),
                        refresh_token.unwrap(),
                    )
                        .and_then(move |rr| -> Box<dyn Future<Item=future::Loop<Token, ()>, Error=RequestError> + Send> {
                            match rr {
                                RefreshResult::Error(ref e) => {
                                    delegate.token_refresh_failed(
                                        format!("{}", e.description().to_string()),
                                        &Some("the request has likely timed out".to_string()),
                                        );
                                    Box::new(Err(RequestError::Refresh(rr)).into_future())
                                }
                                RefreshResult::RefreshError(ref s, ref ss) => {
                                    delegate.token_refresh_failed(
                                        format!("{} {}", s, ss.clone().map(|s| format!("({})", s)).unwrap_or("".to_string())),
                                        &Some("the refresh token is likely invalid and your authorization has been revoked".to_string()),
                                        );
                                    Box::new(Err(RequestError::Refresh(rr)).into_future())
                                }
                                RefreshResult::Success(t) => {
                                    if let Err(e) = store.lock().unwrap().set(scope_key, &scopes.iter().map(|s| s.as_str()).collect(), Some(t.clone())) {
                                        match delegate.token_storage_failure(true, &e) {
                                            Retry::Skip => Box::new(Ok(future::Loop::Break(t)).into_future()),
                                            Retry::Abort => Box::new(Err(RequestError::Cache(Box::new(e))).into_future()),
                                            Retry::After(d) => Box::new(
                                                tokio_timer::sleep(d)
                                                .then(|_| Ok(future::Loop::Continue(()))),
                                                )
                                                as Box<
                                                dyn Future<
                                                Item = future::Loop<Token, ()>,
                                                Error = RequestError> + Send>,
                                        }
                                    } else {
                                        Box::new(Ok(future::Loop::Break(t)).into_future())
                                    }
                                },
                            }
                        });
                    Box::new(refresh_fut)
                }
                Ok(None) => {
                    let store = store.clone();
                    let scopes = scopes.clone();
                    let mut delegate = delegate.clone();
                    Box::new(
                        gettoken
                            .lock()
                            .unwrap()
                            .token(scopes.clone())
                            .and_then(move |t| {
                                if let Err(e) = store.lock().unwrap().set(
                                    scope_key,
                                    &scopes.iter().map(|s| s.as_str()).collect(),
                                    Some(t.clone()),
                                ) {
                                    match delegate.token_storage_failure(true, &e) {
                                        Retry::Skip => {
                                            Box::new(Ok(future::Loop::Break(t)).into_future())
                                        }
                                        Retry::Abort => Box::new(
                                            Err(RequestError::Cache(Box::new(e))).into_future(),
                                        ),
                                        Retry::After(d) => Box::new(
                                            tokio_timer::sleep(d)
                                                .then(|_| Ok(future::Loop::Continue(()))),
                                        )
                                            as Box<
                                                dyn Future<
                                                        Item = future::Loop<Token, ()>,
                                                        Error = RequestError,
                                                    > + Send,
                                            >,
                                    }
                                } else {
                                    Box::new(Ok(future::Loop::Break(t)).into_future())
                                }
                            }),
                    )
                }
                Err(err) => match delegate.token_storage_failure(false, &err) {
                    Retry::Abort | Retry::Skip => {
                        return Box::new(Err(RequestError::Cache(Box::new(err))).into_future())
                    }
                    Retry::After(d) => {
                        return Box::new(
                            tokio_timer::sleep(d).then(|_| Ok(future::Loop::Continue(()))),
                        )
                    }
                },
            }
        };
        Box::new(future::loop_fn((), loopfn))
    }
}
