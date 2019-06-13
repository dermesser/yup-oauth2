use crate::authenticator_delegate::{AuthenticatorDelegate, Retry};
use crate::refresh::{RefreshFlow, RefreshResult};
use crate::storage::{hash_scopes, DiskTokenStorage, MemoryStorage, TokenStorage};
use crate::types::{ApplicationSecret, GetToken, StringError, Token};

use futures::{future, prelude::*};
use tokio_timer;

use std::error::Error;
use std::io;
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
pub struct Authenticator<
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

impl<T: GetToken, AD: AuthenticatorDelegate, C: hyper::client::connect::Connect>
    Authenticator<T, MemoryStorage, AD, C>
{
    /// Create an Authenticator caching tokens for the duration of this authenticator.
    pub fn new(
        client: hyper::Client<C>,
        inner: T,
        delegate: AD,
    ) -> Authenticator<T, MemoryStorage, AD, C> {
        Authenticator {
            client: client,
            inner: Arc::new(Mutex::new(inner)),
            store: Arc::new(Mutex::new(MemoryStorage::new())),
            delegate: delegate,
        }
    }
}

impl<T: GetToken, AD: AuthenticatorDelegate, C: hyper::client::connect::Connect>
    Authenticator<T, DiskTokenStorage, AD, C>
{
    /// Create an Authenticator using the store at `path`.
    pub fn new_disk<P: AsRef<str>>(
        client: hyper::Client<C>,
        inner: T,
        delegate: AD,
        token_storage_path: P,
    ) -> io::Result<Authenticator<T, DiskTokenStorage, AD, C>> {
        Ok(Authenticator {
            client: client,
            inner: Arc::new(Mutex::new(inner)),
            store: Arc::new(Mutex::new(DiskTokenStorage::new(token_storage_path)?)),
            delegate: delegate,
        })
    }
}

impl<
        GT: 'static + GetToken + Send,
        S: 'static + TokenStorage + Send,
        AD: 'static + AuthenticatorDelegate + Send,
        C: 'static + hyper::client::connect::Connect + Clone + Send,
    > GetToken for Authenticator<GT, S, AD, C>
{
    /// Returns the API Key of the inner flow.
    fn api_key(&mut self) -> Option<String> {
        self.inner.lock().unwrap().api_key()
    }
    /// Returns the application secret of the inner flow.
    fn application_secret(&self) -> ApplicationSecret {
        self.inner.lock().unwrap().application_secret()
    }

    fn token<'b, I, T>(
        &mut self,
        scopes: I,
    ) -> Box<dyn Future<Item = Token, Error = Box<dyn Error + Send>> + Send>
    where
        T: AsRef<str> + Ord + 'b,
        I: Iterator<Item = &'b T>,
    {
        let (scope_key, scopes) = hash_scopes(scopes);
        let store = self.store.clone();
        let mut delegate = self.delegate.clone();
        let client = self.client.clone();
        let appsecret = self.inner.lock().unwrap().application_secret();
        let gettoken = self.inner.clone();
        let loopfn = move |()| -> Box<
            dyn Future<Item = future::Loop<Token, ()>, Error = Box<dyn Error + Send>> + Send,
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
                    let refresh_fut = RefreshFlow::refresh_token(
                        client.clone(),
                        appsecret.clone(),
                        refresh_token,
                    )
                    .and_then(move |rr| match rr {
                        RefreshResult::Error(e) => {
                            delegate.token_refresh_failed(
                                format!("{}", e.description().to_string()),
                                &Some("the request has likely timed out".to_string()),
                            );
                            Err(Box::new(e) as Box<dyn Error + Send>)
                        }
                        RefreshResult::RefreshError(ref s, ref ss) => {
                            delegate.token_refresh_failed(
                                format!("{} {}", s, ss.clone().map(|s| format!("({})", s)).unwrap_or("".to_string())),
                                &Some("the refresh token is likely invalid and your authorization has been revoked".to_string()),
                            );
                            Err(Box::new(StringError::new(s.to_string(), ss.as_ref())) as Box<dyn Error + Send>)
                        }
                        RefreshResult::Success(t) => Ok(future::Loop::Break(t)),
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
                            .token(scopes.iter())
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
                                            Err(Box::new(e) as Box<dyn Error + Send>).into_future(),
                                        ),
                                        Retry::After(d) => Box::new(
                                            tokio_timer::sleep(d)
                                                .then(|_| Ok(future::Loop::Continue(()))),
                                        )
                                            as Box<
                                                dyn Future<
                                                        Item = future::Loop<Token, ()>,
                                                        Error = Box<dyn Error + Send>,
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
                        return Box::new(future::err(Box::new(err) as Box<dyn Error + Send>))
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
