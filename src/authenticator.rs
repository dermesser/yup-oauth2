use crate::authenticator_delegate::{
    AuthenticatorDelegate, DefaultAuthenticatorDelegate, FlowDelegate,
};
use crate::device::DeviceFlow;
use crate::installed::{InstalledFlow, InstalledFlowReturnMethod};
use crate::refresh::RefreshFlow;
use crate::storage::{self, Storage};
use crate::types::{ApplicationSecret, RefreshResult, RequestError, Token};
use private::AuthFlow;

use std::borrow::Cow;
use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

pub struct Authenticator<C> {
    hyper_client: hyper::Client<C>,
    app_secret: ApplicationSecret,
    auth_delegate: Box<dyn AuthenticatorDelegate>,
    storage: Storage,
    auth_flow: AuthFlow,
}

impl<C> Authenticator<C>
where
    C: hyper::client::connect::Connect + 'static,
{
    pub async fn token<'a, T>(&'a self, scopes: &'a [T]) -> Result<Token, RequestError>
    where
        T: AsRef<str>,
    {
        let scope_key = storage::ScopeHash::new(scopes);
        match self.storage.get(scope_key, scopes) {
            Some(t) if !t.expired() => {
                // unexpired token found
                Ok(t)
            }
            Some(Token {
                refresh_token: Some(refresh_token),
                ..
            }) => {
                // token is expired but has a refresh token.
                let rr = RefreshFlow::refresh_token(
                    &self.hyper_client,
                    &self.app_secret,
                    &refresh_token,
                )
                .await?;
                match rr {
                    RefreshResult::Error(ref e) => {
                        self.auth_delegate.token_refresh_failed(
                            e.description(),
                            Some("the request has likely timed out"),
                        );
                        Err(RequestError::Refresh(rr))
                    }
                    RefreshResult::RefreshError(ref s, ref ss) => {
                        self.auth_delegate.token_refresh_failed(
                            &format!("{}{}", s, ss.as_ref().map(|s| format!(" ({})", s)).unwrap_or_else(String::new)),
                            Some("the refresh token is likely invalid and your authorization has been revoked"),
                            );
                        Err(RequestError::Refresh(rr))
                    }
                    RefreshResult::Success(t) => {
                        self.storage.set(scope_key, scopes, Some(t.clone())).await;
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
                let t = self
                    .auth_flow
                    .token(&self.hyper_client, &self.app_secret, scopes)
                    .await?;
                self.storage.set(scope_key, scopes, Some(t.clone())).await;
                Ok(t)
            }
        }
    }
}

pub struct AuthenticatorBuilder<C, F> {
    hyper_client_builder: C,
    app_secret: ApplicationSecret,
    auth_delegate: Box<dyn AuthenticatorDelegate>,
    storage_type: StorageType,
    auth_flow: F,
}

pub struct InstalledFlowAuthenticator;
impl InstalledFlowAuthenticator {
    pub fn builder(
        app_secret: ApplicationSecret,
        method: InstalledFlowReturnMethod,
    ) -> AuthenticatorBuilder<DefaultHyperClient, InstalledFlow> {
        AuthenticatorBuilder::<DefaultHyperClient, _>::with_auth_flow(
            app_secret,
            InstalledFlow::new(method),
        )
    }
}

pub struct DeviceFlowAuthenticator;
impl DeviceFlowAuthenticator {
    pub fn builder(
        app_secret: ApplicationSecret,
    ) -> AuthenticatorBuilder<DefaultHyperClient, DeviceFlow> {
        AuthenticatorBuilder::<DefaultHyperClient, _>::with_auth_flow(app_secret, DeviceFlow::new())
    }
}

impl<C, F> AuthenticatorBuilder<C, F> {
    fn with_auth_flow(
        app_secret: ApplicationSecret,
        auth_flow: F,
    ) -> AuthenticatorBuilder<DefaultHyperClient, F> {
        AuthenticatorBuilder {
            hyper_client_builder: DefaultHyperClient,
            app_secret,
            auth_delegate: Box::new(DefaultAuthenticatorDelegate),
            storage_type: StorageType::Memory,
            auth_flow,
        }
    }

    /// Use the provided hyper client.
    pub fn hyper_client<NewC>(
        self,
        hyper_client: hyper::Client<NewC>,
    ) -> AuthenticatorBuilder<hyper::Client<NewC>, F> {
        AuthenticatorBuilder {
            hyper_client_builder: hyper_client,
            app_secret: self.app_secret,
            auth_delegate: self.auth_delegate,
            storage_type: self.storage_type,
            auth_flow: self.auth_flow,
        }
    }

    /// Persist tokens to disk in the provided filename.
    pub fn persist_tokens_to_disk<P: Into<PathBuf>>(self, path: P) -> AuthenticatorBuilder<C, F> {
        AuthenticatorBuilder {
            storage_type: StorageType::Disk(path.into()),
            ..self
        }
    }

    /// Use the provided authenticator delegate.
    pub fn auth_delegate(
        self,
        auth_delegate: Box<dyn AuthenticatorDelegate>,
    ) -> AuthenticatorBuilder<C, F> {
        AuthenticatorBuilder {
            auth_delegate,
            ..self
        }
    }

    /// Create the authenticator.
    pub async fn build(self) -> io::Result<Authenticator<C::Connector>>
    where
        C: HyperClientBuilder,
        F: Into<AuthFlow>,
    {
        let hyper_client = self.hyper_client_builder.build_hyper_client();
        let storage = match self.storage_type {
            StorageType::Memory => Storage::Memory {
                tokens: Mutex::new(storage::JSONTokens::new()),
            },
            StorageType::Disk(path) => Storage::Disk(storage::DiskStorage::new(path).await?),
        };

        Ok(Authenticator {
            hyper_client,
            app_secret: self.app_secret,
            storage,
            auth_delegate: self.auth_delegate,
            auth_flow: self.auth_flow.into(),
        })
    }
}

impl<C> AuthenticatorBuilder<C, DeviceFlow> {
    /// Use the provided device code url.
    pub fn device_code_url(self, url: impl Into<Cow<'static, str>>) -> Self {
        AuthenticatorBuilder {
            auth_flow: DeviceFlow {
                device_code_url: url.into(),
                ..self.auth_flow
            },
            ..self
        }
    }

    /// Use the provided FlowDelegate.
    pub fn flow_delegate(self, flow_delegate: Box<dyn FlowDelegate>) -> Self {
        AuthenticatorBuilder {
            auth_flow: DeviceFlow {
                flow_delegate,
                ..self.auth_flow
            },
            ..self
        }
    }

    /// Use the provided wait duration.
    pub fn wait_duration(self, wait_duration: Duration) -> Self {
        AuthenticatorBuilder {
            auth_flow: DeviceFlow {
                wait_duration,
                ..self.auth_flow
            },
            ..self
        }
    }

    /// Use the provided grant type.
    pub fn grant_type(self, grant_type: impl Into<Cow<'static, str>>) -> Self {
        AuthenticatorBuilder {
            auth_flow: DeviceFlow {
                grant_type: grant_type.into(),
                ..self.auth_flow
            },
            ..self
        }
    }
}

impl<C> AuthenticatorBuilder<C, InstalledFlow> {
    /// Use the provided FlowDelegate.
    pub fn flow_delegate(self, flow_delegate: Box<dyn FlowDelegate>) -> Self {
        AuthenticatorBuilder {
            auth_flow: InstalledFlow {
                flow_delegate,
                ..self.auth_flow
            },
            ..self
        }
    }
}

mod private {
    use crate::device::DeviceFlow;
    use crate::installed::InstalledFlow;
    use crate::types::{ApplicationSecret, RequestError, Token};
    pub enum AuthFlow {
        DeviceFlow(DeviceFlow),
        InstalledFlow(InstalledFlow),
    }

    impl From<DeviceFlow> for AuthFlow {
        fn from(device_flow: DeviceFlow) -> AuthFlow {
            AuthFlow::DeviceFlow(device_flow)
        }
    }

    impl From<InstalledFlow> for AuthFlow {
        fn from(installed_flow: InstalledFlow) -> AuthFlow {
            AuthFlow::InstalledFlow(installed_flow)
        }
    }

    impl AuthFlow {
        pub(crate) async fn token<'a, C, T>(
            &'a self,
            hyper_client: &'a hyper::Client<C>,
            app_secret: &'a ApplicationSecret,
            scopes: &'a [T],
        ) -> Result<Token, RequestError>
        where
            T: AsRef<str>,
            C: hyper::client::connect::Connect + 'static,
        {
            match self {
                AuthFlow::DeviceFlow(device_flow) => {
                    device_flow.token(hyper_client, app_secret, scopes).await
                }
                AuthFlow::InstalledFlow(installed_flow) => {
                    installed_flow.token(hyper_client, app_secret, scopes).await
                }
            }
        }
    }
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

enum StorageType {
    Memory,
    Disk(PathBuf),
}
