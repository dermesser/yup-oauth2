//! Module contianing the core functionality for OAuth2 Authentication.
use crate::authenticator_delegate::{DeviceFlowDelegate, InstalledFlowDelegate};
use crate::device::DeviceFlow;
use crate::error::Error;
use crate::installed::{InstalledFlow, InstalledFlowReturnMethod};
use crate::refresh::RefreshFlow;
use crate::service_account::{ServiceAccountFlow, ServiceAccountFlowOpts, ServiceAccountKey};
use crate::storage::{self, Storage};
use crate::types::{AccessToken, ApplicationSecret, TokenInfo};
use private::AuthFlow;

use futures::lock::Mutex;
use std::borrow::Cow;
use std::fmt;
use std::io;
use std::path::PathBuf;

/// Authenticator is responsible for fetching tokens, handling refreshing tokens,
/// and optionally persisting tokens to disk.
pub struct Authenticator<C> {
    hyper_client: hyper::Client<C>,
    storage: Storage,
    auth_flow: AuthFlow,
}

struct DisplayScopes<'a, T>(&'a [T]);
impl<'a, T> fmt::Display for DisplayScopes<'a, T>
where
    T: AsRef<str>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("[")?;
        let mut iter = self.0.iter();
        if let Some(first) = iter.next() {
            f.write_str(first.as_ref())?;
            for scope in iter {
                f.write_str(", ")?;
                f.write_str(scope.as_ref())?;
            }
        }
        f.write_str("]")
    }
}

impl<C> Authenticator<C>
where
    C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
{
    /// Return the current token for the provided scopes.
    pub async fn token<'a, T>(&'a self, scopes: &'a [T]) -> Result<AccessToken, Error>
    where
        T: AsRef<str>,
    {
        self.find_token(scopes, /* force_refresh = */ false).await
    }

    /// Return a token for the provided scopes, but don't reuse cached tokens. Instead,
    /// always fetch a new token from the OAuth server.
    pub async fn force_refreshed_token<'a, T>(
        &'a self,
        scopes: &'a [T],
    ) -> Result<AccessToken, Error>
    where
        T: AsRef<str>,
    {
        self.find_token(scopes, /* force_refresh = */ true).await
    }

    /// Return a cached token or fetch a new one from the server.
    async fn find_token<'a, T>(
        &'a self,
        scopes: &'a [T],
        force_refresh: bool,
    ) -> Result<AccessToken, Error>
    where
        T: AsRef<str>,
    {
        log::debug!(
            "access token requested for scopes: {}",
            DisplayScopes(scopes)
        );
        let hashed_scopes = storage::ScopeSet::from(scopes);
        match (
            self.storage.get(hashed_scopes).await,
            self.auth_flow.app_secret(),
        ) {
            (Some(t), _) if !t.is_expired() && !force_refresh => {
                // unexpired token found
                log::debug!("found valid token in cache: {:?}", t);
                Ok(t.into())
            }
            (
                Some(TokenInfo {
                    refresh_token: Some(refresh_token),
                    ..
                }),
                Some(app_secret),
            ) => {
                // token is expired but has a refresh token.
                let token_info =
                    RefreshFlow::refresh_token(&self.hyper_client, app_secret, &refresh_token)
                        .await?;
                self.storage.set(hashed_scopes, token_info.clone()).await?;
                Ok(token_info.into())
            }
            _ => {
                // no token in the cache or the token returned can't be refreshed.
                let token_info = self.auth_flow.token(&self.hyper_client, scopes).await?;
                self.storage.set(hashed_scopes, token_info.clone()).await?;
                Ok(token_info.into())
            }
        }
    }
}

/// Configure an Authenticator using the builder pattern.
pub struct AuthenticatorBuilder<C, F> {
    hyper_client_builder: C,
    storage_type: StorageType,
    auth_flow: F,
}

/// Create an authenticator that uses the installed flow.
/// ```
/// # async fn foo() {
/// # use yup_oauth2::InstalledFlowReturnMethod;
/// # let custom_flow_delegate = yup_oauth2::authenticator_delegate::DefaultInstalledFlowDelegate;
/// # let app_secret = yup_oauth2::read_application_secret("/tmp/foo").await.unwrap();
///     let authenticator = yup_oauth2::InstalledFlowAuthenticator::builder(
///         app_secret,
///         InstalledFlowReturnMethod::HTTPRedirect,
///     )
///     .build()
///     .await
///     .expect("failed to create authenticator");
/// # }
/// ```
pub struct InstalledFlowAuthenticator;
impl InstalledFlowAuthenticator {
    /// Use the builder pattern to create an Authenticator that uses the installed flow.
    pub fn builder(
        app_secret: ApplicationSecret,
        method: InstalledFlowReturnMethod,
    ) -> AuthenticatorBuilder<DefaultHyperClient, InstalledFlow> {
        AuthenticatorBuilder::<DefaultHyperClient, _>::with_auth_flow(InstalledFlow::new(
            app_secret, method,
        ))
    }
}

/// Create an authenticator that uses the device flow.
/// ```
/// # async fn foo() {
/// # let app_secret = yup_oauth2::read_application_secret("/tmp/foo").await.unwrap();
///     let authenticator = yup_oauth2::DeviceFlowAuthenticator::builder(app_secret)
///         .build()
///         .await
///         .expect("failed to create authenticator");
/// # }
/// ```
pub struct DeviceFlowAuthenticator;
impl DeviceFlowAuthenticator {
    /// Use the builder pattern to create an Authenticator that uses the device flow.
    pub fn builder(
        app_secret: ApplicationSecret,
    ) -> AuthenticatorBuilder<DefaultHyperClient, DeviceFlow> {
        AuthenticatorBuilder::<DefaultHyperClient, _>::with_auth_flow(DeviceFlow::new(app_secret))
    }
}

/// Create an authenticator that uses a service account.
/// ```
/// # async fn foo() {
/// # let service_account_key = yup_oauth2::read_service_account_key("/tmp/foo").await.unwrap();
///     let authenticator = yup_oauth2::ServiceAccountAuthenticator::builder(service_account_key)
///         .build()
///         .await
///         .expect("failed to create authenticator");
/// # }
/// ```
pub struct ServiceAccountAuthenticator;
impl ServiceAccountAuthenticator {
    /// Use the builder pattern to create an Authenticator that uses a service account.
    pub fn builder(
        service_account_key: ServiceAccountKey,
    ) -> AuthenticatorBuilder<DefaultHyperClient, ServiceAccountFlowOpts> {
        AuthenticatorBuilder::<DefaultHyperClient, _>::with_auth_flow(ServiceAccountFlowOpts {
            key: service_account_key,
            subject: None,
        })
    }
}

/// ## Methods available when building any Authenticator.
/// ```
/// # async fn foo() {
/// # let custom_hyper_client = hyper::Client::new();
/// # let app_secret = yup_oauth2::read_application_secret("/tmp/foo").await.unwrap();
///     let authenticator = yup_oauth2::DeviceFlowAuthenticator::builder(app_secret)
///         .hyper_client(custom_hyper_client)
///         .persist_tokens_to_disk("/tmp/tokenfile.json")
///         .build()
///         .await
///         .expect("failed to create authenticator");
/// # }
/// ```
impl<C, F> AuthenticatorBuilder<C, F> {
    async fn common_build(
        hyper_client_builder: C,
        storage_type: StorageType,
        auth_flow: AuthFlow,
    ) -> io::Result<Authenticator<C::Connector>>
    where
        C: HyperClientBuilder,
    {
        let hyper_client = hyper_client_builder.build_hyper_client();
        let storage = match storage_type {
            StorageType::Memory => Storage::Memory {
                tokens: Mutex::new(storage::JSONTokens::new()),
            },
            StorageType::Disk(path) => Storage::Disk(storage::DiskStorage::new(path).await?),
        };

        Ok(Authenticator {
            hyper_client,
            storage,
            auth_flow,
        })
    }

    fn with_auth_flow(auth_flow: F) -> AuthenticatorBuilder<DefaultHyperClient, F> {
        AuthenticatorBuilder {
            hyper_client_builder: DefaultHyperClient,
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
}

/// ## Methods available when building a device flow Authenticator.
/// ```
/// # async fn foo() {
/// # let custom_flow_delegate = yup_oauth2::authenticator_delegate::DefaultDeviceFlowDelegate;
/// # let app_secret = yup_oauth2::read_application_secret("/tmp/foo").await.unwrap();
///     let authenticator = yup_oauth2::DeviceFlowAuthenticator::builder(app_secret)
///         .device_code_url("foo")
///         .flow_delegate(Box::new(custom_flow_delegate))
///         .grant_type("foo")
///         .build()
///         .await
///         .expect("failed to create authenticator");
/// # }
/// ```
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

    /// Use the provided DeviceFlowDelegate.
    pub fn flow_delegate(self, flow_delegate: Box<dyn DeviceFlowDelegate>) -> Self {
        AuthenticatorBuilder {
            auth_flow: DeviceFlow {
                flow_delegate,
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

    /// Create the authenticator.
    pub async fn build(self) -> io::Result<Authenticator<C::Connector>>
    where
        C: HyperClientBuilder,
    {
        Self::common_build(
            self.hyper_client_builder,
            self.storage_type,
            AuthFlow::DeviceFlow(self.auth_flow),
        )
        .await
    }
}

/// ## Methods available when building an installed flow Authenticator.
/// ```
/// # async fn foo() {
/// # use yup_oauth2::InstalledFlowReturnMethod;
/// # let custom_flow_delegate = yup_oauth2::authenticator_delegate::DefaultInstalledFlowDelegate;
/// # let app_secret = yup_oauth2::read_application_secret("/tmp/foo").await.unwrap();
///     let authenticator = yup_oauth2::InstalledFlowAuthenticator::builder(
///         app_secret,
///         InstalledFlowReturnMethod::HTTPRedirect,
///     )
///     .flow_delegate(Box::new(custom_flow_delegate))
///     .build()
///     .await
///     .expect("failed to create authenticator");
/// # }
/// ```
impl<C> AuthenticatorBuilder<C, InstalledFlow> {
    /// Use the provided InstalledFlowDelegate.
    pub fn flow_delegate(self, flow_delegate: Box<dyn InstalledFlowDelegate>) -> Self {
        AuthenticatorBuilder {
            auth_flow: InstalledFlow {
                flow_delegate,
                ..self.auth_flow
            },
            ..self
        }
    }

    /// Create the authenticator.
    pub async fn build(self) -> io::Result<Authenticator<C::Connector>>
    where
        C: HyperClientBuilder,
    {
        Self::common_build(
            self.hyper_client_builder,
            self.storage_type,
            AuthFlow::InstalledFlow(self.auth_flow),
        )
        .await
    }
}

/// ## Methods available when building a service account authenticator.
/// ```
/// # async fn foo() {
/// # let service_account_key = yup_oauth2::read_service_account_key("/tmp/foo").await.unwrap();
///     let authenticator = yup_oauth2::ServiceAccountAuthenticator::builder(
///         service_account_key,
///     )
///     .subject("mysubject")
///     .build()
///     .await
///     .expect("failed to create authenticator");
/// # }
/// ```
impl<C> AuthenticatorBuilder<C, ServiceAccountFlowOpts> {
    /// Use the provided subject.
    pub fn subject(self, subject: impl Into<String>) -> Self {
        AuthenticatorBuilder {
            auth_flow: ServiceAccountFlowOpts {
                subject: Some(subject.into()),
                ..self.auth_flow
            },
            ..self
        }
    }

    /// Create the authenticator.
    pub async fn build(self) -> io::Result<Authenticator<C::Connector>>
    where
        C: HyperClientBuilder,
    {
        let service_account_auth_flow = ServiceAccountFlow::new(self.auth_flow)?;
        Self::common_build(
            self.hyper_client_builder,
            self.storage_type,
            AuthFlow::ServiceAccountFlow(service_account_auth_flow),
        )
        .await
    }
}

mod private {
    use crate::device::DeviceFlow;
    use crate::error::Error;
    use crate::installed::InstalledFlow;
    use crate::service_account::ServiceAccountFlow;
    use crate::types::{ApplicationSecret, TokenInfo};

    pub enum AuthFlow {
        DeviceFlow(DeviceFlow),
        InstalledFlow(InstalledFlow),
        ServiceAccountFlow(ServiceAccountFlow),
    }

    impl AuthFlow {
        pub(crate) fn app_secret(&self) -> Option<&ApplicationSecret> {
            match self {
                AuthFlow::DeviceFlow(device_flow) => Some(&device_flow.app_secret),
                AuthFlow::InstalledFlow(installed_flow) => Some(&installed_flow.app_secret),
                AuthFlow::ServiceAccountFlow(_) => None,
            }
        }

        pub(crate) async fn token<'a, C, T>(
            &'a self,
            hyper_client: &'a hyper::Client<C>,
            scopes: &'a [T],
        ) -> Result<TokenInfo, Error>
        where
            T: AsRef<str>,
            C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
        {
            match self {
                AuthFlow::DeviceFlow(device_flow) => device_flow.token(hyper_client, scopes).await,
                AuthFlow::InstalledFlow(installed_flow) => {
                    installed_flow.token(hyper_client, scopes).await
                }
                AuthFlow::ServiceAccountFlow(service_account_flow) => {
                    service_account_flow.token(hyper_client, scopes).await
                }
            }
        }
    }
}

/// A trait implemented for any hyper::Client as well as the DefaultHyperClient.
pub trait HyperClientBuilder {
    /// The hyper connector that the resulting hyper client will use.
    type Connector: hyper::client::connect::Connect + Clone + Send + Sync + 'static;

    /// Create a hyper::Client
    fn build_hyper_client(self) -> hyper::Client<Self::Connector>;
}

#[cfg(not(feature = "hyper-tls"))]
/// Default authenticator type
pub type DefaultAuthenticator =
    Authenticator<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>;
#[cfg(feature = "hyper-tls")]
/// Default authenticator type
pub type DefaultAuthenticator =
    Authenticator<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>;

/// The builder value used when the default hyper client should be used.
pub struct DefaultHyperClient;
impl HyperClientBuilder for DefaultHyperClient {
    #[cfg(not(feature = "hyper-tls"))]
    type Connector = hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>;
    #[cfg(feature = "hyper-tls")]
    type Connector = hyper_tls::HttpsConnector<hyper::client::connect::HttpConnector>;

    fn build_hyper_client(self) -> hyper::Client<Self::Connector> {
        #[cfg(not(feature = "hyper-tls"))]
        let connector = hyper_rustls::HttpsConnector::with_native_roots();
        #[cfg(feature = "hyper-tls")]
        let connector = hyper_tls::HttpsConnector::new();

        hyper::Client::builder()
            .pool_max_idle_per_host(0)
            .build::<_, hyper::Body>(connector)
    }
}

impl<C> HyperClientBuilder for hyper::Client<C>
where
    C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_send_sync() {
        fn is_send_sync<T: Send + Sync>() {}
        is_send_sync::<Authenticator<<DefaultHyperClient as HyperClientBuilder>::Connector>>()
    }
}
