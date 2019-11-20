//! Module contianing the core functionality for OAuth2 Authentication.
use crate::authenticator_delegate::{
    AuthenticatorDelegate, DefaultAuthenticatorDelegate, FlowDelegate,
};
use crate::device::DeviceFlow;
use crate::error::Error;
use crate::installed::{InstalledFlow, InstalledFlowReturnMethod};
use crate::refresh::RefreshFlow;
use crate::service_account::{ServiceAccountFlow, ServiceAccountFlowOpts, ServiceAccountKey};
use crate::storage::{self, Storage};
use crate::types::{ApplicationSecret, Token};
use private::AuthFlow;

use std::borrow::Cow;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

/// Authenticator is responsible for fetching tokens, handling refreshing tokens,
/// and optionally persisting tokens to disk.
pub struct Authenticator<C> {
    hyper_client: hyper::Client<C>,
    auth_delegate: Box<dyn AuthenticatorDelegate>,
    storage: Storage,
    auth_flow: AuthFlow,
}

impl<C> Authenticator<C>
where
    C: hyper::client::connect::Connect + 'static,
{
    /// Return the current token for the provided scopes.
    pub async fn token<'a, T>(&'a self, scopes: &'a [T]) -> Result<Token, Error>
    where
        T: AsRef<str>,
    {
        let hashed_scopes = storage::ScopesAndFilter::from(scopes);
        match (self.storage.get(hashed_scopes), self.auth_flow.app_secret()) {
            (Some(t), _) if !t.expired() => {
                // unexpired token found
                Ok(t)
            }
            (
                Some(Token {
                    refresh_token: Some(refresh_token),
                    ..
                }),
                Some(app_secret),
            ) => {
                // token is expired but has a refresh token.
                let token = match RefreshFlow::refresh_token(
                    &self.hyper_client,
                    app_secret,
                    &refresh_token,
                )
                .await
                {
                    Err(err) => {
                        self.auth_delegate.token_refresh_failed(&err);
                        return Err(err.into());
                    }
                    Ok(token) => token,
                };
                self.storage.set(hashed_scopes, token.clone()).await;
                Ok(token)
            }
            _ => {
                // no token in the cache or the token returned can't be refreshed.
                let t = self.auth_flow.token(&self.hyper_client, scopes).await?;
                self.storage.set(hashed_scopes, t.clone()).await;
                Ok(t)
            }
        }
    }
}

/// Configure an Authenticator using the builder pattern.
pub struct AuthenticatorBuilder<C, F> {
    hyper_client_builder: C,
    auth_delegate: Box<dyn AuthenticatorDelegate>,
    storage_type: StorageType,
    auth_flow: F,
}

/// Create an authenticator that uses the installed flow.
/// ```
/// # async fn foo() {
/// # use yup_oauth2::InstalledFlowReturnMethod;
/// # let custom_flow_delegate = yup_oauth2::authenticator_delegate::DefaultFlowDelegate;
/// # let app_secret = yup_oauth2::read_application_secret("/tmp/foo").unwrap();
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
/// # let app_secret = yup_oauth2::read_application_secret("/tmp/foo").unwrap();
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
/// # let service_account_key = yup_oauth2::service_account_key_from_file("/tmp/foo").unwrap();
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
/// # let custom_auth_delegate = yup_oauth2::authenticator_delegate::DefaultAuthenticatorDelegate;
/// # let app_secret = yup_oauth2::read_application_secret("/tmp/foo").unwrap();
///     let authenticator = yup_oauth2::DeviceFlowAuthenticator::builder(app_secret)
///         .hyper_client(custom_hyper_client)
///         .persist_tokens_to_disk("/tmp/tokenfile.json")
///         .auth_delegate(Box::new(custom_auth_delegate))
///         .build()
///         .await
///         .expect("failed to create authenticator");
/// # }
/// ```
impl<C, F> AuthenticatorBuilder<C, F> {
    async fn common_build(
        hyper_client_builder: C,
        storage_type: StorageType,
        auth_delegate: Box<dyn AuthenticatorDelegate>,
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
            auth_delegate,
            auth_flow,
        })
    }

    fn with_auth_flow(auth_flow: F) -> AuthenticatorBuilder<DefaultHyperClient, F> {
        AuthenticatorBuilder {
            hyper_client_builder: DefaultHyperClient,
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
}

/// ## Methods available when building a device flow Authenticator.
/// ```
/// # async fn foo() {
/// # let custom_flow_delegate = yup_oauth2::authenticator_delegate::DefaultFlowDelegate;
/// # let app_secret = yup_oauth2::read_application_secret("/tmp/foo").unwrap();
///     let authenticator = yup_oauth2::DeviceFlowAuthenticator::builder(app_secret)
///         .device_code_url("foo")
///         .flow_delegate(Box::new(custom_flow_delegate))
///         .wait_duration(std::time::Duration::from_secs(120))
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

    /// Create the authenticator.
    pub async fn build(self) -> io::Result<Authenticator<C::Connector>>
    where
        C: HyperClientBuilder,
    {
        Self::common_build(
            self.hyper_client_builder,
            self.storage_type,
            self.auth_delegate,
            AuthFlow::DeviceFlow(self.auth_flow),
        )
        .await
    }
}

/// ## Methods available when building an installed flow Authenticator.
/// ```
/// # async fn foo() {
/// # use yup_oauth2::InstalledFlowReturnMethod;
/// # let custom_flow_delegate = yup_oauth2::authenticator_delegate::DefaultFlowDelegate;
/// # let app_secret = yup_oauth2::read_application_secret("/tmp/foo").unwrap();
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

    /// Create the authenticator.
    pub async fn build(self) -> io::Result<Authenticator<C::Connector>>
    where
        C: HyperClientBuilder,
    {
        Self::common_build(
            self.hyper_client_builder,
            self.storage_type,
            self.auth_delegate,
            AuthFlow::InstalledFlow(self.auth_flow),
        )
        .await
    }
}

/// ## Methods available when building a service account authenticator.
/// ```
/// # async fn foo() {
/// # let service_account_key = yup_oauth2::service_account_key_from_file("/tmp/foo").unwrap();
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
            self.auth_delegate,
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
    use crate::types::{ApplicationSecret, Token};

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
        ) -> Result<Token, Error>
        where
            T: AsRef<str>,
            C: hyper::client::connect::Connect + 'static,
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
    type Connector: hyper::client::connect::Connect + 'static;

    /// Create a hyper::Client
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
