//! Module containing the core functionality for OAuth2 Authentication.
use crate::application_default_credentials::{InstanceMetadataFlow, InstanceMetadataFlowOpts};
use crate::authenticator_delegate::{DeviceFlowDelegate, InstalledFlowDelegate};
use crate::authorized_user::{AuthorizedUserFlow, AuthorizedUserSecret};
use crate::device::DeviceFlow;
use crate::error::Error;
use crate::installed::{InstalledFlow, InstalledFlowReturnMethod};
use crate::refresh::RefreshFlow;
use crate::service_account_impersonator::ServiceAccountImpersonationFlow;

#[cfg(feature = "service_account")]
use crate::service_account::{self, ServiceAccountFlow, ServiceAccountFlowOpts, ServiceAccountKey};
use crate::storage::{self, Storage, TokenStorage};
use crate::types::{AccessToken, ApplicationSecret, TokenInfo};
use private::AuthFlow;

use crate::access_token::AccessTokenFlow;

use futures::lock::Mutex;
use http::Uri;
use hyper::client::connect::Connection;
use std::borrow::Cow;
use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tower_service::Service;

struct InnerAuthenticator<S> {
    hyper_client: hyper::Client<S>,
    storage: Storage,
    auth_flow: AuthFlow,
}

/// Authenticator is responsible for fetching tokens, handling refreshing tokens,
/// and optionally persisting tokens to disk.
#[derive(Clone)]
pub struct Authenticator<S> {
    inner: Arc<InnerAuthenticator<S>>,
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

impl<S> Authenticator<S>
where
    S: Service<Uri> + Clone + Send + Sync + 'static,
    S::Response: Connection + AsyncRead + AsyncWrite + Send + Unpin + 'static,
    S::Future: Send + Unpin + 'static,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    /// Return the current token for the provided scopes.
    pub async fn token<'a, T>(&'a self, scopes: &'a [T]) -> Result<AccessToken, Error>
    where
        T: AsRef<str>,
    {
        self.find_token_info(scopes, /* force_refresh = */ false)
            .await
            .map(|info| info.into())
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
        self.find_token_info(scopes, /* force_refresh = */ true)
            .await
            .map(|info| info.into())
    }

    /// Return the current ID token for the provided scopes, if any
    pub async fn id_token<'a, T>(&'a self, scopes: &'a [T]) -> Result<Option<String>, Error>
    where
        T: AsRef<str>,
    {
        self.find_token_info(scopes, /* force_refresh = */ false)
            .await
            .map(|info| info.id_token)
    }

    /// Return a cached token or fetch a new one from the server.
    async fn find_token_info<'a, T>(
        &'a self,
        scopes: &'a [T],
        force_refresh: bool,
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
    {
        log::debug!(
            "access token requested for scopes: {}",
            DisplayScopes(scopes)
        );
        let hashed_scopes = storage::ScopeSet::from(scopes);
        match (
            self.inner.storage.get(hashed_scopes).await,
            self.inner.auth_flow.app_secret(),
        ) {
            (Some(t), _) if !t.is_expired() && !force_refresh => {
                // unexpired token found
                log::debug!("found valid token in cache: {:?}", t);
                Ok(t)
            }
            (
                Some(TokenInfo {
                    refresh_token: Some(refresh_token),
                    ..
                }),
                Some(app_secret),
            ) => {
                // token is expired but has a refresh token.
                let token_info_result = RefreshFlow::refresh_token(
                    &self.inner.hyper_client,
                    app_secret,
                    &refresh_token,
                )
                .await;
                let token_info = if let Ok(token_info) = token_info_result {
                    token_info
                } else {
                    // token refresh failed.
                    self.inner
                        .auth_flow
                        .token(&self.inner.hyper_client, scopes)
                        .await?
                };
                self.inner
                    .storage
                    .set(hashed_scopes, token_info.clone())
                    .await?;
                Ok(token_info)
            }
            _ => {
                // no token in the cache or the token returned can't be refreshed.
                let token_info = self
                    .inner
                    .auth_flow
                    .token(&self.inner.hyper_client, scopes)
                    .await?;
                self.inner
                    .storage
                    .set(hashed_scopes, token_info.clone())
                    .await?;
                Ok(token_info)
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
/// # #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
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
    #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
    #[cfg_attr(
        yup_oauth2_docsrs,
        doc(cfg(any(feature = "hyper-rustls", feature = "hyper-tls")))
    )]
    pub fn builder(
        app_secret: ApplicationSecret,
        method: InstalledFlowReturnMethod,
    ) -> AuthenticatorBuilder<DefaultHyperClient, InstalledFlow> {
        Self::with_client(app_secret, method, DefaultHyperClient)
    }

    /// Construct a new Authenticator that uses the installed flow and the provided http client.
    pub fn with_client<C>(
        app_secret: ApplicationSecret,
        method: InstalledFlowReturnMethod,
        client: C,
    ) -> AuthenticatorBuilder<C, InstalledFlow> {
        AuthenticatorBuilder::new(InstalledFlow::new(app_secret, method), client)
    }
}

/// Create an authenticator that uses the device flow.
/// ```
/// # #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
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
    #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
    #[cfg_attr(
        yup_oauth2_docsrs,
        doc(cfg(any(feature = "hyper-rustls", feature = "hyper-tls")))
    )]
    pub fn builder(
        app_secret: ApplicationSecret,
    ) -> AuthenticatorBuilder<DefaultHyperClient, DeviceFlow> {
        Self::with_client(app_secret, DefaultHyperClient)
    }

    /// Construct a new Authenticator that uses the installed flow and the provided http client.
    pub fn with_client<C>(
        app_secret: ApplicationSecret,
        client: C,
    ) -> AuthenticatorBuilder<C, DeviceFlow> {
        AuthenticatorBuilder::new(DeviceFlow::new(app_secret), client)
    }
}

/// Create an authenticator that uses a service account.
/// ```
/// # #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
/// # async fn foo() {
/// # let service_account_key = yup_oauth2::read_service_account_key("/tmp/foo").await.unwrap();
///     let authenticator = yup_oauth2::ServiceAccountAuthenticator::builder(service_account_key)
///         .build()
///         .await
///         .expect("failed to create authenticator");
/// # }
/// ```
#[cfg(feature = "service_account")]
pub struct ServiceAccountAuthenticator;

#[cfg(feature = "service_account")]
impl ServiceAccountAuthenticator {
    /// Use the builder pattern to create an Authenticator that uses a service account.
    #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
    #[cfg_attr(
        yup_oauth2_docsrs,
        doc(cfg(any(feature = "hyper-rustls", feature = "hyper-tls")))
    )]
    pub fn builder(
        service_account_key: ServiceAccountKey,
    ) -> AuthenticatorBuilder<DefaultHyperClient, ServiceAccountFlowOpts> {
        Self::with_client(service_account_key, DefaultHyperClient)
    }

    /// Construct a new Authenticator that uses the installed flow and the provided http client.
    pub fn with_client<C>(
        service_account_key: ServiceAccountKey,
        client: C,
    ) -> AuthenticatorBuilder<C, ServiceAccountFlowOpts> {
        AuthenticatorBuilder::new(
            ServiceAccountFlowOpts {
                key: service_account::FlowOptsKey::Key(service_account_key),
                subject: None,
            },
            client,
        )
    }
}

/// Create an authenticator that uses a application default credentials.
/// ```
/// # #[cfg(all(any(feature = "hyper-rustls", feature = "hyper-tls"), feature = "service_account"))]
/// # async fn foo() {
/// #    use yup_oauth2::ApplicationDefaultCredentialsAuthenticator;
/// #    use yup_oauth2::InstanceMetadataFlowOpts;
/// #    use yup_oauth2::authenticator::ApplicationDefaultCredentialsTypes;
///
///     let opts = InstanceMetadataFlowOpts::default();
///     let authenticator = ApplicationDefaultCredentialsAuthenticator::builder(opts)
///        .await
///        .build()
///        .await
///        .expect("failed to build application default credentials authenticator");
/// # }
/// ```
pub struct ApplicationDefaultCredentialsAuthenticator;
impl ApplicationDefaultCredentialsAuthenticator {
    /// Try to build ServiceAccountFlowOpts from the environment
    #[cfg(feature = "service_account")]
    pub async fn from_environment() -> Result<ServiceAccountFlowOpts, std::env::VarError> {
        let key_path = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")?;

        Ok(ServiceAccountFlowOpts {
            key: service_account::FlowOptsKey::Path(key_path.into()),
            subject: None,
        })
    }

    /// Try to build an AuthorizedUserFlow from the application default credentials path.
    pub async fn from_user_credentials() -> Result<AuthorizedUserFlow, Error> {
        let mut path = {
            #[cfg(target_os = "windows")]
            {
                PathBuf::from(std::env::var("APPDATA")?)
            }
            #[cfg(not(target_os = "windows"))]
            {
                let mut path = PathBuf::from(std::env::var("HOME")?);
                path.push(".config");
                path
            }
        };

        path.push("gcloud");
        path.push("application_default_credentials.json");

        let secret = crate::helper::read_authorized_user_secret(&path).await?;
        Ok(AuthorizedUserFlow { secret })
    }

    /// Use the builder pattern to deduce which model of authenticator should be used:
    /// Service account one or GCE instance metadata kind
    #[cfg(feature = "service_account")]
    #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
    #[cfg_attr(
        yup_oauth2_docsrs,
        doc(cfg(any(feature = "hyper-rustls", feature = "hyper-tls")))
    )]
    pub async fn builder(
        opts: InstanceMetadataFlowOpts,
    ) -> ApplicationDefaultCredentialsTypes<DefaultHyperClient> {
        Self::with_client(opts, DefaultHyperClient).await
    }

    /// Use the builder pattern to deduce which model of authenticator should be used and allow providing a hyper client
    #[cfg(feature = "service_account")]
    pub async fn with_client<C>(
        opts: InstanceMetadataFlowOpts,
        client: C,
    ) -> ApplicationDefaultCredentialsTypes<C>
    where
        C: HyperClientBuilder,
    {
        if let Ok(flow_opts) = ApplicationDefaultCredentialsAuthenticator::from_environment().await
        {
            let builder = AuthenticatorBuilder::new(flow_opts, client);
            ApplicationDefaultCredentialsTypes::ServiceAccount(builder)
        } else if let Ok(user_opts) =
            ApplicationDefaultCredentialsAuthenticator::from_user_credentials().await
        {
            let builder = AuthenticatorBuilder::new(user_opts, client);
            ApplicationDefaultCredentialsTypes::AuthorizedUser(builder)
        } else {
            ApplicationDefaultCredentialsTypes::InstanceMetadata(AuthenticatorBuilder::new(
                opts, client,
            ))
        }
    }
}
/// Types of authenticators provided by ApplicationDefaultCredentialsAuthenticator
pub enum ApplicationDefaultCredentialsTypes<C>
where
    C: HyperClientBuilder,
{
    /// Service account based authenticator signature
    #[cfg(feature = "service_account")]
    ServiceAccount(AuthenticatorBuilder<C, ServiceAccountFlowOpts>),
    /// User account authentication
    AuthorizedUser(AuthenticatorBuilder<C, AuthorizedUserFlow>),
    /// GCE Instance Metadata based authenticator signature
    InstanceMetadata(AuthenticatorBuilder<C, InstanceMetadataFlowOpts>),
}

impl<C> ApplicationDefaultCredentialsTypes<C>
where
    C: HyperClientBuilder,
{
    /// Create an authenticator using whichever credentials type was selected.
    pub async fn build(self) -> Result<Authenticator<C::Connector>, Error> {
        match self {
            ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => Ok(auth.build().await?),
            #[cfg(feature = "service_account")]
            ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => Ok(auth.build().await?),
            ApplicationDefaultCredentialsTypes::AuthorizedUser(auth) => Ok(auth.build().await?),
        }
    }
}

/// Create an authenticator that uses a metadata server to access service account credentials.
///
/// Note that this is the final fallback in the Application Default Credentials flow,
/// so you may want to use [`ApplicationDefaultCredentialsAuthenticator`] instead of
/// using this directly.
///
/// ```
/// # #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
/// # async fn foo() {
/// # use yup_oauth2::authenticator::AuthorizedUserAuthenticator;
/// # let secret = yup_oauth2::read_authorized_user_secret("/tmp/foo").await.unwrap();
///     let authenticator = yup_oauth2::InstanceMetadataAuthenticator::builder(Default::default())
///         .build()
///         .await
///         .expect("failed to create authenticator");
/// # }
/// ```
pub struct InstanceMetadataAuthenticator;
impl InstanceMetadataAuthenticator {
    /// Use the builder pattern to create an Authenticator that uses a a metadata server.
    #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
    #[cfg_attr(
        yup_oauth2_docsrs,
        doc(cfg(any(feature = "hyper-rustls", feature = "hyper-tls")))
    )]
    pub fn builder(
        opts: InstanceMetadataFlowOpts,
    ) -> AuthenticatorBuilder<DefaultHyperClient, InstanceMetadataFlowOpts> {
        Self::with_client(opts, DefaultHyperClient)
    }

    /// Construct a new Authenticator that uses the metadata server and the provided http client.
    pub fn with_client<C>(
        opts: InstanceMetadataFlowOpts,
        client: C,
    ) -> AuthenticatorBuilder<C, InstanceMetadataFlowOpts> {
        AuthenticatorBuilder::new(opts, client)
    }
}

/// Create an authenticator that uses an authorized user credentials.
/// ```
/// # #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
/// # async fn foo() {
/// # use yup_oauth2::authenticator::AuthorizedUserAuthenticator;
/// # let secret = yup_oauth2::read_authorized_user_secret("/tmp/foo").await.unwrap();
///     let authenticator = yup_oauth2::AuthorizedUserAuthenticator::builder(secret)
///         .build()
///         .await
///         .expect("failed to create authenticator");
/// # }
/// ```
pub struct AuthorizedUserAuthenticator;
impl AuthorizedUserAuthenticator {
    /// Use the builder pattern to create an Authenticator that uses an authorized user.
    #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
    #[cfg_attr(
        yup_oauth2_docsrs,
        doc(cfg(any(feature = "hyper-rustls", feature = "hyper-tls")))
    )]
    pub fn builder(
        authorized_user_secret: AuthorizedUserSecret,
    ) -> AuthenticatorBuilder<DefaultHyperClient, AuthorizedUserFlow> {
        Self::with_client(authorized_user_secret, DefaultHyperClient)
    }

    /// Construct a new Authenticator that uses the installed flow and the provided http client.
    pub fn with_client<C>(
        authorized_user_secret: AuthorizedUserSecret,
        client: C,
    ) -> AuthenticatorBuilder<C, AuthorizedUserFlow> {
        AuthenticatorBuilder::new(
            AuthorizedUserFlow {
                secret: authorized_user_secret,
            },
            client,
        )
    }
}
/// Create a access token authenticator for use with pre-generated
/// access tokens
/// ```
/// # async fn foo() {
/// #   use yup_oauth2::authenticator::AccessTokenAuthenticator;
/// #   let authenticator = yup_oauth2::AccessTokenAuthenticator::builder("TOKEN".to_string())
/// #     .build()
/// #     .await
/// #     .expect("failed to create authenticator");
/// # }
/// ```
pub struct AccessTokenAuthenticator;
impl AccessTokenAuthenticator {
    /// the builder pattern for the authenticator
    pub fn builder(
        access_token: String,
    ) -> AuthenticatorBuilder<DefaultHyperClient, AccessTokenFlow> {
        Self::with_client(access_token, DefaultHyperClient)
    }
    /// Construct a new Authenticator that uses the installed flow and the provided http client.
    /// the client itself is not used
    pub fn with_client<C>(
        access_token: String,
        client: C,
    ) -> AuthenticatorBuilder<C, AccessTokenFlow> {
        AuthenticatorBuilder::new(
            AccessTokenFlow {
                access_token: access_token,
            },
            client,
        )
    }
}

/// Create a access token authenticator that uses user secrets to impersonate
/// a service account.
///
/// ```
/// # #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
/// # async fn foo() {
/// # use yup_oauth2::authenticator::AuthorizedUserAuthenticator;
/// # let secret = yup_oauth2::read_authorized_user_secret("/tmp/foo").await.unwrap();
/// # let email = "my-test-account@my-test-project.iam.gserviceaccount.com";
///     let authenticator = yup_oauth2::ServiceAccountImpersonationAuthenticator::builder(secret, email)
///         .build()
///         .await
///         .expect("failed to create authenticator");
/// # }
/// ```
pub struct ServiceAccountImpersonationAuthenticator;
impl ServiceAccountImpersonationAuthenticator {
    /// Use the builder pattern to create an Authenticator that uses the device flow.
    #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
    #[cfg_attr(
        yup_oauth2_docsrs,
        doc(cfg(any(feature = "hyper-rustls", feature = "hyper-tls")))
    )]
    pub fn builder(
        authorized_user_secret: AuthorizedUserSecret,
        service_account_email: &str,
    ) -> AuthenticatorBuilder<DefaultHyperClient, ServiceAccountImpersonationFlow> {
        Self::with_client(
            authorized_user_secret,
            service_account_email,
            DefaultHyperClient,
        )
    }

    /// Construct a new Authenticator that uses the installed flow and the provided http client.
    pub fn with_client<C>(
        authorized_user_secret: AuthorizedUserSecret,
        service_account_email: &str,
        client: C,
    ) -> AuthenticatorBuilder<C, ServiceAccountImpersonationFlow> {
        AuthenticatorBuilder::new(
            ServiceAccountImpersonationFlow::new(authorized_user_secret, service_account_email),
            client,
        )
    }
}

/// ## Methods available when building any Authenticator.
/// ```
/// # #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
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
            StorageType::Custom(custom_store) => Storage::Custom(custom_store),
        };

        Ok(Authenticator {
            inner: Arc::new(InnerAuthenticator {
                hyper_client,
                storage,
                auth_flow,
            }),
        })
    }

    fn new(auth_flow: F, hyper_client_builder: C) -> AuthenticatorBuilder<C, F> {
        AuthenticatorBuilder {
            hyper_client_builder,
            storage_type: StorageType::Memory,
            auth_flow,
        }
    }

    /// Use the provided token storage mechanism
    pub fn with_storage(self, storage: Box<dyn TokenStorage>) -> Self {
        AuthenticatorBuilder {
            storage_type: StorageType::Custom(storage),
            ..self
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
/// # #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
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
/// # #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
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
/// # #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
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
#[cfg(feature = "service_account")]
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
        let service_account_auth_flow = ServiceAccountFlow::new(self.auth_flow).await?;
        Self::common_build(
            self.hyper_client_builder,
            self.storage_type,
            AuthFlow::ServiceAccountFlow(service_account_auth_flow),
        )
        .await
    }
}

impl<C> AuthenticatorBuilder<C, InstanceMetadataFlowOpts> {
    /// Create the authenticator.
    pub async fn build(self) -> io::Result<Authenticator<C::Connector>>
    where
        C: HyperClientBuilder,
    {
        let instance_metadata_flow = InstanceMetadataFlow::new(self.auth_flow);
        Self::common_build(
            self.hyper_client_builder,
            self.storage_type,
            AuthFlow::ApplicationDefaultCredentialsFlow(instance_metadata_flow),
        )
        .await
    }
}

/// ## Methods available when building an authorized user flow Authenticator.
impl<C> AuthenticatorBuilder<C, AuthorizedUserFlow> {
    /// Create the authenticator.
    pub async fn build(self) -> io::Result<Authenticator<C::Connector>>
    where
        C: HyperClientBuilder,
    {
        Self::common_build(
            self.hyper_client_builder,
            self.storage_type,
            AuthFlow::AuthorizedUserFlow(self.auth_flow),
        )
        .await
    }
}

/// ## Methods available when building a service account impersonation Authenticator.
impl<C> AuthenticatorBuilder<C, ServiceAccountImpersonationFlow> {
    /// Create the authenticator.
    pub async fn build(self) -> io::Result<Authenticator<C::Connector>>
    where
        C: HyperClientBuilder,
    {
        Self::common_build(
            self.hyper_client_builder,
            self.storage_type,
            AuthFlow::ServiceAccountImpersonationFlow(self.auth_flow),
        )
        .await
    }

    /// Configure this authenticator to impersonate an ID token (rather an an access token,
    /// as is the default).
    ///
    /// For more on impersonating ID tokens, see [google's docs](https://cloud.google.com/iam/docs/create-short-lived-credentials-direct#sa-credentials-oidc).
    pub fn request_id_token(mut self) -> Self {
        self.auth_flow.access_token = false;
        self
    }
}

/// ## Methods available when building an access token flow Authenticator.
impl<C> AuthenticatorBuilder<C, AccessTokenFlow> {
    /// Create the authenticator.
    pub async fn build(self) -> io::Result<Authenticator<C::Connector>>
    where
        C: HyperClientBuilder,
    {
        Self::common_build(
            self.hyper_client_builder,
            self.storage_type,
            AuthFlow::AccessTokenFlow(self.auth_flow),
        )
        .await
    }
}
mod private {
    use crate::access_token::AccessTokenFlow;
    use crate::application_default_credentials::InstanceMetadataFlow;
    use crate::authenticator::{AsyncRead, AsyncWrite, Connection, Service, StdError, Uri};
    use crate::authorized_user::AuthorizedUserFlow;
    use crate::device::DeviceFlow;
    use crate::error::Error;
    use crate::installed::InstalledFlow;
    #[cfg(feature = "service_account")]
    use crate::service_account::ServiceAccountFlow;
    use crate::service_account_impersonator::ServiceAccountImpersonationFlow;
    use crate::types::{ApplicationSecret, TokenInfo};

    pub enum AuthFlow {
        DeviceFlow(DeviceFlow),
        InstalledFlow(InstalledFlow),
        #[cfg(feature = "service_account")]
        ServiceAccountFlow(ServiceAccountFlow),
        ServiceAccountImpersonationFlow(ServiceAccountImpersonationFlow),
        ApplicationDefaultCredentialsFlow(InstanceMetadataFlow),
        AuthorizedUserFlow(AuthorizedUserFlow),
        AccessTokenFlow(AccessTokenFlow),
    }

    impl AuthFlow {
        pub(crate) fn app_secret(&self) -> Option<&ApplicationSecret> {
            match self {
                AuthFlow::DeviceFlow(device_flow) => Some(&device_flow.app_secret),
                AuthFlow::InstalledFlow(installed_flow) => Some(&installed_flow.app_secret),
                #[cfg(feature = "service_account")]
                AuthFlow::ServiceAccountFlow(_) => None,
                AuthFlow::ServiceAccountImpersonationFlow(_) => None,
                AuthFlow::ApplicationDefaultCredentialsFlow(_) => None,
                AuthFlow::AuthorizedUserFlow(_) => None,
                AuthFlow::AccessTokenFlow(_) => None,
            }
        }

        pub(crate) async fn token<'a, S, T>(
            &'a self,
            hyper_client: &'a hyper::Client<S>,
            scopes: &'a [T],
        ) -> Result<TokenInfo, Error>
        where
            T: AsRef<str>,
            S: Service<Uri> + Clone + Send + Sync + 'static,
            S::Response: Connection + AsyncRead + AsyncWrite + Send + Unpin + 'static,
            S::Future: Send + Unpin + 'static,
            S::Error: Into<Box<dyn StdError + Send + Sync>>,
        {
            match self {
                AuthFlow::DeviceFlow(device_flow) => device_flow.token(hyper_client, scopes).await,
                AuthFlow::InstalledFlow(installed_flow) => {
                    installed_flow.token(hyper_client, scopes).await
                }
                #[cfg(feature = "service_account")]
                AuthFlow::ServiceAccountFlow(service_account_flow) => {
                    service_account_flow.token(hyper_client, scopes).await
                }
                AuthFlow::ServiceAccountImpersonationFlow(service_account_impersonation_flow) => {
                    service_account_impersonation_flow
                        .token(hyper_client, scopes)
                        .await
                }
                AuthFlow::ApplicationDefaultCredentialsFlow(adc_flow) => {
                    adc_flow.token(hyper_client, scopes).await
                }
                AuthFlow::AuthorizedUserFlow(authorized_user_flow) => {
                    authorized_user_flow.token(hyper_client, scopes).await
                }
                AuthFlow::AccessTokenFlow(access_token_flow) => {
                    access_token_flow.token(hyper_client, scopes).await
                }
            }
        }
    }
}

/// A trait implemented for any hyper::Client as well as the DefaultHyperClient.
pub trait HyperClientBuilder {
    /// The hyper connector that the resulting hyper client will use.
    type Connector: Service<Uri> + Clone + Send + Sync + 'static;

    /// Create a hyper::Client
    fn build_hyper_client(self) -> hyper::Client<Self::Connector>;

    /// Create a `hyper::Client` for tests (HTTPS not required)
    #[doc(hidden)]
    fn build_test_hyper_client(self) -> hyper::Client<Self::Connector>;
}

#[cfg(feature = "hyper-rustls")]
#[cfg_attr(
    yup_oauth2_docsrs,
    doc(cfg(any(feature = "hyper-rustls", feature = "hyper-tls")))
)]
/// Default authenticator type
pub type DefaultAuthenticator =
    Authenticator<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>;

#[cfg(all(not(feature = "hyper-rustls"), feature = "hyper-tls"))]
#[cfg_attr(
    yup_oauth2_docsrs,
    doc(cfg(any(feature = "hyper-rustls", feature = "hyper-tls")))
)]
/// Default authenticator type
pub type DefaultAuthenticator =
    Authenticator<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>;

/// The builder value used when the default hyper client should be used.
#[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
#[cfg_attr(
    yup_oauth2_docsrs,
    doc(cfg(any(feature = "hyper-rustls", feature = "hyper-tls")))
)]
pub struct DefaultHyperClient;

#[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
#[cfg_attr(
    yup_oauth2_docsrs,
    doc(cfg(any(feature = "hyper-rustls", feature = "hyper-tls")))
)]
impl HyperClientBuilder for DefaultHyperClient {
    #[cfg(feature = "hyper-rustls")]
    type Connector = hyper_rustls::HttpsConnector<hyper::client::connect::HttpConnector>;
    #[cfg(all(not(feature = "hyper-rustls"), feature = "hyper-tls"))]
    type Connector = hyper_tls::HttpsConnector<hyper::client::connect::HttpConnector>;

    fn build_hyper_client(self) -> hyper::Client<Self::Connector> {
        #[cfg(feature = "hyper-rustls")]
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        #[cfg(all(not(feature = "hyper-rustls"), feature = "hyper-tls"))]
        let connector = hyper_tls::HttpsConnector::new();

        hyper::Client::builder()
            .pool_max_idle_per_host(0)
            .build::<_, hyper::Body>(connector)
    }

    fn build_test_hyper_client(self) -> hyper::Client<Self::Connector> {
        #[cfg(feature = "hyper-rustls")]
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        #[cfg(all(not(feature = "hyper-rustls"), feature = "hyper-tls"))]
        let connector = hyper_tls::HttpsConnector::new();

        hyper::Client::builder()
            .pool_max_idle_per_host(0)
            .build::<_, hyper::Body>(connector)
    }
}

impl<S> HyperClientBuilder for hyper::Client<S>
where
    S: Service<Uri> + Clone + Send + Sync + 'static,
    S::Response: Connection + AsyncRead + AsyncWrite + Send + Unpin + 'static,
    S::Future: Send + Unpin + 'static,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    type Connector = S;

    fn build_hyper_client(self) -> hyper::Client<S> {
        self
    }

    fn build_test_hyper_client(self) -> hyper::Client<Self::Connector> {
        self
    }
}

/// How should the acquired tokens be stored?
enum StorageType {
    /// Store tokens in memory (and always log in again to acquire a new token on startup)
    Memory,
    /// Store tokens to disk in the given file. Warning, this may be insecure unless you configure your operating system to restrict read access to the file.
    Disk(PathBuf),
    /// Implement your own storage provider
    Custom(Box<dyn TokenStorage>),
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(any(feature = "hyper-rustls", feature = "hyper-tls"))]
    fn ensure_send_sync() {
        use super::*;
        fn is_send_sync<T: Send + Sync>() {}
        is_send_sync::<Authenticator<<DefaultHyperClient as HyperClientBuilder>::Connector>>()
    }
}
