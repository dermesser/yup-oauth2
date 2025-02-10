//! Module containing the HTTP client used for sending requests
use std::time::Duration;

use http::Uri;
use hyper_util::client::legacy::{connect::Connect, Error as LegacyHyperError};
#[cfg(all(feature = "aws-lc-rs", any(feature = "hyper-rustls", feature = "hyper-rustls-webpki"), not(feature = "ring")))]
use rustls::crypto::aws_lc_rs::default_provider as default_crypto_provider;
#[cfg(all(feature = "ring", any(feature = "hyper-rustls", feature = "hyper-rustls-webpki")))]
use rustls::crypto::ring::default_provider as default_crypto_provider;
#[cfg(all(
    feature = "hyper-rustls",
    not(any(feature = "ring", feature = "aws-lc-rs"))
))]
compile_error!(
    "The `hyper-rustls` feature requires either the `ring` or `aws-lc-rs` feature to be enabled"
);
use thiserror::Error as ThisError;

use crate::Error;

type HyperResponse = http::Response<hyper::body::Incoming>;
pub(crate) type LegacyClient<C> = hyper_util::client::legacy::Client<C, String>;

#[derive(Debug, ThisError)]
/// Errors that can happen when a request is sent
pub enum SendError {
    /// Request could not complete before timeout elapsed
    #[error("Request timed out")]
    Timeout,
    /// Wrapper for hyper errors
    #[error("Hyper error: {0}")]
    Hyper(#[source] LegacyHyperError),
}

/// A trait implemented for any hyper_util::client::legacy::Client as well as the DefaultHyperClient.
pub trait HyperClientBuilder {
    /// The hyper connector that the resulting hyper client will use.
    type Connector: Connect + Clone + Send + Sync + 'static;

    /// Sets duration after which a request times out
    fn with_timeout(self, timeout: Duration) -> Self;

    /// Create a hyper::Client
    fn build_hyper_client(self) -> Result<HttpClient<Self::Connector>, Error>;
}

/// Client that can be configured that a request will timeout after a specified
/// duration.
#[derive(Clone)]
pub struct HttpClient<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    client: LegacyClient<C>,
    timeout: Option<Duration>,
}

impl<C> HttpClient<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    pub(crate) fn new(hyper_client: LegacyClient<C>, timeout: Option<Duration>) -> Self {
        Self {
            client: hyper_client,
            timeout,
        }
    }

    pub(crate) fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = Some(timeout);
    }

    /// Execute a get request with the underlying hyper client
    #[doc(hidden)]
    pub async fn get(&self, uri: Uri) -> Result<HyperResponse, hyper_util::client::legacy::Error> {
        self.client.get(uri).await
    }
}

impl<C> HyperClientBuilder for HttpClient<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    type Connector = C;

    fn with_timeout(mut self, timeout: Duration) -> Self {
        self.set_timeout(timeout);
        self
    }

    fn build_hyper_client(self) -> Result<HttpClient<Self::Connector>, Error> {
        Ok(self)
    }
}

impl<C> SendRequest for HttpClient<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    async fn request(&self, payload: http::Request<String>) -> Result<HyperResponse, SendError> {
        let future = self.client.request(payload);
        match self.timeout {
            Some(duration) => tokio::time::timeout(duration, future)
                .await
                .map_err(|_| SendError::Timeout)?,
            None => future.await,
        }
        .map_err(SendError::Hyper)
    }
}

pub(crate) trait SendRequest {
    async fn request(&self, payload: http::Request<String>) -> Result<HyperResponse, SendError>;
}

/// The builder value used when the default hyper client should be used.
#[cfg(any(feature = "hyper-rustls", feature = "hyper-tls", feature = "hyper-rustls-webpki"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "hyper-rustls", feature = "hyper-tls", feature = "hyper-rustls-webpki"))))]
#[derive(Default)]
pub struct DefaultHyperClientBuilder {
    timeout: Option<Duration>,
}

#[cfg(any(feature = "hyper-rustls", feature = "hyper-tls", feature = "hyper-rustls-webpki"))]
impl DefaultHyperClientBuilder {
    /// Set the duration after which a request times out
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

#[cfg(any(feature = "hyper-rustls", feature = "hyper-tls", feature = "hyper-rustls-webpki"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "hyper-rustls", feature = "hyper-tls", feature = "hyper-rustls-webpki"))))]
impl HyperClientBuilder for DefaultHyperClientBuilder {
    #[cfg(any(feature = "hyper-rustls", feature = "hyper-rustls-webpki"))]
    type Connector =
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;
    #[cfg(all(not(feature = "hyper-rustls"), not(feature = "hyper-rustls-webpki"), feature = "hyper-tls"))]
    type Connector = hyper_tls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;

    fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    fn build_hyper_client(self) -> Result<HttpClient<Self::Connector>, Error> {
        #[cfg(feature = "hyper-rustls")]
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(default_crypto_provider())?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        #[cfg(feature = "hyper-rustls-webpki")]
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(default_crypto_provider())?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        #[cfg(all(not(feature = "hyper-rustls"), not(feature = "hyper-rustls-webpki"), feature = "hyper-tls"))]
        let connector = hyper_tls::HttpsConnector::new();

        Ok(HttpClient::new(
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .pool_max_idle_per_host(0)
                .build::<_, String>(connector),
            self.timeout,
        ))
    }
}

/// Intended for using an existing hyper client with `yup-oauth2`. Instantiate
/// with [`CustomHyperClientBuilder::from`]
pub struct CustomHyperClientBuilder<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    client: HttpClient<C>,
    timeout: Option<Duration>,
}

impl<C> From<LegacyClient<C>> for CustomHyperClientBuilder<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    fn from(client: LegacyClient<C>) -> Self {
        Self {
            client: HttpClient::new(client, None),
            timeout: None,
        }
    }
}

impl<C> HyperClientBuilder for CustomHyperClientBuilder<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    type Connector = C;

    fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    fn build_hyper_client(self) -> Result<HttpClient<Self::Connector>, Error> {
        Ok(self.client)
    }
}
