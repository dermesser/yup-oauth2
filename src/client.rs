use std::time::Duration;

use futures::TryFutureExt;
use http::Uri;
use hyper_util::client::legacy::{connect::Connect, Error as LegacyHyperError};
use thiserror::Error as ThisError;

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
    pub(super) fn new(hyper_client: LegacyClient<C>, timeout: Option<Duration>) -> Self {
        Self {
            client: hyper_client,
            timeout,
        }
    }

    pub(super) fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = Some(timeout);
    }

    /// Execute a get request with the underlying hyper client
    #[doc(hidden)]
    pub async fn get(&self, uri: Uri) -> Result<HyperResponse, hyper_util::client::legacy::Error> {
        self.client.get(uri).await
    }
}

impl<C> SendRequest for HttpClient<C>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    async fn request(&self, payload: http::Request<String>) -> Result<HyperResponse, SendError> {
        let future = self.client.request(payload);
        match self.timeout {
            Some(duration) => {
                tokio::time::timeout(duration, future)
                    .map_err(|_| SendError::Timeout)
                    .await?
            }
            None => future.await,
        }
        .map_err(SendError::Hyper)
    }
}

pub(super) trait SendRequest {
    async fn request(&self, payload: http::Request<String>) -> Result<HyperResponse, SendError>;
}
