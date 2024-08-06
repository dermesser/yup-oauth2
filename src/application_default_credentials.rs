use crate::client::SendRequest;
use crate::error::Error;
use crate::types::TokenInfo;
use http_body_util::BodyExt;

/// Provide options for the Application Default Credential Flow, mostly used for testing
#[derive(Default, Clone, Debug)]
pub struct ApplicationDefaultCredentialsFlowOpts {
    /// Used as base to build the url during token request from GCP metadata server
    pub metadata_url: Option<String>,
}

pub struct ApplicationDefaultCredentialsFlow {
    metadata_url: String,
}

impl ApplicationDefaultCredentialsFlow {
    pub(crate) fn new(opts: ApplicationDefaultCredentialsFlowOpts) -> Self {
        let metadata_url = opts.metadata_url.unwrap_or_else(|| "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token".to_string());
        ApplicationDefaultCredentialsFlow { metadata_url }
    }

    pub(crate) async fn token<T>(
        &self,
        hyper_client: &impl SendRequest,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
    {
        let scope = crate::helper::join(scopes, ",");
        let token_uri = format!("{}?scopes={}", self.metadata_url, scope);
        let request = http::Request::get(token_uri)
            .header("Metadata-Flavor", "Google")
            .body(String::new()) // why body is needed?
            .unwrap();
        log::debug!("requesting token from metadata server: {:?}", request);
        let (head, body) = hyper_client.request(request).await?.into_parts();
        let body = body.collect().await?.to_bytes();
        log::debug!("received response; head: {:?}, body: {:?}", head, body);
        TokenInfo::from_json(&body)
    }
}

// eof
