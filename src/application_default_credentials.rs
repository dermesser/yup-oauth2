use crate::error::Error;
use crate::types::TokenInfo;
use http_body_util::BodyExt;
use hyper_util::client::legacy::connect::Connect;

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

    pub(crate) async fn token<C, T>(
        &self,
        hyper_client: &hyper_util::client::legacy::Client<C, String>,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        C: Connect + Clone + Send + Sync + 'static,
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
