//! This example demonstrates how to use the same connection pool for both obtaining the tokens and
//! using the API that these tokens authorize. In most cases e.g. obtaining the service account key
//! will already establish a keep-alive http connection, so the succeeding API call should be much
//! faster.
//!
//! It is also a better use of resources (memory, sockets, etc.)

use std::error::Error as StdError;

use http::Uri;
use hyper::client::connect::Connection;
use tokio::io::{AsyncRead, AsyncWrite};
use tower_service::Service;

async fn r#use<S>(
    client: hyper::Client<S>,
    authenticator: yup_oauth2::authenticator::Authenticator<S>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: Service<Uri> + Clone + Send + Sync + 'static,
    S::Response: Connection + AsyncRead + AsyncWrite + Send + Unpin + 'static,
    S::Future: Send + Unpin + 'static,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let access_token = authenticator.token(&["email"]).await?;
    let request = http::Request::get("https://example.com")
        .header(
            http::header::AUTHORIZATION,
            format!("Bearer {}", access_token.token().ok_or("no access token")?),
        )
        .body(hyper::body::Body::empty())?;
    let response = client.request(request).await?;
    drop(response); // Implementing handling of the response is left as an exercise for the reader.
    Ok(())
}

#[tokio::main]
async fn main() {
    let google_credentials = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
        .expect("env var GOOGLE_APPLICATION_CREDENTIALS is required");
    let secret = yup_oauth2::read_service_account_key(google_credentials)
        .await
        .expect("$GOOGLE_APPLICATION_CREDENTIALS is not a valid service account key");
    let client = hyper::Client::builder().build(
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_only()
            .enable_http1()
            .enable_http2()
            .build(),
    );
    let authenticator =
        yup_oauth2::ServiceAccountAuthenticator::with_client(secret, client.clone())
            .build()
            .await
            .expect("could not create an authenticator");
    r#use(client, authenticator)
        .await
        .expect("use is successful!");
}
