use std::time::Duration;

use httptest::{
    matchers::request, responders::delay_and_then, responders::json_encoded, Expectation, Server,
};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use yup_oauth2::{
    client::SendError, ApplicationSecret, CustomHyperClientBuilder, DeviceFlowAuthenticator, Error,
    HyperClientBuilder,
};

#[tokio::test]
async fn custom_client_authenticator_honors_timeout() {
    let server = Server::run();
    server.expect(
        Expectation::matching(request::method_path("POST", "/code"))
            .respond_with(delay_and_then(Duration::from_secs(1), || {
                json_encoded(serde_json::json!({"error": "invalid_client"}))
            })),
    );
    let secret = ApplicationSecret {
        client_id: "fake-client".into(),
        client_secret: "fake-secret".into(),
        token_uri: server.url_str("/token"),
        auth_uri: server.url_str("/authorize"),
        ..Default::default()
    };
    let client = Client::builder(TokioExecutor::new()).build_http::<String>();
    let auth = DeviceFlowAuthenticator::with_client(secret, CustomHyperClientBuilder::from(client))
        .device_code_url(server.url_str("/code"))
        .with_timeout(Duration::from_millis(50))
        .build()
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(3), auth.token(&["fake-scope"]))
        .await
        .expect("request did not complete within test deadline");
    assert!(
        matches!(result, Err(Error::HttpClientError(SendError::Timeout))),
        "{result:?}"
    );
}

#[tokio::test]
async fn custom_client_builder_honors_timeout() {
    let server = Server::run();
    server.expect(
        Expectation::matching(request::method_path("POST", "/code"))
            .respond_with(delay_and_then(Duration::from_secs(1), || {
                json_encoded(serde_json::json!({"error": "invalid_client"}))
            })),
    );
    let secret = ApplicationSecret {
        client_id: "fake-client".into(),
        client_secret: "fake-secret".into(),
        token_uri: server.url_str("/token"),
        auth_uri: server.url_str("/authorize"),
        ..Default::default()
    };
    let client = Client::builder(TokioExecutor::new()).build_http::<String>();
    let client = CustomHyperClientBuilder::from(client)
        .with_timeout(Duration::from_millis(50))
        .build_hyper_client()
        .unwrap();
    let auth = DeviceFlowAuthenticator::with_client(secret, client)
        .device_code_url(server.url_str("/code"))
        .build()
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(3), auth.token(&["fake-scope"]))
        .await
        .expect("request did not complete within test deadline");
    assert!(
        matches!(result, Err(Error::HttpClientError(SendError::Timeout))),
        "{result:?}"
    );
}
