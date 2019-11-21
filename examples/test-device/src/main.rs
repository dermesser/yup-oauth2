use yup_oauth2::DeviceFlowAuthenticator;

use std::path;
use tokio;

#[tokio::main]
async fn main() {
    let app_secret = yup_oauth2::read_application_secret(path::Path::new("clientsecret.json"))
        .await
        .expect("clientsecret");
    let auth = DeviceFlowAuthenticator::builder(app_secret)
        .persist_tokens_to_disk("tokenstorage.json")
        .build()
        .await
        .expect("authenticator");

    let scopes = &["https://www.googleapis.com/auth/youtube.readonly"];
    match auth.token(scopes).await {
        Err(e) => println!("error: {:?}", e),
        Ok(t) => println!("token: {:?}", t),
    }
}
