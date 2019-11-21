use yup_oauth2::{InstalledFlowAuthenticator, InstalledFlowReturnMethod};

use std::path::Path;

#[tokio::main]
async fn main() {
    let app_secret = yup_oauth2::read_application_secret(Path::new("clientsecret.json"))
        .await
        .expect("clientsecret.json");

    let auth =
        InstalledFlowAuthenticator::builder(app_secret, InstalledFlowReturnMethod::HTTPRedirect)
            .persist_tokens_to_disk("tokencache.json")
            .build()
            .await
            .unwrap();
    let scopes = &["https://www.googleapis.com/auth/drive.file"];

    match auth.token(scopes).await {
        Err(e) => println!("error: {:?}", e),
        Ok(t) => println!("The token is {:?}", t),
    }
}
