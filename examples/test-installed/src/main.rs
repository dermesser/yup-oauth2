use yup_oauth2::GetToken;
use yup_oauth2::{Authenticator, InstalledFlow};

use std::path::Path;

#[tokio::main]
async fn main() {
    let secret = yup_oauth2::read_application_secret(Path::new("clientsecret.json"))
        .expect("clientsecret.json");

    let auth = Authenticator::new(InstalledFlow::new(
        secret,
        yup_oauth2::InstalledFlowReturnMethod::HTTPRedirectEphemeral,
    ))
    .persist_tokens_to_disk("tokencache.json")
    .build()
    .unwrap();
    let scopes = &["https://www.googleapis.com/auth/drive.file"];

    match auth.token(scopes).await {
        Err(e) => println!("error: {:?}", e),
        Ok(t) => println!("The token is {:?}", t),
    }
}
