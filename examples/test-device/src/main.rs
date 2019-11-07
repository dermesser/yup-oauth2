use yup_oauth2::{self, Authenticator, DeviceFlow, GetToken};

use std::path;
use tokio;

#[tokio::main]
async fn main() {
    let creds = yup_oauth2::read_application_secret(path::Path::new("clientsecret.json"))
        .expect("clientsecret");
    let auth = Authenticator::new(DeviceFlow::new(creds))
        .persist_tokens_to_disk("tokenstorage.json")
        .build()
        .expect("authenticator");

    let scopes = vec!["https://www.googleapis.com/auth/youtube.readonly"];
    match auth.token(scopes).await {
        Err(e) => println!("error: {:?}", e),
        Ok(t) => println!("token: {:?}", t),
    }
}
