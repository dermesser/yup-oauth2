use futures::prelude::*;
use yup_oauth2::{self, Authenticator, DeviceFlow, GetToken};

use std::path;
use tokio;

fn main() {
    let creds = yup_oauth2::read_application_secret(path::Path::new("clientsecret.json"))
        .expect("clientsecret");
    let mut auth = Authenticator::new(DeviceFlow::new(creds))
        .persist_tokens_to_disk("tokenstorage.json")
        .build()
        .expect("authenticator");

    let scopes = vec!["https://www.googleapis.com/auth/youtube.readonly"];
    let mut rt = tokio::runtime::Runtime::new().unwrap();
    let fut = auth.token(scopes).and_then(|tok| Ok(println!("{:?}", tok)));

    println!("{:?}", rt.block_on(fut));
}
