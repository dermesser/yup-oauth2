use futures::prelude::*;
use yup_oauth2::{self, Authenticator, GetToken};

use hyper::client::Client;
use hyper_rustls::HttpsConnector;
use std::path;
use std::time::Duration;
use tokio;

fn main() {
    let creds = yup_oauth2::read_application_secret(path::Path::new("clientsecret.json"))
        .expect("clientsecret");
    let https = HttpsConnector::new(1);
    let client = Client::builder()
        .keep_alive(false)
        .build::<_, hyper::Body>(https);
    let scopes = &["https://www.googleapis.com/auth/youtube.readonly".to_string()];

    let ad = yup_oauth2::DefaultFlowDelegate;
    let mut df = yup_oauth2::DeviceFlow::new::<String>(client.clone(), creds, ad, None);
    df.set_wait_duration(Duration::from_secs(120));
    let mut auth = Authenticator::new_disk(
        client,
        df,
        yup_oauth2::DefaultAuthenticatorDelegate,
        "tokenstorage.json",
    )
    .expect("authenticator");

    let mut rt = tokio::runtime::Runtime::new().unwrap();
    let fut = auth
        .token(scopes.iter())
        .and_then(|tok| Ok(println!("{:?}", tok)));

    println!("{:?}", rt.block_on(fut));
}
