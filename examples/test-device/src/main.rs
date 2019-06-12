use futures::prelude::*;
use yup_oauth2;

use hyper::client::Client;
use hyper_tls::HttpsConnector;
use std::path;
use tokio;

fn main() {
    let creds = yup_oauth2::read_application_secret(path::Path::new("clientsecret.json"))
        .expect("clientsecret");
    let https = HttpsConnector::new(1).expect("tls");
    let client = Client::builder().build::<_, hyper::Body>(https);

    let scopes = &["https://www.googleapis.com/auth/youtube.readonly".to_string()];

    let ad = yup_oauth2::DefaultAuthenticatorDelegate;
    let mut df = yup_oauth2::DeviceFlow::new::<String>(client, creds, ad, None);
    let mut rt = tokio::runtime::Runtime::new().unwrap();

    let fut = df
        .retrieve_device_token(scopes.to_vec())
        .and_then(|tok| Ok(println!("{:?}", tok)));

    rt.block_on(fut).unwrap()
}
