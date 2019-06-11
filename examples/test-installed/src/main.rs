use yup_oauth2::InstalledFlow;

use futures::prelude::*;

use hyper::client::Client;
use hyper_tls::HttpsConnector;

use std::path::Path;

fn main() {
    let https = HttpsConnector::new(1).expect("tls");
    let client = Client::builder().build::<_, hyper::Body>(https);
    let mut inf = InstalledFlow::new(
        client,
        yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect(8081),
    );
    let ad = yup_oauth2::DefaultAuthenticatorDelegate;
    let secret = yup_oauth2::read_application_secret(Path::new("clientsecret.json"))
        .expect("clientsecret.json");
    let s = "https://www.googleapis.com/auth/drive.file".to_string();
    let scopes = vec![s];

    let tok = inf.obtain_token(ad, secret, scopes);
    let fut = tok.map_err(|e| println!("error: {:?}", e)).and_then(|t| {
        println!("The token is {:?}", t);
        Ok(())
    });

    let mut rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(fut).unwrap();
}
