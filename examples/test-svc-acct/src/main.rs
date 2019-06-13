use yup_oauth2;

use futures::prelude::*;
use yup_oauth2::GetToken;

use hyper::client::Client;
use hyper_tls::HttpsConnector;
use tokio;

use std::path;

fn main() {
    let creds =
        yup_oauth2::service_account_key_from_file(path::Path::new("serviceaccount.json")).unwrap();
    let https = HttpsConnector::new(1).expect("tls");
    let client = Client::builder().build::<_, hyper::Body>(https);

    let mut sa = yup_oauth2::ServiceAccountAccess::new(creds, client);

    let fut = sa
        .token(["https://www.googleapis.com/auth/pubsub"].iter())
        .and_then(|tok| {
            println!("token is: {:?}", tok);
            Ok(())
        });
    let fut2 = sa
        .token(["https://www.googleapis.com/auth/pubsub"].iter())
        .and_then(|tok| {
            println!("cached token is {:?} and should be identical", tok);
            Ok(())
        });
    let all = fut.join(fut2);
    let mut rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(all).unwrap();
}
