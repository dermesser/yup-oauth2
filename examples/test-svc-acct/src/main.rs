use yup_oauth2;

use futures::prelude::*;
use yup_oauth2::GetToken;

use tokio;

use std::path;

fn main() {
    let creds =
        yup_oauth2::service_account_key_from_file(path::Path::new("serviceaccount.json")).unwrap();
    let mut sa = yup_oauth2::ServiceAccountAccess::new(creds).build();

    let fut = sa
        .token(vec!["https://www.googleapis.com/auth/pubsub"])
        .and_then(|tok| {
            println!("token is: {:?}", tok);
            Ok(())
        });
    let fut2 = sa
        .token(vec!["https://www.googleapis.com/auth/pubsub"])
        .and_then(|tok| {
            println!("cached token is {:?} and should be identical", tok);
            Ok(())
        });
    let all = fut.join(fut2).then(|_| Ok(()));
    tokio::run(all)
}
