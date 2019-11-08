use std::path;
use tokio;
use yup_oauth2;
use yup_oauth2::GetToken;

#[tokio::main]
async fn main() {
    let creds =
        yup_oauth2::service_account_key_from_file(path::Path::new("serviceaccount.json")).unwrap();
    let sa = yup_oauth2::ServiceAccountAccess::new(creds).build();
    let scopes = &["https://www.googleapis.com/auth/pubsub"];

    let tok = sa
        .token(scopes)
        .await
        .unwrap();
    println!("token is: {:?}", tok);
    let tok = sa
        .token(scopes)
        .await
        .unwrap();
    println!("cached token is {:?} and should be identical", tok);
}
