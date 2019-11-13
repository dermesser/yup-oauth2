use tokio;
use yup_oauth2::ServiceAccountAuthenticator;

#[tokio::main]
async fn main() {
    let creds = yup_oauth2::service_account_key_from_file("serviceaccount.json").unwrap();
    let sa = ServiceAccountAuthenticator::builder(creds).build().unwrap();
    let scopes = &["https://www.googleapis.com/auth/pubsub"];

    let tok = sa.token(scopes).await.unwrap();
    println!("token is: {:?}", tok);
    let tok = sa.token(scopes).await.unwrap();
    println!("cached token is {:?} and should be identical", tok);
}
