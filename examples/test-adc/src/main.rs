use yup_oauth2::ApplicationDefaultCredentialsAuthenticator;
use yup_oauth2::InstanceMetadataFlowOpts;

#[tokio::main]
async fn main() {
    let opts = InstanceMetadataFlowOpts::default();
    let auth = ApplicationDefaultCredentialsAuthenticator::builder(opts)
        .await
        .build()
        .await
        .expect("Unable to create authenticator");
    let scopes = &["https://www.googleapis.com/auth/pubsub"];

    let tok = auth.token(scopes).await.unwrap();
    println!("token is: {:?}", tok);
}
