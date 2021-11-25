use yup_oauth2::authenticator::ApplicationDefaultCredentialsTypes;
use yup_oauth2::ApplicationDefaultCredentialsAuthenticator;
use yup_oauth2::ApplicationDefaultCredentialsFlowOpts;

#[tokio::main]
async fn main() {
    let opts = ApplicationDefaultCredentialsFlowOpts::default();
    let auth = match ApplicationDefaultCredentialsAuthenticator::builder(opts).await {
        ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth
            .build()
            .await
            .expect("Unable to create instance metadata authenticator"),
        ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => auth
            .build()
            .await
            .expect("Unable to create service account authenticator"),
    };
    let scopes = &["https://www.googleapis.com/auth/pubsub"];

    let tok = auth.token(scopes).await.unwrap();
    println!("token is: {:?}", tok);
}
