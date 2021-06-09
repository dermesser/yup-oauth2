use yup_oauth2::ApplicationDefaultCredentialsAuthenticator;

#[tokio::main]
async fn main() {
    let auth = ApplicationDefaultCredentialsAuthenticator::builder()
        .await
        .build()
        .await
        .unwrap();
    let scopes = &["https://www.googleapis.com/auth/pubsub"];

    let tok = auth.token(scopes).await.unwrap();
    println!("token is: {:?}", tok);
}
