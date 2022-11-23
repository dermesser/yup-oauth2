use yup_oauth2::{read_authorized_user_secret, ServiceAccountImpersonationAuthenticator};

#[tokio::main]
async fn main() {
    let svc_email = std::env::args().skip(1).next().unwrap();
    let home = std::env::var("HOME").unwrap();

    let user_secret = read_authorized_user_secret(format!(
        "{}/.config/gcloud/application_default_credentials.json",
        home
    ))
    .await
    .expect("user secret");

    let auth = ServiceAccountImpersonationAuthenticator::builder(user_secret, &svc_email)
        .request_id_token()
        .build()
        .await
        .expect("authenticator");

    let scopes = &["https://www.googleapis.com/auth/youtube.readonly"];
    match auth.id_token(scopes).await {
        Err(e) => println!("error: {:?}", e),
        Ok(t) => println!("token: {:?}", t),
    }
}
