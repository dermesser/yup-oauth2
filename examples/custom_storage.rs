//! Demonstrating how to create a custom token store
use anyhow::anyhow;
use async_trait::async_trait;
use std::sync::RwLock;
use yup_oauth2::storage::{TokenInfo, TokenStorage};

struct ExampleTokenStore {
    store: RwLock<Vec<StoredToken>>,
}

struct StoredToken {
    scopes: Vec<String>,
    serialized_token: String,
}

/// Is this set of scopes covered by the other? Returns true if the other
/// set is a superset of this one. Use this when implementing TokenStorage.get()
fn scopes_covered_by(scopes: &[&str], possible_match_or_superset: &[&str]) -> bool {
    scopes
        .iter()
        .all(|s| possible_match_or_superset.iter().any(|t| t == s))
}

/// Here we implement our own token storage. You could write the serialized token and scope data
/// to disk, an OS keychain, a database or whatever suits your use-case
#[async_trait]
impl TokenStorage for ExampleTokenStore {
    async fn set(&self, scopes: &[&str], token: TokenInfo) -> anyhow::Result<()> {
        let data = serde_json::to_string(&token).unwrap();

        println!("Storing token for scopes {:?}", scopes);

        let mut store = self
            .store
            .write()
            .map_err(|_| anyhow!("Unable to lock store for writing"))?;

        store.push(StoredToken {
            scopes: scopes.iter().map(|str| str.to_string()).collect(),
            serialized_token: data,
        });

        Ok(())
    }

    async fn get(&self, target_scopes: &[&str]) -> Option<TokenInfo> {
        // Retrieve the token data
        self.store.read().ok().and_then(|store| {
            for stored_token in store.iter() {
                if scopes_covered_by(
                    target_scopes,
                    &stored_token
                        .scopes
                        .iter()
                        .map(|s| &s[..])
                        .collect::<Vec<_>>()[..],
                ) {
                    return serde_json::from_str(&stored_token.serialized_token).ok();
                }
            }

            None
        })
    }
}

#[tokio::main]
async fn main() {
    // Put your client secret in the working directory!
    let sec = yup_oauth2::read_application_secret("client_secret.json")
        .await
        .expect("client secret couldn't be read.");
    let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
        sec,
        yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
    )
    .with_storage(Box::new(ExampleTokenStore {
        store: RwLock::new(vec![]),
    }))
    .build()
    .await
    .expect("InstalledFlowAuthenticator failed to build");

    let scopes = &["https://www.googleapis.com/auth/drive.file"];

    match auth.token(scopes).await {
        Err(e) => println!("error: {:?}", e),
        Ok(t) => println!("The token is {:?}", t),
    }
}
