// partially (c) 2016 Google Inc. (Lewin Bormann, lewinb@google.com)
//
// See project root for licensing information.
//
use crate::types::Token;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct HashedScopes<'a, T> {
    hash: u64,
    scopes: &'a [T],
}

// Implement Clone manually. Auto derive fails to work correctly because we want
// Clone to be implemented regardless of whether T is Clone or not.
impl<'a, T> Clone for HashedScopes<'a, T> {
    fn clone(&self) -> Self {
        HashedScopes {
            hash: self.hash,
            scopes: self.scopes,
        }
    }
}
impl<'a, T> Copy for HashedScopes<'a, T> {}

impl<'a, T> From<&'a [T]> for HashedScopes<'a, T>
where
    T: AsRef<str>,
{
    fn from(scopes: &'a [T]) -> Self {
        // Calculate a hash value describing the scopes. The order of the scopes in the
        // list does not change the hash value. i.e. two lists that contains the exact
        // same scopes, but in different order will return the same hash value.
        // Use seahash because it's fast and guaranteed to remain consistent,
        // even across different executions and versions.
        let hash = scopes.iter().fold(0u64, |h, scope| {
            h ^ seahash::hash(scope.as_ref().as_bytes())
        });
        HashedScopes { hash, scopes }
    }
}

impl<'a, T> HashedScopes<'a, T>
where
    T: AsRef<str>,
{
    // implement an inherent from method even though From is implemented. This
    // is because passing an array ref like &[&str; 1] (&["foo"]) will be auto
    // deref'd to a slice on function boundaries, but it will not implement the
    // From trait. This inherent method just serves to auto deref from array
    // refs to slices and proxy to the From impl.
    pub fn from(scopes: &'a [T]) -> Self {
        <Self as From<&'a [T]>>::from(scopes)
    }
}

pub(crate) enum Storage {
    Memory { tokens: Mutex<JSONTokens> },
    Disk(DiskStorage),
}

impl Storage {
    pub(crate) async fn set<T>(&self, scopes: HashedScopes<'_, T>, token: Token)
    where
        T: AsRef<str>,
    {
        match self {
            Storage::Memory { tokens } => tokens.lock().unwrap().set(scopes, token),
            Storage::Disk(disk_storage) => disk_storage.set(scopes, token).await,
        }
    }

    pub(crate) fn get<T>(&self, scopes: HashedScopes<T>) -> Option<Token>
    where
        T: AsRef<str>,
    {
        match self {
            Storage::Memory { tokens } => tokens.lock().unwrap().get(scopes),
            Storage::Disk(disk_storage) => disk_storage.get(scopes),
        }
    }
}

/// A single stored token.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JSONToken {
    pub hash: u64,
    pub scopes: Vec<String>,
    pub token: Token,
}

/// List of tokens in a JSON object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JSONTokens {
    tokens: Vec<JSONToken>,
}

impl JSONTokens {
    pub(crate) fn new() -> Self {
        JSONTokens { tokens: Vec::new() }
    }

    pub(crate) async fn load_from_file(filename: &Path) -> Result<Self, io::Error> {
        let contents = tokio::fs::read(filename).await?;
        let container: JSONTokens = serde_json::from_slice(&contents)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(container)
    }

    fn get<T>(&self, scopes: HashedScopes<T>) -> Option<Token>
    where
        T: AsRef<str>,
    {
        for t in self.tokens.iter() {
            if scopes
                .scopes
                .iter()
                .all(|s| t.scopes.iter().any(|t| t == s.as_ref()))
            {
                return Some(t.token.clone());
            }
        }
        None
    }

    fn set<T>(&mut self, scopes: HashedScopes<T>, token: Token)
    where
        T: AsRef<str>,
    {
        eprintln!("setting: {:?}, {:?}", scopes.hash, token);
        self.tokens.retain(|x| x.hash != scopes.hash);

        self.tokens.push(JSONToken {
            hash: scopes.hash,
            scopes: scopes
                .scopes
                .iter()
                .map(|x| x.as_ref().to_string())
                .collect(),
            token,
        });
    }

    // TODO: ideally this function would accept &Path, but tokio requires the
    // path be 'static. Revisit this and ask why tokio::fs::write has that
    // limitation.
    async fn dump_to_file(&self, path: PathBuf) -> Result<(), io::Error> {
        let serialized = serde_json::to_string(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        tokio::fs::write(path, &serialized).await
    }
}

pub(crate) struct DiskStorage {
    tokens: Mutex<JSONTokens>,
    write_tx: tokio::sync::mpsc::Sender<JSONTokens>,
}

impl DiskStorage {
    pub(crate) async fn new(path: PathBuf) -> Result<Self, io::Error> {
        let tokens = JSONTokens::load_from_file(&path).await?;
        // Writing to disk will happen in a separate task. This means in the
        // common case returning a token to the user will not be required to
        // wait for disk i/o. We communicate with a dedicated writer task via a
        // buffered channel. This ensures that the writes happen in the order
        // received, and if writes fall too far behind we will block GetToken
        // requests until disk i/o completes.
        let (write_tx, mut write_rx) = tokio::sync::mpsc::channel::<JSONTokens>(2);
        tokio::spawn(async move {
            while let Some(tokens) = write_rx.recv().await {
                if let Err(e) = tokens.dump_to_file(path.to_path_buf()).await {
                    log::error!("Failed to write token storage to disk: {}", e);
                }
            }
        });
        Ok(DiskStorage {
            tokens: Mutex::new(tokens),
            write_tx,
        })
    }

    async fn set<T>(&self, scopes: HashedScopes<'_, T>, token: Token)
    where
        T: AsRef<str>,
    {
        let cloned_tokens = {
            let mut tokens = self.tokens.lock().unwrap();
            tokens.set(scopes, token);
            tokens.clone()
        };
        self.write_tx
            .clone()
            .send(cloned_tokens)
            .await
            .expect("disk storage task not running");
    }

    pub(crate) fn get<T>(&self, scopes: HashedScopes<T>) -> Option<Token>
    where
        T: AsRef<str>,
    {
        self.tokens.lock().unwrap().get(scopes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_scopes() {
        // Idential list should hash equal.
        assert_eq!(
            HashedScopes::from(&["foo", "bar"]).hash,
            HashedScopes::from(&["foo", "bar"]).hash,
        );
        // The hash should be order independent.
        assert_eq!(
            HashedScopes::from(&["bar", "foo"]).hash,
            HashedScopes::from(&["foo", "bar"]).hash,
        );
        assert_eq!(
            HashedScopes::from(&["bar", "baz", "bat"]).hash,
            HashedScopes::from(&["baz", "bar", "bat"]).hash,
        );

        // Ensure hashes differ when the contents are different by more than
        // just order.
        assert_ne!(
            HashedScopes::from(&["foo", "bar", "baz"]).hash,
            HashedScopes::from(&["foo", "bar"]).hash,
        );
    }
}
