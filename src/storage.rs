// partially (c) 2016 Google Inc. (Lewin Bormann, lewinb@google.com)
//
// See project root for licensing information.
//
use crate::types::Token;

use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScopeHash(u64);

impl ScopeHash {
    /// Calculate a hash value describing the scopes. The order of the scopes in the
    /// list does not change the hash value. i.e. two lists that contains the exact
    /// same scopes, but in different order will return the same hash value.
    pub fn new<T>(scopes: &[T]) -> Self
    where
        T: AsRef<str>,
    {
        let mut hash_sum = DefaultHasher::new().finish();
        for scope in scopes {
            let mut hasher = DefaultHasher::new();
            scope.as_ref().hash(&mut hasher);
            hash_sum ^= hasher.finish();
        }
        ScopeHash(hash_sum)
    }
}

pub(crate) enum Storage {
    Memory { tokens: Mutex<JSONTokens> },
    Disk(DiskStorage),
}

impl Storage {
    pub(crate) async fn set<T>(&self, h: ScopeHash, scopes: &[T], token: Option<Token>)
    where
        T: AsRef<str>,
    {
        match self {
            Storage::Memory { tokens } => tokens.lock().unwrap().set(h, scopes, token),
            Storage::Disk(disk_storage) => disk_storage.set(h, scopes, token).await,
        }
    }

    pub(crate) fn get<T>(&self, h: ScopeHash, scopes: &[T]) -> Option<Token>
    where
        T: AsRef<str>,
    {
        match self {
            Storage::Memory { tokens } => tokens.lock().unwrap().get(h, scopes),
            Storage::Disk(disk_storage) => disk_storage.get(h, scopes),
        }
    }
}

/// A single stored token.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JSONToken {
    pub hash: ScopeHash,
    pub scopes: Option<Vec<String>>,
    pub token: Token,
}

impl PartialEq for JSONToken {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Eq for JSONToken {}

impl PartialOrd for JSONToken {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for JSONToken {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hash.cmp(&other.hash)
    }
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

    fn get<T>(&self, h: ScopeHash, scopes: &[T]) -> Option<Token>
    where
        T: AsRef<str>,
    {
        for t in self.tokens.iter() {
            if let Some(token_scopes) = &t.scopes {
                if scopes
                    .iter()
                    .all(|s| token_scopes.iter().any(|t| t == s.as_ref()))
                {
                    return Some(t.token.clone());
                }
            } else if h == t.hash {
                return Some(t.token.clone());
            }
        }
        None
    }

    fn set<T>(&mut self, h: ScopeHash, scopes: &[T], token: Option<Token>)
    where
        T: AsRef<str>,
    {
        eprintln!("setting: {:?}, {:?}", h, token);
        self.tokens.retain(|x| x.hash != h);

        match token {
            None => (),
            Some(t) => {
                self.tokens.push(JSONToken {
                    hash: h,
                    scopes: Some(scopes.iter().map(|x| x.as_ref().to_string()).collect()),
                    token: t,
                });
            }
        }
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

    async fn set<T>(&self, h: ScopeHash, scopes: &[T], token: Option<Token>)
    where
        T: AsRef<str>,
    {
        let cloned_tokens = {
            let mut tokens = self.tokens.lock().unwrap();
            tokens.set(h, scopes, token);
            tokens.clone()
        };
        self.write_tx
            .clone()
            .send(cloned_tokens)
            .await
            .expect("disk storage task not running");
    }

    pub(crate) fn get<T>(&self, h: ScopeHash, scopes: &[T]) -> Option<Token>
    where
        T: AsRef<str>,
    {
        self.tokens.lock().unwrap().get(h, scopes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_scopes() {
        // Idential list should hash equal.
        assert_eq!(
            ScopeHash::new(&["foo", "bar"]),
            ScopeHash::new(&["foo", "bar"])
        );
        // The hash should be order independent.
        assert_eq!(
            ScopeHash::new(&["bar", "foo"]),
            ScopeHash::new(&["foo", "bar"])
        );
        assert_eq!(
            ScopeHash::new(&["bar", "baz", "bat"]),
            ScopeHash::new(&["baz", "bar", "bat"])
        );

        // Ensure hashes differ when the contents are different by more than
        // just order.
        assert_ne!(
            ScopeHash::new(&["foo", "bar", "baz"]),
            ScopeHash::new(&["foo", "bar"])
        );
    }
}
