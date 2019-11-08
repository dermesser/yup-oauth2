// partially (c) 2016 Google Inc. (Lewin Bormann, lewinb@google.com)
//
// See project root for licensing information.
//

use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::types::Token;
use itertools::Itertools;

/// Implements a specialized storage to set and retrieve `Token` instances.
/// The `scope_hash` represents the signature of the scopes for which the given token
/// should be stored or retrieved.
/// For completeness, the underlying, sorted scopes are provided as well. They might be
/// useful for presentation to the user.
pub trait TokenStorage: Send + Sync {
    type Error: 'static + Error + Send + Sync;

    /// If `token` is None, it is invalid or revoked and should be removed from storage.
    /// Otherwise, it should be saved.
    fn set<T>(
        &self,
        scope_hash: u64,
        scopes: &[T],
        token: Option<Token>,
    ) -> Result<(), Self::Error>
    where
        T: AsRef<str>;

    /// A `None` result indicates that there is no token for the given scope_hash.
    fn get<T>(&self, scope_hash: u64, scopes: &[T]) -> Result<Option<Token>, Self::Error>
    where
        T: AsRef<str>;
}

/// Calculate a hash value describing the scopes. The order of the scopes in the
/// list does not change the hash value. i.e. two lists that contains the exact
/// same scopes, but in different order will return the same hash value.
pub fn hash_scopes<T>(scopes: &[T]) -> u64
where
    T: AsRef<str>,
{
    let mut hash_sum = DefaultHasher::new().finish();
    for scope in scopes {
        let mut hasher = DefaultHasher::new();
        scope.as_ref().hash(&mut hasher);
        hash_sum ^= hasher.finish();
    }
    hash_sum
}

/// A storage that remembers nothing.
#[derive(Default)]
pub struct NullStorage;

impl TokenStorage for NullStorage {
    type Error = std::convert::Infallible;
    fn set<T>(&self, _: u64, _: &[T], _: Option<Token>) -> Result<(), Self::Error>
    where
        T: AsRef<str>
    {
        Ok(())
    }

    fn get<T>(&self, _: u64, _: &[T]) -> Result<Option<Token>, Self::Error>
    where
        T: AsRef<str>
    {
        Ok(None)
    }
}

/// A storage that remembers values for one session only.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    tokens: Mutex<Vec<JSONToken>>,
}

impl MemoryStorage {
    pub fn new() -> MemoryStorage {
        Default::default()
    }
}

impl TokenStorage for MemoryStorage {
    type Error = std::convert::Infallible;

    fn set<T>(
        &self,
        scope_hash: u64,
        scopes: &[T],
        token: Option<Token>,
    ) -> Result<(), Self::Error>
    where
        T: AsRef<str>
    {
        let mut tokens = self.tokens.lock().expect("poisoned mutex");
        let matched = tokens.iter().find_position(|x| x.hash == scope_hash);
        if let Some((idx, _)) = matched {
            self.tokens.retain(|x| x.hash != scope_hash);
        }

        match token {
            Some(t) => {
                tokens.push(JSONToken {
                    hash: scope_hash,
                    scopes: Some(scopes.into_iter().map(|x| x.as_ref().to_string()).collect()),
                    token: t.clone(),
                });
                ()
            }
            None => {}
        };
        Ok(())
    }

    fn get<T>(&self, scope_hash: u64, scopes: &[T]) -> Result<Option<Token>, Self::Error>
    where
        T: AsRef<str>
    {
        let tokens = self.tokens.lock().expect("poisoned mutex");
        Ok(token_for_scopes(&tokens, scope_hash, scopes))
    }
}

/// A single stored token.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JSONToken {
    pub hash: u64,
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
#[derive(Serialize, Deserialize)]
struct JSONTokens {
    pub tokens: Vec<JSONToken>,
}

/// Serializes tokens to a JSON file on disk.
#[derive(Default)]
pub struct DiskTokenStorage {
    location: PathBuf,
    tokens: Mutex<Vec<JSONToken>>,
}

impl DiskTokenStorage {
    pub fn new<S: Into<PathBuf>>(location: S) -> Result<DiskTokenStorage, io::Error> {
        let filename = location.into();
        let tokens = match load_from_file(&filename) {
            Ok(tokens) => tokens,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(DiskTokenStorage {
            location: filename,
            tokens: Mutex::new(tokens),
        })
    }

    pub fn dump_to_file(&self) -> Result<(), io::Error> {
        let mut jsontokens = JSONTokens { tokens: Vec::new() };

        {
            let tokens = self.tokens.lock().expect("mutex poisoned");
            for token in tokens.iter() {
                jsontokens.tokens.push((*token).clone());
            }
        }

        let serialized;

        match serde_json::to_string(&jsontokens) {
            Result::Err(e) => return Result::Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            Result::Ok(s) => serialized = s,
        }

        // TODO: Write to disk asynchronously so that we don't stall the eventloop if invoked in async context.
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.location)?;
        f.write(serialized.as_ref()).map(|_| ())
    }
}

fn load_from_file(filename: &Path) -> Result<Vec<JSONToken>, io::Error> {
    let contents = std::fs::read_to_string(filename)?;
    let container: JSONTokens = serde_json::from_str(&contents)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(container.tokens)
}

impl TokenStorage for DiskTokenStorage {
    type Error = io::Error;
    fn set<T>(
        &self,
        scope_hash: u64,
        scopes: &[T],
        token: Option<Token>,
    ) -> Result<(), Self::Error>
    where
        T: AsRef<str>
    {
        {
            let mut tokens = self.tokens.lock().expect("poisoned mutex");
            let matched = tokens.iter().find_position(|x| x.hash == scope_hash);
            if let Some((idx, _)) = matched {
                self.tokens.retain(|x| x.hash != scope_hash);
            }

            match token {
                None => (),
                Some(t) => {
                    tokens.push(JSONToken {
                        hash: scope_hash,
                        scopes: Some(scopes.into_iter().map(|x| x.as_ref().to_string()).collect()),
                        token: t.clone(),
                    });
                    ()
                }
            }
        }
        self.dump_to_file()
    }

    fn get<T>(&self, scope_hash: u64, scopes: &[T]) -> Result<Option<Token>, Self::Error>
    where
        T: AsRef<str>
    {
        let tokens = self.tokens.lock().expect("poisoned mutex");
        Ok(token_for_scopes(&tokens, scope_hash, scopes))
    }
}

fn token_for_scopes<T>(tokens: &[JSONToken], scope_hash: u64, scopes: &[T]) -> Option<Token>
where
    T: AsRef<str>,
{
    for t in tokens.iter() {
        if let Some(token_scopes) = &t.scopes {
            if scopes.iter().all(|s| token_scopes.iter().any(|t| t == s.as_ref())) {
                return Some(t.token.clone());
            }
        } else if scope_hash == t.hash {
            return Some(t.token.clone())
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_scopes() {
        // Idential list should hash equal.
        assert_eq!(hash_scopes(&["foo", "bar"]), hash_scopes(&["foo", "bar"]));
        // The hash should be order independent.
        assert_eq!(hash_scopes(&["bar", "foo"]), hash_scopes(&["foo", "bar"]));
        assert_eq!(hash_scopes(&["bar", "baz", "bat"]), hash_scopes(&["baz", "bar", "bat"]));

        // Ensure hashes differ when the contents are different by more than
        // just order.
        assert_ne!(hash_scopes(&["foo", "bar", "baz"]), hash_scopes(&["foo", "bar"]));
    }
}
