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
    fn set<I>(
        &self,
        scope_hash: u64,
        scopes: I,
        token: Option<Token>,
    ) -> Result<(), Self::Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>;

    /// A `None` result indicates that there is no token for the given scope_hash.
    fn get<I>(&self, scope_hash: u64, scopes: I) -> Result<Option<Token>, Self::Error>
    where
        I: IntoIterator + Clone,
        I::Item: AsRef<str>;
}

/// Calculate a hash value describing the scopes, and return a sorted Vec of the scopes.
pub fn hash_scopes<I, T>(scopes: I) -> (u64, Vec<String>)
where
    T: Into<String>,
    I: IntoIterator<Item = T>,
{
    let mut sv: Vec<String> = scopes.into_iter().map(Into::into).collect();
    sv.sort();
    let mut sh = DefaultHasher::new();
    sv.hash(&mut sh);
    (sh.finish(), sv)
}

/// A storage that remembers nothing.
#[derive(Default)]
pub struct NullStorage;

impl TokenStorage for NullStorage {
    type Error = std::convert::Infallible;
    fn set<I>(&self, _: u64, _: I, _: Option<Token>) -> Result<(), Self::Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        Ok(())
    }

    fn get<I>(&self, _: u64, _: I) -> Result<Option<Token>, Self::Error>
    where
        I: IntoIterator + Clone,
        I::Item: AsRef<str>,
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

    fn set<I>(
        &self,
        scope_hash: u64,
        scopes: I,
        token: Option<Token>,
    ) -> Result<(), Self::Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
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

    fn get<I>(&self, scope_hash: u64, scopes: I) -> Result<Option<Token>, Self::Error>
    where
        I: IntoIterator + Clone,
        I::Item: AsRef<str>,
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
    fn set<I>(
        &self,
        scope_hash: u64,
        scopes: I,
        token: Option<Token>,
    ) -> Result<(), Self::Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
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

    fn get<I>(&self, scope_hash: u64, scopes: I) -> Result<Option<Token>, Self::Error>
    where
        I: IntoIterator + Clone,
        I::Item: AsRef<str>,
    {
        let tokens = self.tokens.lock().expect("poisoned mutex");
        Ok(token_for_scopes(&tokens, scope_hash, scopes))
    }
}

fn token_for_scopes<I>(tokens: &[JSONToken], scope_hash: u64, scopes: I) -> Option<Token>
where
    I: IntoIterator + Clone,
    I::Item: AsRef<str>,
{
    for t in tokens.iter() {
        if let Some(token_scopes) = &t.scopes {
            if scopes.clone().into_iter().all(|s| token_scopes.iter().any(|t| t == s.as_ref())) {
                return Some(t.token.clone());
            }
        } else if scope_hash == t.hash {
            return Some(t.token.clone())
        }
    }
    None
}
