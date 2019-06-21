// partially (c) 2016 Google Inc. (Lewin Bormann, lewinb@google.com)
//
// See project root for licensing information.
//

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::io::{Read, Write};

use crate::types::Token;

/// Implements a specialized storage to set and retrieve `Token` instances.
/// The `scope_hash` represents the signature of the scopes for which the given token
/// should be stored or retrieved.
/// For completeness, the underlying, sorted scopes are provided as well. They might be
/// useful for presentation to the user.
pub trait TokenStorage {
    type Error: 'static + Error + Send;

    /// If `token` is None, it is invalid or revoked and should be removed from storage.
    /// Otherwise, it should be saved.
    fn set(
        &mut self,
        scope_hash: u64,
        scopes: &Vec<&str>,
        token: Option<Token>,
    ) -> Result<(), Self::Error>;
    /// A `None` result indicates that there is no token for the given scope_hash.
    fn get(&self, scope_hash: u64, scopes: &Vec<&str>) -> Result<Option<Token>, Self::Error>;
}

/// Calculate a hash value describing the scopes, and return a sorted Vec of the scopes.
pub fn hash_scopes<'a, I, T>(scopes: I) -> (u64, Vec<String>)
where
    T: AsRef<str> + Ord + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut sv: Vec<&str> = scopes
        .into_iter()
        .map(|s| s.as_ref())
        .collect::<Vec<&str>>();
    sv.sort();
    let mut sh = DefaultHasher::new();
    &sv.hash(&mut sh);
    let sv = sv.iter().map(|s| s.to_string()).collect();
    (sh.finish(), sv)
}

/// A storage that remembers nothing.
#[derive(Default)]
pub struct NullStorage;
#[derive(Debug)]
pub struct NullError;

impl Error for NullError {
    fn description(&self) -> &str {
        "NULL"
    }
}

impl fmt::Display for NullError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        "NULL-ERROR".fmt(f)
    }
}

impl TokenStorage for NullStorage {
    type Error = NullError;
    fn set(&mut self, _: u64, _: &Vec<&str>, _: Option<Token>) -> Result<(), NullError> {
        Ok(())
    }
    fn get(&self, _: u64, _: &Vec<&str>) -> Result<Option<Token>, NullError> {
        Ok(None)
    }
}

/// A storage that remembers values for one session only.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    pub tokens: HashMap<u64, Token>,
}

impl MemoryStorage {
    pub fn new() -> MemoryStorage {
        Default::default()
    }
}

impl TokenStorage for MemoryStorage {
    type Error = NullError;

    fn set(
        &mut self,
        scope_hash: u64,
        _: &Vec<&str>,
        token: Option<Token>,
    ) -> Result<(), NullError> {
        match token {
            Some(t) => self.tokens.insert(scope_hash, t),
            None => self.tokens.remove(&scope_hash),
        };
        Ok(())
    }

    fn get(&self, scope_hash: u64, _: &Vec<&str>) -> Result<Option<Token>, NullError> {
        match self.tokens.get(&scope_hash) {
            Some(t) => Ok(Some(t.clone())),
            None => Ok(None),
        }
    }
}

/// A single stored token.
#[derive(Serialize, Deserialize)]
struct JSONToken {
    pub hash: u64,
    pub token: Token,
}

/// List of tokens in a JSON object
#[derive(Serialize, Deserialize)]
struct JSONTokens {
    pub tokens: Vec<JSONToken>,
}

/// Serializes tokens to a JSON file on disk.
#[derive(Default)]
pub struct DiskTokenStorage {
    location: String,
    tokens: HashMap<u64, Token>,
}

impl DiskTokenStorage {
    pub fn new<S: AsRef<str>>(location: S) -> Result<DiskTokenStorage, io::Error> {
        let mut dts = DiskTokenStorage {
            location: location.as_ref().to_owned(),
            tokens: HashMap::new(),
        };

        // best-effort
        let read_result = dts.load_from_file();

        match read_result {
            Result::Ok(()) => Result::Ok(dts),
            Result::Err(e) => {
                match e.kind() {
                    io::ErrorKind::NotFound => Result::Ok(dts), // File not found; ignore and create new one
                    _ => Result::Err(e),                        // e.g. PermissionDenied
                }
            }
        }
    }

    fn load_from_file(&mut self) -> Result<(), io::Error> {
        let mut f = fs::OpenOptions::new().read(true).open(&self.location)?;
        let mut contents = String::new();

        match f.read_to_string(&mut contents) {
            Result::Err(e) => return Result::Err(e),
            Result::Ok(_sz) => (),
        }

        let tokens: JSONTokens;

        match serde_json::from_str(&contents) {
            Result::Err(e) => return Result::Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            Result::Ok(t) => tokens = t,
        }

        for t in tokens.tokens {
            self.tokens.insert(t.hash, t.token);
        }
        return Result::Ok(());
    }

    pub fn dump_to_file(&mut self) -> Result<(), io::Error> {
        let mut jsontokens = JSONTokens { tokens: Vec::new() };

        for (hash, token) in self.tokens.iter() {
            jsontokens.tokens.push(JSONToken {
                hash: *hash,
                token: token.clone(),
            });
        }

        let serialized;;

        match serde_json::to_string(&jsontokens) {
            Result::Err(e) => return Result::Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            Result::Ok(s) => serialized = s,
        }

        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.location)?;
        f.write(serialized.as_ref()).map(|_| ())
    }
}

impl TokenStorage for DiskTokenStorage {
    type Error = io::Error;
    fn set(
        &mut self,
        scope_hash: u64,
        _: &Vec<&str>,
        token: Option<Token>,
    ) -> Result<(), Self::Error> {
        match token {
            None => {
                self.tokens.remove(&scope_hash);
                ()
            }
            Some(t) => {
                self.tokens.insert(scope_hash, t.clone());
                ()
            }
        }
        self.dump_to_file()
    }
    fn get(&self, scope_hash: u64, _: &Vec<&str>) -> Result<Option<Token>, Self::Error> {
        Result::Ok(self.tokens.get(&scope_hash).map(|tok| tok.clone()))
    }
}
