// partially (c) 2016 Google Inc. (Lewin Bormann, lewinb@google.com)
//
// See project root for licensing information.
//
use crate::types::Token;

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

// The storage layer allows retrieving tokens for scopes that have been
// previously granted tokens. One wrinkle is that a token granted for a set
// of scopes X is also valid for any subset of X's scopes. So when retrieving a
// token for a set of scopes provided by the caller it's beneficial to compare
// that set to all previously stored tokens to see if it is a subset of any
// existing set. To do this efficiently we store a bloom filter along with each
// token that represents the set of scopes the token is associated with. The
// bloom filter allows for efficiently skipping any entries that are
// definitively not a superset.
// The current implementation uses a 64bit bloom filter with 4 hash functions.

/// ScopeHash is a hash value derived from a list of scopes. The hash value
/// represents a fingerprint of the set of scopes *independent* of the ordering.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
struct ScopeHash(u64);

/// ScopeFilter represents a filter for a set of scopes. It can definitively
/// prove that a given list of scopes is not a subset of another.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
struct ScopeFilter(u64);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum FilterResponse {
    Maybe,
    No,
}

impl ScopeFilter {
    /// Determine if this ScopeFilter could be a subset of the provided filter.
    fn is_subset_of(self, filter: ScopeFilter) -> FilterResponse {
        if self.0 & filter.0 == self.0 {
            FilterResponse::Maybe
        } else {
            FilterResponse::No
        }
    }
}

#[derive(Debug)]
pub(crate) struct ScopeSet<'a, T> {
    hash: ScopeHash,
    filter: ScopeFilter,
    scopes: &'a [T],
}

// Implement Clone manually. Auto derive fails to work correctly because we want
// Clone to be implemented regardless of whether T is Clone or not.
impl<'a, T> Clone for ScopeSet<'a, T> {
    fn clone(&self) -> Self {
        ScopeSet {
            hash: self.hash,
            filter: self.filter,
            scopes: self.scopes,
        }
    }
}
impl<'a, T> Copy for ScopeSet<'a, T> {}

impl<'a, T> ScopeSet<'a, T>
where
    T: AsRef<str>,
{
    // implement an inherent from method even though From is implemented. This
    // is because passing an array ref like &[&str; 1] (&["foo"]) will be auto
    // deref'd to a slice on function boundaries, but it will not implement the
    // From trait. This inherent method just serves to auto deref from array
    // refs to slices and proxy to the From impl.
    pub fn from(scopes: &'a [T]) -> Self {
        let (hash, filter) = scopes.iter().fold(
            (ScopeHash(0), ScopeFilter(0)),
            |(mut scope_hash, mut scope_filter), scope| {
                let h = seahash::hash(scope.as_ref().as_bytes());

                // Use the first 4 6-bit chunks of the seahash as the 4 hash values
                // in the bloom filter.
                for i in 0..4 {
                    // h is a hash derived value in the range 0..64
                    let h = (h >> (6 * i)) & 0b11_1111;
                    scope_filter.0 |= 1 << h;
                }

                // xor the hashes together to get an order independent fingerprint.
                scope_hash.0 ^= h;
                (scope_hash, scope_filter)
            },
        );
        ScopeSet {
            hash,
            filter,
            scopes,
        }
    }
}

pub(crate) enum Storage {
    Memory { tokens: Mutex<JSONTokens> },
    Disk(DiskStorage),
}

impl Storage {
    pub(crate) async fn set<T>(&self, scopes: ScopeSet<'_, T>, token: Token)
    where
        T: AsRef<str>,
    {
        match self {
            Storage::Memory { tokens } => tokens.lock().unwrap().set(scopes, token),
            Storage::Disk(disk_storage) => disk_storage.set(scopes, token).await,
        }
    }

    pub(crate) fn get<T>(&self, scopes: ScopeSet<T>) -> Option<Token>
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

#[derive(Debug, Clone)]
struct JSONToken {
    scopes: Vec<String>,
    token: Token,
    hash: ScopeHash,
    filter: ScopeFilter,
}

impl<'de> Deserialize<'de> for JSONToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawJSONToken {
            scopes: Vec<String>,
            token: Token,
        }
        let RawJSONToken { scopes, token } = RawJSONToken::deserialize(deserializer)?;
        let ScopeSet { hash, filter, .. } = ScopeSet::from(&scopes);
        Ok(JSONToken {
            scopes,
            token,
            hash,
            filter,
        })
    }
}

impl Serialize for JSONToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct RawJSONToken<'a> {
            scopes: &'a [String],
            token: &'a Token,
        }
        RawJSONToken {
            scopes: &self.scopes,
            token: &self.token,
        }
        .serialize(serializer)
    }
}

/// List of tokens in a JSON object
#[derive(Debug, Clone)]
pub(crate) struct JSONTokens {
    token_map: BTreeMap<ScopeHash, Arc<Mutex<JSONToken>>>,
    tokens: Vec<Arc<Mutex<JSONToken>>>,
}

impl JSONTokens {
    pub(crate) fn new() -> Self {
        JSONTokens {
            token_map: BTreeMap::new(),
            tokens: Vec::new(),
        }
    }

    pub(crate) async fn load_from_file(filename: &Path) -> Result<Self, io::Error> {
        let contents = tokio::fs::read(filename).await?;
        let tokens: Vec<Arc<Mutex<JSONToken>>> =
            serde_json::from_slice::<Vec<JSONToken>>(&contents)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .into_iter()
                .map(|json_token| Arc::new(Mutex::new(json_token)))
                .collect();
        let mut token_map: BTreeMap<ScopeHash, Arc<Mutex<JSONToken>>> = BTreeMap::new();
        for token in tokens.iter().cloned() {
            let hash = token.lock().unwrap().hash;
            token_map.insert(hash, token);
        }
        Ok(JSONTokens { token_map, tokens })
    }

    fn get<T>(
        &self,
        ScopeSet {
            hash,
            filter,
            scopes,
        }: ScopeSet<T>,
    ) -> Option<Token>
    where
        T: AsRef<str>,
    {
        if let Some(json_token) = self.token_map.get(&hash) {
            return Some(json_token.lock().unwrap().token.clone());
        }

        let requested_scopes_are_subset_of = |other_scopes: &[String]| {
            scopes
                .iter()
                .all(|s| other_scopes.iter().any(|t| t.as_str() == s.as_ref()))
        };
        // No exact match for the scopes provided. Search for any tokens that
        // exist for a superset of the scopes requested.
        self.tokens
            .iter()
            .filter(|json_token| {
                filter.is_subset_of(json_token.lock().unwrap().filter) == FilterResponse::Maybe
            })
            .find(|v: &&Arc<Mutex<JSONToken>>| requested_scopes_are_subset_of(&v.lock().unwrap().scopes))
            .map(|t: &Arc<Mutex<JSONToken>>| t.lock().unwrap().token.clone())
    }

    fn set<T>(
        &mut self,
        ScopeSet {
            hash,
            filter,
            scopes,
        }: ScopeSet<T>,
        token: Token,
    ) where
        T: AsRef<str>,
    {
        use std::collections::btree_map::Entry;
        match self.token_map.entry(hash) {
            Entry::Occupied(entry) => {
                entry.get().lock().unwrap().token = token;
            }
            Entry::Vacant(entry) => {
                let json_token = Arc::new(Mutex::new(JSONToken {
                    scopes: scopes.iter().map(|x| x.as_ref().to_owned()).collect(),
                    token,
                    hash,
                    filter,
                }));
                entry.insert(json_token.clone());
                self.tokens.push(json_token);
            }
        }
    }

    fn all_tokens(&self) -> Vec<JSONToken> {
        self.tokens
            .iter()
            .map(|t: &Arc<Mutex<JSONToken>>| t.lock().unwrap().clone())
            .collect()
    }
}

pub(crate) struct DiskStorage {
    tokens: Mutex<JSONTokens>,
    write_tx: tokio::sync::mpsc::Sender<Vec<JSONToken>>,
}

fn is_send<T: Send>() {}

impl DiskStorage {
    pub(crate) async fn new(path: PathBuf) -> Result<Self, io::Error> {
        is_send::<JSONTokens>();
        let tokens = match JSONTokens::load_from_file(&path).await {
            Ok(tokens) => tokens,
            Err(e) if e.kind() == io::ErrorKind::NotFound => JSONTokens::new(),
            Err(e) => return Err(e),
        };

        // Writing to disk will happen in a separate task. This means in the
        // common case returning a token to the user will not be required to
        // wait for disk i/o. We communicate with a dedicated writer task via a
        // buffered channel. This ensures that the writes happen in the order
        // received, and if writes fall too far behind we will block GetToken
        // requests until disk i/o completes.
        let (write_tx, mut write_rx) = tokio::sync::mpsc::channel::<Vec<JSONToken>>(2);
        tokio::spawn(async move {
            while let Some(tokens) = write_rx.recv().await {
                match serde_json::to_string(&tokens) {
                    Err(e) => log::error!("Failed to serialize tokens: {}", e),
                    Ok(ser) => {
                        if let Err(e) = tokio::fs::write(path.clone(), &ser).await {
                            log::error!("Failed to write tokens to disk: {}", e);
                        }
                    }
                }
            }
        });
        Ok(DiskStorage {
            tokens: Mutex::new(tokens),
            write_tx,
        })
    }

    async fn set<T>(&self, scopes: ScopeSet<'_, T>, token: Token)
    where
        T: AsRef<str>,
    {
        let cloned_tokens = {
            let mut tokens = self.tokens.lock().unwrap();
            tokens.set(scopes, token);
            tokens.all_tokens()
        };
        self.write_tx
            .clone()
            .send(cloned_tokens)
            .await
            .expect("disk storage task not running");
    }

    pub(crate) fn get<T>(&self, scopes: ScopeSet<T>) -> Option<Token>
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
    fn test_scope_filter() {
        let foo = ScopeSet::from(&["foo"]).filter;
        let bar = ScopeSet::from(&["bar"]).filter;
        let foobar = ScopeSet::from(&["foo", "bar"]).filter;

        // foo and bar are both subsets of foobar. This condition should hold no
        // matter what changes are made to the bloom filter implementation.
        assert!(foo.is_subset_of(foobar) == FilterResponse::Maybe);
        assert!(bar.is_subset_of(foobar) == FilterResponse::Maybe);

        // These conditions hold under the current bloom filter implementation
        // because "foo" and "bar" don't collide, but if the bloom filter
        // implementations change it could be valid for them to return Maybe.
        assert!(foo.is_subset_of(bar) == FilterResponse::No);
        assert!(bar.is_subset_of(foo) == FilterResponse::No);
        assert!(foobar.is_subset_of(foo) == FilterResponse::No);
        assert!(foobar.is_subset_of(bar) == FilterResponse::No);
    }
}
