// partially (c) 2016 Google Inc. (Lewin Bormann, lewinb@google.com)
//
// See project root for licensing information.
//
use crate::types::Token;

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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

/// ScopeFilter represents a filter for a set of scopes. It can definitively
/// prove that a given list of scopes is not a subset of another.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
struct ScopeFilter {
    bitmask: u64,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum FilterResponse {
    Maybe,
    No,
}

impl ScopeFilter {
    fn new<T>(scopes: &[T]) -> Self
    where
        T: AsRef<str>,
    {
        let mut bitmask = 0u64;
        for scope in scopes {
            let scope_hash = seahash::hash(scope.as_ref().as_bytes());
            // Use the first 4 6-bit chunks of the seahash as the 4 hash values
            // in the bloom filter.
            for i in 0..4 {
                // h is a hash derived value in the range 0..64
                let h = (scope_hash >> (6 * i)) & 0b11_1111;
                bitmask |= 1 << h;
            }
        }
        ScopeFilter { bitmask }
    }

    /// Determine if this ScopeFilter could be a subset of the provided filter.
    fn is_subset_of(self, filter: ScopeFilter) -> FilterResponse {
        if self.bitmask & filter.bitmask == self.bitmask {
            FilterResponse::Maybe
        } else {
            FilterResponse::No
        }
    }
}

#[derive(Debug)]
pub struct ScopesAndFilter<'a, T> {
    filter: ScopeFilter,
    scopes: &'a [T],
}

// Implement Clone manually. Auto derive fails to work correctly because we want
// Clone to be implemented regardless of whether T is Clone or not.
impl<'a, T> Clone for ScopesAndFilter<'a, T> {
    fn clone(&self) -> Self {
        ScopesAndFilter {
            filter: self.filter,
            scopes: self.scopes,
        }
    }
}
impl<'a, T> Copy for ScopesAndFilter<'a, T> {}

impl<'a, T> From<&'a [T]> for ScopesAndFilter<'a, T>
where
    T: AsRef<str>,
{
    fn from(scopes: &'a [T]) -> Self {
        let filter = ScopeFilter::new(scopes);
        ScopesAndFilter { filter, scopes }
    }
}

impl<'a, T> ScopesAndFilter<'a, T>
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
    pub(crate) async fn set<T>(&self, scopes: ScopesAndFilter<'_, T>, token: Token)
    where
        T: AsRef<str>,
    {
        match self {
            Storage::Memory { tokens } => tokens.lock().unwrap().set(scopes, token),
            Storage::Disk(disk_storage) => disk_storage.set(scopes, token).await,
        }
    }

    pub(crate) fn get<T>(&self, scopes: ScopesAndFilter<T>) -> Option<Token>
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
    pub scopes: Vec<String>,
    pub token: Token,
}

/// List of tokens in a JSON object
#[derive(Debug, Clone)]
pub(crate) struct JSONTokens {
    token_map: BTreeMap<ScopeFilter, Vec<JSONToken>>,
}

impl JSONTokens {
    pub(crate) fn new() -> Self {
        JSONTokens {
            token_map: BTreeMap::new(),
        }
    }

    pub(crate) async fn load_from_file(filename: &Path) -> Result<Self, io::Error> {
        let contents = tokio::fs::read(filename).await?;
        let token_vec: Vec<JSONToken> = serde_json::from_slice(&contents)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut token_map: BTreeMap<ScopeFilter, Vec<JSONToken>> = BTreeMap::new();
        for token in token_vec {
            let filter = ScopesAndFilter::from(&token.scopes).filter;
            token_map.entry(filter).or_default().push(token);
        }
        Ok(JSONTokens { token_map })
    }

    fn get<T>(&self, ScopesAndFilter { filter, scopes }: ScopesAndFilter<T>) -> Option<Token>
    where
        T: AsRef<str>,
    {
        let requested_scopes_are_subset_of = |other_scopes: &[String]| {
            scopes
                .iter()
                .all(|s| other_scopes.iter().any(|t| t.as_str() == s.as_ref()))
        };
        // Check for exact match of bloom filter first. In the common case an
        // application will provide the same set of scopes repeatedly. If a
        // token exists for the exact scope list requested a lookup of the
        // ScopeFilter will return a list that would contain it.
        if let Some(t) = self
            .token_map
            .get(&filter)
            .into_iter()
            .flat_map(|tokens_matching_filter| tokens_matching_filter.iter())
            .find(|js_token: &&JSONToken| requested_scopes_are_subset_of(&js_token.scopes))
        {
            return Some(t.token.clone());
        }

        // No exact match for the scopes provided. Search for any tokens that
        // exist for a superset of the scopes requested.
        self.token_map
            .iter()
            .filter(|(k, _)| filter.is_subset_of(**k) == FilterResponse::Maybe)
            .flat_map(|(_, tokens_matching_filter)| tokens_matching_filter.iter())
            .find(|v: &&JSONToken| requested_scopes_are_subset_of(&v.scopes))
            .map(|t: &JSONToken| t.token.clone())
    }

    fn set<T>(&mut self, ScopesAndFilter { filter, scopes }: ScopesAndFilter<T>, token: Token)
    where
        T: AsRef<str>,
    {
        self.token_map.entry(filter).or_default().push(JSONToken {
            scopes: scopes.iter().map(|x| x.as_ref().to_string()).collect(),
            token,
        });
    }

    fn all_tokens(&self) -> Vec<JSONToken> {
        self.token_map
            .values()
            .flat_map(|v| v.iter())
            .cloned()
            .collect()
    }
}

pub(crate) struct DiskStorage {
    tokens: Mutex<JSONTokens>,
    write_tx: tokio::sync::mpsc::Sender<Vec<JSONToken>>,
}

impl DiskStorage {
    pub(crate) async fn new(path: PathBuf) -> Result<Self, io::Error> {
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

    async fn set<T>(&self, scopes: ScopesAndFilter<'_, T>, token: Token)
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

    pub(crate) fn get<T>(&self, scopes: ScopesAndFilter<T>) -> Option<Token>
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
        let foo = ScopeFilter::new(&["foo"]);
        let bar = ScopeFilter::new(&["bar"]);
        let foobar = ScopeFilter::new(&["foo", "bar"]);

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
