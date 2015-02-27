use std::borrow::BorrowMut;
use std::marker::PhantomData;
use std::collections::HashMap;

use common::{Token, AuthenticationType, ApplicationSecret};

use hyper;


/// Implements a specialised storage to set and retrieve `Token` instances.
/// The `scope_hash` represents the signature of the scopes for which the given token
/// should be stored or retrieved.
pub trait TokenStorage {
    /// If `token` is None, it is invalid or revoked and should be removed from storage.
    fn set(&mut self, scope_hash: i64, token: Option<Token>);
    /// A `None` result indicates that there is no token for the given scope_hash.
    fn get(&self, scope_hash: i64) -> Option<Token>;
}

/// A storage that remembers nothing.
pub struct NullStorage;

impl TokenStorage for NullStorage {
    fn set(&mut self, _: i64, _: Option<Token>) {}
    fn get(&self, _: i64) -> Option<Token> { None }
}

/// A storage that remembers values for one session only.
pub struct MemoryStorage {
    pub tokens: HashMap<i64, Token>
}

impl TokenStorage for MemoryStorage {
    fn set(&mut self, scope_hash: i64, token: Option<Token>) {
        match token {
            Some(t) => self.tokens.insert(scope_hash, t),
            None => self.tokens.remove(&scope_hash),
        };
    }

    fn get(&self, scope_hash: i64) -> Option<Token> {
        match self.tokens.get(&scope_hash) {
            Some(t) => Some(t.clone()),
            None => None,
        }
    }
}

/// A generalized authenticator which will keep tokens valid and store them. 
///
/// It is the go-to helper to deal with any kind of supported authentication flow,
/// which will be kept valid and usable.
pub struct Authenticator<S, C, NC> {
    auth_type: AuthenticationType,
    storage: S,
    client: C,

    _m: PhantomData<NC>
}

impl<S, C, NC> Authenticator<S, C, NC>
    where  S: TokenStorage,
          NC: hyper::net::NetworkConnector,
           C: BorrowMut<hyper::Client<NC>> {

    // 
    // fn new() -> Authenticator<S, C, NC> {

    // }

    // Will retrieve a token, from storage, retrieve a new one, or refresh 
    // an existing one.
    // fn token() -> 
}