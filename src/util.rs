use common::{Token, AuthenticationType};

/// Implements a specialised storage to set and retrieve `Token` instances.
/// The `scope_hash` represents the signature of the scopes for which the given token
/// should be stored or retrieved.
pub trait TokenStorage {
    /// If `token` is None, it is invalid or revoked and should be removed from storage.
    fn set(&mut self, scope_hash: i64, token: Option<Token>);
    /// A `None` result indicates that there is no token for the given scope_hash.
    /// It is assumed that a token previously `set` will be retrievable using `get`
    fn get(&self, scope_hash: i64) -> Option<Token>;
}


/// A generalized authenticator which will keep tokens valid and store them. 
///
/// It is the go-to helper to deal with any kind of supported authentication flow,
/// which will be kept valid and usable.
pub struct Authenticator<S> {
    auth_type: AuthenticationType,
    storage: S,
    // client ref ... 
}