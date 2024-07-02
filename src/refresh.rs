use crate::client::SendRequest;
use crate::error::Error;
use crate::types::{ApplicationSecret, TokenInfo};

use http::header;
use http_body_util::BodyExt;
use url::form_urlencoded;

/// Implements the [OAuth2 Refresh Token Flow](https://developers.google.com/youtube/v3/guides/authentication#devices).
///
/// Refresh an expired access token, as obtained by any other authentication flow.
/// This flow is useful when your `Token` is expired and allows to obtain a new
/// and valid access token.
pub(crate) struct RefreshFlow;

impl RefreshFlow {
    /// Attempt to refresh the given token, and obtain a new, valid one.
    /// If the `RefreshResult` is `RefreshResult::Error`, you may retry within an interval
    /// of your choice. If it is `RefreshResult:RefreshError`, your refresh token is invalid
    /// or your authorization was revoked. Therefore no further attempt shall be made,
    /// and you will have to re-authorize using the `DeviceFlow`
    ///
    /// # Arguments
    /// * `authentication_url` - URL matching the one used in the flow that obtained
    ///                          your refresh_token in the first place.
    /// * `client_id` & `client_secret` - as obtained when [registering your application](https://developers.google.com/youtube/registering_an_application)
    /// * `refresh_token` - obtained during previous call to `DeviceFlow::poll_token()` or equivalent
    ///
    /// # Examples
    /// Please see the crate landing page for an example.
    pub(crate) async fn refresh_token(
        client: &impl SendRequest,
        client_secret: &ApplicationSecret,
        refresh_token: &str,
    ) -> Result<TokenInfo, Error>
where {
        log::debug!(
            "refreshing access token with refresh token: {}",
            refresh_token
        );
        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", client_secret.client_id.as_str()),
                ("client_secret", client_secret.client_secret.as_str()),
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token"),
            ])
            .finish();

        let request = http::Request::post(&client_secret.token_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(req)
            .unwrap();
        log::debug!("Sending request: {:?}", request);
        let (head, body) = client.request(request).await?.into_parts();
        let body = body.collect().await?.to_bytes();
        log::debug!("Received response; head: {:?}, body: {:?}", head, body);
        let mut token = TokenInfo::from_json(&body)?;
        // If the refresh result contains a refresh_token use it, otherwise
        // continue using our previous refresh_token.
        token
            .refresh_token
            .get_or_insert_with(|| refresh_token.to_owned());
        Ok(token)
    }
}
