use serde::{Deserialize, Serialize};

use crate::models::jwt::jwt_token_type::JwtTokenType;

/// The header of a JWT token. Used to identify what signing algorithm is used and what type of
/// token it is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtHeader<T = JwtTokenType> {
    /// The algorithm of that the server used to sign the JWT token. Possible values can be found in
    /// [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518#section-3).
    pub alg: String,

    /// The type of token. This is probably here for future-proofing as currently it should always
    /// be "JWT".
    pub typ: String,

    /// This is usually used when using nested JWT tokens, but here it's used to differentiate
    /// between access tokens and refresh tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<T>,
}

impl<T> JwtHeader<T> {
    pub fn with_cty(value: T) -> JwtHeader<T> {
        JwtHeader {
            cty: Some(value),
            ..JwtHeader::default()
        }
    }
}

impl<T> Default for JwtHeader<T> {
    fn default() -> JwtHeader<T> {
        Self {
            alg: "RS256".to_string(),
            typ: "JWT".to_string(),
            cty: None,
        }
    }
}
