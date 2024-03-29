use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

/// Claims as defined in [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519). Should be included in
/// the payload of a JWT token to add context and control to the token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtClaims {
    /// From [RFC 7519 section 4.1.1](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1):
    /// The "iss" (issuer) claim identifies the principal that issued the JWT. The processing of
    /// this claim is generally application specific. The "iss" value is a case-sensitive string
    /// containing a StringOrURI value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// From [RFC 7519 section 4.1.2](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2):
    /// The "sub" (subject) claim identifies the principal that is the subject of the JWT. The
    /// claims in a JWT are normally statements about the subject. The subject value MUST either be
    /// scoped to be locally unique in the context of the issuer or be globally unique. The
    /// processing of this claim is generally application specific. The "sub" value is a
    /// case-sensitive string containing a StringOrURI value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// From [RFC 7519 section 4.1.3](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3):
    /// The "aud" (audience) claim identifies the recipients that the JWT is intended for. Each
    /// principal intended to process the JWT MUST identify itself with a value in the audience
    /// claim. If the principal processing the claim does not identify itself with a value in the
    /// "aud" claim when this claim is present, then the JWT MUST be rejected. In the general case,
    /// the "aud" value is an array of case-sensitive strings, each containing a StringOrURI value.
    /// In the special case when the JWT has one audience, the "aud" value MAY be a single
    /// case-sensitive string containing a StringOrURI value. The interpretation of audience values
    /// is generally application specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// From [RFC 7519 section 4.1.4](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4):
    /// The "exp" (expiration time) claim identifies the expiration time on or after which the JWT
    /// MUST NOT be accepted for processing. The processing of the "exp" claim requires that the
    /// current date/time MUST be before the expiration date/time listed in the "exp" claim.
    /// Implementers MAY provide for some small leeway, usually no more than a few minutes, to
    /// account for clock skew. Its value MUST be a number containing a NumericDate value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// From [RFC 7519 section 4.1.5](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5):
    /// The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted
    /// for processing. The processing of the "nbf" claim requires that the current date/time MUST
    /// be after or equal to the not-before date/time listed in the "nbf" claim. Implementers MAY
    /// provide for some small leeway, usually no more than a few minutes, to account for clock
    /// skew. Its value MUST be a number containing a NumericDate value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// From [RFC 7519 section 4.1.6](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6):
    /// The "iat" (issued at) claim identifies the time at which the JWT was issued. This claim can
    /// be used to determine the age of the JWT. Its value MUST be a number containing a NumericDate
    /// value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// From [RFC 7519 section 4.1.7](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7):
    /// The "jti" (JWT ID) claim provides a unique identifier for the JWT. The identifier value MUST
    /// be assigned in a manner that ensures that there is a negligible probability that the same
    /// value will be accidentally assigned to a different data object; if the application uses
    /// multiple issuers, collisions MUST be prevented among values produced by different issuers as
    /// well. The "jti" claim can be used to prevent the JWT from being replayed. The "jti" value is
    /// a case-sensitive string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl Default for JwtClaims {
    fn default() -> Self {
        let now_timestamp = Utc::now().timestamp();

        Self {
            iss: None,
            sub: None,
            aud: None,
            exp: Some(now_timestamp + 5),
            nbf: Some(now_timestamp + 5),
            iat: Some(now_timestamp),
            jti: None,
        }
    }
}

impl JwtClaims {
    /// Creates empty claims without any default values.
    pub fn new() -> Self {
        JwtClaims {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
        }
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.iss = Some(issuer.into());
        self
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.sub = Some(subject.into());
        self
    }

    pub fn for_audience(mut self, audience: impl Into<String>) -> Self {
        self.aud = Some(audience.into());
        self
    }

    pub fn expire_in(mut self, duration: Duration) -> Self {
        self.exp = Some(Utc::now().timestamp() + duration.num_seconds());
        self
    }

    pub fn valid_after(mut self, duration: Duration) -> Self {
        self.nbf = Some(Utc::now().timestamp() + duration.num_seconds());
        self
    }

    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }
}
