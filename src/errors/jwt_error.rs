use std::fmt::{Display, Formatter};
use std::string::FromUtf8Error;
use base64_url::base64::DecodeError;

#[derive(Debug)]
pub enum JwtError {
    PayloadIsNotJson,
    PayloadNotAnObject,
    NotAnAccessToken,
    NotARefreshToken,
    MissingHeader,
    MissingPayload,
    MissingSignature,
    InvalidSignature,
    UsedBeforeNotBeforeClaim,
    UsedAfterExpireClaim,
    FailedToSerializeJson,
    FailedToDecodeBase64Url,
    FailedToReadStringAsUtf8,

    // These values are not actually used within this crate, but are still available to make it a
    // bit easier when working with the error.
    NotEnoughPermissions,
    MissingToken,
}

impl Display for JwtError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let slice = match self {
            JwtError::PayloadIsNotJson => "The payload of the JWT is not JSON",
            JwtError::PayloadNotAnObject => "The payload of the JWT is not an object",
            JwtError::NotAnAccessToken => "The provided JWT token is not an access token",
            JwtError::NotARefreshToken => "The provided JWT token is not a refresh token",
            JwtError::MissingHeader => "The provided JWT token is missing the headers",
            JwtError::MissingPayload => "The provided JWT token is missing the payload",
            JwtError::MissingSignature => "The provided JWT token is missing the signature",
            JwtError::InvalidSignature => "The signature is not valid",
            JwtError::UsedBeforeNotBeforeClaim => "Token was used before the 'not before' claim",
            JwtError::UsedAfterExpireClaim => "Token was used after the 'expire' claim",
            JwtError::FailedToSerializeJson => "Failed to serialize JSON payload",
            JwtError::FailedToDecodeBase64Url => "Failed to decode base64url encoded part of token",
            JwtError::FailedToReadStringAsUtf8 => "Failed to read token as UTF-8",
            JwtError::NotEnoughPermissions => "This token does not have enough permissions for this operation",
            JwtError::MissingToken => "Expected a JWT token, but none was provided",
        };

        write!(f, "{}", slice)
    }
}

impl std::error::Error for JwtError {}

impl From<serde_json::Error> for JwtError {
    fn from(_: serde_json::Error) -> Self {
        JwtError::FailedToSerializeJson
    }
}

impl From<DecodeError> for JwtError {
    fn from(_: DecodeError) -> Self {
        JwtError::FailedToDecodeBase64Url
    }
}

impl From<FromUtf8Error> for JwtError {
    fn from(_: FromUtf8Error) -> Self {
        JwtError::FailedToReadStringAsUtf8
    }
}
