#[cfg(feature = "jwt")]
pub use jwt_error::JwtError;

#[cfg(feature = "totp")]
pub use totp_error::TotpError;

pub(crate) mod jwt_error;
pub(crate) mod totp_error;

