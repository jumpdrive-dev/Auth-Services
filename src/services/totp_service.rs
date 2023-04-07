use std::io::Read;

use chrono::Utc;
use hmac::Hmac;
use hmac::Mac;
use hmacsha1::hmac_sha1;
use rand::RngCore;

use crate::errors::TotpError;

/// Service for implementing multi-factor authentication using time bases passwords.
pub struct TotpService;

const ALPHABET: base32::Alphabet = base32::Alphabet::RFC4648 { padding: true };

impl TotpService {
    /// Generates a secret key which needs to be shared with the user to sync password generation.
    pub fn generate_secret_key() -> String {
        let mut rng = rand::thread_rng();
        let mut buffer: [u8; 20] = [0; 20];

        rng.fill_bytes(&mut buffer);

        base32::encode(ALPHABET, &buffer)
    }

    /// Takes a secret key and generates a one-time password for using the current UTC time.
    pub fn generate_code(secret_key: impl Into<String>) -> Result<String, TotpError> {
        Self::generate_code_with_step(secret_key, Self::get_time_step())
    }

    fn generate_code_with_step(
        secret_key: impl Into<String>,
        step: u64,
    ) -> Result<String, TotpError> {
        let k =
            base32::decode(ALPHABET, &secret_key.into()).ok_or(TotpError::FailedToDecodeSecret)?;

        let m: [u8; 8] = step.to_be_bytes();
        let hash = hmac_sha1(&k, &m);
        let offset = (hash.last().unwrap() & 0xf) as usize;

        let slice_offset = [
            hash[offset] & 0x7f,
            hash[offset + 1] & 0xff,
            hash[offset + 2] & 0xff,
            hash[offset + 3] & 0xff,
        ];

        let code = u32::from_be_bytes(slice_offset) % 1000000;
        Ok(format!("{:0>6}", code))
    }

    fn get_time_step() -> u64 {
        (Utc::now().timestamp() / 30) as u64
    }

    /// Takes a secret key and a one-time password and checks whether it's still valid. One-time
    /// passwords last for two steps (or 60 second cycles.)
    pub fn validate_code(
        secret_key: impl Into<String>,
        code: impl Into<String>,
    ) -> Result<bool, TotpError> {
        let code = code.into();
        let secret_key = secret_key.into();
        let current_step = Self::get_time_step();

        let last = Self::generate_code_with_step(&secret_key, current_step - 1)?;

        let current = Self::generate_code_with_step(&secret_key, current_step)?;

        Ok(code == last || code == current)
    }

    /// Takes a secret key and a one-time password and checks whether it's still valid. Returns an
    /// Err if the password it not valid. One-time passwords last for two steps
    /// (or 60 second cycles.)
    pub fn guard_code(
        secret_key: impl Into<String>,
        code: impl Into<String>,
    ) -> Result<(), TotpError> {
        let valid = Self::validate_code(secret_key, code)?;

        if !valid {
            return Err(TotpError::InvalidOneTimePassword);
        }

        Ok(())
    }
}
