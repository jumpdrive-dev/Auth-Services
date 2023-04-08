use chrono::Utc;

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
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
        ];

        let code = u32::from_be_bytes(slice_offset) % 1000000;
        Ok(format!("{:0>6}", code))
    }

    fn get_time_step() -> u64 {
        (Utc::now().timestamp() / 30) as u64
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::TotpError;
    use crate::services::TotpService;

    const SECRET_KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc_6238_test_cases_are_correct() {
        let cases = [
            (0x0000000000000001, 94287082),
            (0x00000000023523ec, 07081804),
            (0x00000000023523ed, 14050471),
            (0x000000000273ef07, 89005924),
            (0x0000000003f940aa, 69279037),
            (0x0000000027bc86aa, 65353130),
        ];

        for (step, expected) in cases {
            let code = TotpService::generate_code_with_step(SECRET_KEY, step)
                .unwrap();

            let expected_code = expected % 1000000;
            assert_eq!(code, format!("{:0>6}", expected_code));
        }
    }

    #[test]
    fn correct_code_can_be_validated() {
        let code = TotpService::generate_code_with_step(
            SECRET_KEY,
            TotpService::get_time_step()
        )
            .unwrap();

        let valid = TotpService::validate_code(
            SECRET_KEY,
            code,
        )
            .unwrap();

        assert!(valid);
    }

    #[test]
    fn code_from_previous_step_is_still_valid() {
        let code = TotpService::generate_code_with_step(
            SECRET_KEY,
            TotpService::get_time_step() - 1
        )
            .unwrap();

        let valid = TotpService::validate_code(
            SECRET_KEY,
            code,
        )
            .unwrap();

        assert!(valid);
    }

    #[test]
    fn expired_code_is_invalid() {
        let code = TotpService::generate_code_with_step(
            SECRET_KEY,
            TotpService::get_time_step() - 10
        )
            .unwrap();

        let valid = TotpService::validate_code(
            SECRET_KEY,
            code,
        )
            .unwrap();

        assert!(!valid);
    }

    #[test]
    fn future_code_is_invalid() {
        let code = TotpService::generate_code_with_step(
            SECRET_KEY,
            TotpService::get_time_step() + 1
        )
            .unwrap();

        let valid = TotpService::validate_code(
            SECRET_KEY,
            code,
        )
            .unwrap();

        assert!(!valid);
    }
}
