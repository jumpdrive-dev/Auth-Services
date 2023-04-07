#[derive(Debug)]
pub enum TotpError {
    FailedToDecodeSecret,
    InvalidOneTimePassword,
}
