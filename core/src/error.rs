/// Errors returned by `op-core`.
///
/// Messages never include key material or decrypted data.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("the system random number generator failed")]
    Rng,
    #[error("invalid KDF parameters: {0}")]
    KdfParams(&'static str),
    #[error("key derivation failed")]
    Kdf,
    #[error("decryption failed: wrong key or tampered data")]
    Decrypt,
    #[error("wrong master password or secret key")]
    WrongCredentials,
    #[error("the secret key does not belong to this vault")]
    WrongSecretKey,
    #[error("invalid secret key: {0}")]
    InvalidSecretKey(&'static str),
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("malformed data: {0}")]
    Malformed(&'static str),
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u32),
}

pub type Result<T> = core::result::Result<T, Error>;
