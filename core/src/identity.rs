use crate::stanza::Stanza;
use thiserror::Error;
use zeroize::Zeroizing;

pub type FileKey = Zeroizing<[u8; 16]>;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("cancelled by user")]
    Cancelled,

    #[error("hardware error: {0}")]
    Hardware(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub trait Identity: Send + Sync {
    fn try_unwrap_stanza(&self, stanza: &Stanza) -> Result<Option<FileKey>, IdentityError>;

    fn display(&self) -> &str;

    fn as_software_age_identity(&self) -> Option<&age::x25519::Identity> {
        None
    }
}
