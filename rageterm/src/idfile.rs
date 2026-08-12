use std::fs;
use std::io;
use std::path::Path;

use age::secrecy::ExposeSecret;
use thiserror::Error;

use crate::config;

#[derive(Debug, Error)]
pub enum IdFileError {
    #[error("identity file io: {0}")]
    Io(#[from] io::Error),

    #[error("identity file parse: {0}")]
    Parse(String),

    #[error("no identity enrolled at {path} -- run `rageterm enroll-software-identity`")]
    NotEnrolled { path: String },
}

pub fn generate_and_write(path: &Path) -> Result<String, IdFileError> {
    let id = age::x25519::Identity::generate();
    let secret_armored = id.to_string();
    let pub_armored = id.to_public().to_string();

    config::write_private(path, secret_armored.expose_secret().as_bytes())?;
    Ok(pub_armored)
}

pub fn read(path: &Path) -> Result<age::x25519::Identity, IdFileError> {
    let bytes = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(IdFileError::NotEnrolled {
                path: path.display().to_string(),
            });
        }
        Err(e) => return Err(e.into()),
    };

    let line = bytes
        .lines()
        .find(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .ok_or_else(|| IdFileError::Parse("identity file empty".into()))?;

    let id: age::x25519::Identity = line
        .parse()
        .map_err(|e: &str| IdFileError::Parse(e.to_string()))?;
    Ok(id)
}

pub fn read_public_key_armored(path: &Path) -> Result<String, IdFileError> {
    let id = read(path)?;
    Ok(id.to_public().to_string())
}
