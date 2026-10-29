use std::io::{self, IsTerminal, Write};
use std::path::Path;

use ragewarden_core::recovery;
#[cfg(test)]
use ragewarden_core::recovery::GeneratedRecovery;
use ragewarden_core::{Identity, IdentityError, Stanza};
use thiserror::Error;

use crate::config;

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("recovery io: {0}")]
    Io(#[from] io::Error),

    #[error("{0}")]
    Core(#[from] ragewarden_core::recovery::RecoveryError),

    #[error("recovery words did not match the printed mnemonic; nothing was written")]
    ConfirmFailed,

    #[error(
        "enroll-recovery needs a terminal so the 24 words can be shown and typed back; \
         pass `--no-confirm` to print them to stderr without the check"
    )]
    NoTerminal,
}

/// Generate a paper recovery recipient. The secret leaves this process only as
/// the 24 words: nothing is written to disk (`recover --save` is the explicit
/// way to put it on a machine that lost its other keys).
pub fn enroll(auto_confirm: bool) -> Result<EnrolledRecovery, RecoveryError> {
    let interactive = io::stdin().is_terminal();
    if !auto_confirm && !interactive {
        return Err(RecoveryError::NoTerminal);
    }

    let generated = recovery::generate()?;
    let phrase = generated.mnemonic.to_string();

    print_mnemonic(&phrase, interactive)?;

    if !auto_confirm {
        confirm_words(&phrase)?;
    }

    Ok(EnrolledRecovery {
        armored_pubkey: generated.armored_pubkey,
    })
}

pub struct EnrolledRecovery {
    pub armored_pubkey: ragewarden_core::ArmoredAgeRecipient,
}

/// The words go to the controlling terminal when there is one, so they do not
/// land in a log that captures stderr.
fn print_mnemonic(phrase: &str, interactive: bool) -> io::Result<()> {
    let mut out: Box<dyn Write> = match std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        Ok(tty) if interactive => Box::new(tty),
        _ => Box::new(io::stderr()),
    };
    let words: Vec<&str> = phrase.split_whitespace().collect();
    writeln!(out)?;
    writeln!(out, "=== Ragewarden recovery mnemonic ===")?;
    writeln!(out)?;
    writeln!(
        out,
        "Write these 24 words on paper, in order. Anyone who has these words can"
    )?;
    writeln!(
        out,
        "decrypt your rage-protected ciphers -- treat them like the master password."
    )?;
    writeln!(out)?;
    for row in 0..6 {
        let mut line = String::new();
        for col in 0..4 {
            let i = row * 4 + col;
            if i < words.len() {
                line.push_str(&format!("  {:>2}. {:<10}", i + 1, words[i]));
            }
        }
        writeln!(out, "{line}")?;
    }
    writeln!(out)?;
    out.flush()
}

fn confirm_words(expected_phrase: &str) -> Result<(), RecoveryError> {
    eprintln!("Confirm: re-type the 24 words separated by spaces (input is not echoed).");
    eprint!("> ");
    io::stderr().flush()?;
    let typed = rpassword::read_password()?;
    let normalize = |s: &str| {
        s.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    };
    if normalize(&typed) != normalize(expected_phrase) {
        return Err(RecoveryError::ConfirmFailed);
    }
    eprintln!("Confirmed.");
    Ok(())
}

/// The phrase from the terminal (not echoed), or the first line of stdin when
/// stdin is not a terminal, the same rule as the master password.
pub fn recover_from_typed_phrase() -> Result<age::x25519::Identity, RecoveryError> {
    let typed = zeroize::Zeroizing::new(if io::stdin().is_terminal() {
        eprintln!("Type your 24-word recovery phrase (input is not echoed):");
        eprint!("> ");
        io::stderr().flush()?;
        rpassword::read_password()?
    } else {
        let mut line = String::new();
        io::BufRead::read_line(&mut io::stdin().lock(), &mut line)?;
        line
    });
    Ok(recovery::from_phrase(typed.trim())?)
}

pub fn read_if_enrolled() -> Result<Option<age::x25519::Identity>, RecoveryError> {
    let path = config::recovery_path()?;
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(read_from_path(&path)?))
}

fn read_from_path(path: &Path) -> Result<age::x25519::Identity, RecoveryError> {
    let bytes = std::fs::read_to_string(path)?;
    let line = bytes
        .lines()
        .find(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .ok_or_else(|| RecoveryError::Io(io::Error::new(io::ErrorKind::InvalidData, "empty")))?;
    let id: age::x25519::Identity = line.parse().map_err(|e: &str| {
        RecoveryError::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    })?;
    Ok(id)
}

pub struct RecoveryIdentity {
    inner: age::x25519::Identity,
    label: String,
}

impl RecoveryIdentity {
    pub fn new(inner: age::x25519::Identity, label: impl Into<String>) -> Self {
        Self {
            inner,
            label: label.into(),
        }
    }

    pub fn load_if_enrolled() -> Result<Option<Self>, RecoveryError> {
        Ok(read_if_enrolled()?.map(|id| Self::new(id, "recovery (paper backup)")))
    }
}

impl Identity for RecoveryIdentity {
    fn try_unwrap_stanza(
        &self,
        _stanza: &Stanza,
    ) -> Result<Option<ragewarden_core::FileKey>, IdentityError> {
        Ok(None)
    }

    fn display(&self) -> &str {
        &self.label
    }

    fn as_software_age_identity(&self) -> Option<&age::x25519::Identity> {
        Some(&self.inner)
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn generate_for_test() -> Result<GeneratedRecovery, RecoveryError> {
    Ok(recovery::generate()?)
}
