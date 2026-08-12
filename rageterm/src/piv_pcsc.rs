//! The PC/SC transport -- the only code in rageterm that talks to a real smart
//! card. Nothing above this file knows `pcsc` exists.
//!
//! DEVICE-BLOCKED: none of this can be exercised without a reader and a card.
//! It is deliberately thin (establish, list, connect, transmit) so that the
//! logic worth testing lives in `piv_apdu.rs` and `piv::PivSession`, both of
//! which are covered by unit tests.

use std::ffi::CString;

use pcsc::{Context, Protocols, Scope, ShareMode};

use crate::piv::{CardTransport, PivError};

const RECEIVE_BUFFER_LEN: usize = 4096;

pub struct PcscTransport {
    card: pcsc::Card,
    reader: String,
    // Held so the resource-manager context outlives the card handle.
    _context: Context,
}

impl CardTransport for PcscTransport {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, PivError> {
        let mut buffer = [0u8; RECEIVE_BUFFER_LEN];
        let response = self
            .card
            .transmit(apdu, &mut buffer)
            .map_err(|e| map_pcsc_error(e, &self.reader))?;
        Ok(response.to_vec())
    }

    fn describe(&self) -> String {
        self.reader.clone()
    }
}

/// Connect to the first reader that has a card in it.
///
/// The distinction between "no reader", "reader but no card" and "pcscd is not
/// running" is preserved all the way out, because those three need three
/// different things from the user.
pub fn open_first_piv_card() -> Result<PcscTransport, PivError> {
    let context = Context::establish(Scope::User).map_err(|e| match e {
        pcsc::Error::NoService | pcsc::Error::ServiceStopped => PivError::Pcsc(
            "the PC/SC daemon is not running (start it with `systemctl start pcscd`)".into(),
        ),
        other => PivError::Pcsc(other.to_string()),
    })?;

    let readers: Vec<CString> = match context.list_readers_owned() {
        Ok(r) => r,
        Err(pcsc::Error::NoReadersAvailable) => return Err(PivError::NoReader),
        Err(e) => return Err(PivError::Pcsc(e.to_string())),
    };
    if readers.is_empty() {
        return Err(PivError::NoReader);
    }

    let mut last_empty: Option<String> = None;
    for reader in &readers {
        let name = reader.to_string_lossy().to_string();
        match context.connect(reader, ShareMode::Shared, Protocols::ANY) {
            Ok(card) => {
                return Ok(PcscTransport {
                    card,
                    reader: name,
                    _context: context,
                })
            }
            Err(pcsc::Error::NoSmartcard) | Err(pcsc::Error::RemovedCard) => {
                last_empty = Some(name);
            }
            Err(pcsc::Error::SharingViolation) => {
                return Err(PivError::Pcsc(format!(
                    "reader `{name}` is exclusively held by another process (a browser or \
                     `gpg-agent`, typically); close it and retry"
                )));
            }
            Err(e) => return Err(map_pcsc_error(e, &name)),
        }
    }

    match last_empty {
        Some(name) => Err(PivError::NoCard(name)),
        None => Err(PivError::NoReader),
    }
}

fn map_pcsc_error(e: pcsc::Error, reader: &str) -> PivError {
    match e {
        pcsc::Error::NoSmartcard | pcsc::Error::RemovedCard => PivError::NoCard(reader.to_string()),
        pcsc::Error::NoReadersAvailable | pcsc::Error::ReaderUnavailable => PivError::NoReader,
        pcsc::Error::NoService | pcsc::Error::ServiceStopped => {
            PivError::Pcsc("the PC/SC daemon stopped mid-operation".into())
        }
        pcsc::Error::Timeout => PivError::TouchNotRegistered,
        other => PivError::Pcsc(format!("{other} (reader `{reader}`)")),
    }
}
