//! The browser's route from a synced vault to the recipients a new secret is
//! wrapped to: the registry document in the vault, then the shared policy.

use ragewarden_core::policy::{self, LocalAuthenticators, Selection};
use ragewarden_core::registry;
use ragewarden_core::sync::{Session, SyncError, Vault};

/// `local_prf_entry_ids`: registry ids of the PRF authenticators this browser
/// profile can evaluate; `None` when it can reach none.
pub fn select_encrypt_recipients(
    session: &Session,
    vault: &Vault,
    local_prf_entry_ids: Option<Vec<String>>,
) -> Result<Selection, SyncError> {
    let entries = registry::extract_document(session, vault)?
        .map(|d| d.entries)
        .unwrap_or_default();
    let local = local_prf_entry_ids
        .map(LocalAuthenticators::from_ids)
        .unwrap_or_else(LocalAuthenticators::none);
    Ok(policy::select_for_encrypt(&entries, &[], &local))
}
