import { b64FromHex } from './b64.js';
import { loadAllPasskeyRecipients, loadSoftwareIdentity } from './passkey-store.js';
import { relayCredentialsFromRegistry } from './prf-relay.js';

/*
 * What this profile can open, in the LocalIdentityInventory shape the wasm
 * snapshot expects. piv/fido2 registry entries are claimed only when a
 * native-messaging port to rageterm can be opened; that can over-claim (the
 * decrypt then fails with no_matching_identity), which beats dimming items the
 * native host genuinely opens.
 */
/**
 * The PIV/FIDO2 registry entries that publish a device key for signing
 * native-host touch proofs (native-proof.js). A stanza addressed to one of them
 * must come back with that key's proof; see attestationKeysForStanza.
 */
export async function attestationEntriesFromRegistry(mod, session) {
    try {
        const reg = await mod.wasm_fetch_registry(session);
        return ((reg && reg.entries) || [])
            .filter(e => e && (e.kind === 'Fido2' || e.pivPubkey) && typeof e.attestationPublicKey === 'string')
            .map(e => ({
                pivPubkey: e.pivPubkey || null,
                fido2CredentialId: e.fido2CredentialId || null,
                attestationPublicKey: e.attestationPublicKey,
            }));
    } catch {
        return [];
    }
}

export async function registryEntries(mod, session) {
    try {
        const reg = await mod.wasm_fetch_registry(session);
        return (reg && reg.entries) || [];
    } catch {
        return [];
    }
}

/*
 * Phone passkeys (rp id ragewarden.decent.foundation) count as reachable: the
 * passkey relay asks them (prf-relay.js). `entries` is the registry when the
 * caller already holds it.
 */
export async function localIdentityInventory(mod, session, { nativeCapable = false, entries = null } = {}) {
    const inventory = {
        software_armored_pubkeys: [],
        passkey_credential_ids_b64: [],
        fido2_credential_ids_b64: [],
        piv_pubkeys_hex: [],
        keystore_handles: [],
    };
    try {
        const software = await loadSoftwareIdentity();
        if (software && software.armored_pubkey && software.wrap_credential_id_b64) {
            inventory.software_armored_pubkeys.push(software.armored_pubkey);
        }
        for (const r of await loadAllPasskeyRecipients()) {
            if (r && r.credential_id_b64) inventory.passkey_credential_ids_b64.push(r.credential_id_b64);
        }
    } catch (e) {
        console.warn('[ragewarden] could not read local identities for the snapshot:', e);
    }
    const registry = entries || await registryEntries(mod, session);
    for (const c of relayCredentialsFromRegistry(registry)) {
        inventory.passkey_credential_ids_b64.push(c.credentialIdB64);
    }
    if (nativeCapable) {
        for (const e of registry) {
            if (!e) continue;
            if (e.pivPubkey) inventory.piv_pubkeys_hex.push(String(e.pivPubkey));
            if (e.kind === 'Fido2' && e.fido2CredentialId) {
                inventory.fido2_credential_ids_b64.push(b64FromHex(String(e.fido2CredentialId)));
            }
        }
    }
    return inventory;
}
