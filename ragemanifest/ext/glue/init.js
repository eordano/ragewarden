import * as vault from './vault.js';
import * as crypto from './crypto.js';
import { backendIsMock, backendLabel, selectedBackend, webauthnAvailable } from './hardware-tap.js';
import { hardwareInventory } from './unlock.js';
import { assertReleaseSafe } from './build-flags.js';

function publishInitState(state) {
    window.RagewardenInit = state;
    try {
        window.dispatchEvent(new CustomEvent('ragewarden:init', { detail: state }));
    } catch {}
}

async function main() {
    publishInitState({ phase: 'starting', error: null, result: null });
    try {
        assertReleaseSafe();
        if (backendIsMock()) {
            console.warn(`[ragewarden] ${backendLabel()}`);
        }
        const tag = await crypto.moduleTag();
        // eslint-disable-next-line no-console
        console.info('[ragewarden] WASM loaded:', tag);

        const result = await vault.bootstrap();

        window.RagewardenVault = {
            status: vault.status,
            revealPassword: vault.revealPassword,
            autofillPassword: vault.autofillPassword,
            copyPassword: vault.copyPassword,
            setCipher: vault.setCipher,
            editCipher: vault.editCipher,
            rotateCipher: vault.rotateCipher,
            clearClipboard: vault.clearClipboardNow,
            verifyMasterPassword: vault.verifyMasterPassword,
            previewEncryptRecipients: vault.previewEncryptRecipients,
            bulkProtect: vault.bulkProtect,
            deleteCipher: vault.deleteCipher,
            createFolder: vault.createFolder,
            renameFolder: vault.renameFolder,
            deleteFolder: vault.deleteFolder,
            enrollRecovery: vault.enrollRecovery,
            enrollPasskey: vault.enrollPasskey,
            recoverFromPhrase: vault.recoverFromPhrase,
            validateRecoveryPhrase: vault.validateRecoveryPhrase,
            listRecipients: vault.listRecipients,
            removeRecipient: vault.removeRecipient,
            refresh: vault.refresh,
            logout: vault.logout,
            hardware: {
                backend: selectedBackend,
                label: backendLabel,
                isMock: backendIsMock,
                webauthnAvailable,
                inventory: async () => {
                    const { recipients, software } = await hardwareInventory();
                    return {
                        passkeys: recipients.map(r => ({
                            label: r.label || '', rpId: r.rp_id || '',
                        })),
                        hasSoftwareIdentity: !!software,
                    };
                },
            },
            crypto,
            bootstrapResult: result,
            tapCounters: vault.tapCountersSnapshot,
            audit: {
                tail: (limit) => vault.audit.tail(limit),
                clear: () => vault.audit.clear(),
            },
            history: {
                load: (cipherId) => vault.loadHistory(cipherId),
                record: (cipherId, prior, recipients) =>
                    vault.recordHistoryRevision(cipherId, prior, recipients),
            },
        };
        publishInitState({
            phase: 'ready',
            error: null,
            result,
            mockTap: backendIsMock(),
            backendLabel: backendLabel(),
        });
        triggerDesignReload();
    } catch (err) {
        const cancelled = !!(err && err.message === 'cancelled');
        const message = cancelled
            ? 'sign-in cancelled'
            : ((err && err.message) || String(err));
        // eslint-disable-next-line no-console
        if (cancelled) console.warn('[ragewarden] onboarding cancelled');
        else console.error('[ragewarden] init failed:', err);
        publishInitState({
            phase: cancelled ? 'cancelled' : 'failed',
            error: message,
            result: null,
        });
    }
}

function triggerDesignReload() {
    try {
        const root = document.getElementById('root');
        if (root && root._ragewardenRefresh) {
            root._ragewardenRefresh();
        }
    } catch {}
    window.dispatchEvent(new CustomEvent('ragewarden:vault-updated'));
}

main();
