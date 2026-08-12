import * as wasmGlue from './crypto.js';
import { unwrapWithPrf } from './passkey.js';
import { loadAllPasskeyRecipients, loadSoftwareIdentity } from './passkey-store.js';
import { bumpCounter } from './tap-counters.js';
import {
    NativeTapRefusedError,
    NoHardwareError,
    assertReceiptIsRealTap,
    isUserDecline,
    performPresenceTap,
    performPrfTap,
} from './hardware-tap.js';
import {
    NATIVE_ONLY_STANZA_TAGS,
    NativeHostUnavailableError,
    nativeHostUnwrapCallback,
    probe as probeNativeHost,
} from './native-host.js';

export { NativeTapRefusedError, NoHardwareError, isUserDecline };

const NO_BROWSER_IDENTITY_MESSAGE =
    'This item is hardware-protected but no passkey is enrolled in this browser '
    + 'profile. Enrol a passkey, use another enrolled device, or recover with your '
    + 'paper phrase. There is no software fallback.';

/**
 * The words a decrypt failure reaches the user in.
 *
 * The wasm now rejects with Error objects carrying a stable `code`, and the
 * message next to the code is an internal (`rage decrypt: no supplied identity
 * matched any stanza in the header`, `decrypt: no login.password`). Branching
 * is on the code, never the message; the two legacy message patterns are kept
 * only for a stale wasm bundle that predates the codes. Errors this module
 * mints itself (NoHardwareError, NativeTapRefusedError, a user's decline)
 * already say the right thing and pass through untouched, as does anything
 * unrecognised -- an unknown failure must not be dressed up as a known one.
 */
function recipientPhrase(cipher) {
    const n = (cipher && typeof cipher.recipient_count === 'number')
        ? cipher.recipient_count : 0;
    return n > 0
        ? `wrapped to ${n} recipient${n === 1 ? '' : 's'}, none on this device`
        : 'not encrypted for this device';
}

export function friendlyDecryptError(err, cipher) {
    if (err instanceof NoHardwareError || err instanceof NativeTapRefusedError) return err;
    if (isUserDecline(err)) return err;

    const raw = String((err && err.message) || err);
    let code = err && err.code;
    if (!code) {
        if (/matched any stanza/.test(raw)) code = 'no_matching_identity';
        else if (/decrypt: no login\./.test(raw)) code = 'missing_field';
    }

    const message = {
        no_matching_identity:
            `this item is ${recipientPhrase(cipher)} -- re-wrap it from a device that `
            + 'holds one of its keys. Nothing was decrypted.',
        missing_field:
            'this item has no such field to reveal.',
        tap_unavailable:
            'this item needs a hardware tap and no authenticator is reachable from here.',
        no_identity_available: NO_BROWSER_IDENTITY_MESSAGE,
        decrypt_failed:
            'this item could not be decrypted with the session key -- the stored blob '
            + 'may be damaged.',
        identity_failed:
            'the identity held here could not open this item.',
        age_error:
            'this item\'s encrypted envelope could not be read.',
        io_error:
            'the vault could not be reached while opening this item.',
    }[code];
    if (!message) return (err instanceof Error) ? err : new Error(raw);

    const friendly = new Error(message);
    friendly.code = code;
    friendly.cause = err;
    return friendly;
}

/*
 * Identity for a receipt that has crossed the wasm boundary.
 *
 * Reference equality is what normally holds -- wasm hands back the same JsValue
 * it was given -- but it is not something this side should depend on, and the
 * consequence of it not holding must not be a refused unlock on a real tap.
 * These four fields are what the ceremony produced; nothing else in the receipt
 * is minted per-tap.
 */
function sameReceipt(a, b) {
    return !!a && !!b
        && a.backend === b.backend
        && a.at === b.at
        && a.device === b.device
        && a.slot === b.slot;
}

/*
 * Route a blob this browser cannot open through `rageterm --native-host`.
 *
 * Reached only when the browser-local identities are absent or have already
 * failed, because every attempt here demands a physical touch on the
 * workstation: asking speculatively would raise a desktop prompt for an item
 * the browser could have opened by itself.
 *
 * Failure semantics are the whole design:
 *   - no host, no reply, or "I cannot open this" -> NativeHostUnavailableError,
 *     which this function converts back into the error the browser-local path
 *     produced. A profile without rageterm therefore behaves exactly as it did
 *     before this bridge had an importer; nothing degrades, nothing new is
 *     claimed.
 *   - a host that answers without a verified touch, or with a malformed `tap`
 *     block -> NativeTapRefusedError, which propagates. No fallback, no
 *     plaintext. This is the case that matters: an operator running the host
 *     with RAGEWARDEN_NATIVE_HOST_ALLOW_SOFTWARE=1 gets a refusal, not a
 *     silent software unwrap wearing a hardware receipt.
 */
async function decryptThroughNativeHost({
    mod, session, cipher, fieldName, receipts, action, destination, origin, fallbackError,
}) {
    const refuse = fallbackError || new Error(
        'internal: the native-host route was entered with no plaintext and no prior error',
    );
    /*
     * Both of these mean "there is no route", not "the route said no", so both
     * restore the browser-local error rather than inventing a new one. The
     * missing-export case is narrated to the console because it is a build
     * mismatch (glue newer than wasm), not a user-visible condition -- and it
     * must not rewrite the message a user sees on every ordinary failure of an
     * item that has nothing to do with the native host.
     */
    if (typeof mod.wasm_decrypt_cipher_field_with_native !== 'function') {
        console.warn(
            '[ragewarden] wasm module has no wasm_decrypt_cipher_field_with_native export; '
            + `${NATIVE_ONLY_STANZA_TAGS.join('/')} stanzas cannot be routed to rageterm in `
            + 'this build (rebuild the wasm: npm run build:wasm)',
        );
        throw refuse;
    }
    const host = await probeNativeHost();
    if (!host.capable) throw refuse;
    const inner = nativeHostUnwrapCallback({
        action,
        destination,
        origin,
        onReceipt: r => receipts.push(r),
    });
    /*
     * `asked` separates "the native route was never entered" from "the native
     * route was entered and failed". wasm refuses before calling back whenever
     * the item carries no piv-p256/fido2-hmac stanza at all -- the common case
     * for an ordinary item that simply could not be opened -- and in that case
     * the user must see the error the browser's own identities produced, not a
     * message about a host that was never relevant. Once the callback HAS run,
     * the native failure is the informative one and it survives.
     */
    let asked = false;
    const callback = async (stanzas) => {
        asked = true;
        return inner(stanzas);
    };
    try {
        const bytes = await mod.wasm_decrypt_cipher_field_with_native(
            session, cipher, fieldName, callback,
        );
        /*
         * wasm re-attaches the receipt it was handed to the plaintext it
         * produced. It must be one of the receipts sealed above -- if the value
         * that came back carries a receipt this side never minted, something
         * between here and the blob substituted one, and nothing about that is
         * recoverable.
         */
        const attached = bytes && bytes.receipt;
        if (attached && !receipts.some(r => r === attached || sameReceipt(r, attached))) {
            throw new NativeTapRefusedError(
                'the decrypt returned a tap receipt this side did not seal',
            );
        }
        bumpCounter('native_unwrap');
        bumpCounter('wasm_decrypt');
        return bytes;
    } catch (e) {
        if (e instanceof NativeTapRefusedError) throw e;
        /*
         * wasm rejects with a JsValue, so a refusal raised inside the callback
         * can reach here as a string rather than as the Error that was thrown.
         * Losing the class must not lose the refusal.
         */
        const text = (e && e.message) || String(e);
        if (/native_tap_refused|hardware-tap:/.test(text)) {
            throw new NativeTapRefusedError(text.replace(/^hardware-tap:\s*/, ''));
        }
        if (!asked || e instanceof NativeHostUnavailableError
            || /native_host_unavailable|native host unavailable/.test(text)) {
            if (!asked) {
                console.warn('[ragewarden] native-host route not taken:', text);
            }
            throw refuse;
        }
        throw (e instanceof Error) ? e : new Error(text);
    }
}

export async function hardwareInventory() {
    const recipients = await loadAllPasskeyRecipients();
    const software = await loadSoftwareIdentity();
    return { recipients, software };
}

export async function unlockCipherField(opts) {
    const session = opts.session;
    const cipher = opts.cipher;
    const fieldName = opts.fieldName || 'password';
    const action = opts.action || 'reveal';
    const destination = opts.destination || '';
    const origin = opts.origin || '';

    if (!session) throw new Error('not signed in');
    if (!cipher) throw new Error('unknown cipher');

    const mod = await wasmGlue.init();
    const { recipients, software } = await hardwareInventory();
    const receipts = [];

    let bytes;
    if (cipher.rage) {
        const armoredSecrets = [];
        if (software) {
            try {
                const tap = await performPrfTap({
                    pairs: [{
                        credentialId: software.wrap_credential_id_b64,
                        salt: software.wrap_salt_b64,
                    }],
                    rpId: software.wrap_rp_id,
                    action,
                    destination,
                    origin,
                });
                bumpCounter('prf_eval');
                receipts.push(tap.receipt);
                armoredSecrets.push(await unwrapWithPrf(
                    tap.prfOutput,
                    software.wrapped_secret_iv_b64,
                    software.wrapped_secret_ct_b64,
                ));
                if (tap.prfOutput && tap.prfOutput.fill) tap.prfOutput.fill(0);
            } catch (e) {
                if (isUserDecline(e)) throw e;
                console.warn('[ragewarden] software-identity unwrap failed:', e);
            }
        }

        let prfCallback = null;
        if (recipients.length > 0) {
            const rpId = recipients[0].rp_id;
            prfCallback = async (pairs) => {
                const tap = await performPrfTap({
                    pairs, rpId, action, destination, origin,
                });
                bumpCounter('prf_eval');
                receipts.push(tap.receipt);
                return { credentialId: tap.credentialId, prfOutput: tap.prfOutput };
            };
        }

        /*
         * Everything above opens `webauthn-prf-v1` stanzas: the passkey
         * recipients, and this profile's software-wrap credential. A blob
         * wrapped to a YubiKey PIV slot (`piv-p256`) or to a FIDO2 hmac-secret
         * recipient (`fido2-hmac`) -- written by rageterm or ragedroid -- has no
         * opener in this browser at all.
         *
         * Those now route through `rageterm --native-host`
         * (glue/native-host.js), which performs the touch on the workstation
         * and returns a file key plus a `tap` block describing the ceremony.
         * The route is taken only when the browser's own identities are absent
         * or have failed, and the receipt it produces goes through the same
         * assertReceiptIsRealTap() below as every other unlock: a host that
         * reports `touched: false` -- which is what it reports under
         * RAGEWARDEN_NATIVE_HOST_ALLOW_SOFTWARE=1 -- produces a refusal here and
         * no plaintext.
         *
         * What is NOT proven: the `tap` block is the host's word. It is not
         * signed and this side cannot check it, so a native-host receipt
         * asserts "rageterm says a verified touch happened", not "a verified
         * touch happened". None of this has met a real key -- the fail-closed
         * half (no host / untouched / malformed) is what has been exercised.
         * See the header of glue/native-host.js.
         */
        const noBrowserIdentity = !prfCallback && armoredSecrets.length === 0;
        let browserPathError = noBrowserIdentity
            ? new NoHardwareError(NO_BROWSER_IDENTITY_MESSAGE)
            : null;

        if (!noBrowserIdentity) {
            try {
                bytes = await mod.wasm_decrypt_cipher_field_with_secrets(
                    session, cipher, fieldName, prfCallback, armoredSecrets,
                );
                bumpCounter('wasm_decrypt');
            } catch (e) {
                // A cancelled ceremony is an answer, not a reason to go and ask
                // for another one on a different device.
                if (isUserDecline(e)) throw e;
                browserPathError = e;
            }
        }
        for (let i = 0; i < armoredSecrets.length; i++) armoredSecrets[i] = '';

        if (bytes === undefined) {
            bytes = await decryptThroughNativeHost({
                mod,
                session,
                cipher,
                fieldName,
                receipts,
                action,
                destination,
                origin,
                fallbackError: browserPathError,
            });
        }
    } else {
        const credentialIds = recipients
            .map(r => r.credential_id_b64)
            .filter(Boolean);
        const tap = await performPresenceTap({
            credentialIds,
            rpId: recipients.length > 0 ? recipients[0].rp_id : undefined,
            action,
            destination,
            origin,
        });
        bumpCounter('presence_tap');
        receipts.push(tap.receipt);
        bytes = await mod.wasm_decrypt_cipher_field(session, cipher, fieldName, null);
        bumpCounter('wasm_decrypt');
    }

    if (receipts.length === 0) {
        throw new Error(
            'internal: plaintext produced with no tap receipt -- refusing to return it',
        );
    }
    for (const r of receipts) assertReceiptIsRealTap(r);

    const value = new TextDecoder().decode(bytes);
    if (bytes && bytes.fill) bytes.fill(0);
    return { value, receipts };
}
