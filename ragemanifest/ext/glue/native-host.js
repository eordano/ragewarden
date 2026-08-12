/*
 * Native-messaging bridge to `rageterm --native-host`.
 *
 * WHAT THIS IS. A blob written by rageterm or ragedroid can carry recipient
 * stanzas no browser can open: `piv-p256` (a YubiKey PIV slot) and
 * `fido2-hmac` (a FIDO2 hmac-secret credential). WebAuthn cannot reach either.
 * rageterm can -- rageterm/src/native_host.rs answers
 * `{"method":"unwrap_stanza", stanza, context}` and blocks on a physical touch
 * inside PivIdentity / FidoIdentity before it returns a file key. This module
 * is the adapter between that host and glue/unlock.js, and it is now imported:
 * unlock.js routes here when the browser's own identities cannot open a blob.
 *
 * WHAT MAKES IT SAFE ENOUGH TO IMPORT. Two things that did not exist before:
 *
 *   1. CONTRACT 1 -- the reply carries a `tap` block:
 *        { ok, file_key, tap: { backend, touched, verified, device, slot, at } }
 *      `touched` is false whenever the key came from software (the host running
 *      with RAGEWARDEN_NATIVE_HOST_ALLOW_SOFTWARE=1) or whenever the host
 *      cannot prove a touch happened. Before this, `{ok, file_key}` from a
 *      touched key and from an untouched file read off disk were the same three
 *      bytes on the wire, and any receipt minted here would have asserted a
 *      ceremony that sometimes did not happen.
 *
 *   2. CONTRACT 2 -- a seam to spend the file key through:
 *      `wasm_decrypt_cipher_field_with_native(session, cipher, field, cb)`,
 *      where `cb(stanzas)` resolves `{ fileKeyB64, receipt }`. wasm hands out
 *      the stanzas it could not open and verifies that the returned key
 *      actually opens the blob. Before this, JS had no route to the blob at all
 *      -- `cipher.rage` is a boolean, not a payload.
 *
 * WHAT IS STILL UNPROVEN, AND WILL STAY UNPROVEN UNTIL A KEY IS PLUGGED IN.
 * The `tap` block is an assertion by a separate process on the other end of a
 * pipe. Nothing in it is signed; this side cannot distinguish a truthful host
 * from a patched one that writes `touched: true` over a software unwrap. The
 * trust boundary this bridge actually enforces is therefore narrower than the
 * WebAuthn path's: the browser fails closed on every reply that does not CLAIM
 * a verified touch, and records the claim in the same receipt trail as a real
 * assertion. It does not, and from here cannot, verify the claim. Attestation
 * over a signed channel (a per-unwrap challenge the device signs, checkable
 * here) is the next thing to build, and until then a native-host receipt should
 * be read as "rageterm says a key was touched", never as "a key was touched".
 *
 * No hardware key existed on the machine where this was written. Every success
 * path below is unexercised. The refusal paths -- no host, `touched: false`,
 * malformed reply -- are the tested ones.
 */

import {
    BACKEND_NATIVE_HOST,
    NATIVE_HOST_TAP_BACKENDS,
    NativeTapRefusedError,
    performNativeHostTap,
} from './hardware-tap.js';

export { BACKEND_NATIVE_HOST, NativeTapRefusedError };

export const NATIVE_HOST_NAME = 'com.ragewarden.host';

/*
 * Stanza tags this bridge will carry to the host.
 *
 * Mirrors `tag_is_hardware_gated` in rageterm/src/native_host.rs minus
 * `webauthn-prf-v1`: the host would serve that one too, but the browser opens
 * PRF stanzas itself with a real WebAuthn assertion and a receipt whose
 * user-presence bits come from authenticatorData rather than from a claim.
 * Given a choice between evidence and hearsay, take the evidence.
 */
export const NATIVE_ONLY_STANZA_TAGS = Object.freeze(['piv-p256', 'fido2-hmac']);

/* Field on the reply that carries CONTRACT 1. */
export const HOST_ATTESTATION_FIELD = 'tap';

/**
 * The host is not reachable: no native-messaging port, no host installed, no
 * reply, or a reply that says it could not unwrap.
 *
 * This is the "there is nothing here" signal, and unlock.js treats it as such --
 * it restores whatever error the browser-local identities produced, so a
 * profile with no rageterm behaves exactly as it did before this file had an
 * importer. It is emphatically NOT the signal for a host that answered badly;
 * that is NativeTapRefusedError, which never degrades into a fallback.
 */
export class NativeHostUnavailableError extends Error {
    constructor(detail) {
        super(`rageterm native host unavailable: ${detail}`);
        this.name = 'NativeHostUnavailableError';
        this.code = 'native_host_unavailable';
    }
}

function chromeApi() {
    const g = typeof globalThis !== 'undefined' ? globalThis : null;
    const c = g && g.chrome;
    if (!c || !c.runtime || typeof c.runtime.sendMessage !== 'function') return null;
    return c;
}

function sendToWorker(message) {
    const c = chromeApi();
    if (!c) {
        return Promise.reject(new NativeHostUnavailableError(
            'not running in an extension context, so there is no worker to relay through',
        ));
    }
    return new Promise((resolve, reject) => {
        try {
            c.runtime.sendMessage(message, r => {
                const err = c.runtime.lastError;
                if (err) reject(new NativeHostUnavailableError(err.message || 'port error'));
                else resolve(r);
            });
        } catch (e) {
            reject(new NativeHostUnavailableError((e && e.message) || String(e)));
        }
    });
}

/**
 * Read the age stanza tag off whatever wasm handed us.
 *
 * The seam passes stanzas as `{ tag, args, body }` (the shape
 * rageterm's WireStanza deserialises). A raw armored line is accepted too, so a
 * change on the wasm side degrades into "not a tag we serve" rather than into
 * an unfiltered forward of something to the host.
 */
export function stanzaTag(stanza) {
    if (!stanza) return '';
    if (typeof stanza === 'string') {
        const m = /^\s*->\s+(\S+)/.exec(stanza);
        return m ? m[1] : '';
    }
    if (typeof stanza !== 'object') return '';
    if (typeof stanza.tag === 'string') return stanza.tag;
    if (typeof stanza.type === 'string') return stanza.type;
    return '';
}

function toWireStanza(stanza) {
    const tag = stanzaTag(stanza);
    if (!tag || typeof stanza !== 'object') return null;
    const args = Array.isArray(stanza.args) ? stanza.args.map(a => String(a)) : [];
    const body = typeof stanza.body === 'string' ? stanza.body : '';
    if (!body) return null;
    return { tag, args, body };
}

/*
 * The index wasm gave this stanza, when it gave one. Handed back with the file
 * key so the Rust side can check that the answer names a stanza it actually
 * offered -- the same refusal invoke_prf_callback_multi makes for a credentialId
 * outside the supplied set. Omitted rather than guessed when absent.
 */
function stanzaIndexOf(stanza) {
    return (stanza && typeof stanza.index === 'number' && Number.isInteger(stanza.index))
        ? stanza.index
        : undefined;
}

/**
 * What is known about the host, without conflating capability with presence.
 *
 * `native.probe` in background.js answers
 * `available: typeof chrome.runtime.connectNative === 'function'`, which is true
 * in every build carrying the nativeMessaging permission whether or not
 * rageterm is installed. So it is reported as `capable`: worth attempting, not
 * known to be there. Presence is only ever learned by attempting an unwrap,
 * which is also the moment a touch is demanded -- there is no way to ask "are
 * you there" without asking "please touch your key", so nothing here probes
 * speculatively.
 */
export async function probe() {
    if (!chromeApi()) {
        return { capable: false, host: NATIVE_HOST_NAME, reason: 'not in an extension context' };
    }
    try {
        const resp = await sendToWorker({ kind: 'native.probe' });
        return {
            capable: !!(resp && resp.available),
            host: NATIVE_HOST_NAME,
            reason: (resp && resp.available)
                ? 'the browser can open a native-messaging port; whether rageterm answers it '
                  + 'is only knowable by asking for an unwrap'
                : 'this browser exposes no native-messaging port',
        };
    } catch (err) {
        return {
            capable: false,
            host: NATIVE_HOST_NAME,
            reason: (err && err.message) || String(err),
        };
    }
}

/**
 * Ask the host to unwrap one stanza; resolve `{ fileKeyB64, receipt }`.
 *
 * Throws NativeHostUnavailableError when there is nothing on the other end, and
 * NativeTapRefusedError when something answered but the answer does not
 * evidence a verified touch. The second is never retried and never falls back:
 * a host that returns a file key with `touched: false` has just told us the key
 * came off disk, and the correct response to that is no plaintext.
 */
export async function unwrapStanzaWithReceipt(stanza, context = {}) {
    const wire = toWireStanza(stanza);
    if (!wire) {
        throw new NativeHostUnavailableError(
            'the stanza handed to this bridge has no tag/body to send',
        );
    }
    if (!NATIVE_ONLY_STANZA_TAGS.includes(wire.tag)) {
        throw new NativeHostUnavailableError(
            `refusing to relay a \`${wire.tag}\` stanza; this bridge serves only `
            + NATIVE_ONLY_STANZA_TAGS.join(', '),
        );
    }

    const reply = await sendToWorker({
        kind: 'native.unwrap',
        stanza: wire,
        context: {
            action: String(context.action || ''),
            destination: String(context.destination || ''),
            origin: String(context.origin || ''),
        },
    });

    if (!reply || reply.ok !== true) {
        throw new NativeHostUnavailableError(
            (reply && reply.error)
                ? `the host did not unwrap this stanza: ${reply.error}`
                : 'no host answered the unwrap (rageterm not installed, or it declined)',
        );
    }

    const fileKeyB64 = typeof reply.fileKeyB64 === 'string' ? reply.fileKeyB64 : '';
    if (!fileKeyB64) {
        throw new NativeTapRefusedError(
            'the host reported success but sent no file key',
        );
    }

    /*
     * Order matters: seal the receipt BEFORE handing the key on. Building the
     * receipt is what can refuse, and a refusal after the key has been passed
     * to a caller is not a refusal.
     */
    const receipt = performNativeHostTap({
        tap: reply[HOST_ATTESTATION_FIELD],
        host: NATIVE_HOST_NAME,
        action: context.action,
        destination: context.destination,
        origin: context.origin,
    });
    const stanzaIndex = stanzaIndexOf(stanza);
    return {
        fileKeyB64,
        receipt,
        tag: wire.tag,
        ...(stanzaIndex === undefined ? {} : { stanzaIndex }),
    };
}

/**
 * The CONTRACT 2 callback: `stanzas -> Promise<{ fileKeyB64, receipt }>`.
 *
 * Tries each stanza this bridge can serve, in the order wasm supplied them. A
 * stanza the host cannot open (wrong key plugged in, no such PIV slot) is an
 * ordinary miss and the next one is tried; a stanza it opens without evidence
 * of a verified touch aborts the whole callback. `onReceipt` is called with
 * every receipt that gets sealed, so the caller's audit trail sees the ceremony
 * even though only one of them ends up spending a key.
 */
export function nativeHostUnwrapCallback({
    action = '', destination = '', origin = '', onReceipt = null,
} = {}) {
    const context = { action, destination, origin };
    return async function nativeUnwrap(stanzas) {
        const list = Array.isArray(stanzas) ? stanzas : Array.from(stanzas || []);
        const candidates = list.filter(s => NATIVE_ONLY_STANZA_TAGS.includes(stanzaTag(s)));
        if (candidates.length === 0) {
            throw new NativeHostUnavailableError(
                'this item carries no stanza the native host serves '
                + `(looked for ${NATIVE_ONLY_STANZA_TAGS.join(', ')})`,
            );
        }
        let lastUnavailable = null;
        for (const stanza of candidates) {
            let out;
            try {
                out = await unwrapStanzaWithReceipt(stanza, context);
            } catch (e) {
                if (e instanceof NativeTapRefusedError) throw e;
                lastUnavailable = e;
                continue;
            }
            if (typeof onReceipt === 'function') onReceipt(out.receipt);
            return {
                fileKeyB64: out.fileKeyB64,
                receipt: out.receipt,
                ...(out.stanzaIndex === undefined ? {} : { stanzaIndex: out.stanzaIndex }),
            };
        }
        throw lastUnavailable || new NativeHostUnavailableError(
            'no stanza on this item could be unwrapped by the host',
        );
    };
}

/**
 * Identity-source adapter, in the `{ kind, tryUnwrap(stanza) }` shape the rest
 * of the extension uses. `tryUnwrap` resolves `null` for stanzas this source
 * could never answer -- an ordinary "not mine" -- and otherwise yields
 * `{ fileKeyB64, receipt }`, never a bare key.
 */
export function nativeMessagingPivIdentity(opts = {}) {
    const context = opts.context || {};
    const tags = Object.freeze([...(opts.stanzaTags || NATIVE_ONLY_STANZA_TAGS)]);
    return {
        kind: 'native-messaging-piv',
        host: NATIVE_HOST_NAME,
        tags,
        backends: NATIVE_HOST_TAP_BACKENDS,
        async tryUnwrap(stanza) {
            if (!tags.includes(stanzaTag(stanza))) return null;
            return unwrapStanzaWithReceipt(stanza, context);
        },
    };
}
