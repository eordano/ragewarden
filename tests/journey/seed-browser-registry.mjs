// Seed a vault with a registry the BROWSER published, and audit it afterwards.
//
// WHY THIS FILE EXISTS. `BitwardenVaultRepository.pushRecipientRegistry` is the
// only one of ragedroid's cross-client fixes whose code never executed under any
// test: all four of its callers are enrolment paths, and JourneyTest deliberately
// skips both enrolment steps ("skip passkey enrolment", "skip the backup
// recipient"). The bug it fixes needs a vault that ALREADY holds another
// client's `__ragedroid_recipients_v1__` marker -- a phone pushing into an empty
// vault cannot duplicate a marker that is not there. Producing that precondition
// is this script's whole job.
//
// It is the SHIPPED ragemanifest/ext/wasm bundle, loaded under node with
// `initSync` -- the same module the extension loads in a browser, byte for byte.
// Nothing here reimplements the wire format, the crypto or the Bitwarden
// protocol; it only calls `wasm_*` exports, so a registry written here is the
// registry a browser really writes. (Everything the bundle needs from a browser
// global is present in node >= 18: `fetch`/`Request`/`Headers`/`Response` from
// undici and `crypto.getRandomValues` / `crypto.subtle`.)
//
// The entry kinds are the two from the original report: a `Software` identity
// (the browser's own age key) and a `PasskeyPrf` credential. Publishing a
// passkey entry needs no authenticator -- only WRAPPING to one does -- so both are
// reachable headlessly.
//
// SUBCOMMANDS
//   seed  <server> <state.json>  register a throwaway account, publish the two
//                                browser entries, write one browser item, and
//                                record everything in <state.json>.
//   audit <state.json>           re-read the vault AS THE BROWSER and fail
//                                (exit 1) unless there is exactly one marker
//                                cipher and both browser entries survive.
//
// The audit is deliberately a SECOND, independent reading of the same server
// state that the on-device test asserts against
// (registry/RegistryPushInstrumentedTest.kt). It is not redundant:
// `core::registry::find_marker_cipher` takes whichever marker the server returns
// FIRST, so with two markers on the server the phone and the browser can read
// different documents and a device-only assertion could pass by luck of the
// ordering. Two clients disagreeing is the actual failure mode; checking it from
// both ends is how it is caught rather than assumed.
//
// EVERYTHING IS THROWAWAY: a fresh account on a loopback Vaultwarden, a random
// password written to disk in the clear. Never point this at a real vault.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');
const wasmDir = join(repoRoot, 'ragemanifest', 'ext', 'wasm');

// The one name every client agrees on: core::registry::MARKER_NAME,
// RecipientRegistry.MARKER_NAME in Kotlin. Duplicating it is the bug.
const MARKER = '__ragedroid_recipients_v1__';

const wasm = await import(join(wasmDir, 'ragemanifest.js'));
wasm.initSync({ module: readFileSync(join(wasmDir, 'ragemanifest_bg.wasm')) });

const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
const b64 = (u8) => Buffer.from(u8).toString('base64');
const sha256Hex = async (s) => hex(new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)),
));
const say = (...m) => console.log('[seed]', ...m);

async function seed(server, statePath) {
    const rand = hex(crypto.getRandomValues(new Uint8Array(4)));
    const email = `browser-${rand}@ragewarden.test`;
    // Not a secret worth protecting: a throwaway account on a loopback server
    // that run.sh deletes with its data directory.
    const password = `browser-correct-horse-battery-staple-${rand}`;
    const item = `browser-item-${rand}`;
    const secret = `browser-plaintext-${rand}`;

    say('module tag:', wasm.wasm_module_tag());
    say(`registering ${email} in the BROWSER (wasm_register)`);
    // 600000, not a smaller number chosen to keep the emulator's PBKDF2 quick:
    // the client refuses anything lower ("a server that lowers this is trying to
    // weaken your master password"), and lowering it here would only be
    // discovered as a register-time error anyway.
    await wasm.wasm_register(server, email, 'Browser', password, 600_000);
    const session = await wasm.wasm_login(server, email, password, 'ragemanifest-seed');

    // 1. The browser's software identity, shaped exactly as ext/glue/vault.js's
    //    softwareIdentityToRegistryEntry() shapes it.
    const sw = wasm.wasm_software_keygen();
    const swSecret = new TextDecoder().decode(sw.secret);
    const swEntryId = 'browser-sw-' + (await sha256Hex(sw.armored_pubkey)).slice(0, 32);
    const swEntry = {
        id: swEntryId,
        kind: 'Software',
        displayName: 'Browser software identity',
        deviceLabel: 'Browser extension',
        createdAt: Date.now(),
        defaultEncrypt: true,
        recoveryArmoredPubkey: sw.armored_pubkey,
    };

    // 2. The browser's PRF passkey -- kind PasskeyPrf, NOT Fido2: the two wrap
    //    into different stanza tags, and core/src/registry.rs keeps them apart
    //    for that reason. No authenticator is touched to publish it.
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const pkEntryId = 'browser-passkey-' + (await sha256Hex(b64(credentialId))).slice(0, 32);
    const pkEntry = {
        id: pkEntryId,
        kind: 'PasskeyPrf',
        displayName: 'Browser passkey',
        deviceLabel: 'Browser extension',
        createdAt: Date.now(),
        defaultEncrypt: true,
        fido2CredentialId: hex(credentialId),
        fido2RpId: 'ragewarden.test',
        fido2Salt: hex(salt),
    };

    const swMarker = await wasm.wasm_publish_recipient_to_registry(session, swEntry);
    const pkMarker = await wasm.wasm_publish_recipient_to_registry(session, pkEntry);
    say(`published Software   ${swEntryId} -> marker cipher ${swMarker}`);
    say(`published PasskeyPrf ${pkEntryId} -> marker cipher ${pkMarker}`);

    // 3. One item, wrapped by the canonical policy (ragewarden_core::policy, the
    //    same selection rageterm and ragedroid run). This is what the browser
    //    loses the ability to open once its entries stop being recipients, so it
    //    is worth existing even though the assertions below are about the
    //    registry rather than about this blob.
    const selection = await wasm.wasm_select_encrypt_recipients(session, null);
    say('policy selection at seed time:', JSON.stringify(selection));
    const created = await wasm.wasm_create_cipher(
        session,
        { name: item, rage: secret },
        selection.recipients,
    );

    // The precondition the phone is about to be pointed at. Asserted here rather
    // than assumed: if the browser somehow left two markers of its own, the
    // phone's "exactly one marker" assertion would go red for a reason that has
    // nothing to do with the phone.
    const vault = await wasm.wasm_fetch_vault(session);
    const markers = vault.ciphers.filter((c) => c.name === MARKER);
    if (markers.length !== 1) {
        throw new Error(
            `seeding produced ${markers.length} ${MARKER} ciphers, expected exactly 1 -- ` +
            'the phone cannot be tested against a precondition that is already broken',
        );
    }

    writeFileSync(statePath, JSON.stringify({
        server, email, password,
        item, secret, itemId: created.id,
        swEntryId, swArmoredPubkey: sw.armored_pubkey, swSecret,
        pkEntryId,
        markerCipherId: markers[0].id,
    }, null, 2));
    say(`seeded: 1 marker cipher (${markers[0].id}), 2 browser entries, 1 browser item`);
}

async function audit(statePath) {
    const state = JSON.parse(readFileSync(statePath, 'utf8'));
    const session = await wasm.wasm_login(
        state.server, state.email, state.password, 'ragemanifest-audit',
    );

    const vault = await wasm.wasm_fetch_vault(session);
    const markers = vault.ciphers.filter((c) => c.name === MARKER);
    say(`marker ciphers on the server: ${markers.length}`);
    for (const m of markers) {
        const notes = new TextDecoder().decode(
            await wasm.wasm_decrypt_cipher_field(session, m, 'notes'),
        );
        let described;
        try {
            described = JSON.parse(notes).entries.map((e) => `${e.id}(${e.kind})`).join(', ');
        } catch (e) {
            described = `<unparseable: ${e.message}>`;
        }
        say(`  ${m.id}: ${described}`);
    }

    // What a client ACTUALLY reads, i.e. through find_marker_cipher's
    // first-one-wins rule rather than through the list above.
    const registry = await wasm.wasm_fetch_registry(session);
    const entries = registry?.entries ?? [];
    say(`the browser reads ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}:`);
    for (const e of entries) say(`  ${e.id} kind=${e.kind} device=${e.deviceLabel}`);

    const problems = [];
    if (markers.length !== 1) {
        problems.push(
            `${markers.length} \`${MARKER}\` ciphers exist; there must be exactly 1. ` +
            'find_marker_cipher takes whichever the server returns first, so a second ' +
            'marker hands different clients different registries.',
        );
    }
    for (const [label, id] of [['Software', state.swEntryId], ['PasskeyPrf', state.pkEntryId]]) {
        if (!entries.some((e) => e.id === id)) {
            problems.push(
                `the browser's own ${label} entry ${id} is no longer in the registry the ` +
                'browser reads -- it can no longer be wrapped to, and the browser can no ' +
                'longer open its own writes.',
            );
        }
    }
    if (problems.length > 0) {
        for (const p of problems) console.error('[seed] FAIL:', p);
        process.exit(1);
    }
    say('audit OK: exactly one marker, both browser entries intact');
}

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === 'seed' && rest.length === 2) {
    await seed(rest[0], rest[1]);
} else if (cmd === 'audit' && rest.length === 1) {
    await audit(rest[0]);
} else {
    console.error('usage: seed-browser-registry.mjs seed <server> <state.json>');
    console.error('       seed-browser-registry.mjs audit <state.json>');
    process.exit(2);
}
