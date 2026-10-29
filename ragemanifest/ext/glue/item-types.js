/*
 * The item types the popup edits, by the field names core uses (Bitwarden's
 * camelCase block names), and the pure planning behind a typed save: which
 * values go into the Type-2 block, which are sealed into the rage blob, and
 * when the current blob has to be read first so no protected field is lost.
 */

const f = (name, label, opts = {}) => Object.freeze({ name, label, ...opts });

export const ITEM_KINDS = Object.freeze({
    login: Object.freeze({ label: 'Login', primary: 'password', fields: [] }),
    note: Object.freeze({ label: 'Secure note', primary: 'notes', fields: [] }),
    card: Object.freeze({
        label: 'Card', primary: 'number', block: 'card',
        fields: Object.freeze([
            f('cardholderName', 'Cardholder name'),
            f('brand', 'Brand'),
            f('number', 'Number', { secret: true, protect: true }),
            f('expMonth', 'Expiry month'),
            f('expYear', 'Expiry year'),
            f('code', 'Security code', { secret: true, protect: true }),
        ]),
    }),
    identity: Object.freeze({
        label: 'Identity', primary: 'ssn', block: 'identity',
        fields: Object.freeze([
            f('title', 'Title'),
            f('firstName', 'First name'),
            f('middleName', 'Middle name'),
            f('lastName', 'Last name'),
            f('company', 'Company'),
            f('email', 'Email'),
            f('phone', 'Phone'),
            f('username', 'Username'),
            f('address1', 'Address'),
            f('address2', 'Address line 2'),
            f('address3', 'Address line 3'),
            f('city', 'City'),
            f('state', 'State'),
            f('postalCode', 'Postal code'),
            f('country', 'Country'),
            f('ssn', 'Social security number', { secret: true, protect: true }),
            f('passportNumber', 'Passport number', { secret: true, protect: true }),
            f('licenseNumber', 'Licence number', { secret: true, protect: true }),
        ]),
    }),
    ssh_key: Object.freeze({
        label: 'SSH key', primary: 'privateKey', block: 'sshKey',
        fields: Object.freeze([
            f('privateKey', 'Private key', { secret: true, protect: true, multiline: true }),
            f('publicKey', 'Public key', { multiline: true }),
            f('keyFingerprint', 'Fingerprint'),
        ]),
    }),
});

export function isTypedKind(kind) {
    return !!(ITEM_KINDS[kind] && ITEM_KINDS[kind].block);
}

export function primaryField(kind) {
    return (ITEM_KINDS[kind] || ITEM_KINDS.login).primary;
}

export function fieldLabel(kind, name) {
    const spec = ((ITEM_KINDS[kind] || {}).fields || []).find(x => x.name === name);
    if (spec) return spec.label;
    return { password: 'Password', notes: 'Note', username: 'Username', totp: 'TOTP seed' }[name] || name;
}

/** Whether writing one secret over this item would drop protected fields. */
export function refusesSingleSecret(kind, protectedNames) {
    const primary = primaryField(kind);
    return (protectedNames || []).some(n => n !== primary);
}

export function multiFieldError(kind, protectedNames) {
    const labels = (protectedNames || []).map(n => fieldLabel(kind, n));
    return Object.assign(new Error(
        `This item protects several fields (${labels.join(', ')}). Saving one secret would `
        + 'discard the others, so nothing was changed. Edit each field in the item editor, '
        + 'which keeps all of them.',
    ), { code: 'multi_field' });
}

const nonEmpty = v => typeof v === 'string' && v.length > 0;

/** A new typed item: the core CipherDraft and the fields to seal (null: none). */
export function buildDraft(kind, { name, values = {}, protect = [], folderId = null }) {
    const spec = ITEM_KINDS[kind];
    if (!spec || !spec.block) throw new Error(`not a typed item kind: ${kind}`);
    const block = {};
    const sealed = {};
    for (const { name: field } of spec.fields) {
        const v = values[field];
        if (!nonEmpty(v)) continue;
        if (protect.includes(field)) sealed[field] = v;
        else block[field] = v;
    }
    const draft = { name, [spec.block]: block };
    if (folderId) draft.folderId = folderId;
    return { draft, protectedFields: Object.keys(sealed).length > 0 ? sealed : null };
}

/**
 * An edit of a typed item. `values` are the editor's inputs: an unprotected
 * descriptive field holds its full new value; a secret or protected field is
 * blank to keep what is stored. `previous` holds the stored Type-2 values,
 * `wasProtected` what the blob holds now, and `payload` the blob's fields once
 * read (null before). Returns { needsPayload: true } when the blob must be
 * read first, otherwise { edit, protectedFields } -- protectedFields null
 * keeps the blob as it is.
 */
export function planEdit(kind, { name, previousName, values = {}, previous = {}, protect = [],
    wasProtected = [], payload = null }) {
    const spec = ITEM_KINDS[kind];
    if (!spec || !spec.block) throw new Error(`not a typed item kind: ${kind}`);
    const sameSet = protect.length === wasProtected.length && protect.every(n => wasProtected.includes(n));
    let reseal = !sameSet;
    let needsPayload = false;
    const block = {};
    for (const { name: field, secret } of spec.fields) {
        const typed = values[field];
        const inNew = protect.includes(field);
        const inOld = wasProtected.includes(field);
        if (inNew) {
            if (nonEmpty(typed)) reseal = true;
            continue;
        }
        if (inOld) {
            if (nonEmpty(typed)) block[field] = typed;
            else if (payload) block[field] = payload[field] ?? '';
            else needsPayload = true;
        } else if (secret) {
            if (nonEmpty(typed) && typed !== (previous[field] ?? '')) block[field] = typed;
        } else if ((typed ?? '') !== (previous[field] ?? '')) {
            block[field] = typed ?? '';
        }
    }
    if (reseal && wasProtected.length > 0) needsPayload = needsPayload || !payload;
    if (needsPayload && !payload) return { needsPayload: true };

    const edit = {};
    if (nonEmpty(name) && name !== previousName) edit.name = name;
    if (Object.keys(block).length > 0) edit[spec.block] = block;
    if (!reseal) return { edit, protectedFields: null };

    const sealed = {};
    for (const field of protect) {
        const typed = values[field];
        const v = nonEmpty(typed) ? typed
            : wasProtected.includes(field) ? (payload || {})[field] : previous[field];
        if (nonEmpty(v)) sealed[field] = v;
    }
    if (Object.keys(sealed).length === 0) {
        if (wasProtected.length > 0) {
            throw new Error('a protected item keeps at least one protected field with a value');
        }
        return { edit, protectedFields: null };
    }
    return { edit, protectedFields: sealed };
}
