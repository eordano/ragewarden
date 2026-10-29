import test from 'node:test';
import assert from 'node:assert/strict';
import {
    ITEM_KINDS, buildDraft, multiFieldError, planEdit, primaryField, refusesSingleSecret,
} from '../../ext/glue/item-types.js';

test('a single secret over a multi-field item is refused with a message that names the fields', () => {
    assert.equal(refusesSingleSecret('card', ['code', 'number']), true);
    assert.equal(refusesSingleSecret('login', ['password', 'totp']), true);
    assert.equal(refusesSingleSecret('card', ['number']), false);
    assert.equal(refusesSingleSecret('login', ['password']), false);
    assert.equal(refusesSingleSecret('note', ['notes']), false);
    assert.equal(refusesSingleSecret('login', []), false);
    const err = multiFieldError('card', ['code', 'number']);
    assert.equal(err.code, 'multi_field');
    assert.match(err.message, /Security code, Number/);
    assert.match(err.message, /nothing was changed/);
});

test('primary fields match core', () => {
    assert.deepEqual(
        Object.keys(ITEM_KINDS).map(k => [k, primaryField(k)]),
        [['login', 'password'], ['note', 'notes'], ['card', 'number'], ['identity', 'ssn'], ['ssh_key', 'privateKey']],
    );
});

test('a new card seals the protected fields and keeps the rest in the block', () => {
    const { draft, protectedFields } = buildDraft('card', {
        name: 'Visa',
        values: { cardholderName: 'A B', number: '4111', code: '123', expMonth: '', brand: 'Visa' },
        protect: ['number', 'code'],
        folderId: 'f1',
    });
    assert.deepEqual(draft, { name: 'Visa', card: { cardholderName: 'A B', brand: 'Visa' }, folderId: 'f1' });
    assert.deepEqual(protectedFields, { number: '4111', code: '123' });
    const plain = buildDraft('ssh_key', { name: 'k', values: { publicKey: 'ssh-ed25519 AAAA' }, protect: ['privateKey'] });
    assert.equal(plain.protectedFields, null);
    assert.deepEqual(plain.draft.sshKey, { publicKey: 'ssh-ed25519 AAAA' });
});

const card = {
    name: 'Visa', previousName: 'Visa',
    previous: { cardholderName: 'A B', brand: 'Visa' },
    wasProtected: ['code', 'number'],
};

test('a plain-field edit sends only what changed and keeps the blob', () => {
    const plan = planEdit('card', {
        ...card, name: 'Visa 2', protect: ['number', 'code'],
        values: { cardholderName: 'A B', brand: 'Mastercard', number: '', code: '' },
    });
    assert.deepEqual(plan, { edit: { name: 'Visa 2', card: { brand: 'Mastercard' } }, protectedFields: null });
});

test('changing one protected field reads the payload first and seals every field again', () => {
    const args = { ...card, protect: ['number', 'code'], values: { cardholderName: 'A B', brand: 'Visa', code: '999' } };
    assert.deepEqual(planEdit('card', args), { needsPayload: true });
    const plan = planEdit('card', { ...args, payload: { number: '4111', code: '123' } });
    assert.deepEqual(plan.protectedFields, { number: '4111', code: '999' });
    assert.deepEqual(plan.edit, {});
});

test('unprotecting a field moves its stored value into the block; protecting one seals the Type-2 value', () => {
    const payload = { number: '4111', code: '123' };
    const unprotect = planEdit('card', { ...card, protect: ['number'], values: { cardholderName: 'A B', brand: 'Visa' }, payload });
    assert.deepEqual(unprotect.protectedFields, { number: '4111' });
    assert.deepEqual(unprotect.edit, { card: { code: '123' } });
    const protect = planEdit('card', {
        ...card, protect: ['number', 'code', 'cardholderName'], values: { cardholderName: 'A B', brand: 'Visa' }, payload,
    });
    assert.deepEqual(protect.protectedFields, { number: '4111', code: '123', cardholderName: 'A B' });
});

test('an edit never empties a protected item\'s blob', () => {
    assert.throws(
        () => planEdit('card', { ...card, protect: [], values: {}, payload: { number: '', code: '' } }),
        /keeps at least one protected field/,
    );
});
