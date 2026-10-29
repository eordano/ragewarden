package ragewarden.ragedroid.identities

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.data.PrfRequest
import ragewarden.ragedroid.data.RecipientDescriptors
import ragewarden.ragedroid.data.RecipientPolicy.toPolicyWire
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.data.toUiRecipient
import ragewarden.ragedroid.model.RecipientKind

/**
 * New passkeys enrol as PasskeyPrf (`webauthn-prf-v1`); a passkey enrolled as
 * Fido2 keeps working and moves without losing what it already wrapped.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class PasskeyKindTest {
    private val credentialId = byteArrayOf(9, 8, 7, 6)
    private val salt = ByteArray(32) { 3 }
    private val prfTag = "${StanzaTags.WEBAUTHN_PRF_V1}:${StanzaCrypto.b64UrlEncode(credentialId)}"
    private val hmacTag = "${StanzaTags.FIDO2_HMAC}:${StanzaCrypto.b64UrlEncode(credentialId)}"

    private fun oldFido2() = StoredRecipient(
        id = "old", kind = RecipientKind.Fido2, displayName = "Passkey", createdAt = 0L, lastUsedAt = 0L,
        fido2CredentialId = credentialId, fido2RpId = PasskeyRp.LEGACY_ID, fido2Salt = salt,
    )

    @Test
    fun a_new_passkey_is_a_passkey_prf_recipient() {
        val r = newPasskeyRecipient(credentialId, salt, PasskeyRp.ID, "Passkey", 0L)
        assertEquals(RecipientKind.PasskeyPrf, r.kind)
        assertNull(r.fido2CredentialId)
        assertEquals(listOf(prfTag), RecipientDescriptors.forStored(r))
        val wire = r.toPolicyWire("phone")
        assertEquals("PasskeyPrf", wire.kind)
        assertEquals("09080706", wire.fido2CredentialId)
        assertEquals(PasskeyRp.ID, wire.fido2RpId)
    }

    @Test
    fun a_new_passkey_is_discoverable_es256_and_publishes_rp_credential_and_public_key() {
        val request = org.json.JSONObject(buildEnrollmentJson(PasskeyRp.ID, "account", ByteArray(32), salt))
        val selection = request.getJSONObject("authenticatorSelection")
        assertEquals("required", selection.getString("residentKey"))
        assertEquals(true, selection.getBoolean("requireResidentKey"))
        val algs = request.getJSONArray("pubKeyCredParams").let { a -> (0 until a.length()).map { a.getJSONObject(it).getInt("alg") } }
        assertEquals(listOf(-7), algs)

        val spki = ByteArray(91) { (it + 1).toByte() }
        val b64u = { b: ByteArray -> java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b) }
        val responseJson = org.json.JSONObject()
            .put("id", b64u(credentialId))
            .put("response", org.json.JSONObject().put("publicKeyAlgorithm", -7).put("publicKey", b64u(spki)))
            .toString()
        val reg = parseRegistration(responseJson)!!
        assertEquals(credentialId.toList(), reg.credentialId.toList())
        assertEquals(spki.toList(), reg.publicKeySpki!!.toList())

        val wire = newPasskeyRecipient(credentialId, salt, PasskeyRp.ID, "Passkey", 0L, reg.publicKeySpki).toPolicyWire("phone")
        assertEquals(PasskeyRp.ID, wire.fido2RpId)
        assertEquals("09080706", wire.fido2CredentialId)
        assertEquals(java.util.Base64.getEncoder().encodeToString(spki), wire.attestationPublicKey)
        assertNull("an RS256 credential publishes no P-256 key", parseRegistration(
            org.json.JSONObject(responseJson).apply { getJSONObject("response").put("publicKeyAlgorithm", -257) }.toString(),
        )!!.publicKeySpki)
    }

    @Test
    fun an_old_fido2_passkey_still_matches_its_own_stanzas() {
        assertEquals(listOf(hmacTag), RecipientDescriptors.forStored(oldFido2()))
        assertEquals("Fido2", oldFido2().toPolicyWire("phone").kind)
    }

    @Test
    fun moving_keeps_the_old_wraps_openable_and_writes_the_new_format() {
        val moved = oldFido2().migratedToPasskeyPrf()
        assertEquals(RecipientKind.PasskeyPrf, moved.kind)
        assertEquals(PasskeyRp.LEGACY_ID, moved.passkeyRpId)
        assertEquals("the fido2 fields stay for the old stanzas", PasskeyRp.LEGACY_ID, moved.fido2RpId)
        assertEquals(setOf(prfTag, hmacTag), RecipientDescriptors.forStored(moved).toSet())
        assertEquals("PasskeyPrf", moved.toPolicyWire("phone").kind)
        assertThrows(IllegalStateException::class.java) { moved.migratedToPasskeyPrf() }
    }

    @Test
    fun an_items_fido2_wraps_count_as_renewable_once_the_passkey_moved() {
        val itemDescriptors = listOf(hmacTag, "piv-p256:abcd")
        assertEquals(0, RecipientDescriptors.movedPasskeyWraps(itemDescriptors, listOf(oldFido2().toUiRecipient())))
        assertEquals(1, RecipientDescriptors.movedPasskeyWraps(itemDescriptors, listOf(oldFido2().migratedToPasskeyPrf().toUiRecipient())))
        assertEquals(0, RecipientDescriptors.movedPasskeyWraps(listOf(prfTag), listOf(oldFido2().migratedToPasskeyPrf().toUiRecipient())))
    }

    @Test
    fun the_prf_tapper_finds_passkeys_of_both_kinds() {
        val new = newPasskeyRecipient(credentialId, salt, PasskeyRp.ID, "Passkey", 0L)
        val old = oldFido2()
        assertSame(new, prfRecipientFor(listOf(old, new), PrfRequest(PasskeyRp.ID, credentialId, salt)))
        assertSame(old, prfRecipientFor(listOf(old, new), PrfRequest(PasskeyRp.LEGACY_ID, credentialId, salt)))
        val moved = old.migratedToPasskeyPrf()
        assertSame(moved, prfRecipientFor(listOf(moved), PrfRequest(PasskeyRp.LEGACY_ID, credentialId, salt)))
        assertNull(prfRecipientFor(listOf(moved), PrfRequest("other.example", credentialId, salt)))
    }
}
