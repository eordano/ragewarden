package ragewarden.ragedroid.identities

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.data.RecipientPolicy.toPolicyWire
import ragewarden.ragedroid.data.RecipientStore
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.model.RecipientKind

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class PasskeyRpTest {
    private val salt = ByteArray(32) { 7 }
    private val credentialId = byteArrayOf(1, 2, 3, 4)

    @Test
    fun a_passkey_stored_before_rp_ids_were_kept_asserts_with_ragewarden_local() {
        val old = StoredRecipient(
            id = "old",
            kind = RecipientKind.Fido2,
            displayName = "Passkey on this device",
            createdAt = 0L,
            lastUsedAt = 0L,
            fido2CredentialId = credentialId,
            fido2Salt = salt,
        )
        val stored = RecipientStore.decodeStored(Json.encodeToString(listOf(old))).single()

        assertEquals(PasskeyRp.LEGACY_ID, stored.fido2RpId)
        assertEquals("ragewarden.local", JSONObject(PrfAssertion.buildAssertionJson(stored.fido2RpId!!, salt, credentialId)).getString("rpId"))
        assertEquals("the registry entry carries it", PasskeyRp.LEGACY_ID, stored.toPolicyWire("phone").fido2RpId)
    }

    @Test
    fun a_stored_rp_id_is_kept_as_is() {
        val kept = StoredRecipient(
            id = "kept",
            kind = RecipientKind.Fido2,
            displayName = "Passkey",
            createdAt = 0L,
            lastUsedAt = 0L,
            fido2CredentialId = credentialId,
            fido2RpId = "ragewarden.local",
            fido2Salt = salt,
        )
        val stored = RecipientStore.decodeStored(Json.encodeToString(listOf(kept))).single()
        assertEquals("ragewarden.local", stored.fido2RpId)
        assertNull("no credential, no RP", RecipientStore.decodeStored(Json.encodeToString(listOf(kept.copy(fido2CredentialId = null, fido2RpId = null)))).single().fido2RpId)
    }

    @Test
    fun a_new_enrolment_uses_ragewarden_decent_foundation() {
        assertEquals("ragewarden.decent.foundation", PasskeyRp.ID)
        val request = JSONObject(buildEnrollmentJson(PasskeyRp.ID, "account", ByteArray(32), salt))
        assertEquals(PasskeyRp.ID, request.getJSONObject("rp").getString("id"))

        val recipient = newPasskeyRecipient(credentialId, salt, PasskeyRp.ID, "Passkey", 0L)
        assertEquals(PasskeyRp.ID, recipient.passkeyRpId)
        assertEquals(PasskeyRp.ID, recipient.toPolicyWire("phone").fido2RpId)
        assertEquals(PasskeyRp.ID, JSONObject(PrfAssertion.buildAssertionJson(recipient.passkeyRpId!!, salt, credentialId)).getString("rpId"))
    }
}
