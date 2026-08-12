package ragewarden.ragedroid.data

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import ragewarden.ragedroid.model.RecipientKind

class RecipientStoreTest {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private fun newStoredRecipient(
        id: String,
        kind: RecipientKind = RecipientKind.StrongBox,
        defaultEncrypt: Boolean = true,
    ): StoredRecipient = StoredRecipient(
        id = id,
        kind = kind,
        displayName = "device-$id",
        createdAt = 1_700_000_000_000L,
        lastUsedAt = 1_700_000_000_000L,
        defaultEncrypt = defaultEncrypt,
        keystorePubkey = ByteArray(32) { i -> ((i + id.hashCode()) and 0xFF).toByte() },
        keystoreHandle = "handle-$id",
    )

    @Test
    fun stored_recipient_equals_is_id_based() {
        val a = newStoredRecipient(id = "same").copy(displayName = "Alice's StrongBox")
        val b = newStoredRecipient(id = "same").copy(displayName = "Bob's StrongBox")

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun stored_recipient_inequality_when_ids_differ() {
        val a = newStoredRecipient(id = "one")
        val b = newStoredRecipient(id = "two")
        assertNotEquals(a, b)
    }

    @Test
    fun stored_recipient_default_encrypt_defaults_to_true() {

        val r = StoredRecipient(
            id = "x",
            kind = RecipientKind.StrongBox,
            displayName = "x",
            createdAt = 0L,
            lastUsedAt = 0L,
        )
        assertTrue(r.defaultEncrypt)
    }

    @Test
    fun json_round_trip_preserves_strongbox_fields() {
        val r = newStoredRecipient(id = "sb-1")
        val encoded = json.encodeToString(r)
        val decoded = json.decodeFromString<StoredRecipient>(encoded)

        assertEquals(r, decoded)
        assertEquals(r.kind, decoded.kind)
        assertEquals(r.displayName, decoded.displayName)
        assertEquals(r.createdAt, decoded.createdAt)
        assertEquals(r.lastUsedAt, decoded.lastUsedAt)
        assertEquals(r.defaultEncrypt, decoded.defaultEncrypt)
        assertNotNull(decoded.keystorePubkey)
        assertTrue(r.keystorePubkey!!.contentEquals(decoded.keystorePubkey!!))
        assertEquals(r.keystoreHandle, decoded.keystoreHandle)
    }

    @Test
    fun json_round_trip_preserves_yubikey_fields() {
        val r = StoredRecipient(
            id = "yk-1",
            kind = RecipientKind.YubiKey,
            displayName = "Maya's YubiKey 5C",
            createdAt = 1_700_000_000_000L,
            lastUsedAt = 1_700_000_500_000L,
            defaultEncrypt = true,
            pivPubkey = ByteArray(32) { i -> i.toByte() },
            pivSerial = 1234567,
            pivSlot = 0x95.toByte(),
        )
        val encoded = json.encodeToString(r)
        val decoded = json.decodeFromString<StoredRecipient>(encoded)
        assertEquals(r, decoded)
        assertEquals(r.pivSerial, decoded.pivSerial)
        assertEquals(r.pivSlot, decoded.pivSlot)
        assertNotNull(decoded.pivPubkey)
        assertTrue(r.pivPubkey!!.contentEquals(decoded.pivPubkey!!))
    }

    @Test
    fun json_round_trip_preserves_fido2_fields() {
        val r = StoredRecipient(
            id = "fido2-1",
            kind = RecipientKind.Fido2,
            displayName = "Synced FIDO2 device",
            createdAt = 1_700_000_000_000L,
            lastUsedAt = 1_700_000_000_000L,
            fido2CredentialId = byteArrayOf(0x01, 0x02, 0x03),
            fido2RpId = "ragewarden.example",
            fido2Salt = ByteArray(32) { 0x42 },
        )
        val encoded = json.encodeToString(r)
        val decoded = json.decodeFromString<StoredRecipient>(encoded)
        assertEquals(r, decoded)
        assertEquals(r.fido2RpId, decoded.fido2RpId)
        assertNotNull(decoded.fido2Salt)
        assertTrue(r.fido2Salt!!.contentEquals(decoded.fido2Salt!!))
        assertNotNull(decoded.fido2CredentialId)
        assertTrue(r.fido2CredentialId!!.contentEquals(decoded.fido2CredentialId!!))
    }

    @Test
    fun json_round_trip_preserves_recovery_armored_pubkey() {
        val r = StoredRecipient(
            id = "rec-1",
            kind = RecipientKind.Recovery,
            displayName = "Recovery mnemonic",
            createdAt = 0L,
            lastUsedAt = 0L,
            recoveryArmoredPubkey = "age1examplerecoverypubkey",
        )
        val encoded = json.encodeToString(r)
        val decoded = json.decodeFromString<StoredRecipient>(encoded)
        assertEquals(r, decoded)
        assertEquals(r.recoveryArmoredPubkey, decoded.recoveryArmoredPubkey)
    }

    @Test
    fun json_round_trip_via_list_preserves_order_and_content() {

        val list = listOf(
            newStoredRecipient(id = "a"),
            newStoredRecipient(id = "b").copy(defaultEncrypt = false),
            newStoredRecipient(id = "c", kind = RecipientKind.YubiKey).copy(
                pivPubkey = ByteArray(32) { 0xAB.toByte() },
                pivSerial = 1,
                pivSlot = 0x82.toByte(),
            ),
        )
        val encoded = json.encodeToString(list)
        val decoded = json.decodeFromString<List<StoredRecipient>>(encoded)
        assertEquals(list.size, decoded.size)
        assertEquals(list, decoded)

        assertFalse(decoded[1].defaultEncrypt)
        assertTrue(decoded[0].defaultEncrypt)
    }

    @Test
    fun unknown_fields_are_ignored_for_forward_compatibility() {

        val rawWithExtra = """
            {
              "id": "x",
              "kind": "StrongBox",
              "displayName": "x",
              "createdAt": 0,
              "lastUsedAt": 0,
              "defaultEncrypt": true,
              "futureField": "ignored please",
              "anotherFutureField": 42
            }
        """.trimIndent()
        val decoded = json.decodeFromString<StoredRecipient>(rawWithExtra)
        assertEquals("x", decoded.id)
        assertEquals(RecipientKind.StrongBox, decoded.kind)
        assertTrue(decoded.defaultEncrypt)
    }

    @Test
    fun missing_optional_fields_decode_to_null() {

        val raw = """
            {
              "id": "yk-only",
              "kind": "YubiKey",
              "displayName": "n",
              "createdAt": 0,
              "lastUsedAt": 0,
              "pivSerial": 1,
              "pivSlot": -107
            }
        """.trimIndent()
        val decoded = json.decodeFromString<StoredRecipient>(raw)
        assertEquals(1, decoded.pivSerial)
        assertEquals((-107).toByte(), decoded.pivSlot)
        assertNull(decoded.keystorePubkey)
        assertNull(decoded.keystoreHandle)
        assertNull(decoded.fido2Salt)
    }
}
