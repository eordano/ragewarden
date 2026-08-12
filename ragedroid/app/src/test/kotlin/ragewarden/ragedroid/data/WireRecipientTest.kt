package ragewarden.ragedroid.data

import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class WireRecipientTest {

    private val samplePubkey: ByteArray = byteArrayOf(
        0x00,
        0xFF.toByte(),
        0xAB.toByte(),
        0x42,
    )

    @Test
    fun x25519_round_trip_preserves_bytes_and_uses_unsigned_array_encoding() {
        val original: WireRecipient = WireRecipient.X25519(public_key = samplePubkey)
        val encoded = WireJson.encodeToString(WireRecipient.serializer(), original)

        assertTrue(
            "expected discriminator \"type\":\"x25519\" in $encoded",
            encoded.contains("\"type\":\"x25519\""),
        )

        assertTrue(
            "expected unsigned 0 in $encoded",
            encoded.contains("\"public_key\":[0,255,171,66]"),
        )

        val decoded = WireJson.decodeFromString(WireRecipient.serializer(), encoded)
        assertEquals(original, decoded)
    }

    @Test
    fun snake_case_discriminator_matches_rust_for_every_variant() {

        val cases: List<Pair<WireRecipient, String>> = listOf(
            WireRecipient.X25519(samplePubkey) to "x25519",
            WireRecipient.YubiKeyPiv(
                public_key = samplePubkey,
                serial = 1234L,
                slot = 0x95,
            ) to "yubi_key_piv",
            WireRecipient.Fido2HmacSecret(
                credential_id = byteArrayOf(1, 2, 3),
                salt = ByteArray(32) { 0 },
                rp_id = "ragewarden",
            ) to "fido2_hmac_secret",
            WireRecipient.PasskeyPrf(
                credential_id = byteArrayOf(1, 2, 3),
                salt = ByteArray(32) { 0 },
                rp_id = "ragewarden",
                label = "primary",
            ) to "passkey_prf",
            WireRecipient.AndroidKeystore(
                public_key = samplePubkey,
                key_handle = "ragedroid-keystore-handle",
            ) to "android_keystore",
            WireRecipient.SoftwarePassphrase(
                armored_pubkey = "age1examplepubkey",
            ) to "software_passphrase",
        )

        for ((value, expected) in cases) {
            val json = WireJson.encodeToString(WireRecipient.serializer(), value)
            assertTrue(
                "expected \"type\":\"$expected\" in $json",
                json.contains("\"type\":\"$expected\""),
            )
        }
    }

    @Test
    fun unsigned_byte_array_serializer_rejects_negative_values() {

        val json = """{"type":"x25519","public_key":[0,-1,255]}"""
        try {
            WireJson.decodeFromString(WireRecipient.serializer(), json)
            fail("expected deserialisation to reject -1 as out-of-range byte")
        } catch (e: IllegalArgumentException) {
            assertTrue(
                "expected message to mention out of range, got: ${e.message}",
                e.message?.contains("out of range") == true,
            )
        } catch (e: SerializationException) {

            assertTrue(
                "expected wrapped IAE message to mention out of range, got: ${e.message}",
                (e.message?.contains("out of range") == true) ||
                    (e.cause?.message?.contains("out of range") == true),
            )
        }
    }

    @Test
    fun unsigned_byte_array_serializer_rejects_above_255() {
        val json = """{"type":"x25519","public_key":[256]}"""
        try {
            WireJson.decodeFromString(WireRecipient.serializer(), json)
            fail("expected deserialisation to reject 256 as out-of-range byte")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message?.contains("out of range") == true)
        } catch (e: SerializationException) {
            assertTrue(
                (e.message?.contains("out of range") == true) ||
                    (e.cause?.message?.contains("out of range") == true),
            )
        }
    }

    @Test
    fun list_serialisation_round_trip_with_mixed_variants() {
        val list: List<WireRecipient> = listOf(
            WireRecipient.X25519(samplePubkey),
            WireRecipient.YubiKeyPiv(samplePubkey, serial = 7L, slot = 0x82),
            WireRecipient.AndroidKeystore(samplePubkey, key_handle = "h"),
            WireRecipient.SoftwarePassphrase("age1xyz"),
        )
        val json = WireJson.encodeToString(WireRecipientListSerializer, list)

        assertTrue(json.startsWith("["))
        assertTrue(json.endsWith("]"))

        assertTrue(json.contains("\"type\":\"x25519\""))
        assertTrue(json.contains("\"type\":\"yubi_key_piv\""))
        assertTrue(json.contains("\"type\":\"android_keystore\""))
        assertTrue(json.contains("\"type\":\"software_passphrase\""))

        val decoded = WireJson.decodeFromString(WireRecipientListSerializer, json)
        assertEquals(list.size, decoded.size)

        assertEquals(list[0], decoded[0])
        assertEquals(list[1], decoded[1])
        assertEquals(list[2], decoded[2])
        assertEquals(list[3], decoded[3])
    }

    @Test
    fun prf_input_round_trip_uses_unsigned_byte_arrays() {
        val prf = WirePrfInput(
            rp_id = "ragewarden.example",
            salt = ByteArray(32) { i -> i.toByte() },
            prf_output = ByteArray(32) { i -> (255 - i).toByte() },
        )
        val json = WireJson.encodeToString(WirePrfInput.serializer(), prf)

        assertTrue(json.contains("\"salt\":[0,1,2,"))

        assertTrue(json.contains("\"prf_output\":[255,254,253,"))

        val decoded = WireJson.decodeFromString(WirePrfInput.serializer(), json)
        assertEquals(prf, decoded)
    }
}
