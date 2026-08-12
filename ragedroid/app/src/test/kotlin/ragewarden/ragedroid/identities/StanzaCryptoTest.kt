package ragewarden.ragedroid.identities

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class StanzaCryptoTest {
    @Test
    fun base64_std_round_trips_with_and_without_padding() {
        val payload = byteArrayOf(0, 1, 2, 3, 4, 5)
        val encoded = StanzaCrypto.b64StdEncode(payload)
        val decoded = StanzaCrypto.b64StdDecode(encoded)
        assertArrayEquals(payload, decoded)
    }

    @Test
    fun base64_url_round_trips() {
        val payload = byteArrayOf(0xff.toByte(), 0xaa.toByte(), 0x55, 0x00, 0x42)
        val encoded = StanzaCrypto.b64UrlEncode(payload)
        val decoded = StanzaCrypto.b64UrlDecode(encoded)
        assertArrayEquals(payload, decoded)
    }

    @Test
    fun hmac_sha256_matches_known_vector() {
        val key = "Jefe".toByteArray(Charsets.UTF_8)
        val data = "what do ya want for nothing?".toByteArray(Charsets.UTF_8)
        val mac = StanzaCrypto.hmacSha256(key, data)
        val expected = listOf(
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
            0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
            0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
        ).map { it.toByte() }.toByteArray()
        assertArrayEquals(expected, mac)
    }
}
