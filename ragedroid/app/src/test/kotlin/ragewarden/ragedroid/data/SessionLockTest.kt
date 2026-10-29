package ragewarden.ragedroid.data

import java.nio.file.Files
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class SessionLockTest {
    private val unlocked =
        """{"email":"a@example.org","userEncKeyB64":"ZW5j","userMacKeyB64":"bWFj","protectedUserKey":"2.x|y|z","deviceId":"d1"}"""
            .toByteArray()

    @Test
    fun stripping_a_session_removes_both_user_keys_and_keeps_the_rest() {
        assertTrue(SessionBlobs.hasKeys(unlocked))
        val locked = SessionBlobs.strip(unlocked)
        assertFalse(SessionBlobs.hasKeys(locked))
        assertTrue(SessionBlobs.hasProtectedKey(locked))
        assertEquals("d1", SessionBlobs.field(locked, "deviceId"))
        assertFalse(String(locked).contains("ZW5j"))
        assertFalse(String(locked).contains("bWFj"))
    }

    @Test
    fun the_vault_cache_is_sealed_at_rest_and_round_trips() {
        val dir = Files.createTempDirectory("vc").toFile()
        val cache = VaultCache(java.io.File(dir, "v.bin"), JcaKeys)
        assertNull(cache.load())
        val raw = """{"ciphers":[{"Id":"c1","Name":"2.a|b|c"}]}""".toByteArray()
        cache.save(raw)
        assertFalse(String(java.io.File(dir, "v.bin").readBytes(), Charsets.ISO_8859_1).contains("c1"))
        assertArrayEquals(raw, cache.load())
        cache.clear()
        assertNull(cache.load())
    }
}
