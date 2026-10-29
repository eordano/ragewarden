package ragewarden.ragedroid.data

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class PrfRequestTest {
    @Test
    fun every_write_gets_a_fresh_32_byte_salt_for_the_same_credential() {
        val cred = byteArrayOf(1, 2, 3)
        val a = PrfRequest.fresh("example.org", cred)
        val b = PrfRequest.fresh("example.org", cred)
        assertEquals(32, a.salt.size)
        assertArrayEquals(cred, a.credentialId)
        assertFalse(a.salt.contentEquals(b.salt))
    }
}
