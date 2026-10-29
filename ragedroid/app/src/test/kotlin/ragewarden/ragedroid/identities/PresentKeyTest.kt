package ragewarden.ragedroid.identities

import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.YubiKeyConnection
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.util.Callback
import com.yubico.yubikit.core.util.Result
import java.io.IOException
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/** HW-04: a YubiKey already plugged in when the prompt opens is used at once. */
class PresentKeyTest {
    private class FakeKey : YubiKeyDevice {
        override fun getTransport(): Transport = Transport.USB
        override fun supportsConnection(connectionType: Class<out YubiKeyConnection>): Boolean = false
        override fun <T : YubiKeyConnection> requestConnection(connectionType: Class<T>, callback: Callback<Result<T, IOException>>) = Unit
        override fun <T : YubiKeyConnection> openConnection(connectionType: Class<T>): T = throw IOException("fake key")
    }

    @Test
    fun a_key_plugged_in_before_the_prompt_is_returned_immediately() = runBlocking {
        val present = PresentKey()
        val key = FakeKey()
        present.attached(key)
        assertSame(key, withTimeout(100) { present.next() })
    }

    @Test
    fun a_removed_key_is_not_returned_and_the_next_one_is_awaited() = runBlocking {
        val present = PresentKey()
        val first = FakeKey()
        present.attached(first)
        present.detached(first)
        assertNull(withTimeoutOrNull(100) { present.next() })
        val waiting = async { present.next() }
        yield()
        val second = FakeKey()
        present.attached(second)
        assertSame(second, withTimeout(1_000) { waiting.await() })
    }

    @Test
    fun closing_an_older_key_does_not_forget_the_one_now_attached() = runBlocking {
        val present = PresentKey()
        val old = FakeKey()
        val now = FakeKey()
        present.attached(old)
        present.attached(now)
        present.detached(old)
        assertSame(now, withTimeout(100) { present.next() })
    }
}
