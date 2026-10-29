package ragewarden.ragedroid.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IdleLockTest {
    @Test
    fun idles_out_after_the_timeout_and_interaction_resets_it() {
        var t = 0L
        val lock = IdleLock({ 5 * 60_000L }, { t })
        t = 4 * 60_000L
        assertFalse(lock.expired())
        lock.touch()
        t += 4 * 60_000L
        assertFalse(lock.expired())
        t += 60_000L
        assertTrue(lock.expired())
    }

    @Test
    fun zero_timeout_disables_idle_lock() {
        var t = 0L
        val lock = IdleLock({ 0L }, { t })
        t = Long.MAX_VALUE / 2
        assertFalse(lock.expired())
    }
}
