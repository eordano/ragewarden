package ragewarden.ragedroid.data

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Pins the lock's two survival properties.
 *
 * The lock used to be `var locked by remember { mutableStateOf(signedInAtLaunch && lockPolicy.lockOnLaunch) }`
 * inside `RageApp`. `MainActivity` declares no `android:configChanges`, so a
 * rotation destroyed the Activity, threw away the composition and re-ran that
 * initialiser -- which with `lockOnLaunch` off evaluates to `false`. Rotating the
 * phone unlocked the vault.
 *
 * Constructing a second [LockState] over the same `Context` is the unit-test
 * stand-in for "the process was killed and started again": nothing is carried in
 * memory, so anything the new instance knows it read back off disk.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class LockStateTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private fun policy(lockOnLaunch: Boolean): LockPolicy =
        LockPolicy(context).apply { this.lockOnLaunch = lockOnLaunch }

    private fun lockState(lockOnLaunch: Boolean, hasSession: Boolean = true) =
        LockState(context, policy(lockOnLaunch)) { hasSession }

    @Before
    fun clearPrefs() {
        context.deleteSharedPreferences("ragewarden.lockstate.v1")
        context.deleteSharedPreferences("ragewarden.lock.v1")
    }

    @Test
    fun a_signed_in_process_starts_locked_by_default() {
        assertTrue(lockState(lockOnLaunch = true).isLocked)
    }

    @Test
    fun with_no_session_there_is_nothing_to_lock() {
        assertFalse(lockState(lockOnLaunch = true, hasSession = false).isLocked)
    }

    @Test
    fun an_absent_persisted_flag_reads_as_locked() {
        // lockOnLaunch off, so the only thing that can produce `true` here is the
        // fail-closed default of the persisted flag.
        assertTrue(lockState(lockOnLaunch = false).isLocked)
    }

    @Test
    fun a_lock_survives_a_new_instance_over_the_same_storage() {
        val first = lockState(lockOnLaunch = false)
        first.unlock()
        assertFalse(first.isLocked)

        first.lock()

        // This is the case the old `remember`-scoped flag got wrong: with
        // lockOnLaunch off, re-deriving from policy alone yields `false`.
        val second = lockState(lockOnLaunch = false)
        assertTrue("a lock must not be dropped by rebuilding the holder", second.isLocked)
    }

    @Test
    fun an_unlock_survives_a_new_instance_when_the_launch_policy_allows_it() {
        lockState(lockOnLaunch = false).unlock()
        assertFalse(lockState(lockOnLaunch = false).isLocked)
    }

    @Test
    fun lock_on_launch_is_a_floor_over_the_persisted_flag() {
        lockState(lockOnLaunch = true).unlock()
        assertTrue(lockState(lockOnLaunch = true).isLocked)
    }

    @Test
    fun the_flow_and_the_snapshot_agree() {
        val state = lockState(lockOnLaunch = true)
        assertTrue(state.locked.value)
        state.unlock()
        assertFalse(state.locked.value)
        assertFalse(state.isLocked)
        state.lock()
        assertTrue(state.locked.value)
        assertTrue(state.isLocked)
    }
}
