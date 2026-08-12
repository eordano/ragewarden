package ragewarden.ragedroid.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Process-wide vault lock.
 *
 * This used to be `var locked by remember { ... }` inside the `RageApp`
 * composable, which made it wrong in two directions at once:
 *
 * 1. **It did not survive an Activity recreation.** `MainActivity` declares no
 *    `android:configChanges`, so a rotation destroys and recreates it, the
 *    composition is thrown away, and `remember` re-ran the initialiser
 *    `signedInAtLaunch && lockPolicy.lockOnLaunch`. With `lockOnLaunch` turned
 *    off that re-derivation is `false`: a lock the user had explicitly asked for
 *    ("Lock now") or that the ON_STOP observer had applied was *dropped by
 *    rotating the phone*.
 * 2. **Nothing outside that one composition could see it.** The IME service and
 *    the autofill service run in the same process but have no composition; they
 *    read the shared `VaultBridge` cache and committed plaintext with no idea
 *    the vault was locked.
 *
 * So the flag lives here: a `@Singleton` (see `AppModule.provideLockState`) that
 * outlives every Activity in the process, exposed as a [StateFlow] that Compose,
 * the IME and the autofill service all observe, and mirrored into a
 * `SharedPreferences` boolean so it also survives process death.
 *
 * **Fail-closed rules**, in the order they apply at construction:
 * - no session on this device -> nothing to protect -> unlocked (and the stale
 *   persisted flag is dropped);
 * - otherwise [LockPolicy.lockOnLaunch] is a *floor*, not a value: when it is on
 *   (the default) a fresh process always starts locked regardless of what was
 *   persisted;
 * - otherwise the persisted flag wins, and its default when absent is `true`.
 *
 * What this still does *not* do, unchanged from before: `BitwardenVaultRepository`
 * keeps its decrypted cache and the session blob stays on disk while locked.
 * Locking gates every *reader* of that material (that is what the IME and
 * autofill guards are for); it is not a key-zeroisation boundary.
 */
class LockState internal constructor(
    context: Context,
    private val policy: LockPolicy,
    hasSession: () -> Boolean,
) {
    private val prefs = context.applicationContext
        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val _locked = MutableStateFlow(initialLocked(hasSession))

    val locked: StateFlow<Boolean> = _locked.asStateFlow()

    /**
     * Snapshot read for non-Compose callers (the IME service, the autofill
     * service). Every one of them must consult this before touching plaintext.
     */
    val isLocked: Boolean get() = _locked.value

    fun lock() {
        set(true)
    }

    /**
     * Only two callers are legitimate: a verified unlock on the lock screen, and
     * sign-out (which destroys the session, so there is nothing left to lock).
     */
    fun unlock() {
        set(false)
    }

    private fun set(value: Boolean) {
        // commit(), not apply(): a lock must be on disk before the call returns,
        // otherwise a process kill in the window between the two loses it.
        prefs.edit().putBoolean(KEY_LOCKED, value).commit()
        _locked.value = value
    }

    private fun initialLocked(hasSession: () -> Boolean): Boolean {
        if (!hasSession()) {
            prefs.edit().remove(KEY_LOCKED).commit()
            return false
        }
        return policy.lockOnLaunch || prefs.getBoolean(KEY_LOCKED, true)
    }

    private companion object {
        const val PREFS_NAME = "ragewarden.lockstate.v1"
        const val KEY_LOCKED = "locked"
    }
}
