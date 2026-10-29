package ragewarden.ragedroid.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class LockPolicy @Inject constructor(@ApplicationContext context: Context) {
    private val prefs = context.getSharedPreferences("ragewarden.lock.v1", Context.MODE_PRIVATE)

    var lockOnLaunch: Boolean
        get() = prefs.getBoolean(KEY_LOCK_ON_LAUNCH, true)
        set(value) {
            prefs.edit().putBoolean(KEY_LOCK_ON_LAUNCH, value).apply()
        }

    var idleTimeoutMs: Long
        get() = prefs.getLong(KEY_IDLE_TIMEOUT, DEFAULT_IDLE_TIMEOUT_MS)
        set(value) {
            prefs.edit().putLong(KEY_IDLE_TIMEOUT, value).apply()
        }

    private companion object {
        const val KEY_LOCK_ON_LAUNCH = "lock_on_launch"
        const val KEY_IDLE_TIMEOUT = "idle_timeout_ms"
        const val DEFAULT_IDLE_TIMEOUT_MS = 5 * 60 * 1000L
    }
}
