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

    private companion object {
        const val KEY_LOCK_ON_LAUNCH = "lock_on_launch"
    }
}
