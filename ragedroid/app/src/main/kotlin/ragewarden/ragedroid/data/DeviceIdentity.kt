package ragewarden.ragedroid.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DeviceIdentity @Inject constructor(@ApplicationContext context: Context) {
    private val prefs = context.getSharedPreferences("ragewarden.device.v1", Context.MODE_PRIVATE)

    val id: String
        @Synchronized get() = prefs.getString(KEY, null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString(KEY, it).commit()
        }

    private companion object {
        const val KEY = "device_id"
    }
}
