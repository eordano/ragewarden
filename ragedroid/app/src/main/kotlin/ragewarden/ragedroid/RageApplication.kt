package ragewarden.ragedroid

import android.app.Application
import dagger.hilt.android.HiltAndroidApp
import ragewarden.ragedroid.identities.YubiKitTransport
import ragewarden.ragedroid.jni.RageNative

@HiltAndroidApp
class RageApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        RageNative.initTls(applicationContext)
        YubiKitTransport.startUsbDiscovery(this)
    }
}
