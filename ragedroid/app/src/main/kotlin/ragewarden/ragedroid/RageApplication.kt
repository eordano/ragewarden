package ragewarden.ragedroid

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import ragewarden.ragedroid.di.appEntryPoint
import dagger.hilt.android.HiltAndroidApp
import ragewarden.ragedroid.identities.YubiKitTransport
import ragewarden.ragedroid.jni.RageNative

@HiltAndroidApp
class RageApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        ragewarden.ragedroid.ui.UiStrings.install(this)
        RageNative.initTls(applicationContext)
        YubiKitTransport.startUsbDiscovery(this)
        ContextCompat.registerReceiver(
            this,
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    if (intent.action == Intent.ACTION_SCREEN_OFF) appEntryPoint().lockState().lock()
                }
            },
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }
}
