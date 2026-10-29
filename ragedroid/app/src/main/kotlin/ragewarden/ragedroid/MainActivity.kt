package ragewarden.ragedroid

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import android.os.Handler
import android.os.Looper
import dagger.hilt.android.AndroidEntryPoint
import ragewarden.ragedroid.data.IdleLock
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.data.SensitiveClipClearer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import ragewarden.ragedroid.ui.RageApp
import ragewarden.ragedroid.ui.secureWindow
import ragewarden.ragedroid.ui.theme.RageTheme

@AndroidEntryPoint
class MainActivity : FragmentActivity() {
    private val idleHandler = Handler(Looper.getMainLooper())
    private val idleLock by lazy { IdleLock({ appEntryPoint().lockPolicy().idleTimeoutMs }) }
    private val idleCheck = object : Runnable {
        override fun run() {
            if (idleLock.expired()) appEntryPoint().lockState().lock()
            idleHandler.postDelayed(this, IDLE_CHECK_MS)
        }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        idleLock.touch()
    }

    override fun onResume() {
        super.onResume()
        idleLock.touch()
        idleHandler.postDelayed(idleCheck, IDLE_CHECK_MS)
    }

    override fun onPause() {
        idleHandler.removeCallbacks(idleCheck)
        super.onPause()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The "Authorize" press is the consent gesture for every credential use,
        // so an overlay that supplies the touch is a complete bypass of it.
        // Reject touches delivered while another window sits on top of ours.
        // This Activity hosts every reveal surface in the app.
        secureWindow()
        enableEdgeToEdge()
        setContent {
            RageTheme {
                androidx.compose.foundation.layout.Box(
                    androidx.compose.ui.Modifier
                        .fillMaxSize()
                        .semantics { testTagsAsResourceId = true },
                ) {
                    RageApp()
                }
            }
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) SensitiveClipClearer.clearLeftoverOnStart(this)
    }

    private companion object {
        const val IDLE_CHECK_MS = 15_000L
    }
}
