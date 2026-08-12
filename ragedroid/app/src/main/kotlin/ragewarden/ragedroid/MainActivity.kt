package ragewarden.ragedroid

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import dagger.hilt.android.AndroidEntryPoint
import ragewarden.ragedroid.ui.RageApp
import ragewarden.ragedroid.ui.secureWindow
import ragewarden.ragedroid.ui.theme.RageTheme

@AndroidEntryPoint
class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The "Authorize" press is the consent gesture for every credential use,
        // so an overlay that supplies the touch is a complete bypass of it.
        // Reject touches delivered while another window sits on top of ours.
        window.decorView.filterTouchesWhenObscured = true
        // This Activity hosts every reveal surface in the app.
        secureWindow()
        enableEdgeToEdge()
        setContent {
            RageTheme {
                RageApp()
            }
        }
    }
}
