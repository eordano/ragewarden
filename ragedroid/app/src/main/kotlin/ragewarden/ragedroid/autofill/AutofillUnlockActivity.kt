package ragewarden.ragedroid.autofill

import android.app.assist.AssistStructure
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.autofill.AutofillManager
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.ui.screens.LockScreen
import ragewarden.ragedroid.ui.secureWindow
import ragewarden.ragedroid.ui.theme.RageTheme

class AutofillUnlockActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        secureWindow()
        val lockState = appEntryPoint().lockState()
        setContent {
            RageTheme {
                LockScreen(
                    onUnlock = {
                        lockState.unlock()
                        finishWithDatasets()
                    },
                    onSignOut = {
                        setResult(RESULT_CANCELED)
                        finish()
                    },
                    repo = VaultBridge.repository() ?: appEntryPoint().bitwardenRepo(),
                )
            }
        }
    }

    private fun finishWithDatasets() {
        val structure = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        }
        val response = structure?.let(AutofillDatasets::target)?.let { AutofillDatasets.matchingResponse(this, it) }
        if (response == null) {
            setResult(RESULT_CANCELED)
        } else {
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response))
        }
        finish()
    }

    companion object {
        fun intent(context: Context): Intent = Intent(context, AutofillUnlockActivity::class.java)
    }
}
