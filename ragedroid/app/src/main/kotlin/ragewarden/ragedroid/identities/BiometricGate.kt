package ragewarden.ragedroid.identities

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlin.coroutines.resume
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

sealed interface BiometricOutcome {
    data object Authenticated : BiometricOutcome

    data object UserCancelled : BiometricOutcome

    data class Unavailable(val reason: String) : BiometricOutcome

    data class Failed(val errorCode: Int, val message: String) : BiometricOutcome
}

object BiometricGate {

    suspend fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String? = null,
    ): BiometricOutcome {
        val mgr = BiometricManager.from(activity)
        val allowed = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        when (val canAuth = mgr.canAuthenticate(allowed)) {
            BiometricManager.BIOMETRIC_SUCCESS -> Unit
            else -> return BiometricOutcome.Unavailable("canAuthenticate=$canAuth")
        }
        return withContext(Dispatchers.Main) {
            suspendCancellableCoroutine { cont ->
                val executor = ContextCompat.getMainExecutor(activity)
                val callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (cont.isActive) cont.resume(BiometricOutcome.Authenticated)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (!cont.isActive) return
                        val outcome = when (errorCode) {
                            BiometricPrompt.ERROR_USER_CANCELED,
                            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                            BiometricPrompt.ERROR_CANCELED,
                            -> BiometricOutcome.UserCancelled
                            else -> BiometricOutcome.Failed(errorCode, errString.toString())
                        }
                        cont.resume(outcome)
                    }

                    override fun onAuthenticationFailed() {
                    }
                }
                val prompt = BiometricPrompt(activity, executor, callback)
                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(title)
                    .apply { if (subtitle != null) setSubtitle(subtitle) }
                    .setAllowedAuthenticators(allowed)
                    .build()
                prompt.authenticate(info)
            }
        }
    }

    fun isEnrolled(context: Context): Boolean {
        val allowed = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        return BiometricManager.from(context).canAuthenticate(allowed) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }
}
