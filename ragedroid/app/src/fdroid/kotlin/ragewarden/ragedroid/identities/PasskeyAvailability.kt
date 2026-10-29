package ragewarden.ragedroid.identities

import android.os.Build
import androidx.fragment.app.FragmentActivity

private val platformCredentialManager: Boolean get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE

fun passkeyEnrollmentSupported(): Boolean = platformCredentialManager

fun passkeyIdentityForUse(
    credentialId: ByteArray,
    rpId: String,
    label: String,
    activity: FragmentActivity?,
): KotlinIdentity? = if (platformCredentialManager) {
    PasskeyIdentity(mockPrfKey = null, credentialId = credentialId, rpId = rpId, activity = activity, label = label)
} else {
    null
}

fun passkeyUnavailableReason(): String? = if (platformCredentialManager) {
    null
} else {
    "Passkeys in the F-Droid build use Android 14's built-in Credential Manager. On this " +
        "Android version use a YubiKey, this phone's Keystore key, or the paper recovery phrase."
}
