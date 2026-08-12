package ragewarden.ragedroid.identities

import androidx.fragment.app.FragmentActivity
import ragewarden.ragedroid.data.StoredRecipient

@Suppress("UNUSED_PARAMETER")
suspend fun enrollPasskeyWithPrf(
    activity: FragmentActivity,
    accountId: String,
    rpId: String = "ragewarden.local",
    displayName: String = "Passkey on this device",
): Pair<StoredRecipient, PasskeyIdentity> {
    error(
        "FIDO2 enrollment requires Google Play Services in this build; " +
            "install the standard build or use a YubiKey/Keystore.",
    )
}
