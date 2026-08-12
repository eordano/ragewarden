package ragewarden.ragedroid.identities

import androidx.fragment.app.FragmentActivity

fun passkeyEnrollmentSupported(): Boolean = false

/**
 * F-Droid build: Credential Manager needs `credentials-play-services-auth`,
 * which this flavor deliberately does not ship. Returning null (rather than
 * throwing) lets `IdentityResolver` report the recipient as skipped-with-reason
 * so the tap prompt can say why, instead of the item looking un-decryptable for
 * no stated cause.
 */
@Suppress("UNUSED_PARAMETER")
fun passkeyIdentityForUse(
    credentialId: ByteArray,
    rpId: String,
    label: String,
    activity: FragmentActivity?,
): KotlinIdentity? = null

fun passkeyUnavailableReason(): String? =
    "The F-Droid build has no Credential Manager. Use a YubiKey, this phone's " +
        "Keystore key, or the paper recovery phrase."
