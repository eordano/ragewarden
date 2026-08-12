package ragewarden.ragedroid.identities

import androidx.fragment.app.FragmentActivity

fun passkeyEnrollmentSupported(): Boolean = true

/**
 * Flavor boundary for *use-time* passkey identities. `IdentityResolver` lives in
 * `main/` and cannot reference the flavor-specific `PasskeyIdentity`
 * constructors directly (the F-Droid one is private), so it goes through here.
 *
 * Returns null when this build cannot drive a passkey at all; the resolver then
 * records a `SkippedRecipient` carrying [passkeyUnavailableReason] instead of
 * silently dropping the recipient.
 */
fun passkeyIdentityForUse(
    credentialId: ByteArray,
    rpId: String,
    label: String,
    activity: FragmentActivity?,
): KotlinIdentity? = PasskeyIdentity(
    mockPrfKey = null,
    credentialId = credentialId,
    rpId = rpId,
    activity = activity,
    label = label,
)

fun passkeyUnavailableReason(): String? = null
