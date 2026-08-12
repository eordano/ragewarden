package ragewarden.ragedroid.identities

import android.util.Log
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import ragewarden.ragedroid.data.RecipientStore

/** A pending "type your PIV PIN" request the UI must render and answer. */
class PinRequest internal constructor(val recipientLabel: String) {
    internal val answer = CompletableDeferred<CharArray?>()

    fun submit(pin: CharArray) {
        answer.complete(pin)
    }

    fun cancel() {
        answer.complete(null)
    }
}

/**
 * Owns one hardware ceremony from "the user asked for a secret" to "plaintext or
 * a named failure".
 *
 * This is the boundary the rest of the app talks to. Everything device-specific
 * sits below it in the individual `KotlinIdentity` implementations, each with a
 * single clearly-marked "THE DEVICE CALL" method; everything above it is
 * hardware-free and can be exercised without a YubiKey.
 *
 * The blocking wait on the physical action happens *inside* [authorize], because
 * the tap is what produces the ECDH share / PRF output that decrypts the blob.
 * That is the structural fix for the old flow, where a Compose button set a
 * state to `Connected`, waited 700 ms, and called `onComplete` -- the "tap" and
 * the decrypt were unrelated events, so nothing about the decrypt depended on
 * the user having done anything.
 */
class HardwareTapCoordinator(
    private val activity: FragmentActivity?,
    private val recipientStore: RecipientStore,
    private val accountId: String,
) {
    private val _pinRequest = MutableStateFlow<PinRequest?>(null)
    val pinRequest: StateFlow<PinRequest?> = _pinRequest.asStateFlow()

    /**
     * Identity set for this surface. Cheap and side-effect free; safe to call
     * during composition to decide what the prompt should say.
     */
    fun identitySet(onlyRecipientIds: Set<String>? = null): IdentitySet =
        IdentityResolver.resolve(
            recipientStore = recipientStore,
            accountId = accountId,
            activity = activity,
            pinProvider = if (activity == null) null else ::collectPin,
            onlyRecipientIds = onlyRecipientIds,
        )

    /**
     * Runs the full ceremony and returns whatever [decrypt] produces.
     *
     * Order matters and is deliberate:
     *  1. resolve identities -- refuse up front if nothing on this device can
     *     satisfy the item, with the per-recipient reasons attached;
     *  2. biometric gate, but only when an auth-bound Keystore key is in play,
     *     and *failing closed* when the device has no biometric or credential
     *     enrolled (the old code accepted `Unavailable` as a pass, which meant a
     *     phone with no lock screen decrypted with no gate at all);
     *  3. hand the identities to [decrypt], which drives the JNI decrypt; the
     *     physical tap is consumed inside the identities during this call.
     */
    suspend fun authorize(
        purpose: String,
        onlyRecipientIds: Set<String>? = null,
        decrypt: suspend (List<KotlinIdentity>) -> ByteArray,
    ): ByteArray {
        val set = identitySet(onlyRecipientIds)
        if (set.isEmpty) {
            throw NoUsableIdentityException(
                skipped = set.skipped,
                message = buildString {
                    append("No recipient on this device can unlock this item.")
                    set.skipped.forEach { append("\n• ${it.label}: ${it.reason}") }
                    if (set.skipped.isEmpty()) {
                        append(" Enrol a key, or use Settings -> Recover from phrase.")
                    }
                },
            )
        }
        if (set.biometricRequired) {
            val act = activity ?: throw HardwareTapUnavailableException(
                "This item needs a device unlock and this surface cannot show one.",
            )
            when (val outcome = BiometricGate.authenticate(
                activity = act,
                title = purpose,
                subtitle = "Unlock with biometrics or device credential",
            )) {
                is BiometricOutcome.Authenticated -> Unit
                is BiometricOutcome.UserCancelled ->
                    throw HardwareTapCancelledException("Unlock cancelled.")
                is BiometricOutcome.Failed ->
                    throw HardwareTapFailedException("Unlock failed: ${outcome.message}")
                is BiometricOutcome.Unavailable ->
                    // Fail closed. The auth-bound Keystore key would reject the
                    // ECDH anyway (UserNotAuthenticatedException); saying so here
                    // is the difference between "protected item stayed protected"
                    // and "protection silently evaporated on this phone".
                    throw HardwareTapUnavailableException(
                        "This item is bound to a device-unlock key, but this phone has no " +
                            "biometric or screen lock enrolled (${outcome.reason}). " +
                            "Set a screen lock, or unlock with another recipient.",
                    )
            }
        }
        return decrypt(set.identities)
    }

    private suspend fun collectPin(): CharArray {
        val label = identitySet().identities
            .firstOrNull { it is YubiKeyPivIdentity }?.displayLabel
            ?: "your YubiKey"
        val request = PinRequest(label)
        _pinRequest.value = request
        try {
            return request.answer.await()
                ?: throw HardwareTapCancelledException("PIV PIN entry cancelled.")
        } finally {
            _pinRequest.value = null
        }
    }

    companion object {
        private const val TAG = "HardwareTapCoordinator"

        /**
         * Maps any throwable from [authorize] onto copy that names the actual
         * problem. Callers must not render raw exception messages from the JNI
         * layer; they leak stanza internals and read as noise.
         */
        fun describe(t: Throwable): String = when (t) {
            is NoUsableIdentityException -> t.message ?: "No usable recipient."
            is HardwareTapException -> t.message ?: "The key did not authorize this use."
            else -> {
                Log.w(TAG, "unclassified tap failure", t)
                val msg = t.message.orEmpty()
                when {
                    msg.contains("no identities", ignoreCase = true) ||
                        msg.contains("NoMatchingIdentity", ignoreCase = true) ->
                        "None of the keys you presented are recipients of this item."
                    else -> "The key did not authorize this use."
                }
            }
        }

        fun isRetryable(t: Throwable): Boolean =
            (t as? HardwareTapException)?.retryable ?: true
    }
}
