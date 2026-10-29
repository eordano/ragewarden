package ragewarden.ragedroid.identities

import android.util.Log
import androidx.fragment.app.FragmentActivity
import ragewarden.ragedroid.jni.RageNative

/**
 * age recipient backed by a WebAuthn passkey's PRF extension
 * (`webauthn-prf-v1` stanzas). Distinct from [Fido2HmacIdentity] only in the
 * stanza tag and argument order: core puts the rp id at `args[1]` and the salt
 * at `args[2]` here (`core/src/stanza_format.rs:244-249`), and the salt at
 * `args[1]` for `fido2-hmac` (`:171-176`).
 *
 * The device call is confined to [invokeRealCredentialManager].
 */
class PasskeyIdentity(
    private val mockPrfKey: ByteArray?,
    val credentialId: ByteArray,
    val rpId: String,
    val activity: FragmentActivity? = null,
    private val label: String = "Passkey on this device",
) : KotlinIdentity {
    override val isMock: Boolean get() = mockPrfKey != null

    override val displayLabel: String get() = MockHardware.label(label, isMock)

    override val requiresPhysicalPresence: Boolean get() = !isMock

    override val transportHint: String? get() = if (isMock) null else "this device · security key"

    override suspend fun tryUnwrap(
        stanzaTag: String,
        stanzaArgs: Array<String>,
        stanzaBody: ByteArray,
    ): ByteArray? {
        if (stanzaTag != StanzaTags.WEBAUTHN_PRF_V1) return null
        // 3 args = pre-wrap-salt blobs, 4 = current. See StanzaTags.isPrfArity.
        if (!StanzaTags.isPrfArity(stanzaArgs.size)) return null
        val stanzaCred = runCatching { StanzaCrypto.b64UrlDecode(stanzaArgs[0]) }.getOrNull() ?: return null
        if (!stanzaCred.contentEquals(credentialId)) return null
        val salt = runCatching { StanzaCrypto.b64StdDecode(stanzaArgs[2]) }.getOrNull() ?: return null
        if (salt.size != 32) return null

        val prfOutput = if (mockPrfKey != null) {
            MockHardware.requireEnabled("PasskeyIdentity mock PRF")
            StanzaCrypto.hmacSha256(mockPrfKey, salt)
        } else {
            invokeRealCredentialManager(salt)
        }

        return try {
            RageNative.unwrapStanza(StanzaTags.WEBAUTHN_PRF_V1, stanzaArgs, stanzaBody, prfOutput)
        } catch (t: Throwable) {
            Log.w(TAG, "webauthn-prf-v1 unwrap failed after a successful assertion", t)
            throw HardwareTapFailedException(
                "$displayLabel returned a PRF value the blob rejected.",
                t,
            )
        } finally {
            prfOutput.fill(0)
        }
    }

    /** THE DEVICE CALL; see [PrfAssertion]. */
    private suspend fun invokeRealCredentialManager(salt: ByteArray): ByteArray = PrfAssertion.first(
        activity, rpId, salt, credentialId, displayLabel, TAG,
        dismissed = "Passkey prompt dismissed.",
        noPrfHint = "The credential was not created with the prf extension.",
    )

    companion object {
        private const val TAG = "PasskeyIdentity"

        fun enrollMock(rpId: String = "ragewarden"): PasskeyIdentity {
            MockHardware.requireEnabled("PasskeyIdentity.enrollMock")
            val rng = java.security.SecureRandom()
            val cid = ByteArray(16).also { rng.nextBytes(it) }
            val key = ByteArray(32).also { rng.nextBytes(it) }
            return PasskeyIdentity(mockPrfKey = key, credentialId = cid, rpId = rpId)
        }

        fun fromEnrollment(
            enrollment: PasskeyEnrollment,
            activity: FragmentActivity? = null,
        ): PasskeyIdentity = PasskeyIdentity(
            mockPrfKey = enrollment.mockPrfKey,
            credentialId = enrollment.credentialId,
            rpId = enrollment.rpId,
            activity = activity,
        )
    }
}
