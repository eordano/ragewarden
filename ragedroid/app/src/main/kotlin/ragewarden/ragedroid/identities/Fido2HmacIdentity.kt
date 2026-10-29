package ragewarden.ragedroid.identities

import android.util.Log
import androidx.fragment.app.FragmentActivity
import ragewarden.ragedroid.jni.RageNative

/**
 * age recipient backed by a FIDO2 authenticator's hmac-secret / PRF output.
 * The authenticator enforces user presence (a touch) and, with
 * `userVerification=required`, user verification; the app cannot obtain the PRF
 * output without both.
 *
 * The device call is confined to [invokeRealCredentialManager].
 */
class Fido2HmacIdentity(
    private val mockHmacKey: ByteArray?,
    val credentialId: ByteArray,
    val rpId: String,
    val activity: FragmentActivity? = null,
    private val label: String = "FIDO2 hmac-secret",
) : KotlinIdentity {
    override val isMock: Boolean get() = mockHmacKey != null

    override val displayLabel: String get() = MockHardware.label(label, isMock)

    override val requiresPhysicalPresence: Boolean get() = !isMock

    override val transportHint: String? get() = if (isMock) null else "NFC · USB-C · internal"

    override suspend fun tryUnwrap(
        stanzaTag: String,
        stanzaArgs: Array<String>,
        stanzaBody: ByteArray,
    ): ByteArray? {
        if (stanzaTag != StanzaTags.FIDO2_HMAC) return null
        // 3 args = pre-wrap-salt blobs, 4 = current. See StanzaTags.isPrfArity.
        if (!StanzaTags.isPrfArity(stanzaArgs.size)) return null
        val stanzaCred = runCatching { StanzaCrypto.b64UrlDecode(stanzaArgs[0]) }.getOrNull() ?: return null
        if (!stanzaCred.contentEquals(credentialId)) return null
        val salt = runCatching { StanzaCrypto.b64StdDecode(stanzaArgs[1]) }.getOrNull() ?: return null
        if (salt.size != 32) return null

        val prfOutput = if (mockHmacKey != null) {
            MockHardware.requireEnabled("Fido2HmacIdentity mock PRF")
            StanzaCrypto.hmacSha256(mockHmacKey, salt)
        } else {
            invokeRealCredentialManager(salt)
        }

        return try {
            RageNative.unwrapStanza(StanzaTags.FIDO2_HMAC, stanzaArgs, stanzaBody, prfOutput)
        } catch (t: Throwable) {
            Log.w(TAG, "fido2-hmac unwrap failed after a successful assertion", t)
            throw HardwareTapFailedException(
                "$displayLabel returned a PRF value the blob rejected.",
                t,
            )
        } finally {
            prfOutput.fill(0)
        }
    }

    /**
     * Same tap, used at *encryption* time by [CredentialManagerPrfTapper].
     * Exposed so enrol / encrypt / decrypt all go through one assertion builder.
     */
    internal suspend fun obtainPrfOutput(salt: ByteArray): ByteArray {
        if (mockHmacKey != null) {
            MockHardware.requireEnabled("Fido2HmacIdentity mock PRF")
            return StanzaCrypto.hmacSha256(mockHmacKey, salt)
        }
        return invokeRealCredentialManager(salt)
    }

    /** THE DEVICE CALL; see [PrfAssertion]. */
    private suspend fun invokeRealCredentialManager(salt: ByteArray): ByteArray = PrfAssertion.first(
        activity, rpId, salt, credentialId, displayLabel, TAG,
        dismissed = "Authenticator prompt dismissed.",
        noPrfHint = "The authenticator or the credential does not support the hmac-secret/PRF extension.",
    )

    companion object {
        private const val TAG = "Fido2HmacIdentity"

        fun enrollMock(rpId: String = "ragewarden"): Fido2HmacIdentity {
            MockHardware.requireEnabled("Fido2HmacIdentity.enrollMock")
            val rng = java.security.SecureRandom()
            val cid = ByteArray(16).also { rng.nextBytes(it) }
            val key = ByteArray(32).also { rng.nextBytes(it) }
            return Fido2HmacIdentity(mockHmacKey = key, credentialId = cid, rpId = rpId)
        }
    }
}
