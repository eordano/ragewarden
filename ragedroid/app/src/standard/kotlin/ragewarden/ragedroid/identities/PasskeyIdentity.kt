package ragewarden.ragedroid.identities

import android.util.Base64
import android.util.Log
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.fragment.app.FragmentActivity
import org.json.JSONArray
import org.json.JSONObject
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

    /** THE DEVICE CALL. Needs a real authenticator behind Credential Manager. */
    private suspend fun invokeRealCredentialManager(salt: ByteArray): ByteArray {
        val act = activity ?: throw HardwareTapUnavailableException(
            "$displayLabel cannot be used from this surface: Credential Manager needs an Activity.",
        )
        val requestJson = buildAssertionJson(rpId, salt, credentialId)
        val option = GetPublicKeyCredentialOption(requestJson)
        val request = GetCredentialRequest(listOf(option))
        val response = try {
            CredentialManager.create(act).getCredential(act, request)
        } catch (e: GetCredentialCancellationException) {
            throw HardwareTapCancelledException("Passkey prompt dismissed.", e)
        } catch (e: GetCredentialException) {
            Log.w(TAG, "PasskeyIdentity: getCredential failed", e)
            throw HardwareTapFailedException(
                "$displayLabel did not produce an assertion: ${e.type}",
                e,
            )
        }
        val credential = response.credential as? PublicKeyCredential
            ?: throw HardwareTapFailedException(
                "Credential Manager returned a ${response.credential.type} credential, not a passkey.",
            )
        return parsePrfFirstFromAssertion(credential.authenticationResponseJson)
            ?: throw HardwareTapFailedException(
                "$displayLabel completed the assertion but returned no PRF output. " +
                    "The credential was not created with the prf extension.",
            )
    }

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

        internal fun buildAssertionJson(
            rpId: String,
            salt: ByteArray,
            credentialId: ByteArray,
        ): String {
            val challenge = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
            val allowed = JSONObject()
                .put("type", "public-key")
                .put("id", b64Url(credentialId))
            val prfFirst = JSONObject().put("first", b64Url(salt))
            val prfEval = JSONObject().put("eval", prfFirst)
            val extensions = JSONObject().put("prf", prfEval)
            return JSONObject()
                .put("challenge", b64Url(challenge))
                .put("rpId", rpId)
                .put("userVerification", "required")
                .put("allowCredentials", JSONArray().put(allowed))
                .put("extensions", extensions)
                .toString()
        }

        internal fun parsePrfFirstFromAssertion(authenticationResponseJson: String): ByteArray? {
            return runCatching {
                val root = JSONObject(authenticationResponseJson)
                val ext = root.optJSONObject("clientExtensionResults") ?: return@runCatching null
                val prf = ext.optJSONObject("prf") ?: return@runCatching null
                val results = prf.optJSONObject("results") ?: return@runCatching null
                val first = results.optString("first", "")
                if (first.isEmpty()) null else b64UrlDecode(first)
            }.onFailure {
                Log.w(TAG, "PasskeyIdentity: failed to parse PRF result", it)
            }.getOrNull().also {
                if (it == null) {
                    Log.w(TAG, "PasskeyIdentity: assertion response missing prf.results.first")
                }
            }
        }

        private fun b64Url(bytes: ByteArray): String =
            Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

        private fun b64UrlDecode(s: String): ByteArray =
            Base64.decode(s, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }
}
