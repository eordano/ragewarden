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
import org.json.JSONObject
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

    /**
     * THE DEVICE CALL. Requires a real authenticator (or a platform one) behind
     * Credential Manager. Failures are raised, never nulled -- see
     * HardwareTapErrors.kt for why.
     */
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
            throw HardwareTapCancelledException("Authenticator prompt dismissed.", e)
        } catch (e: GetCredentialException) {
            Log.w(TAG, "Fido2HmacIdentity: getCredential failed", e)
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
                    "The authenticator or the credential does not support the hmac-secret/PRF extension.",
            )
    }

    companion object {
        private const val TAG = "Fido2HmacIdentity"

        fun enrollMock(rpId: String = "ragewarden"): Fido2HmacIdentity {
            MockHardware.requireEnabled("Fido2HmacIdentity.enrollMock")
            val rng = java.security.SecureRandom()
            val cid = ByteArray(16).also { rng.nextBytes(it) }
            val key = ByteArray(32).also { rng.nextBytes(it) }
            return Fido2HmacIdentity(mockHmacKey = key, credentialId = cid, rpId = rpId)
        }

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
                .put("allowCredentials", org.json.JSONArray().put(allowed))
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
                Log.w(TAG, "Fido2HmacIdentity: failed to parse PRF result", it)
            }.getOrNull().also {
                if (it == null) {
                    Log.w(TAG, "Fido2HmacIdentity: assertion response missing prf.results.first")
                }
            }
        }

        private fun b64Url(bytes: ByteArray): String =
            Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

        private fun b64UrlDecode(s: String): ByteArray =
            Base64.decode(s, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }
}
