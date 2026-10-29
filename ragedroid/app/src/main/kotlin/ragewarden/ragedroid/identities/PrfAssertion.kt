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

/**
 * THE DEVICE CALL behind [Fido2HmacIdentity] and PasskeyIdentity: one WebAuthn assertion with
 * the PRF extension through Credential Manager. Requires a real authenticator (or a platform
 * one). Failures are raised, never nulled -- see HardwareTapErrors.kt for why.
 */
internal object PrfAssertion {
    suspend fun first(
        activity: FragmentActivity?,
        rpId: String,
        salt: ByteArray,
        credentialId: ByteArray,
        displayLabel: String,
        tag: String,
        dismissed: String,
        noPrfHint: String,
    ): ByteArray {
        val act = activity ?: throw HardwareTapUnavailableException(
            "$displayLabel cannot be used from this surface: Credential Manager needs an Activity.",
        )
        val request = GetCredentialRequest(listOf(GetPublicKeyCredentialOption(buildAssertionJson(rpId, salt, credentialId))))
        val response = try {
            CredentialManager.create(act).getCredential(act, request)
        } catch (e: GetCredentialCancellationException) {
            throw HardwareTapCancelledException(dismissed, e)
        } catch (e: GetCredentialException) {
            Log.w(tag, "$tag: getCredential failed", e)
            throw HardwareTapFailedException(
                "$displayLabel did not produce an assertion: ${e.type}",
                e,
            )
        }
        val credential = response.credential as? PublicKeyCredential
            ?: throw HardwareTapFailedException(
                "Credential Manager returned a ${response.credential.type} credential, not a passkey.",
            )
        return parsePrfFirst(credential.authenticationResponseJson, tag)
            ?: throw HardwareTapFailedException(
                "$displayLabel completed the assertion but returned no PRF output. $noPrfHint",
            )
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
            .put("allowCredentials", JSONArray().put(allowed))
            .put("extensions", extensions)
            .toString()
    }

    internal fun parsePrfFirst(authenticationResponseJson: String, tag: String): ByteArray? {
        return runCatching {
            val root = JSONObject(authenticationResponseJson)
            val ext = root.optJSONObject("clientExtensionResults") ?: return@runCatching null
            val prf = ext.optJSONObject("prf") ?: return@runCatching null
            val results = prf.optJSONObject("results") ?: return@runCatching null
            val first = results.optString("first", "")
            if (first.isEmpty()) null else b64UrlDecode(first)
        }.onFailure {
            Log.w(tag, "$tag: failed to parse PRF result", it)
        }.getOrNull().also {
            if (it == null) {
                Log.w(tag, "$tag: assertion response missing prf.results.first")
            }
        }
    }

    private fun b64Url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private fun b64UrlDecode(s: String): ByteArray =
        Base64.decode(s, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
}
