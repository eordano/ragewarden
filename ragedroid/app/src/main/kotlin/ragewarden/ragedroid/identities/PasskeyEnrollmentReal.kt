package ragewarden.ragedroid.identities

import android.util.Base64
import android.util.Log
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.model.RecipientKind
import java.security.SecureRandom
import java.util.UUID

private const val TAG = "PasskeyEnrollmentReal"

suspend fun enrollPasskeyWithPrf(
    activity: FragmentActivity,
    accountId: String,
    rpId: String = PasskeyRp.ID,
    displayName: String = "Passkey on this device",
): Pair<StoredRecipient, PasskeyIdentity> = withContext(Dispatchers.Main) {
    val rng = SecureRandom()
    val challenge = ByteArray(32).also { rng.nextBytes(it) }
    val salt = ByteArray(32).also { rng.nextBytes(it) }

    val requestJson = buildEnrollmentJson(
        rpId = rpId,
        accountId = accountId,
        challenge = challenge,
        salt = salt,
    )
    val request = CreatePublicKeyCredentialRequest(requestJson)
    val response = CredentialManager.create(activity).createCredential(activity, request)
    val credResponse = response as? CreatePublicKeyCredentialResponse
        ?: error("Credential Manager returned unexpected response type: ${response::class.java.name}")

    val registration = parseRegistration(credResponse.registrationResponseJson)
        ?: error("Credential Manager response missing credential id")
    val credentialId = registration.credentialId

    val recipient = newPasskeyRecipient(
        credentialId,
        salt.copyOf(),
        rpId,
        displayName,
        System.currentTimeMillis(),
        publicKeySpki = registration.publicKeySpki,
    )

    val identity = PasskeyIdentity.fromEnrollment(
        enrollment = PasskeyEnrollment(
            credentialId = credentialId,
            rpId = rpId,
            mockPrfKey = null,
        ),
        activity = activity,
    )
    recipient to identity
}

internal fun newPasskeyRecipient(
    credentialId: ByteArray,
    salt: ByteArray,
    rpId: String,
    displayName: String,
    now: Long,
    publicKeySpki: ByteArray? = null,
): StoredRecipient = StoredRecipient(
    id = UUID.randomUUID().toString(),
    kind = RecipientKind.PasskeyPrf,
    displayName = displayName,
    createdAt = now,
    lastUsedAt = now,
    defaultEncrypt = false,
    passkeyCredentialId = credentialId,
    passkeyRpId = rpId,
    passkeySalt = salt,
    passkeyPublicKeySpki = publicKeySpki,
)

internal fun buildEnrollmentJson(
    rpId: String,
    accountId: String,
    challenge: ByteArray,
    salt: ByteArray,
): String {
    val rp = JSONObject()
        .put("id", rpId)
        .put("name", "Ragewarden")

    val userId = b64Url(accountId.toByteArray(Charsets.UTF_8))
    val user = JSONObject()
        .put("id", userId)
        .put("name", accountId)
        .put("displayName", "Ragewarden vault")

    val pubKeyParams = JSONArray()
        .put(JSONObject().put("type", "public-key").put("alg", -7))

    // Discoverable, so the PRF relay page (https://<rpId>/prf) can ask for it
    // without knowing the credential id; ES256 only, so the public key the
    // registry publishes is the P-256 SPKI the browser verifies against.
    val authenticatorSelection = JSONObject()
        .put("residentKey", "required")
        .put("requireResidentKey", true)
        .put("userVerification", "required")

    val prfFirst = JSONObject().put("first", b64Url(salt))
    val prfEval = JSONObject().put("eval", prfFirst)
    val extensions = JSONObject().put("prf", prfEval)

    return JSONObject()
        .put("rp", rp)
        .put("user", user)
        .put("challenge", b64Url(challenge))
        .put("pubKeyCredParams", pubKeyParams)
        .put("authenticatorSelection", authenticatorSelection)
        .put("extensions", extensions)
        .toString()
}

internal class Registration(val credentialId: ByteArray, val publicKeySpki: ByteArray?)

/**
 * The credential id, and the credential's public key as SPKI DER when the
 * provider reports it (`response.publicKey`, WebAuthn's getPublicKey()) for an
 * ES256 credential.
 */
internal fun parseRegistration(registrationResponseJson: String): Registration? {
    return runCatching {
        val root = JSONObject(registrationResponseJson)
        val id = root.optString("id", "").ifEmpty { root.optString("rawId", "") }
        if (id.isEmpty()) return@runCatching null
        val response = root.optJSONObject("response")
        val spki = response
            ?.takeIf { it.optInt("publicKeyAlgorithm", -7) == -7 }
            ?.optString("publicKey", "")
            ?.takeIf { it.isNotEmpty() }
            ?.let(::b64UrlDecode)
        Registration(b64UrlDecode(id), spki)
    }.onFailure {
        Log.w(TAG, "Failed to parse the registration response", it)
    }.getOrNull()
}

private fun b64Url(bytes: ByteArray): String =
    Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

private fun b64UrlDecode(s: String): ByteArray =
    Base64.decode(s, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
