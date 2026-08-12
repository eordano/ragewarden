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
    rpId: String = "ragewarden.local",
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

    val credentialId = parseCredentialIdFromAttestation(credResponse.registrationResponseJson)
        ?: error("Credential Manager response missing credential id")

    val storedSalt = salt.copyOf()

    val now = System.currentTimeMillis()
    val recipient = StoredRecipient(
        id = UUID.randomUUID().toString(),
        kind = RecipientKind.Fido2,
        displayName = displayName,
        createdAt = now,
        lastUsedAt = now,
        defaultEncrypt = false,
        fido2CredentialId = credentialId,
        fido2RpId = rpId,
        fido2Salt = storedSalt,
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

private fun buildEnrollmentJson(
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
        .put(JSONObject().put("type", "public-key").put("alg", -257))

    val authenticatorSelection = JSONObject()
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

private fun parseCredentialIdFromAttestation(registrationResponseJson: String): ByteArray? {
    return runCatching {
        val root = JSONObject(registrationResponseJson)
        val id = root.optString("id", "")
        if (id.isNotEmpty()) {
            return@runCatching b64UrlDecode(id)
        }
        val rawId = root.optString("rawId", "")
        if (rawId.isNotEmpty()) {
            return@runCatching b64UrlDecode(rawId)
        }
        null
    }.onFailure {
        Log.w(TAG, "Failed to parse credentialId from attestation response", it)
    }.getOrNull()
}

private fun b64Url(bytes: ByteArray): String =
    Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

private fun b64UrlDecode(s: String): ByteArray =
    Base64.decode(s, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
