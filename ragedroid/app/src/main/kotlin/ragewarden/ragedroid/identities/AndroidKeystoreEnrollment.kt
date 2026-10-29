package ragewarden.ragedroid.identities

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.model.RecipientKind
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID

private const val TAG = "AndroidKeystoreEnrollment"

private const val KEY_VALIDITY_SECONDS = 30

data class KeystoreBacking(val strongBox: Boolean, val biometric: Boolean) {
    fun describe(): String = when {
        strongBox && biometric -> "StrongBox + biometric"
        strongBox -> "StrongBox (no biometric)"
        biometric -> "TEE + biometric"
        else -> "TEE (no biometric)"
    }
}

class KeystoreEnrollmentException(
    message: String,
    cause: Throwable? = null,
    val attempts: List<Pair<KeystoreBacking, Throwable>> = emptyList(),
) : RuntimeException(message, cause)

suspend fun enrollKeystoreIdentity(
    displayName: String,
    handle: String = "ragewarden-keystore-${UUID.randomUUID()}",
    useStrongBox: Boolean = true,
    requireBiometric: Boolean = true,
): Pair<StoredRecipient, AndroidKeystoreIdentity> = withContext(Dispatchers.IO) {
    val plan = buildList {
        if (useStrongBox && requireBiometric) add(KeystoreBacking(strongBox = true, biometric = true))
        if (useStrongBox) add(KeystoreBacking(strongBox = true, biometric = false))
        if (requireBiometric) add(KeystoreBacking(strongBox = false, biometric = true))
        add(KeystoreBacking(strongBox = false, biometric = false))
    }.distinct()

    val attempts = mutableListOf<Pair<KeystoreBacking, Throwable>>()
    for ((index, backing) in plan.withIndex()) {
        val attemptHandle = if (index == 0) handle else "$handle-fb${index}"
        runCatching { generateKeyPairOnce(attemptHandle, backing) }
            .onSuccess { pub ->
                val effectiveDisplayName = if (backing == plan.first()) displayName else
                    "$displayName · ${backing.describe()}"
                val now = System.currentTimeMillis()
                val recipient = StoredRecipient(
                    id = UUID.randomUUID().toString(),
                    kind = RecipientKind.StrongBox,
                    displayName = effectiveDisplayName,
                    createdAt = now,
                    lastUsedAt = now,
                    defaultEncrypt = true,
                    keystorePubkey = pub,
                    keystoreHandle = attemptHandle,
                    keystoreAuthBound = backing.biometric,
                    keystorePerUse = backing.biometric && keystorePerUse(),
                )
                val identity = AndroidKeystoreIdentity(
                    mockKey = null,
                    expectedPublicKey = pub,
                    keyHandle = attemptHandle,
                    label = effectiveDisplayName,
                    authBound = backing.biometric,
                    perUse = backing.biometric && keystorePerUse(),
                )
                return@withContext recipient to identity
            }
            .onFailure { t ->
                Log.w(TAG, "Keystore enrollment fallback ${backing.describe()} failed: ${t.javaClass.simpleName}: ${t.message}")
                attempts.add(backing to t)
            }
    }

    val summary = attempts.joinToString("; ") { (b, t) ->
        "${b.describe()} -> ${t.javaClass.simpleName}: ${t.message ?: "no message"}"
    }
    throw KeystoreEnrollmentException(
        message = "All Keystore backings failed: $summary",
        cause = attempts.lastOrNull()?.second,
        attempts = attempts,
    )
}

/** Whether an auth-bound Keystore key enrolled now is per use (API 35+) rather than a 30-second window. */
fun keystorePerUse(): Boolean = android.os.Build.VERSION.SDK_INT >= 35

private fun generateKeyPairOnce(handle: String, backing: KeystoreBacking): ByteArray {
    val specBuilder = KeyGenParameterSpec.Builder(handle, KeyProperties.PURPOSE_AGREE_KEY)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
    if (backing.strongBox) {
        specBuilder.setIsStrongBoxBacked(true)
    }
    if (backing.biometric) {
        specBuilder.setUserAuthenticationRequired(true)
        // Validity 0 is per use: each ECDH needs its own prompt, run with the
        // KeyAgreement as the CryptoObject (Android 15 added that). Below 35 a
        // KeyAgreement cannot be a CryptoObject, so the key falls back to a
        // 30-second window opened by a prompt just before the decrypt.
        specBuilder.setUserAuthenticationParameters(
            if (keystorePerUse()) 0 else KEY_VALIDITY_SECONDS,
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
        )
    }
    val spec = specBuilder.build()

    val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
        initialize(spec)
    }
    val kp = generator.generateKeyPair()
    return extractP256SecCompressed(kp.public)
}

private fun extractP256SecCompressed(publicKey: java.security.PublicKey): ByteArray {
    val ec = publicKey as? ECPublicKey
        ?: throw KeystoreEnrollmentException(
            "Expected ECPublicKey from keystore, got ${publicKey.javaClass.name}",
        )
    val w = ec.w
    val x = w.affineX
    val y = w.affineY
    val xBytes = x.toByteArray()
    val xPadded = ByteArray(32)
    val xLen = xBytes.size
    if (xLen <= 32) {
        val srcOff = if (xLen == 33 && xBytes[0] == 0.toByte()) 1 else 0
        val effective = xLen - srcOff
        System.arraycopy(xBytes, srcOff, xPadded, 32 - effective, effective)
    } else {
        System.arraycopy(xBytes, xBytes.size - 32, xPadded, 0, 32)
    }
    val parityByte: Byte = if (y.testBit(0)) 0x03 else 0x02
    val out = ByteArray(33)
    out[0] = parityByte
    System.arraycopy(xPadded, 0, out, 1, 32)
    return out
}

fun isStrongBoxAvailable(context: Context): Boolean =
    context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

fun isBiometricEnrollable(context: Context): Boolean {
    val mgr = androidx.biometric.BiometricManager.from(context)
    val allowed = androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
        androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
    return mgr.canAuthenticate(allowed) == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
}
