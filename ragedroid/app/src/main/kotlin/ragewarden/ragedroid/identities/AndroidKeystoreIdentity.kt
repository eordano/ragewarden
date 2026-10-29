package ragewarden.ragedroid.identities

import ragewarden.ragedroid.jni.RageNative
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.AlgorithmParameters
import java.security.spec.ECParameterSpec
import javax.crypto.KeyAgreement

class AndroidKeystoreIdentity(
    private val mockKey: PrivateKey?,
    val expectedPublicKey: ByteArray,
    val keyHandle: String,
    private val label: String = "This phone (StrongBox)",
    /**
     * True when the underlying key was generated with
     * `setUserAuthenticationRequired(true)` (`AndroidKeystoreEnrollment.kt:99`).
     * A non-auth-bound key is a *silent* TEE operation -- it is not a deliberate
     * physical action, and the UI must not describe it as one.
     */
    val authBound: Boolean = false,
    /** Each ECDH runs its own prompt with the KeyAgreement as CryptoObject (API 35+); needs [activity]. */
    val perUse: Boolean = false,
    private val activity: androidx.fragment.app.FragmentActivity? = null,
) : KotlinIdentity {
    override val isMock: Boolean get() = mockKey != null

    override val displayLabel: String get() = MockHardware.label(label, isMock)

    override val requiresPhysicalPresence: Boolean get() = authBound && !isMock

    override val transportHint: String? get() = if (authBound && !isMock) "this device" else null

    /** Base32 of the key handle, as core writes it into `args[0]`. */
    private val handleArg: String by lazy { Base32NoPad.encode(keyHandle) }

    override suspend fun tryUnwrap(
        stanzaTag: String,
        stanzaArgs: Array<String>,
        stanzaBody: ByteArray,
    ): ByteArray? {
        if (stanzaTag != StanzaTags.RAGEDROID_KEYSTORE_V1 && stanzaTag != StanzaTags.RAGEDROID_KEYSTORE_V2) return null
        if (stanzaArgs.size != 2) return null
        // args[0] is base32(key_handle) (core/src/stanza_format.rs:335). Without
        // this check the identity attempts an ECDH for *every* keystore stanza in
        // the header, including other devices' -- and on a biometric-bound key that
        // burns the 30-second auth window the caller just paid a prompt for.
        if (!stanzaArgs[0].equals(handleArg, ignoreCase = true)) return null
        val ephemeralPub = runCatching { StanzaCrypto.b64StdDecode(stanzaArgs[1]) }.getOrNull() ?: return null
        if (ephemeralPub.size != 33) return null

        val share = if (mockKey != null) {
            MockHardware.requireEnabled("AndroidKeystoreIdentity mock ECDH")
            KeyAgreement.getInstance("ECDH").apply {
                init(mockKey)
                doPhase(decompressP256Sec1(ephemeralPub), true)
            }.generateSecret()
        } else {
            performKeystoreEcdh(ephemeralPub)
        }
        if (share.size != 32) {
            share.fill(0)
            throw HardwareTapFailedException(
                "$displayLabel produced a ${share.size}-byte ECDH share; expected 32.",
            )
        }

        return try {
            RageNative.unwrapStanzaForRecipient(stanzaTag, stanzaArgs, stanzaBody, share, expectedPublicKey)
        } catch (t: Throwable) {
            throw HardwareTapFailedException(
                "$displayLabel matched the key handle but could not unwrap the stanza.",
                t,
            )
        } finally {
            share.fill(0)
        }
    }

    /**
     * THE DEVICE CALL for the on-phone recipient. Runs inside StrongBox/TEE. On
     * an auth-bound key this throws `UserNotAuthenticatedException` unless a
     * biometric/device-credential prompt succeeded within the last
     * `KEY_VALIDITY_SECONDS` (30 s) -- which is why the caller re-prompts before
     * each decrypt rather than trusting an old window.
     */
    private suspend fun performKeystoreEcdh(ephemeralPub: ByteArray): ByteArray {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val priv = keyStore.getKey(keyHandle, null) as? PrivateKey
            ?: throw HardwareTapUnavailableException(
                "Keystore handle '$keyHandle' is gone. The key was invalidated " +
                    "(biometrics re-enrolled, or the app's data cleared); this item must be " +
                    "recovered with another recipient or the paper phrase.",
            )
        val ephemeralPublic = decompressP256Sec1(ephemeralPub)
        if (perUse && android.os.Build.VERSION.SDK_INT >= 35) return perUseEcdh(priv, ephemeralPublic)
        return try {
            KeyAgreement.getInstance("ECDH", "AndroidKeyStore").apply {
                init(priv)
                doPhase(ephemeralPublic, true)
            }.generateSecret()
        } catch (t: android.security.keystore.UserNotAuthenticatedException) {
            throw HardwareTapFailedException(
                "$displayLabel needs a fresh unlock -- the 30-second authentication window expired.",
                t,
            )
        } catch (t: android.security.keystore.KeyPermanentlyInvalidatedException) {
            throw HardwareTapUnavailableException(
                "$displayLabel was permanently invalidated (biometrics changed). " +
                    "Use another recipient or the paper recovery phrase.",
                t,
            )
        }
    }

    private fun decompressP256Sec1(sec1Compressed: ByteArray): java.security.PublicKey = P256.decompress(sec1Compressed)

    companion object {
        internal fun sec1Compressed(pub: java.security.interfaces.ECPublicKey): ByteArray = P256.compress(pub)

        fun enrollMock(handle: String = "mock-keystore"): AndroidKeystoreIdentity {
            MockHardware.requireEnabled("AndroidKeystoreIdentity.enrollMock")
            val pair = java.security.KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }.generateKeyPair()
            return AndroidKeystoreIdentity(
                mockKey = pair.private,
                expectedPublicKey = sec1Compressed(pair.public as java.security.interfaces.ECPublicKey),
                keyHandle = handle,
            )
        }
    }

    /**
     * The per-use ECDH: the KeyAgreement is initialised with the key, then
     * unlocked by a prompt that carries it as the CryptoObject, and used once.
     */
    @androidx.annotation.RequiresApi(35)
    private suspend fun perUseEcdh(priv: PrivateKey, peer: java.security.PublicKey): ByteArray {
        val act = activity ?: throw HardwareTapUnavailableException(
            "$displayLabel asks for authentication on every use and this surface cannot show the prompt. " +
                "Open the item in Ragewarden.",
        )
        val agreement = try {
            KeyAgreement.getInstance("ECDH", "AndroidKeyStore").apply { init(priv) }
        } catch (t: android.security.keystore.KeyPermanentlyInvalidatedException) {
            throw HardwareTapUnavailableException(
                "$displayLabel was permanently invalidated (biometrics changed). " +
                    "Use another recipient or the paper recovery phrase.",
                t,
            )
        }
        val unlocked = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
            kotlinx.coroutines.suspendCancellableCoroutine<KeyAgreement> { cont ->
                val cancel = android.os.CancellationSignal()
                cont.invokeOnCancellation { cancel.cancel() }
                val prompt = android.hardware.biometrics.BiometricPrompt.Builder(act)
                    .setTitle(displayLabel)
                    .setSubtitle("Confirm to open this item")
                    .setAllowedAuthenticators(
                        android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                    )
                    .build()
                prompt.authenticate(
                    android.hardware.biometrics.BiometricPrompt.CryptoObject(agreement),
                    cancel,
                    act.mainExecutor,
                    object : android.hardware.biometrics.BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: android.hardware.biometrics.BiometricPrompt.AuthenticationResult) {
                            val ka = result.cryptoObject?.keyAgreement
                            if (ka == null) {
                                cont.resumeWith(Result.failure(HardwareTapFailedException("$displayLabel unlocked without its key agreement.")))
                            } else {
                                cont.resumeWith(Result.success(ka))
                            }
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            val e = when (errorCode) {
                                android.hardware.biometrics.BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
                                android.hardware.biometrics.BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
                                -> HardwareTapCancelledException("Unlock cancelled.")
                                else -> HardwareTapFailedException("Unlock failed: $errString")
                            }
                            cont.resumeWith(Result.failure(e))
                        }
                    },
                )
            }
        }
        return unlocked.apply { doPhase(peer, true) }.generateSecret()
    }
}
