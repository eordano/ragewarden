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
    private val mockSecret: ByteArray?,
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
) : KotlinIdentity {
    override val isMock: Boolean get() = mockSecret != null

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
        if (stanzaTag != StanzaTags.RAGEDROID_KEYSTORE_V1) return null
        if (stanzaArgs.size != 2) return null
        // args[0] is base32(key_handle) (core/src/stanza_format.rs:335). Without
        // this check the identity attempts an ECDH for *every* keystore stanza in
        // the header, including other devices' -- and on a biometric-bound key that
        // burns the 30-second auth window the caller just paid a prompt for.
        if (!stanzaArgs[0].equals(handleArg, ignoreCase = true)) return null
        val ephemeralPub = runCatching { StanzaCrypto.b64StdDecode(stanzaArgs[1]) }.getOrNull() ?: return null
        if (ephemeralPub.size != 33) return null

        val share = if (mockSecret != null) {
            MockHardware.requireEnabled("AndroidKeystoreIdentity mock ECDH")
            RageNative.x25519Diffie(mockSecret, ephemeralPub)
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
            RageNative.unwrapStanza(StanzaTags.RAGEDROID_KEYSTORE_V1, stanzaArgs, stanzaBody, share)
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
    private fun performKeystoreEcdh(ephemeralPub: ByteArray): ByteArray {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val priv = keyStore.getKey(keyHandle, null) as? PrivateKey
            ?: throw HardwareTapUnavailableException(
                "Keystore handle '$keyHandle' is gone. The key was invalidated " +
                    "(biometrics re-enrolled, or the app's data cleared); this item must be " +
                    "recovered with another recipient or the paper phrase.",
            )
        val ephemeralPublic = decompressP256Sec1(ephemeralPub)
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

    private fun decompressP256Sec1(sec1Compressed: ByteArray): java.security.PublicKey {
        require(sec1Compressed.size == 33) { "P-256 SEC1-compressed pubkey must be 33 bytes" }
        val tag = sec1Compressed[0].toInt() and 0xFF
        require(tag == 0x02 || tag == 0x03) { "Bad SEC1-compressed prefix: 0x${tag.toString(16)}" }
        val xBytes = ByteArray(32)
        System.arraycopy(sec1Compressed, 1, xBytes, 0, 32)
        val x = BigInteger(1, xBytes)
        val params = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)
        val y = solveYForP256(x, params, oddY = (tag == 0x03))
        val point = ECPoint(x, y)
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params))
    }

    private fun solveYForP256(x: BigInteger, params: ECParameterSpec, oddY: Boolean): BigInteger {
        val curve = params.curve
        val p = (curve.field as java.security.spec.ECFieldFp).p
        val a = curve.a
        val b = curve.b
        val rhs = (x.modPow(BigInteger.valueOf(3), p) + a.multiply(x).mod(p) + b).mod(p)
        val exponent = p.add(BigInteger.ONE).shiftRight(2)
        val candidate = rhs.modPow(exponent, p)
        check(candidate.multiply(candidate).mod(p) == rhs) {
            "x is not on the secp256r1 curve"
        }
        return if (candidate.testBit(0) == oddY) candidate else p.subtract(candidate)
    }

    companion object {
        fun enrollMock(handle: String = "mock-keystore"): AndroidKeystoreIdentity {
            MockHardware.requireEnabled("AndroidKeystoreIdentity.enrollMock")
            val secret = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
            // NOTE: this pubkey is not a real P-256 point -- the mock unwraps via
            // X25519 (RageNative.x25519Diffie), which predates the P-256 switch.
            // It exists only to exercise the plumbing; it cannot round-trip
            // against a real `ragedroid-keystore-v1` stanza.
            val pub = ByteArray(33).also { it[0] = 0x02 }
            return AndroidKeystoreIdentity(
                mockSecret = secret,
                expectedPublicKey = pub,
                keyHandle = handle,
            )
        }
    }
}
