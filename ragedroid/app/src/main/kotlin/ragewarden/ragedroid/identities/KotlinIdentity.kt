package ragewarden.ragedroid.identities

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

interface KotlinIdentity {
    val displayLabel: String

    /**
     * True when this identity's "hardware" is simulated. Mocks must be visibly
     * labelled everywhere they surface and can only exist in a debug build with
     * [MockHardware.enabled] -- see MockHardware.kt.
     */
    val isMock: Boolean get() = false

    /**
     * True when unwrapping through this identity costs a deliberate physical
     * action on off-CPU hardware (YubiKey touch, authenticator user-presence,
     * biometric-bound Keystore key). False means the unwrap is a silent
     * software/TEE operation the user is not asked to consent to -- the UI must
     * not claim a tap happened for those.
     */
    val requiresPhysicalPresence: Boolean get() = false

    /** Short transport hint for the tap prompt, e.g. "NFC · USB-C". */
    val transportHint: String? get() = null

    suspend fun tryUnwrap(
        stanzaTag: String,
        stanzaArgs: Array<String>,
        stanzaBody: ByteArray,
    ): ByteArray?

    fun tryUnwrapBlocking(
        stanzaTag: String,
        stanzaArgs: Array<String>,
        stanzaBody: ByteArray,
    ): ByteArray? = runBlocking(Dispatchers.IO) {
        withContext(Dispatchers.IO) {
            tryUnwrap(stanzaTag, stanzaArgs, stanzaBody)
        }
    }
}

object StanzaTags {
    const val X25519: String = "X25519"
    const val SCRYPT: String = "scrypt"
    const val PIV_P256: String = "piv-p256"
    const val FIDO2_HMAC: String = "fido2-hmac"
    const val WEBAUTHN_PRF_V1: String = "webauthn-prf-v1"
    const val RAGEDROID_KEYSTORE_V1: String = "ragedroid-keystore-v1"

    /**
     * PRF-family stanzas (`fido2-hmac`, `webauthn-prf-v1`) carry 4 args in the
     * current core format -- the 4th is a per-encryption wrap salt
     * (`core/src/stanza_format.rs:49-50`, `PRF_ARGS_LEGACY`/`PRF_ARGS_CURRENT`).
     * Blobs written before that change carry 3. Core accepts both
     * (`check_prf_stanza_arity`, `core/src/stanza_format.rs:388`), so the Kotlin
     * identities must too -- a hard `== 3` check silently refuses to decrypt
     * anything written by a current core and looks like "no matching identity".
     */
    const val PRF_ARGS_LEGACY: Int = 3
    const val PRF_ARGS_CURRENT: Int = 4

    fun isPrfArity(n: Int): Boolean = n == PRF_ARGS_LEGACY || n == PRF_ARGS_CURRENT
}

/**
 * Base32 as core encodes the `ragedroid-keystore-v1` key-handle argument
 * (`core/src/stanza_format.rs:23` + `base32_encode` at `:489`): RFC 4648
 * alphabet, no padding.
 */
internal object Base32NoPad {
    private const val CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun encode(input: ByteArray): String {
        val out = StringBuilder((input.size * 8 + 4) / 5)
        var acc = 0
        var bits = 0
        for (b in input) {
            acc = (acc shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                out.append(CHARSET[(acc shr bits) and 0x1F])
            }
        }
        if (bits > 0) {
            out.append(CHARSET[(acc shl (5 - bits)) and 0x1F])
        }
        return out.toString()
    }

    fun encode(s: String): String = encode(s.toByteArray(Charsets.UTF_8))
}
