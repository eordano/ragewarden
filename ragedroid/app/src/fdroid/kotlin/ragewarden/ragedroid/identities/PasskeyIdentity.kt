package ragewarden.ragedroid.identities

/**
 * F-Droid counterpart of the standard flavor's `PasskeyIdentity`. It exists only
 * so `PasskeyEnrollmentReal.enrollPasskeyWithPrf` has a return type to name; it
 * is uninstantiable by construction (private constructor, both factories throw)
 * and `IdentityResolver` never mentions it -- the flavor boundary is
 * `passkeyIdentityForUse`, which returns null here (`PasskeyAvailability.kt:15`)
 * so a `webauthn-prf-v1` recipient becomes a `SkippedRecipient` carrying
 * [passkeyUnavailableReason] rather than a silent failure.
 *
 * Consequently this class deliberately has **no** stanza parsing and no
 * [StanzaTags.isPrfArity] check: it never sees a stanza. The PRF wrap-salt
 * arity contract (3 legacy args / 4 current) is enforced in the two classes that
 * do parse stanzas -- `Fido2HmacIdentity` (shipped in both flavors, so F-Droid
 * decrypts current `fido2-hmac` blobs correctly) and the standard flavor's
 * `PasskeyIdentity`. Do not "fix" this file by adding an arity check; the
 * absence is the point.
 */
class PasskeyIdentity private constructor() : KotlinIdentity {
    override val displayLabel: String = "Passkey (unavailable in F-Droid build)"

    override suspend fun tryUnwrap(
        stanzaTag: String,
        stanzaArgs: Array<String>,
        stanzaBody: ByteArray,
    ): ByteArray? {
        error(
            "Credential Manager not available in F-Droid build; " +
                "use a YubiKey or AndroidKeystore identity instead.",
        )
    }

    companion object {
        fun enrollMock(rpId: String = "ragewarden"): PasskeyIdentity {
            error(
                "Credential Manager not available in F-Droid build; " +
                    "use a YubiKey or AndroidKeystore identity instead.",
            )
        }

        fun fromEnrollment(enrollment: PasskeyEnrollment): PasskeyIdentity {
            error(
                "Credential Manager not available in F-Droid build; " +
                    "use a YubiKey or AndroidKeystore identity instead.",
            )
        }
    }
}
