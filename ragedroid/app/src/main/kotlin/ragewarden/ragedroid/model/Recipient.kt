package ragewarden.ragedroid.model

import androidx.compose.runtime.Immutable
import kotlinx.serialization.Serializable

@Immutable
data class Recipient(
    val id: String,
    val kind: RecipientKind,
    val name: String,
    val serial: String,
    val fingerprint: String,
    val enrolled: String,
    val lastUsed: String,
    val slot: String? = null,
    val firmware: String? = null,
    val coverage: Int? = null,
    /**
     * Stanza descriptors this recipient can satisfy, matched against the ones
     * the JNI layer parses out of an item's age header. See
     * `data/RecipientDescriptors.kt`.
     */
    val descriptors: List<String> = emptyList(),
    /** Simulated hardware. Debug builds only; always rendered as such. */
    val isMock: Boolean = false,
)

/**
 * Must stay name-for-name in step with `registry::kinds` in
 * `core/src/registry.rs` -- the enum name is what goes on the wire, and the
 * registry is read by rageterm and ragemanifest too.
 *
 * [PasskeyPrf] is deliberately distinct from [Fido2]: the two wrap into
 * *different stanza tags* (`webauthn-prf-v1` vs `fido2-hmac`) with different
 * HKDF info strings, so a passkey published as `Fido2` comes back as an
 * hmac-secret recipient and gets wrapped into a stanza its own authenticator
 * will not unwrap. Core has carried the distinction since `kinds::PASSKEY_PRF`;
 * this side collapsing it was how the two disagreed.
 */
@Serializable
enum class RecipientKind { YubiKey, Fido2, PasskeyPrf, StrongBox, Recovery, Software }
