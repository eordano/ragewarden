package ragewarden.ragedroid.data

import ragewarden.ragedroid.identities.Base32NoPad
import ragewarden.ragedroid.identities.StanzaCrypto
import ragewarden.ragedroid.identities.StanzaTags
import ragewarden.ragedroid.identities.YubiKeyPivIdentity
import ragewarden.ragedroid.model.RecipientKind

/**
 * The Kotlin half of the recipient descriptors the JNI layer parses out of an
 * age header (`jni/src/lib.rs::rage_recipient_descriptors`).
 *
 * A descriptor is `"<stanza tag>:<identifying arg>"`, computed here from public
 * material we already hold for each enrolled recipient. It is how "which keys
 * can open this item" is answered without decrypting anything -- the previous
 * answer was the literal string `"software-demo"`, which matched no recipient
 * and made every protected item look un-openable.
 *
 * Every value below must byte-match what core writes:
 *  - `piv-p256` arg[1] is `STANDARD_NO_PAD(sha256(pubkey)[..4])`
 *    (`core/src/stanza_format.rs:87`, `:102`)
 *  - `ragedroid-keystore-v1` arg[0] is unpadded base32 of the key handle (`:335`)
 *  - `fido2-hmac` / `webauthn-prf-v1` arg[0] is `URL_SAFE_NO_PAD(credential_id)`
 *    (`:172`, `:245`)
 */
object RecipientDescriptors {

    /** Descriptors this stored recipient could satisfy. */
    fun forStored(r: StoredRecipient): List<String> = buildList {
        when (r.kind) {
            RecipientKind.YubiKey -> {
                val pub = r.pivPubkey
                if (pub != null && pub.size == 32) {
                    val tag = YubiKeyPivIdentity.expectedRecipientTag(pub)
                    add("${StanzaTags.PIV_P256}:${StanzaCrypto.b64StdEncode(tag)}")
                }
            }
            RecipientKind.StrongBox -> {
                val handle = r.keystoreHandle
                if (!handle.isNullOrBlank()) {
                    add("${StanzaTags.RAGEDROID_KEYSTORE_V1}:${Base32NoPad.encode(handle)}")
                }
            }
            RecipientKind.Fido2 -> {
                r.fido2CredentialId?.takeIf { it.isNotEmpty() }?.let {
                    add("${StanzaTags.FIDO2_HMAC}:${StanzaCrypto.b64UrlEncode(it)}")
                }
                r.passkeyCredentialId?.takeIf { it.isNotEmpty() }?.let {
                    add("${StanzaTags.WEBAUTHN_PRF_V1}:${StanzaCrypto.b64UrlEncode(it)}")
                }
            }
            // A `PasskeyPrf` recipient is wrapped under `webauthn-prf-v1` only
            // -- that is the whole reason core keeps the kind apart from Fido2
            // (different stanza tag, different HKDF info). The credential id
            // may sit in either column depending on which client enrolled it.
            RecipientKind.PasskeyPrf -> {
                (r.passkeyCredentialId ?: r.fido2CredentialId)?.takeIf { it.isNotEmpty() }?.let {
                    add("${StanzaTags.WEBAUTHN_PRF_V1}:${StanzaCrypto.b64UrlEncode(it)}")
                }
            }
            // An age X25519 stanza's only arg is the *ephemeral* share, so a
            // software or paper recipient is not identifiable from the header at
            // all. These recipients therefore match nothing, by construction --
            // which is the truthful outcome, not a gap to paper over.
            RecipientKind.Recovery, RecipientKind.Software -> Unit
        }
    }

    data class Resolution(
        /** Enrolled recipients that provably appear in the blob header. */
        val matched: List<StoredRecipient>,
        /**
         * Number of `X25519`/`scrypt` stanzas: software or paper recipients that
         * can open the item but cannot be named from the header.
         */
        val anonymousSoftwareCount: Int,
        /** Hardware descriptors present in the blob that no local recipient matches. */
        val unknownHardware: List<String>,
    )

    fun resolve(
        descriptors: List<String>,
        stored: List<StoredRecipient>,
    ): Resolution {
        val byDescriptor = mutableMapOf<String, StoredRecipient>()
        stored.forEach { r -> forStored(r).forEach { byDescriptor.putIfAbsent(it, r) } }

        val matched = LinkedHashMap<String, StoredRecipient>()
        var anonymous = 0
        val unknown = mutableListOf<String>()
        for (d in descriptors) {
            if (d == StanzaTags.X25519 || d == StanzaTags.SCRYPT) {
                anonymous += 1
                continue
            }
            val hit = byDescriptor[d]
            if (hit != null) matched[hit.id] = hit else unknown += d
        }
        return Resolution(
            matched = matched.values.toList(),
            anonymousSoftwareCount = anonymous,
            unknownHardware = unknown,
        )
    }
}
