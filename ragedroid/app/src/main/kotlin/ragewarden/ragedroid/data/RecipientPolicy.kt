package ragewarden.ragedroid.data

import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import ragewarden.ragedroid.jni.RageNative
import ragewarden.ragedroid.model.RecipientKind

/**
 * Kotlin's edge of the ONE canonical recipient-selection policy.
 *
 * The policy itself lives in `core/src/policy.rs` and is shared with rageterm
 * and ragemanifest; this file only projects Android's local storage onto the
 * registry wire shape the policy consumes and decodes what it returns. Before
 * this, each of the three clients decided the recipient set itself, in its own
 * language, and the three disagreed: ragedroid dropped `Software` entries
 * entirely (`RecipientKind.Software -> Unit`), so an item saved on the phone
 * was cryptographically unopenable by the terminal's or the browser's software
 * key -- silently, with the save reporting success.
 *
 * If you are about to add a `when` branch that decides whether a recipient is
 * included: don't. Change `core/src/policy.rs` so all three clients move
 * together, and extend `core/tests/recipient_policy_cross_client.rs`.
 */
object RecipientPolicy {

    /** `policy::SkipReason`, snake_case as serialized by serde. */
    object Reasons {
        const val DEFAULT_ENCRYPT_OFF = "default_encrypt_off"
        const val UNKNOWN_KIND = "unknown_kind"
        const val MALFORMED_KEY_MATERIAL = "malformed_key_material"

        /**
         * The one sanctioned per-client divergence: a PRF recipient whose
         * authenticator this client cannot reach during a wrap. Reported, never
         * silent -- the holder of that authenticator cannot open the item unless
         * another recipient of theirs is also in the set.
         */
        const val NO_LOCAL_AUTHENTICATOR = "no_local_authenticator"
    }

    @Serializable
    data class Skip(val id: String, val kind: String, val reason: String)

    @Serializable
    data class Selection(
        val recipients: List<WireRecipient> = emptyList(),
        val skipped: List<Skip> = emptyList(),
    ) {
        fun unreachableAuthenticators(): List<Skip> =
            skipped.filter { it.reason == Reasons.NO_LOCAL_AUTHENTICATOR }
    }

    private val docJson = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private val idListSerializer = ListSerializer(String.serializer())

    /**
     * A locally stored recipient rendered as a registry entry so it goes
     * through the same policy as the cross-device registry instead of being
     * appended on a separate code path.
     *
     * `passkey*` fields fall back onto the `fido2*` ones, matching how this app
     * has always wrapped Android passkeys -- as `fido2-hmac` stanzas. Do not
     * "fix" that here: it would change the stanza tag of already-written items.
     */
    /**
     * SPKI DER of a P-256 key the recipient's device signs with: a passkey's
     * credential key, or a P-256 PIV slot's own key (what rageterm publishes).
     */
    private fun StoredRecipient.attestationKey(): ByteArray? = when {
        kind == RecipientKind.PasskeyPrf -> passkeyPublicKeySpki
        kind == RecipientKind.YubiKey -> pivPubkey?.takeIf { it.size == 33 }
            ?.let { runCatching { ragewarden.ragedroid.identities.P256.spkiDer(it) }.getOrNull() }
        else -> null
    }

    fun StoredRecipient.toPolicyWire(deviceLabel: String): RecipientRegistry.WireEntry =
        RecipientRegistry.WireEntry(
            id = id,
            kind = kind.name,
            displayName = displayName,
            deviceLabel = deviceLabel,
            createdAt = createdAt,
            defaultEncrypt = defaultEncrypt,
            pivPubkey = pivPubkey?.let(::encodeHexLower),
            pivSerial = pivSerial,
            pivSlot = pivSlot?.toInt()?.and(0xFF),
            keystorePubkey = keystorePubkey?.let(::encodeHexLower),
            keystoreHandle = keystoreHandle,
            fido2CredentialId = (fido2CredentialId ?: passkeyCredentialId)?.let(::encodeHexLower),
            fido2RpId = fido2RpId ?: passkeyRpId,
            fido2Salt = (fido2Salt ?: passkeySalt)?.let(::encodeHexLower),
            recoveryArmoredPubkey = recoveryArmoredPubkey,
            stanzaVersion = if (kind == RecipientKind.StrongBox) 2 else null,
            attestationPublicKey = attestationKey()?.let { java.util.Base64.getEncoder().encodeToString(it) },
        )

    /**
     * Registry ids of the authenticators this device can evaluate a PRF on
     * during a wrap: the PRF-kind recipients enrolled here. Entries that only
     * arrived from the registry belong to some other device and are skipped
     * with [Reasons.NO_LOCAL_AUTHENTICATOR].
     */
    fun localPrfEntryIds(local: List<StoredRecipient>): List<String> =
        local.filter { it.kind == RecipientKind.Fido2 || it.kind == RecipientKind.PasskeyPrf }
            .map { it.id }

    fun select(
        registry: List<RecipientRegistry.WireEntry>,
        local: List<RecipientRegistry.WireEntry>,
        localPrfEntryIds: List<String>,
    ): Selection {
        val out = RageNative.selectEncryptRecipients(
            docJson.encodeToString(
                RecipientRegistry.WireDocument.serializer(),
                RecipientRegistry.WireDocument(schema = 1, entries = registry),
            ).toByteArray(Charsets.UTF_8),
            docJson.encodeToString(
                RecipientRegistry.WireDocument.serializer(),
                RecipientRegistry.WireDocument(schema = 1, entries = local),
            ).toByteArray(Charsets.UTF_8),
            docJson.encodeToString(idListSerializer, localPrfEntryIds)
                .toByteArray(Charsets.UTF_8),
        )
        return decodeSelection(String(out, Charsets.UTF_8))
    }

    /** Split out from [select] so it is exercisable without the native lib. */
    fun decodeSelection(json: String): Selection =
        WireJson.decodeFromString(Selection.serializer(), json)

    private fun encodeHexLower(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}
