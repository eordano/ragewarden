package ragewarden.ragedroid.data

import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toImmutableList
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import ragewarden.ragedroid.model.RecipientKind

/**
 * The cross-device recipient registry: one secure-note cipher, named
 * [RecipientRegistry.MARKER_NAME], holding every device's public recipient
 * material. Same document `core::registry` reads for rageterm and ragemanifest.
 *
 * This class only *reads and shapes* the document. Publishing it is
 * `BitwardenVaultRepository.pushRecipientRegistry`, which owns the sync that
 * has to happen first -- a push that builds its payload from a stale cache is
 * how the browser's entries were destroyed. There used to be a second,
 * caller-supplied-snapshot `pushToServer` here that could not sync at all and
 * did not merge remote entries; it had no callers and has been removed rather
 * than left as a second way to make the same mistake.
 */
@Singleton
class RecipientRegistry @Inject constructor(
    // Unused since `pushToServer`/`buildPayload` were removed -- the local list
    // now reaches the wire through `RecipientPolicy.toPolicyWire`, one shaping
    // function instead of two that drifted. Kept only because
    // ui/screens/RecipientsScreen.kt hand-builds `RecipientRegistry(store)`
    // instead of taking the injected singleton; drop it once that is fixed.
    @Suppress("unused") private val recipientStore: RecipientStore,
) {

    @Serializable
    data class WireEntry(
        val id: String,
        val kind: String,
        val displayName: String,
        val deviceLabel: String,
        val createdAt: Long,
        val defaultEncrypt: Boolean = true,
        val pivPubkey: String? = null,
        val pivSerial: Int? = null,
        val pivSlot: Int? = null,
        val keystorePubkey: String? = null,
        val keystoreHandle: String? = null,
        val fido2CredentialId: String? = null,
        val fido2RpId: String? = null,
        val fido2Salt: String? = null,
        val recoveryArmoredPubkey: String? = null,
        val stanzaVersion: Int? = null,
        val attestationPublicKey: String? = null,
    )

    @Serializable
    data class WireDocument(
        val schema: Int = 1,
        val entries: List<WireEntry>,
    )

    /**
     * Every cipher on the server carrying the registry marker name.
     *
     * There must be at most one. `core::registry::find_marker_cipher` takes
     * whichever the *server* returns first, so a vault holding two of them
     * hands different clients different registries -- see
     * [DuplicateRegistryMarkerException].
     */
    fun markerItems(snapshot: List<ragewarden.ragedroid.model.VaultItem>): List<ragewarden.ragedroid.model.VaultItem> =
        snapshot.filter { it.name == MARKER_NAME }

    /**
     * The published registry, or a thrown exception. Every path that is about
     * to *write* the registry, or to decide which recipients a secret is
     * wrapped to, must use this one -- never [extractFromSnapshot].
     *
     * A registry the browser considers corrupt used to read back here as an
     * empty list, and the next push then wrote that empty list over it: one
     * unparseable byte and every other device's key was gone. A marker we
     * cannot read is a marker we must not replace, so this refuses instead.
     */
    fun readEntries(snapshot: List<ragewarden.ragedroid.model.VaultItem>): ImmutableList<WireEntry> {
        val markers = markerItems(snapshot)
        if (markers.size > 1) throw DuplicateRegistryMarkerException(markers.size)
        val marker = markers.firstOrNull() ?: return persistentListOf()
        val notes = marker.notes
            ?: throw RegistryUnreadableException("the registry cipher has no notes field")
        return runCatching {
            val doc: WireDocument = JSON.decodeFromString(notes)
            doc.entries.toImmutableList()
        }.getOrElse { throw RegistryUnreadableException(it.message ?: it.toString()) }
    }

    /**
     * Display-only. Renders an unreadable registry as "nothing published"
     * because a recipients screen that throws is worse than one that is empty.
     * Do not reach for this on a write or a wrap: showing nothing is harmless,
     * *storing* nothing is what destroyed the browser's entries. Use
     * [readEntries] there.
     */
    fun extractFromSnapshot(snapshot: List<ragewarden.ragedroid.model.VaultItem>): ImmutableList<WireEntry> =
        runCatching { readEntries(snapshot) }.getOrElse { persistentListOf() }

    fun markerCipherId(snapshot: List<ragewarden.ragedroid.model.VaultItem>): String? =
        snapshot.firstOrNull { it.name == MARKER_NAME }?.id

    /**
     * A registry entry as this device would store it, or null when the wire
     * `kind` is one this build does not know.
     *
     * Unknown kinds used to land on [RecipientKind.Software], which is not a
     * weaker claim than "unknown" but a *different and stronger* one: it says
     * "this is an age X25519 key I can wrap to". Newer clients publish kinds
     * older ones have never heard of (`PasskeyPrf` was exactly that), and
     * mislabelling one as Software both misdraws it and invites wrapping to
     * key material of the wrong shape. Core reports these as
     * `policy::SkipReason::UnknownKind`; so do we, by refusing to guess.
     */
    fun WireEntry.toStored(): StoredRecipient? {
        val parsed = kindFromWire(kind) ?: return null
        return StoredRecipient(
            id = id,
            kind = parsed,
            displayName = "$displayName · $deviceLabel",
            createdAt = createdAt,
            lastUsedAt = 0L,
            defaultEncrypt = defaultEncrypt,
            pivPubkey = pivPubkey?.let { decodeHex(it) },
            pivSerial = pivSerial,
            pivSlot = pivSlot?.toByte(),
            keystorePubkey = keystorePubkey?.let { decodeHex(it) },
            keystoreHandle = keystoreHandle,
            fido2CredentialId = fido2CredentialId?.let { decodeHex(it) },
            fido2RpId = fido2RpId,
            fido2Salt = fido2Salt?.let { decodeHex(it) },
            recoveryArmoredPubkey = recoveryArmoredPubkey,
        )
    }

    companion object {
        const val MARKER_NAME: String = "__ragedroid_recipients_v1__"
        private val JSON = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    }
}

/**
 * Two (or more) `__ragedroid_recipients_v1__` ciphers exist on the server.
 *
 * Writing to either one leaves the other alive and every client picking
 * whichever the server lists first, so the push refuses instead of deepening
 * the split. Recovering means deleting the extra cipher -- the app cannot pick
 * a survivor on the user's behalf without silently discarding someone's key.
 */
class DuplicateRegistryMarkerException(val markerCount: Int) :
    RuntimeException(
        "$markerCount recipient-registry ciphers are on the server; refusing to " +
            "write to one of them. Delete the extra `${RecipientRegistry.MARKER_NAME}` " +
            "item, keeping the one that lists every device's recipients.",
    )

/** The registry cipher exists but its payload does not parse. */
class RegistryUnreadableException(detail: String) :
    RuntimeException(
        "The published recipient registry could not be read ($detail). Refusing " +
            "to overwrite it -- replacing it would drop every recipient it holds.",
    )

private fun kindFromWire(name: String): RecipientKind? =
    RecipientKind.entries.firstOrNull { it.name == name }

private fun decodeHex(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "hex string must have even length" }
    val out = ByteArray(hex.length / 2)
    for (i in out.indices) {
        out[i] = ((hex[i * 2].digitToInt(16) shl 4) or hex[i * 2 + 1].digitToInt(16)).toByte()
    }
    return out
}
