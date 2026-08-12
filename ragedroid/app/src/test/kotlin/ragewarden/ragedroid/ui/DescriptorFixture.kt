package ragewarden.ragedroid.ui

import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.toImmutableList
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import ragewarden.ragedroid.data.RecipientDescriptors
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.data.toUiRecipient
import ragewarden.ragedroid.identities.StanzaTags
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.model.VaultItem
import java.util.UUID

/**
 * One enrolled recipient, held in the two shapes the app actually deals in.
 *
 * The whole point of this fixture is that neither shape is hand-written:
 *
 *  - [ui] comes out of [toUiRecipient], the same mapper `RecipientStore` uses,
 *    so `Recipient.id` is whatever the enrolment minted (a UUID) and
 *    `Recipient.descriptors` is whatever `RecipientDescriptors.forStored`
 *    computes.
 *  - [descriptors] comes out of `RecipientDescriptors.forStored`, whose output
 *    is pinned byte-for-byte against the Rust producer by
 *    `data/RecipientDescriptorsTest.kt`.
 *
 * A hand-written descriptor literal here would be worth nothing: the last
 * conformance test in this repo asserted an input its producer could never
 * emit, and stayed green for it. Anything a screen is asked to match must have
 * been produced by the code that produces it in the app.
 */
class Enrolled(val stored: StoredRecipient) {

    /** What `LocalLiveRecipients` carries: id is a UUID, descriptors are stanza tags. */
    val ui: Recipient = stored.toUiRecipient()

    /** What an age header of an item wrapped to this recipient carries. */
    val descriptors: List<String> = RecipientDescriptors.forStored(stored)

    val descriptor: String get() = descriptors.single()

    val name: String get() = ui.name

    init {
        // A recipient with no descriptor cannot be matched from a header at all
        // and would make every assertion below vacuous. Software/paper keys are
        // built by [DescriptorFixture.software], which does not come through
        // here expecting a descriptor.
        require(stored.kind == RecipientKind.Software || stored.kind == RecipientKind.Recovery ||
            descriptors.isNotEmpty()) {
            "fixture recipient ${stored.kind} produced no descriptor; it cannot exercise anything"
        }
    }
}

object DescriptorFixture {

    fun yubiKey(name: String, keyByte: Int): Enrolled = Enrolled(
        StoredRecipient(
            id = UUID.randomUUID().toString(),
            kind = RecipientKind.YubiKey,
            displayName = name,
            createdAt = 0L,
            lastUsedAt = 0L,
            pivPubkey = ByteArray(32) { keyByte.toByte() },
            pivSerial = 13371337,
        ),
    )

    fun strongBox(name: String, handle: String): Enrolled = Enrolled(
        StoredRecipient(
            id = UUID.randomUUID().toString(),
            kind = RecipientKind.StrongBox,
            displayName = name,
            createdAt = 0L,
            lastUsedAt = 0L,
            keystoreHandle = handle,
            keystorePubkey = ByteArray(33).also { it[0] = 0x02 },
        ),
    )

    /**
     * A software key: a real recipient that an age header genuinely cannot
     * name, so [Enrolled.descriptors] is empty by construction. Used to pin the
     * "coverage is unknowable, not zero" branch apart from "coverage is zero".
     */
    fun software(name: String): Enrolled = Enrolled(
        StoredRecipient(
            id = UUID.randomUUID().toString(),
            kind = RecipientKind.Software,
            displayName = name,
            createdAt = 0L,
            lastUsedAt = 0L,
        ),
    )

    /**
     * An item whose age header names [wrappedTo] -- i.e. `recipients` holds
     * stanza descriptors, never recipient ids. That is the mismatch the four
     * screens under test used to get wrong.
     *
     * [anonymous] adds bare `X25519` stanzas: software/paper recipients that
     * are wrapped in but unnameable.
     */
    fun protectedItem(
        name: String,
        folder: String = "Work",
        wrappedTo: List<Enrolled> = emptyList(),
        anonymous: Int = 0,
    ): VaultItem = VaultItem(
        id = "item-${name.lowercase().replace(' ', '-')}",
        name = name,
        username = "maya@feldspar.fm",
        site = "${name.lowercase().replace(' ', '-')}.example",
        folder = folder,
        rage = true,
        recipients = (
            wrappedTo.flatMap { it.descriptors } + List(anonymous) { StanzaTags.X25519 }
            ).toImmutableList(),
        password = "********",
        lastUsed = "5m ago",
        history = 0,
    )

    /** An unprotected item: never counted, never listed, whatever is enrolled. */
    fun plainItem(name: String, folder: String = "Personal"): VaultItem = VaultItem(
        id = "item-${name.lowercase().replace(' ', '-')}",
        name = name,
        username = "maya@personal.example",
        site = "${name.lowercase().replace(' ', '-')}.example",
        folder = folder,
        rage = false,
        recipients = emptyList<String>().toImmutableList(),
        password = "p@ssw0rd",
        lastUsed = "Last week",
        history = 0,
    )

    fun live(vararg enrolled: Enrolled): ImmutableList<Recipient> =
        enrolled.map { it.ui }.toImmutableList()

    fun items(vararg items: VaultItem): ImmutableList<VaultItem> = items.toList().toImmutableList()

    /**
     * The precondition every test in this lane rests on: the id namespace and
     * the descriptor namespace are disjoint, so a screen that compares one
     * against the other can only ever produce an empty result.
     *
     * Asserted rather than assumed. If a future `toUiRecipient` started putting
     * the descriptor in `id` -- or an enrolment started minting descriptor-shaped
     * ids -- every "non-empty" assertion in this lane would pass for the wrong
     * reason, and this is the only place that would notice.
     */
    fun assertNamespacesAreDisjoint(items: List<VaultItem>, live: List<Enrolled>) {
        val ids = live.map { it.ui.id }.toSet()
        val descriptors = items.flatMap { it.recipients }.toSet()
        assertEquals(
            "recipient ids and stanza descriptors must not intersect, or these tests prove nothing",
            emptySet<String>(),
            ids intersect descriptors,
        )
        live.forEach { e ->
            assertTrue(
                "recipient id ${e.ui.id} is not a UUID; the id/descriptor mismatch is the bug",
                UUID_RE.matches(e.ui.id),
            )
        }
    }

    /** The shape `UUID.randomUUID()` mints, which is what enrolment stores. */
    private val UUID_RE =
        Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
}
