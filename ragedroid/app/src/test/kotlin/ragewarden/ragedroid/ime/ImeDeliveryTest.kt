package ragewarden.ragedroid.ime

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toPersistentList
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.data.Folder
import ragewarden.ragedroid.data.LockPolicy
import ragewarden.ragedroid.data.LockState
import ragewarden.ragedroid.data.VaultBackend
import ragewarden.ragedroid.identities.KotlinIdentity
import ragewarden.ragedroid.model.VaultItem

/**
 * The regression test for the defect this class exists to close:
 * `RagewardenInputMethodService` contained no reference to the vault lock at
 * all, and typed plaintext out of `VaultBridge`'s in-process cache -- which stays
 * populated while locked -- into whatever editor had focus.
 *
 * `commit` is the exact lambda the service supplies (`currentInputConnection.commitText`),
 * so "the IME refuses while locked" is expressible as "commit was never called".
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class ImeDeliveryTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private val plainItem = item(id = "plain", name = "Example login", rage = false)
    private val rageItem = item(id = "protected", name = "Bank", rage = true)
    private val session = ImeSession("com.example.bank", 42)

    private lateinit var backend: RecordingBackend

    @Before
    fun setUp() {
        context.deleteSharedPreferences("ragewarden.lockstate.v1")
        context.deleteSharedPreferences("ragewarden.lock.v1")
        backend = RecordingBackend(persistentListOf(plainItem, rageItem))
    }

    private fun lockState(locked: Boolean): LockState {
        val policy = LockPolicy(context).apply { lockOnLaunch = locked }
        return LockState(context, policy) { true }.also {
            if (!locked) it.unlock() else it.lock()
        }
    }

    private fun delivery(locked: Boolean) = ImeDelivery(lockState(locked), backend)

    @Test
    fun a_locked_vault_never_reaches_the_editor() {
        val committed = mutableListOf<String>()
        val outcome = runBlocking {
            delivery(locked = true).deliver(plainItem.id) { committed += it.toString() }
        }

        assertTrue("expected refusal, got $outcome", outcome is ImeDelivery.Outcome.Refused)
        assertEquals(
            ImeDelivery.LOCKED,
            (outcome as ImeDelivery.Outcome.Refused).reason,
        )
        assertEquals("nothing may be committed while locked", emptyList<String>(), committed)
        assertNull("a locked vault must not even be asked to decrypt", backend.decryptedId)
    }

    @Test
    fun a_locked_vault_lists_nothing() {
        val offer = delivery(locked = true).offer()

        assertTrue(offer.locked)
        assertEquals(emptyList<VaultItem>(), offer.deliverable)
        assertEquals(0, offer.protectedCount)
        assertFalse("a locked vault must not enumerate itself", backend.snapshotTaken)
    }

    @Test
    fun an_unlocked_vault_still_delivers_unprotected_items() {
        val committed = mutableListOf<String>()
        val outcome = runBlocking {
            delivery(locked = false).deliver(plainItem.id) { committed += it.toString() }
        }

        assertEquals(ImeDelivery.Outcome.Delivered, outcome)
        assertEquals(listOf(SECRET), committed)
    }

    @Test
    fun an_unlocked_vault_lists_protected_items_too() {
        val offer = delivery(locked = false).offer()

        assertFalse(offer.locked)
        assertEquals(listOf(plainItem, rageItem), offer.deliverable)
        assertEquals(1, offer.protectedCount)
    }

    @Test
    fun a_protected_item_is_never_decrypted_by_the_keyboard_itself() {
        val committed = mutableListOf<String>()
        val outcome = runBlocking {
            delivery(locked = false).deliver(rageItem.id, session) { committed += it.toString() }
        }

        assertEquals(ImeDelivery.Outcome.Refused(ImeDelivery.DECLINED), outcome)
        assertEquals(emptyList<String>(), committed)
        assertNull(backend.decryptedId)
    }

    @Test
    fun a_protected_item_is_typed_after_the_tap_into_the_same_field() {
        val broker = FakeBroker(returnsTo = session)
        val committed = mutableListOf<String>()
        val outcome = runBlocking {
            ImeDelivery(lockState(locked = false), backend, broker).deliver(rageItem.id, session) { committed += it.toString() }
        }

        assertEquals(ImeDelivery.Outcome.Delivered, outcome)
        assertEquals(listOf(SECRET), committed)
        assertEquals(listOf(rageItem.id to session), broker.asked)
        assertTrue("plaintext zeroed after commit", broker.handedOut!!.all { it == 0.toByte() })
        assertNull("the keyboard never decrypts a protected item itself", backend.decryptedId)
    }

    @Test
    fun a_protected_item_is_not_typed_into_a_different_field() {
        val broker = FakeBroker(returnsTo = ImeSession("other.app", 7))
        val committed = mutableListOf<String>()
        val outcome = runBlocking {
            ImeDelivery(lockState(locked = false), backend, broker).deliver(rageItem.id, session) { committed += it.toString() }
        }

        assertEquals(ImeDelivery.Outcome.Refused(ImeDelivery.FIELD_CHANGED), outcome)
        assertEquals(emptyList<String>(), committed)
        assertTrue(broker.handedOut!!.all { it == 0.toByte() })
    }

    @Test
    fun locking_during_the_tap_stops_the_commit() {
        val state = lockState(locked = false)
        val broker = FakeBroker(returnsTo = session, during = { state.lock() })
        val committed = mutableListOf<String>()
        val outcome = runBlocking {
            ImeDelivery(state, backend, broker).deliver(rageItem.id, session) { committed += it.toString() }
        }

        assertEquals(ImeDelivery.Outcome.Refused(ImeDelivery.LOCKED_MID_FLIGHT), outcome)
        assertEquals(emptyList<String>(), committed)
        assertTrue(broker.handedOut!!.all { it == 0.toByte() })
    }

    @Test
    fun a_protected_item_without_a_field_is_refused_before_the_tap() {
        val broker = FakeBroker(returnsTo = session)
        val outcome = runBlocking {
            ImeDelivery(lockState(locked = false), backend, broker).deliver(rageItem.id, null) { }
        }

        assertEquals(ImeDelivery.Outcome.Refused(ImeDelivery.NO_FIELD), outcome)
        assertEquals(emptyList<Pair<String, ImeSession>>(), broker.asked)
    }

    @Test
    fun a_stale_nonce_cannot_answer_a_new_request() {
        val (old, _) = ImeAuthChannel.open()
        ImeAuthChannel.close(old)
        val (fresh, result) = ImeAuthChannel.open()
        assertFalse(ImeAuthChannel.complete(old, byteArrayOf(1)))
        assertFalse(result.isCompleted)
        assertTrue(ImeAuthChannel.complete(fresh, byteArrayOf(2)))
        assertFalse("a nonce answers once", ImeAuthChannel.complete(fresh, byteArrayOf(3)))
    }

    private class FakeBroker(
        private val returnsTo: ImeSession,
        private val during: () -> Unit = {},
    ) : ImeAuthBroker {
        val asked = mutableListOf<Pair<String, ImeSession>>()
        var handedOut: ByteArray? = null

        override suspend fun authorize(item: VaultItem, session: ImeSession): ByteArray? {
            asked += item.id to session
            during()
            return SECRET.toByteArray(Charsets.UTF_8).also { handedOut = it }
        }

        override suspend fun awaitReturn(session: ImeSession): Boolean = returnsTo == session
    }

    @Test
    fun an_unknown_item_is_refused() {
        val committed = mutableListOf<String>()
        val outcome = runBlocking {
            delivery(locked = false).deliver("nope") { committed += it.toString() }
        }

        assertTrue(outcome is ImeDelivery.Outcome.Refused)
        assertEquals(emptyList<String>(), committed)
    }

    /**
     * The decrypt suspends and can wait on a network sync; "Lock now" in the
     * main Activity, or an ON_STOP lock, can land inside that window. A single
     * check on entry would let the plaintext through anyway.
     */
    @Test
    fun locking_during_the_decrypt_still_stops_the_commit() {
        val state = lockState(locked = false)
        backend.onDecrypt = { state.lock() }
        val committed = mutableListOf<String>()

        val outcome = runBlocking {
            ImeDelivery(state, backend).deliver(plainItem.id) { committed += it.toString() }
        }

        assertTrue(outcome is ImeDelivery.Outcome.Refused)
        assertEquals(
            ImeDelivery.LOCKED_MID_FLIGHT,
            (outcome as ImeDelivery.Outcome.Refused).reason,
        )
        assertEquals(emptyList<String>(), committed)
    }

    private companion object {
        const val SECRET = "correct-horse-battery-staple"

        fun item(id: String, name: String, rage: Boolean) = VaultItem(
            id = id,
            name = name,
            username = "user@example.com",
            site = "example.com",
            folder = "All",
            rage = rage,
            recipients = persistentListOf(),
            password = "",
            lastUsed = "now",
            history = 0,
        )
    }

    private class RecordingBackend(
        private val items: ImmutableList<VaultItem>,
    ) : VaultBackend {
        var snapshotTaken = false
            private set
        var decryptedId: String? = null
            private set
        var onDecrypt: (() -> Unit)? = null

        override fun snapshot(): ImmutableList<VaultItem> {
            snapshotTaken = true
            return items.toPersistentList()
        }

        override fun get(id: String): VaultItem? = items.firstOrNull { it.id == id }

        override suspend fun decrypt(itemId: String, identities: List<KotlinIdentity>, use: ragewarden.ragedroid.data.audit.AuditAction?): ByteArray {
            decryptedId = itemId
            onDecrypt?.invoke()
            return SECRET.toByteArray(Charsets.UTF_8)
        }

        override suspend fun update(item: VaultItem, plaintext: ByteArray?): VaultItem =
            throw UnsupportedOperationException()

        override suspend fun create(item: VaultItem, plaintext: ByteArray?): VaultItem =
            throw UnsupportedOperationException()

        override suspend fun delete(itemId: String) = throw UnsupportedOperationException()

        override suspend fun listFolders(): ImmutableList<Folder> =
            throw UnsupportedOperationException()

        override suspend fun createFolder(name: String): Folder =
            throw UnsupportedOperationException()

        override suspend fun updateFolder(folderId: String, name: String): Folder =
            throw UnsupportedOperationException()

        override suspend fun deleteFolder(folderId: String) = throw UnsupportedOperationException()
    }
}
