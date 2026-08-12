package ragewarden.ragedroid.data

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import ragewarden.ragedroid.model.RecipientKind

@RunWith(AndroidJUnit4::class)
class RecipientStoreInstrumentedTest {

    private lateinit var ctx: Context
    private lateinit var store: RecipientStore

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        ctx.getSharedPreferences("ragewarden.recipients.v2", Context.MODE_PRIVATE)
            .edit().clear().commit()
        store = RecipientStore(ctx)
    }

    @After
    fun tearDown() {
        ctx.getSharedPreferences("ragewarden.recipients.v2", Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    @Test
    fun add_and_round_trip_returns_same_recipient() = runBlocking {
        val rec = StoredRecipient(
            id = "r1",
            kind = RecipientKind.StrongBox,
            displayName = "This phone",
            createdAt = 1_700_000_000_000L,
            lastUsedAt = 0L,
            keystorePubkey = ByteArray(33) { it.toByte() },
            keystoreHandle = "keystore-handle:r1",
        )

        store.add("acct-A", rec)
        val loaded = store.forAccount("acct-A").single()
        assertEquals(rec.id, loaded.id)
        assertEquals(rec.kind, loaded.kind)
        assertEquals(rec.displayName, loaded.displayName)
        assertEquals(33, loaded.keystorePubkey?.size)
        assertEquals("keystore-handle:r1", loaded.keystoreHandle)
    }

    @Test
    fun account_isolation_reads_only_named_account() = runBlocking {
        val a = StoredRecipient(
            id = "r-a", kind = RecipientKind.YubiKey, displayName = "Yubi A",
            createdAt = 0L, lastUsedAt = 0L,
            pivPubkey = ByteArray(32), pivSerial = 1, pivSlot = 0x82.toByte(),
        )
        val b = StoredRecipient(
            id = "r-b", kind = RecipientKind.YubiKey, displayName = "Yubi B",
            createdAt = 0L, lastUsedAt = 0L,
            pivPubkey = ByteArray(32), pivSerial = 2, pivSlot = 0x82.toByte(),
        )
        store.add("acct-A", a)
        store.add("acct-B", b)
        assertEquals(setOf("r-a"), store.forAccount("acct-A").map { it.id }.toSet())
        assertEquals(setOf("r-b"), store.forAccount("acct-B").map { it.id }.toSet())
    }

    @Test
    fun remove_clears_specific_recipient() = runBlocking {
        val first = StoredRecipient(
            id = "r1", kind = RecipientKind.Recovery, displayName = "Paper",
            createdAt = 0L, lastUsedAt = 0L,
            recoveryArmoredPubkey = "age1placeholder",
        )
        val second = first.copy(id = "r2", displayName = "Paper 2")
        store.add("acct-A", first)
        store.add("acct-A", second)
        store.remove("acct-A", "r1")
        val ids = store.forAccount("acct-A").map { it.id }.toSet()
        assertEquals(setOf("r2"), ids)
    }

    @Test
    fun set_default_encrypt_persists() = runBlocking {
        val rec = StoredRecipient(
            id = "r1", kind = RecipientKind.StrongBox, displayName = "This phone",
            createdAt = 0L, lastUsedAt = 0L, defaultEncrypt = true,
            keystorePubkey = ByteArray(33),
            keystoreHandle = "h1",
        )
        store.add("acct-A", rec)
        store.setDefaultEncrypt("acct-A", "r1", false)
        assertEquals(false, store.forAccount("acct-A").single().defaultEncrypt)
        store.setDefaultEncrypt("acct-A", "r1", true)
        assertEquals(true, store.forAccount("acct-A").single().defaultEncrypt)
    }

    @Test
    fun clear_account_wipes_only_that_account() = runBlocking {
        val rec = StoredRecipient(
            id = "r1", kind = RecipientKind.StrongBox, displayName = "x",
            createdAt = 0L, lastUsedAt = 0L,
            keystorePubkey = ByteArray(33), keystoreHandle = "h",
        )
        store.add("acct-A", rec)
        store.add("acct-B", rec.copy(id = "r2"))
        store.clearAccount("acct-A")
        assertTrue(store.forAccount("acct-A").isEmpty())
        assertEquals(setOf("r2"), store.forAccount("acct-B").map { it.id }.toSet())
    }

    @Test
    fun stored_values_are_not_plaintext_in_prefs() {
        val rec = StoredRecipient(
            id = "r1", kind = RecipientKind.StrongBox,
            displayName = "marker-display-name",
            createdAt = 0L, lastUsedAt = 0L,
            keystorePubkey = ByteArray(33),
            keystoreHandle = "marker-handle",
        )
        runBlocking { store.add("acct-A", rec) }
        val raw = ctx.getSharedPreferences("ragewarden.recipients.v2", Context.MODE_PRIVATE)
            .getString("recipients:acct-A", null)
        assertNotNull(raw)
        assertTrue(
            "raw prefs payload should not contain plaintext marker",
            raw!!.contains("marker-display-name").not(),
        )
        assertTrue(
            "raw prefs payload should not contain plaintext handle marker",
            raw.contains("marker-handle").not(),
        )
    }

    @Test
    fun missing_account_returns_empty_list() {
        assertEquals(emptyList<StoredRecipient>(), store.forAccount("never-seen"))
    }

    @Test
    fun add_with_blank_account_is_a_no_op() = runBlocking {
        val rec = StoredRecipient(
            id = "r1", kind = RecipientKind.Software, displayName = "blank",
            createdAt = 0L, lastUsedAt = 0L,
        )
        store.add("", rec)
        assertNull(store.forAccount("real-acct").firstOrNull())
    }
}
