package ragewarden.ragedroid.data

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import java.time.Duration
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import ragewarden.ragedroid.data.audit.AuditAction
import ragewarden.ragedroid.data.audit.AuditFeed

/** A copy is audited under the item's name, and "cleared" only once the secret has left the clipboard. */
@RunWith(RobolectricTestRunner::class)
class ClipboardAuditTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    @Before fun keys() { KeystorePrefs.keySourceOverride = JcaKeys }
    @After fun noKeys() { KeystorePrefs.keySourceOverride = null }

    @Test
    fun a_card_number_copy_names_the_item_and_the_field() {
        val copies = mutableListOf<SensitiveCopy>()
        Clipboard(context, onSensitiveCopy = { copies += it; null })
            .copySensitive("4111111111111111".toByteArray(), "card number", item = "Visa · personal")
        assertEquals(listOf(SensitiveCopy("Visa · personal", "card number", AuditAction.Copy)), copies)
    }

    @Test
    fun cleared_is_reported_when_the_window_clears_the_secret_not_at_copy_time() {
        var gone = 0
        Clipboard(context, clearAfterMillis = 30_000L, onSensitiveCopy = { { gone++ } })
            .copySensitive("hunter2".toByteArray(), "password", item = "Stripe")
        assertEquals(0, gone)
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(31))
        assertEquals(1, gone)
    }

    @Test
    fun a_secret_replaced_by_the_next_copy_counts_as_gone() {
        var firstGone = 0
        val clipboard = Clipboard(context, clearAfterMillis = 30_000L, onSensitiveCopy = { copy -> if (copy.item == "first") ({ firstGone++ }) else null })
        clipboard.copySensitive("one".toByteArray(), "password", item = "first")
        clipboard.copySensitive("two".toByteArray(), "password", item = "second")
        assertEquals(1, firstGone)
    }

    @Test
    fun a_foreign_clip_in_between_still_ends_the_copy() {
        var gone = 0
        Clipboard(context, clearAfterMillis = 30_000L, onSensitiveCopy = { { gone++ } })
            .copySensitive("hunter2".toByteArray(), "password", item = "Stripe")
        cm.setPrimaryClip(ClipData.newPlainText("note", "shopping list"))
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(31))
        assertEquals(1, gone)
    }

    @Test
    fun the_feed_marks_an_entry_cleared_after_the_fact() = runBlocking {
        val feed = AuditFeed(context)
        val id = feed.recordReturningId(action = AuditAction.Copy, item = "Stripe", reason = "password")
        assertFalse(feed.list().first { it.id == id }.cleared)
        feed.markCleared(id)
        val entry = feed.list().first { it.id == id }
        assertTrue(entry.cleared)
        assertEquals("Stripe", entry.item)
        assertEquals("password", entry.reason)
    }
}
