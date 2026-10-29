package ragewarden.ragedroid.data

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import java.time.Duration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf

@RunWith(RobolectricTestRunner::class)
class ClipboardTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    private fun current(): String? = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()

    @Test
    fun sensitive_copy_is_cleared_after_the_window_even_when_its_creator_is_gone() {
        // On a device setPrimaryClip parcels the text to the clipboard service;
        // Robolectric keeps the ClipData object, so read what the service would
        // have received at the moment of the copy.
        val delivered = mutableListOf<String>()
        val listener = android.content.ClipboardManager.OnPrimaryClipChangedListener { delivered += current().orEmpty() }
        cm.addPrimaryClipChangedListener(listener)
        Clipboard(context, clearAfterMillis = 30_000L).copySensitive("hunter2".toByteArray(), "password")
        cm.removePrimaryClipChangedListener(listener)
        assertEquals("hunter2", delivered.first())
        assertTrue("this process keeps no readable copy after the copy returns", current().orEmpty().all { it == '\u0000' })
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(31))
        assertFalse(cm.hasPrimaryClip())
    }

    @Test
    fun a_foreign_clip_copied_in_between_is_left_alone() {
        Clipboard(context, clearAfterMillis = 30_000L).copySensitive("hunter2".toByteArray(), "password")
        cm.setPrimaryClip(ClipData.newPlainText("note", "shopping list"))
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(31))
        assertEquals("shopping list", current())
    }
}
