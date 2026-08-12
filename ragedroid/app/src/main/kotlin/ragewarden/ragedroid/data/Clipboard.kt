package ragewarden.ragedroid.data

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Context.CLIPBOARD_SERVICE
import android.os.Build
import android.os.PersistableBundle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class Clipboard(
    private val context: Context,
    private val scope: CoroutineScope,
    private val clearAfterMillis: Long = 30_000L,
    private val onSensitiveCopy: ((label: String) -> Unit)? = null,
) {
    private var pending: Job? = null

    fun copySensitive(plaintext: ByteArray, label: String) {
        val cm = context.getSystemService(CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val text = String(plaintext, Charsets.UTF_8)
        val clip = ClipData.newPlainText(label, text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean("android.content.extra.IS_SENSITIVE", true)
            }
        }
        cm.setPrimaryClip(clip)
        onSensitiveCopy?.invoke(label)
        pending?.cancel()
        pending = scope.launch {
            delay(clearAfterMillis)
            tryClear(cm, text)
        }
    }

    fun copyVisible(text: String, label: String) {
        val cm = context.getSystemService(CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
    }

    private fun tryClear(cm: ClipboardManager, expected: String) {
        val current = cm.primaryClip?.getItemAt(0)?.text?.toString()
        if (current == expected) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                cm.clearPrimaryClip()
            } else {
                cm.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        }
    }
}
