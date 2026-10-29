package ragewarden.ragedroid.data

import ragewarden.ragedroid.data.audit.AuditAction
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Context.CLIPBOARD_SERVICE
import android.os.Build
import android.os.PersistableBundle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** One audited copy: which item, which of its fields, under which action. */
data class SensitiveCopy(val item: String, val field: String, val action: AuditAction)

/**
 * [onSensitiveCopy] records an audited copy and may return a callback that runs
 * once the secret has left the clipboard (cleared by us, or replaced).
 */
class Clipboard(
    private val context: Context,
    private val clearAfterMillis: Long = 30_000L,
    private val onSensitiveCopy: ((SensitiveCopy) -> (() -> Unit)?)? = null,
) {
    fun copySensitive(plaintext: ByteArray, label: String, audit: AuditAction? = AuditAction.Copy, item: String = label) {
        val cm = context.getSystemService(CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val onGone = if (audit != null) onSensitiveCopy?.invoke(SensitiveCopy(item, label, audit)) else null
        // setPrimaryClip parcels the text before it returns; the characters are
        // zeroed right after, so no copy of the secret outlives this call here.
        SecretText.withChars(plaintext) { text ->
            val clip = ClipData.newPlainText(label, text)
            val nonce = java.util.UUID.randomUUID().toString()
            clip.description.extras = PersistableBundle().apply {
                putBoolean(SensitiveClipClearer.MARKER, true)
                putString(SensitiveClipClearer.NONCE, nonce)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    putBoolean("android.content.extra.IS_SENSITIVE", true)
                }
            }
            SensitiveClipClearer.schedule(cm, clip, nonce, clearAfterMillis, onGone)
        }
    }

    fun copyVisible(text: String, label: String) {
        val cm = context.getSystemService(CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        cm.setPrimaryClip(ClipData.newPlainText(label, text))
    }
}

object SensitiveClipClearer {
    const val MARKER = "ragewarden.ragedroid.SENSITIVE_CLIP"
    const val NONCE = "ragewarden.ragedroid.SENSITIVE_CLIP_NONCE"

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var pending: Job? = null
    private var expectedNonce: String? = null
    private var ownClipShowing = false
    private var selfChangesToIgnore = 0
    private var listening: ClipboardManager? = null
    private var onGone: (() -> Unit)? = null
    private val listener = ClipboardManager.OnPrimaryClipChangedListener {
        if (selfChangesToIgnore > 0) selfChangesToIgnore-- else ownClipShowing = false
    }

    @Synchronized
    fun schedule(cm: ClipboardManager, clip: ClipData, nonce: String, clearAfterMillis: Long, onGone: (() -> Unit)? = null) {
        takeOnGone()?.invoke()
        this.onGone = onGone
        if (listening !== cm) {
            listening?.removePrimaryClipChangedListener(listener)
            cm.addPrimaryClipChangedListener(listener)
            listening = cm
        }
        expectedNonce = nonce
        selfChangesToIgnore++
        cm.setPrimaryClip(clip)
        ownClipShowing = true
        pending?.cancel()
        pending = scope.launch {
            delay(clearAfterMillis)
            clearIfOurs(cm)
        }
    }

    @Synchronized
    fun clearIfOurs(cm: ClipboardManager) {
        pending = null
        val gone = takeOnGone()
        val expected = expectedNonce
        expectedNonce = null
        // The description alone: reading the clip's text back would bring the
        // secret into this process again just to compare it.
        val current = runCatching { cm.primaryClipDescription }.getOrNull()
        val ours = when {
            current != null && expected != null -> current.extras?.getString(NONCE) == expected
            current != null -> current.extras?.getBoolean(MARKER) == true
            else -> ownClipShowing
        }
        ownClipShowing = false
        if (ours) {
            selfChangesToIgnore++
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) cm.clearPrimaryClip() else cm.setPrimaryClip(ClipData.newPlainText("", ""))
        }
        gone?.invoke()
    }

    private fun takeOnGone(): (() -> Unit)? = onGone.also { onGone = null }

    fun clearLeftoverOnStart(context: Context) {
        val cm = context.getSystemService(CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val description = runCatching { cm.primaryClipDescription }.getOrNull() ?: return
        if (description.extras?.getBoolean(MARKER) == true) clearIfOurs(cm)
    }
}
