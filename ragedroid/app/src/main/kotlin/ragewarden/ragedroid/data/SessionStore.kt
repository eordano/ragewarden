package ragewarden.ragedroid.data

import android.content.Context
import android.util.Base64
import android.util.Log

/**
 * On-disk home of the Bitwarden session blob.
 *
 * The blob is `SessionDto` (`jni/src/sync_jni.rs`): it carries
 * `user_enc_key_b64` and `user_mac_key_b64` -- the user symmetric key pair
 * derived from the master password -- plus the access and refresh tokens. It is
 * the outer layer of the whole vault, so it is the *most* sensitive thing this
 * app persists.
 *
 * It used to be written as base64 into a plain
 * `getSharedPreferences(MODE_PRIVATE)` file
 * (`/data/data/<pkg>/shared_prefs/ragedroid_session.xml`) while every less
 * sensitive store in the app -- recipients, audit feed, history, rotation state
 * -- already went through [KeystorePrefs]. It now goes through [KeystorePrefs]
 * too: AES-256-GCM under a non-exportable AndroidKeyStore key.
 *
 * [migrateLegacyCleartext] rewrites any pre-existing cleartext blob into the
 * encrypted store and then deletes the cleartext file. The delete happens even
 * if the encrypted write fails: the worst case is that the user signs in again,
 * which is recoverable, whereas leaving the key material readable on disk is
 * the defect being fixed.
 */
class SessionStore(context: Context) {
    private val appContext = context.applicationContext

    private val prefs = KeystorePrefs(
        context = appContext,
        prefsName = PREFS_NAME,
        keyAlias = KEY_ALIAS,
    )

    init {
        migrateLegacyCleartext(appContext, prefs)
    }

    fun save(sessionBlob: ByteArray) {
        prefs.putString(KEY_SESSION_BLOB, Base64.encodeToString(sessionBlob, Base64.NO_WRAP))
    }

    fun load(): ByteArray? {
        val encoded = prefs.getString(KEY_SESSION_BLOB, null) ?: return null
        return runCatching { Base64.decode(encoded, Base64.NO_WRAP) }.getOrNull()
    }

    fun clear() {
        prefs.remove(KEY_SESSION_BLOB)
    }

    /**
     * True only when a session is present *and* still decryptable. A stored blob
     * whose Keystore key has been invalidated is reported as absent, because the
     * caller ([ragewarden.ragedroid.ui.RageApp]) uses this to decide "signed in",
     * and claiming a session it cannot read would strand the user on a locked
     * vault with no session behind it.
     */
    fun has(): Boolean = load() != null

    private companion object {
        const val PREFS_NAME = "ragewarden.session.v2"
        const val KEY_ALIAS = "ragewarden.session.aead.v1"
        const val KEY_SESSION_BLOB = "session_blob_v1"
        const val LEGACY_PREFS_NAME = "ragedroid_session"
        const val TAG = "SessionStore"

        fun migrateLegacyCleartext(context: Context, prefs: KeystorePrefs) {
            val legacy = context.getSharedPreferences(LEGACY_PREFS_NAME, Context.MODE_PRIVATE)
            if (legacy.all.isEmpty()) return
            val encoded = legacy.getString(KEY_SESSION_BLOB, null)
            if (encoded != null) {
                val rewritten = runCatching { prefs.putString(KEY_SESSION_BLOB, encoded) }
                    .getOrDefault(false)
                if (!rewritten) {
                    Log.w(TAG, "could not re-encrypt legacy session; dropping it, sign-in required")
                }
            }
            legacy.edit().clear().commit()
            context.deleteSharedPreferences(LEGACY_PREFS_NAME)
        }
    }
}
