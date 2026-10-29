package ragewarden.ragedroid.data

import android.content.Context

/**
 * The KDF parameters each (server, email) last signed in with, kept apart from
 * the session so they outlive sign-out. Every login hands them to core, which
 * refuses a server that now offers weaker ones -- a server cannot lower the
 * work factor on a later sign-in just because the user signed out in between.
 */
class KdfPinStore(context: Context) {
    private val prefs = KeystorePrefs(
        context = context.applicationContext,
        prefsName = "ragewarden.kdfpins.v1",
        keyAlias = "ragewarden.kdfpins.aead.v1",
    )

    fun get(server: String, email: String): String? =
        runCatching { prefs.getString(key(server, email), null) }.getOrNull()

    fun put(server: String, email: String, pinJson: String) {
        prefs.putString(key(server, email), pinJson)
    }

    private fun key(server: String, email: String): String =
        "pin:" + server.trim().trimEnd('/').lowercase() + "|" + email.trim().lowercase()
}
