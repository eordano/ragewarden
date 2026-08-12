package ragewarden.ragedroid.data

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import java.security.KeyStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Pins the property that made this class a P0: the session blob -- which carries
 * `user_enc_key_b64` / `user_mac_key_b64`, i.e. the vault's outer key material --
 * must not be readable from `shared_prefs/ragedroid_session.xml`.
 *
 * The migration half runs without a working AndroidKeyStore, because the
 * cleartext file is dropped whether or not the re-encrypt succeeds. The
 * round-trip half needs a real Keystore provider and is skipped when the test
 * JVM has none.
 */
@RunWith(RobolectricTestRunner::class)
class SessionStoreMigrationTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    private val blob = "{\"userEncKeyB64\":\"AAAA\",\"accessToken\":\"secret\"}".toByteArray()

    private fun legacyPrefs() =
        context.getSharedPreferences(LEGACY_PREFS, Context.MODE_PRIVATE)

    private fun keystoreAvailable(): Boolean = runCatching {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }.isSuccess

    @Before
    fun clearLegacy() {
        legacyPrefs().edit().clear().commit()
        context.deleteSharedPreferences(LEGACY_PREFS)
    }

    @Test
    fun constructing_the_store_drops_the_cleartext_file() {
        legacyPrefs().edit()
            .putString(KEY_BLOB, Base64.encodeToString(blob, Base64.NO_WRAP))
            .commit()
        assertEquals(1, legacyPrefs().all.size)

        SessionStore(context)

        val after = context.getSharedPreferences(LEGACY_PREFS, Context.MODE_PRIVATE)
        assertNull(after.getString(KEY_BLOB, null))
        assertTrue("legacy cleartext prefs must be empty", after.all.isEmpty())
    }

    @Test
    fun migration_is_idempotent_and_survives_an_empty_legacy_file() {
        SessionStore(context)
        SessionStore(context)
        assertTrue(context.getSharedPreferences(LEGACY_PREFS, Context.MODE_PRIVATE).all.isEmpty())
    }

    @Test
    fun migrated_blob_is_readable_through_the_store_but_not_as_plaintext_on_disk() {
        assumeTrue("no AndroidKeyStore in this JVM", keystoreAvailable())
        val encoded = Base64.encodeToString(blob, Base64.NO_WRAP)
        legacyPrefs().edit().putString(KEY_BLOB, encoded).commit()

        val store = SessionStore(context)

        assertTrue(store.has())
        assertArrayEquals(blob, store.load())
        // Same key name, new file -- and the value there is ciphertext, not the
        // base64 the legacy file held.
        val onDisk = context.getSharedPreferences(NEW_PREFS, Context.MODE_PRIVATE)
            .getString(KEY_BLOB, null)
        assertFalse("stored value must not be the cleartext base64", encoded == onDisk)
    }

    @Test
    fun clear_removes_the_session() {
        assumeTrue("no AndroidKeyStore in this JVM", keystoreAvailable())
        val store = SessionStore(context)
        store.save(blob)
        assertTrue(store.has())

        store.clear()

        assertFalse(store.has())
        assertNull(store.load())
    }

    private companion object {
        const val LEGACY_PREFS = "ragedroid_session"
        const val NEW_PREFS = "ragewarden.session.v2"
        const val KEY_BLOB = "session_blob_v1"
    }
}
