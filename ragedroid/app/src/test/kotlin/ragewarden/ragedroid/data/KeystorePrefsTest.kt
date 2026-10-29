package ragewarden.ragedroid.data

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class KeystorePrefsTest {
    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        KeystorePrefs.keySourceOverride = JcaKeys
        context.getSharedPreferences("kp.test", Context.MODE_PRIVATE).edit().clear().commit()
    }

    @Test
    fun pref_names_do_not_reveal_account_ids_and_legacy_names_migrate() {
        val raw = context.getSharedPreferences("kp.test", Context.MODE_PRIVATE)
        val prefs = KeystorePrefs(context, "kp.test", "kp.alias.a")
        prefs.putString("recipients:acct-123", "v1")
        assertTrue(raw.all.keys.none { "acct-123" in it })
        assertEquals("v1", prefs.getString("recipients:acct-123", null))

        val legacyValue = raw.getString(prefs.storedName("recipients:acct-123"), null)
        raw.edit().clear().putString("recipients:acct-456", legacyValue).commit()
        assertEquals("v1", prefs.getString("recipients:acct-456", null))
        assertNull(raw.getString("recipients:acct-456", null))
    }

    @Test
    fun a_value_the_key_cannot_open_is_reported_not_read_as_empty() {
        KeystorePrefs(context, "kp.test", "kp.alias.b").putString("k", "secret")
        JcaKeys.forget("kp.alias.b")
        try {
            KeystorePrefs(context, "kp.test", "kp.alias.b").getString("k", null)
            fail("expected StoreUnreadableException")
        } catch (_: StoreUnreadableException) {
        }
    }

    @Test
    fun an_unreadable_recipient_list_is_flagged_and_never_silently_overwritten() {
        val store = RecipientStore(context)
        val account = "acct-unreadable"
        KeystorePrefs(context, "ragewarden.recipients.v2", "ragewarden.recipients.aead.v1").putString("recipients:$account", "[]")
        JcaKeys.forget("ragewarden.recipients.aead.v1")
        assertEquals(emptyList<StoredRecipient>(), store.forAccount(account))
        assertTrue(store.isUnreadable(account))
        try {
            runBlocking { store.add(account, sampleRecipient()) }
            fail("expected StoreUnreadableException")
        } catch (_: StoreUnreadableException) {
        }
        store.resetUnreadable(account)
        assertFalse(store.isUnreadable(account))
    }

    private fun sampleRecipient() = StoredRecipient(
        id = "r1", kind = ragewarden.ragedroid.model.RecipientKind.StrongBox, displayName = "d",
        createdAt = 0, lastUsedAt = 0, defaultEncrypt = true, keystorePubkey = ByteArray(32), keystoreHandle = "h",
    )
}
