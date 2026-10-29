package ragewarden.ragedroid.data

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class KdfPinStoreTest {
    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private val pin = """{"kdf":0,"iterations":600000}"""

    @Before fun keys() { KeystorePrefs.keySourceOverride = JcaKeys }
    @After fun reset() { KeystorePrefs.keySourceOverride = null }

    @Test
    fun a_pin_is_per_server_and_email_and_survives_a_new_instance() {
        KdfPinStore(context).put("https://Vault.example/", "Me@Example.com", pin)
        val again = KdfPinStore(context)
        assertEquals(pin, again.get("https://vault.example", "me@example.com"))
        assertNull(again.get("https://vault.example", "someone@example.com"))
        assertNull(again.get("https://other.example", "me@example.com"))
    }

    @Test
    fun a_kdf_pin_outlives_logout() {
        val pins = KdfPinStore(context)
        pins.put("https://vault.example", "me@example.com", pin)
        val recipientStore = RecipientStore(context)
        val repo = BitwardenVaultRepository(
            sessionStore = SessionStore(context),
            recipientStore = recipientStore,
            auditFeed = ragewarden.ragedroid.data.audit.AuditFeed(context),
            rotationTracker = RotationTracker(context, recipientStore),
            historyStore = HistoryStore(context),
            recipientRegistry = RecipientRegistry(recipientStore),
            lockState = LockState(context, LockPolicy(context), hasSession = { false }),
            vaultCache = VaultCache(context),
            deviceIdentity = DeviceIdentity(context),
            kdfPins = pins,
        )
        repo.logout()
        assertEquals(pin, KdfPinStore(context).get("https://vault.example", "me@example.com"))
    }
}
