package ragewarden.ragedroid.ui

import android.content.Context
import android.os.Looper
import androidx.fragment.app.FragmentActivity
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import ragewarden.ragedroid.data.JcaKeys
import ragewarden.ragedroid.data.KeystorePrefs
import ragewarden.ragedroid.data.RecipientStore
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.data.audit.AuditFeed
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.ui.screens.AddRecipientAction
import ragewarden.ragedroid.ui.screens.AddRecipientViewModel
import ragewarden.ragedroid.ui.screens.EnrollKind

/** HW-01: no Keystore key without user authentication is generated before the user agrees to it. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class UnboundKeyConsentTest {
    private val context: Context get() = ApplicationProvider.getApplicationContext()
    private val calls = mutableListOf<Triple<String, Boolean, Boolean>>()

    @Before fun keys() { KeystorePrefs.keySourceOverride = JcaKeys }
    @After fun reset() { KeystorePrefs.keySourceOverride = null }

    private fun vm(bindable: Boolean) = AddRecipientViewModel(RecipientStore(context), AuditFeed(context), context).apply {
        authBindable = { bindable }
        keystoreEnroll = { name, strongBox, biometric ->
            calls += Triple(name, strongBox, biometric)
            StoredRecipient(id = "k", kind = RecipientKind.StrongBox, displayName = name, createdAt = 0L, lastUsedAt = 0L)
        }
    }

    private val activity: FragmentActivity get() = Robolectric.buildActivity(FragmentActivity::class.java).setup().get()

    private fun idle() = shadowOf(Looper.getMainLooper()).idle()

    @Test
    fun without_a_screen_lock_nothing_is_generated_until_the_user_agrees() {
        val vm = vm(bindable = false)
        vm.onAction(AddRecipientAction.PickKind(EnrollKind.StrongBox, activity))
        idle()
        assertTrue(vm.state.value.unboundKeyConsentOpen)
        assertEquals(emptyList<Triple<String, Boolean, Boolean>>(), calls)

        vm.onAction(AddRecipientAction.ConfirmUnboundKey)
        idle()
        assertFalse(vm.state.value.unboundKeyConsentOpen)
        assertEquals(1, calls.size)
        assertEquals("This phone (no confirmation)", calls.single().first)
        assertFalse("not bound to user authentication", calls.single().third)
    }

    @Test
    fun choosing_to_set_a_screen_lock_generates_nothing() {
        val vm = vm(bindable = false)
        vm.onAction(AddRecipientAction.PickKind(EnrollKind.StrongBox, activity))
        vm.onAction(AddRecipientAction.DeclineUnboundKey)
        idle()
        assertFalse(vm.state.value.unboundKeyConsentOpen)
        assertEquals(emptyList<Triple<String, Boolean, Boolean>>(), calls)
    }

    @Test
    fun with_a_screen_lock_the_key_is_bound_and_no_question_is_asked() {
        val vm = vm(bindable = true)
        vm.onAction(AddRecipientAction.PickKind(EnrollKind.StrongBox, activity))
        idle()
        assertFalse(vm.state.value.unboundKeyConsentOpen)
        assertTrue(calls.single().third)
    }
}
