package ragewarden.ragedroid.identities

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * HW-02: from API 35 an auth-bound Keystore key asks on every use (its own
 * prompt, with the KeyAgreement as CryptoObject); below 35 it keeps the
 * 30-second window opened by the coordinator's prompt.
 */
@RunWith(RobolectricTestRunner::class)
class KeystorePerUseTest {
    private fun identity(perUse: Boolean) = AndroidKeystoreIdentity(
        mockKey = null, expectedPublicKey = ByteArray(33), keyHandle = "h", authBound = true, perUse = perUse,
    )

    @Test
    @Config(sdk = [35])
    fun api_35_enrols_per_use_keys() {
        assertTrue(keystorePerUse())
    }

    @Test
    @Config(sdk = [34])
    fun below_35_the_30_second_window_remains() {
        assertFalse(keystorePerUse())
    }

    @Test
    @Config(sdk = [35])
    fun a_per_use_key_brings_its_own_prompt_so_the_coordinator_asks_nothing_up_front() {
        assertFalse(IdentitySet(listOf(identity(perUse = true)), emptyList()).biometricRequired)
        assertTrue(IdentitySet(listOf(identity(perUse = false)), emptyList()).biometricRequired)
        assertTrue("still a deliberate action", identity(perUse = true).requiresPhysicalPresence)
    }
}
