package ragewarden.ragedroid.identities

import org.junit.Assume.assumeTrue
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The mock fence has two independent conditions (see MockHardware.kt). Only the
 * runtime one is observable from a unit test -- unit tests run against the
 * `debug` variant, where `BuildConfig.MOCK_HARDWARE_ALLOWED` is `true` by
 * design. The compile-time half is enforced by
 * `app/build.gradle.kts` setting the field to `false` for `release` and
 * `benchmark`, and cannot be asserted from here.
 */
class MockHardwareFenceTest {

    @Test
    fun mock_is_off_unless_explicitly_requested() {
        assumeTrue("env RAGEWARDEN_MOCK_HARDWARE is set for this run", System.getenv(MockHardware.ENV_VAR) != "1")
        System.clearProperty(MockHardware.ENV_VAR)
        assertFalse(MockHardware.enabled())
    }

    @Test
    fun enroll_mock_refuses_when_the_fence_is_closed() {
        assumeTrue(System.getenv(MockHardware.ENV_VAR) != "1")
        System.clearProperty(MockHardware.ENV_VAR)
        val failures = listOf<() -> Any>(
            { AndroidKeystoreIdentity.enrollMock() },
            { Fido2HmacIdentity.enrollMock() },
        )
        failures.forEach { factory ->
            val threw = try {
                factory()
                false
            } catch (_: IllegalStateException) {
                true
            }
            assertTrue("mock factory must refuse when MockHardware.enabled() is false", threw)
        }
    }

    @Test
    fun mock_labels_are_impossible_to_confuse_with_real_hardware() {
        val labelled = MockHardware.label("YubiKey #12345678", isMock = true)
        assertTrue(labelled.startsWith(MockHardware.LABEL_PREFIX))
        assertTrue(labelled.contains("MOCK"))
        assertFalse(MockHardware.label("YubiKey #12345678", isMock = false).contains("MOCK"))
    }
}
