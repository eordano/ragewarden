package ragewarden.ragedroid.identities

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test
import ragewarden.ragedroid.ui.screens.TapFailureKind
import ragewarden.ragedroid.ui.screens.classifyTapFailure

/** HW-03: the presented YubiKey's serial is checked against the enrolled one before its PIN is used. */
class YubiKeySerialTest {
    private fun identity(serial: UInt) = YubiKeyPivIdentity(mockSecret = null, expectedPublicKey = ByteArray(33), serial = serial, slot = 0x9au)

    @Test
    fun another_yubikey_is_a_typed_wrong_key_error_naming_both() {
        val e = identity(12345678u).wrongKey(87654321)!!
        assertEquals(12345678u, e.expectedSerial)
        assertEquals(87654321u, e.presentedSerial)
        assertEquals(TapFailureKind.WrongKey, classifyTapFailure(e))
    }

    @Test
    fun the_enrolled_key_or_an_unknown_serial_passes() {
        assertNull(identity(12345678u).wrongKey(12345678))
        assertNull("firmware that reports no serial", identity(12345678u).wrongKey(null))
        assertNull("enrolled without a serial", identity(0u).wrongKey(87654321))
    }

    @Test
    fun the_typed_failure_survives_the_jni_callback() {
        val wrong = identity(1u).wrongKey(2)!!
        HardwareFailures.clear()
        HardwareFailures.record(wrong)
        assertSame(wrong, HardwareFailures.rethrowable(RuntimeException("decrypt: kotlin threw during tryUnwrapBlocking")))
        val generic = RuntimeException("decrypt: no matching identity")
        assertSame("nothing recorded: the decrypt error itself", generic, HardwareFailures.rethrowable(generic))
    }
}
