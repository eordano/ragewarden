package ragewarden.ragedroid.identities

import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.piv.PivSession
import com.yubico.yubikit.piv.Slot
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The slot touch policy, read back with GET METADATA (INS 0xF7) over yubikit,
 * against a scripted card. Only ALWAYS passes, at enrolment and before every
 * unwrap; a refused slot never sees the PIN.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class PivTouchPolicyTest {
    private val slotKey: ECPublicKey = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair().public as ECPublicKey

    /** A YubiKey PIV applet reduced to the APDUs these paths send, by INS. */
    private inner class FakeCard(
        private val version: ByteArray = byteArrayOf(5, 7, 1),
        private val touchByte: Int = 0x02,
        private val serial: Int = 12345678,
    ) : SmartCardConnection {
        val seen = mutableListOf<Int>()
        val secret = ByteArray(32) { (it + 1).toByte() }

        override fun sendAndReceive(apdu: ByteArray): ByteArray {
            val ins = apdu[1].toInt() and 0xFF
            val p2 = apdu[3].toInt() and 0xFF
            seen += ins
            return when (ins) {
                0xA4 -> ok(ByteArray(0))
                0xFD -> ok(version)
                0xF8 -> ok(bytes(serial ushr 24, serial ushr 16, serial ushr 8, serial))
                0xF7 -> if (p2 == 0x9B) {
                    ok(bytes(0x01, 0x01, 0x03, 0x05, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01))
                } else {
                    val point = bytes(0x86, 0x41) + uncompressed()
                    ok(bytes(0x01, 0x01, 0x11, 0x02, 0x02, 0x02, touchByte, 0x03, 0x01, 0x01, 0x04, point.size) + point)
                }
                0x20 -> ok(ByteArray(0))
                0x47 -> ok(bytes(0x7F, 0x49, 0x43, 0x86, 0x41) + uncompressed())
                0x87 -> ok(bytes(0x7C, 0x22, 0x82, 0x20) + secret)
                else -> bytes(0x6D, 0x00)
            }
        }

        private fun uncompressed(): ByteArray {
            fun b32(x: java.math.BigInteger) = x.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else ByteArray(32 - it.size) + it }
            return byteArrayOf(0x04) + b32(slotKey.w.affineX) + b32(slotKey.w.affineY)
        }

        private fun ok(data: ByteArray) = data + bytes(0x90, 0x00)
        private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

        override fun getTransport(): Transport = Transport.USB
        override fun isExtendedLengthApduSupported(): Boolean = false
        override fun getAtr(): ByteArray = ByteArray(0)
        override fun close() = Unit
    }

    private fun touchOf(card: FakeCard) = SlotTouch.read(PivSession(card), Slot.AUTHENTICATION)

    @Test
    fun every_policy_byte_reads_back() {
        assertEquals(SlotTouch.Always, touchOf(FakeCard(touchByte = 0x02)))
        assertEquals(SlotTouch.Weaker("never"), touchOf(FakeCard(touchByte = 0x01)))
        assertEquals(SlotTouch.Weaker("default"), touchOf(FakeCard(touchByte = 0x00)))
        assertEquals(SlotTouch.Weaker("cached"), touchOf(FakeCard(touchByte = 0x03)))
        assertTrue(touchOf(FakeCard(touchByte = 0x7F)) is SlotTouch.Weaker)
    }

    @Test
    fun firmware_before_5_3_cannot_say_and_is_not_asked() {
        val card = FakeCard(version = byteArrayOf(5, 2, 7))
        assertEquals(SlotTouch.Unreadable, touchOf(card))
        assertFalse(0xF7 in card.seen)
    }

    private fun identity() = YubiKeyPivIdentity(
        mockSecret = null,
        expectedPublicKey = P256.compress(slotKey),
        serial = 12345678u,
        slot = 0x9Au,
    )

    private fun ephemeral(): ByteArray = P256.compress(
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair().public as ECPublicKey,
    )

    @Test
    fun unwrap_on_an_always_slot_verifies_the_pin_and_agrees() = runBlocking {
        val card = FakeCard(touchByte = 0x02)
        var pinAsked = false
        val share = identity().agreeOnCard(card, Slot.AUTHENTICATION, ephemeral(), true) {
            pinAsked = true
            "123456".toCharArray()
        }
        assertArrayEquals(card.secret, share)
        assertTrue(pinAsked)
        assertTrue(card.seen.containsAll(listOf(0xF7, 0x20, 0x87)))
    }

    @Test
    fun unwrap_refuses_a_slot_that_does_not_wait_for_a_touch_before_the_pin() = runBlocking {
        for (weak in listOf(0x00, 0x01, 0x03)) {
            val card = FakeCard(touchByte = weak)
            var pinAsked = false
            try {
                identity().agreeOnCard(card, Slot.AUTHENTICATION, ephemeral(), true) {
                    pinAsked = true
                    "123456".toCharArray()
                }
                fail("touch byte $weak was accepted")
            } catch (e: PivTouchPolicyException) {
                assertFalse(e.retryable)
            }
            assertFalse(pinAsked)
            assertFalse(0x20 in card.seen)
            assertFalse(0x87 in card.seen)
        }
    }

    @Test
    fun unwrap_on_old_firmware_goes_ahead() = runBlocking {
        val card = FakeCard(version = byteArrayOf(5, 2, 7))
        val share = identity().agreeOnCard(card, Slot.AUTHENTICATION, ephemeral(), true) { "123456".toCharArray() }
        assertArrayEquals(card.secret, share)
    }

    @Test
    fun enrolment_reads_the_policy_back_and_keeps_an_always_slot() {
        val card = FakeCard(touchByte = 0x02)
        val (recipient, _) = enrollOnCard(card, Slot.AUTHENTICATION, "123456".toCharArray(), null, PivCurve.P256, null)
        assertArrayEquals(P256.compress(slotKey), recipient.pivPubkey)
        assertEquals(12345678, recipient.pivSerial)
        assertTrue(card.seen.lastIndexOf(0xF7) > card.seen.indexOf(0x47))
    }

    @Test
    fun enrolment_refuses_a_slot_the_card_reports_as_weaker() {
        for (weak in listOf(0x00, 0x01, 0x03)) {
            try {
                enrollOnCard(FakeCard(touchByte = weak), Slot.AUTHENTICATION, "123456".toCharArray(), null, PivCurve.P256, null)
                fail("touch byte $weak was enrolled")
            } catch (e: PivTouchPolicyException) {
                assertTrue(e.message.orEmpty().isNotBlank())
            }
        }
    }

    @Test
    fun enrolment_on_old_firmware_keeps_the_policy_it_requested() {
        val (recipient, _) = enrollOnCard(
            FakeCard(version = byteArrayOf(5, 2, 7)), Slot.AUTHENTICATION, "123456".toCharArray(), null, PivCurve.P256, null,
        )
        assertArrayEquals(P256.compress(slotKey), recipient.pivPubkey)
    }
}
