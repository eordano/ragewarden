package ragewarden.ragedroid.identities

import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.data.RecipientDescriptors
import ragewarden.ragedroid.data.RecipientPolicy.toPolicyWire
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.model.RecipientKind

/**
 * P-256 PIV slots: age-plugin-yubikey's `piv-p256` stanza (recipient tag
 * first, 33-byte ephemeral point second) is recognised and routed to the
 * slot's own curve; enrolment, descriptors and the registry carry the
 * 33-byte compressed key. The ECDH itself needs a YubiKey.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class PivP256Test {
    private val slotKey: ECPublicKey = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair().public as ECPublicKey
    private val slotPub = P256.compress(slotKey)
    private val ephemeral = P256.compress(
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public as ECPublicKey,
    )
    private val p256Args = arrayOf(
        StanzaCrypto.b64StdEncode(YubiKeyPivIdentity.expectedRecipientTag(slotPub)),
        StanzaCrypto.b64StdEncode(ephemeral),
    )

    @Test
    fun a_compressed_point_round_trips_and_its_spki_is_the_key() {
        assertEquals(33, slotPub.size)
        val back = P256.decompress(slotPub)
        assertEquals(slotKey.w, back.w)
        assertArrayEquals(slotKey.encoded, P256.spkiDer(slotPub))
        assertTrue(P256.isCompressedPoint(slotPub))
    }

    @Test
    fun the_two_piv_p256_shapes_are_told_apart() {
        val p256 = YubiKeyPivIdentity.stanzaShape(StanzaTags.PIV_P256, p256Args)!!
        assertTrue(p256.p256)
        assertEquals(p256Args[0], p256.tagArg)
        val x25519Args = arrayOf("A".repeat(43), "AAAAAA")
        val x = YubiKeyPivIdentity.stanzaShape(StanzaTags.PIV_P256, x25519Args)!!
        assertEquals(false, x.p256)
        assertEquals(x25519Args[1], x.tagArg)
        assertNull(YubiKeyPivIdentity.stanzaShape(StanzaTags.PIV_X25519_V2, p256Args))
    }

    @Test
    fun a_p256_slot_claims_its_own_stanza_and_an_x25519_slot_does_not() = runBlocking {
        val x25519Slot = YubiKeyPivIdentity(mockSecret = null, expectedPublicKey = ByteArray(32) { 1 }, serial = 1u, slot = 0x9au)
        assertNull(x25519Slot.tryUnwrap(StanzaTags.PIV_P256, p256Args, ByteArray(32)))
        val otherP256 = YubiKeyPivIdentity(mockSecret = null, expectedPublicKey = ephemeral, serial = 1u, slot = 0x9au)
        assertNull("another slot's tag", otherP256.tryUnwrap(StanzaTags.PIV_P256, p256Args, ByteArray(32)))
        val ours = YubiKeyPivIdentity(mockSecret = null, expectedPublicKey = slotPub, serial = 1u, slot = 0x9au)
        // Ours: it goes on to the device, which this surface does not have.
        assertThrows(HardwareTapUnavailableException::class.java) {
            runBlocking { ours.tryUnwrap(StanzaTags.PIV_P256, p256Args, ByteArray(32)) }
        }
        Unit
    }

    @Test
    fun a_p256_piv_recipient_matches_and_publishes_its_slot_key() {
        val r = StoredRecipient(
            id = "yk", kind = RecipientKind.YubiKey, displayName = "YubiKey", createdAt = 0L, lastUsedAt = 0L,
            pivPubkey = slotPub, pivSerial = 1, pivSlot = 0x9a.toByte(),
        )
        assertEquals(listOf("${StanzaTags.PIV_P256}:${p256Args[0]}"), RecipientDescriptors.forStored(r))
        val wire = r.toPolicyWire("phone")
        assertEquals(slotPub.joinToString("") { "%02x".format(it) }, wire.pivPubkey)
        assertEquals(java.util.Base64.getEncoder().encodeToString(slotKey.encoded), wire.attestationPublicKey)
    }
}
