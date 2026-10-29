package ragewarden.ragedroid.identities

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement
import ragewarden.ragedroid.jni.RageNative

class SoftwareP256Identity(private val handle: String) : KotlinIdentity {
    private val pair: KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    val publicKey: ByteArray = (pair.public as ECPublicKey).let { pub ->
        val x = pub.w.affineX.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        ByteArray(33).also { out ->
            out[0] = if (pub.w.affineY.testBit(0)) 0x03 else 0x02
            System.arraycopy(x, 0, out, 33 - x.size, x.size)
        }
    }

    override val displayLabel: String get() = "test P-256 key"

    override suspend fun tryUnwrap(stanzaTag: String, stanzaArgs: Array<String>, stanzaBody: ByteArray): ByteArray? {
        if (stanzaTag != "ragedroid-keystore-v1" || stanzaArgs.size != 2) return null
        val ephemeral = java.util.Base64.getDecoder().decode(stanzaArgs[1].padEnd((stanzaArgs[1].length + 3) / 4 * 4, '='))
        val peer = java.security.KeyFactory.getInstance("EC").generatePublic(
            java.security.spec.X509EncodedKeySpec(spkiFor(ephemeral)),
        )
        val share = KeyAgreement.getInstance("ECDH").apply {
            init(pair.private)
            doPhase(peer, true)
        }.generateSecret()
        return try {
            RageNative.unwrapStanza(stanzaTag, stanzaArgs, stanzaBody, share)
        } finally {
            share.fill(0)
        }
    }

    private fun spkiFor(compressed: ByteArray): ByteArray {
        val header = byteArrayOf(
            0x30, 0x39, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03, 0x22, 0x00,
        )
        return header + compressed
    }
}
