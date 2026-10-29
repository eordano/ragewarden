package ragewarden.ragedroid.identities

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/** SEC1 compressed P-256 points, as every ragewarden stanza and registry entry carries them. */
object P256 {
    private val params: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
    }

    fun decompress(sec1Compressed: ByteArray): ECPublicKey {
        require(sec1Compressed.size == 33) { "P-256 SEC1-compressed pubkey must be 33 bytes" }
        val tag = sec1Compressed[0].toInt() and 0xFF
        require(tag == 0x02 || tag == 0x03) { "Bad SEC1-compressed prefix: 0x${tag.toString(16)}" }
        val x = BigInteger(1, sec1Compressed.copyOfRange(1, 33))
        val curve = params.curve
        val p = (curve.field as ECFieldFp).p
        val rhs = (x.modPow(BigInteger.valueOf(3), p) + curve.a.multiply(x).mod(p) + curve.b).mod(p)
        val candidate = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p)
        check(candidate.multiply(candidate).mod(p) == rhs) { "x is not on the secp256r1 curve" }
        val y = if (candidate.testBit(0) == (tag == 0x03)) candidate else p.subtract(candidate)
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params)) as ECPublicKey
    }

    fun compress(pub: ECPublicKey): ByteArray {
        val x = pub.w.affineX.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        val out = ByteArray(33)
        out[0] = if (pub.w.affineY.testBit(0)) 0x03 else 0x02
        System.arraycopy(x, 0, out, 33 - x.size, x.size)
        return out
    }

    /** SPKI DER of a compressed point: what `attestationPublicKey` publishes. */
    fun spkiDer(sec1Compressed: ByteArray): ByteArray = decompress(sec1Compressed).encoded

    fun isCompressedPoint(bytes: ByteArray): Boolean =
        bytes.size == 33 && runCatching { decompress(bytes) }.isSuccess
}
