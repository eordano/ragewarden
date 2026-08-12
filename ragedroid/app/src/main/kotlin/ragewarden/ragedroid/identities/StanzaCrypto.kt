package ragewarden.ragedroid.identities

import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal object StanzaCrypto {
    private val b64Std = Base64.getEncoder().withoutPadding()
    private val b64StdDecoder = Base64.getDecoder()
    private val b64Url = Base64.getUrlEncoder().withoutPadding()
    private val b64UrlDecoder = Base64.getUrlDecoder()

    fun b64StdEncode(bytes: ByteArray): String = b64Std.encodeToString(bytes)
    fun b64StdDecode(s: String): ByteArray = b64StdDecoder.decode(padIfNeeded(s))
    fun b64UrlEncode(bytes: ByteArray): String = b64Url.encodeToString(bytes)
    fun b64UrlDecode(s: String): ByteArray = b64UrlDecoder.decode(padIfNeeded(s))

    private fun padIfNeeded(s: String): String {
        val mod = s.length % 4
        return if (mod == 0) s else s + "====".substring(mod)
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)
}
