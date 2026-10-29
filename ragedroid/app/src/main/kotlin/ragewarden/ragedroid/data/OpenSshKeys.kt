package ragewarden.ragedroid.data

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64

/**
 * Reads the public half out of an OpenSSH private key. Bitwarden needs an SSH
 * key item's public key and fingerprint next to the private key, and the
 * `openssh-key-v1` format stores the public key unencrypted in its header, so
 * both come from the pasted key even when it is passphrase-protected.
 */
object OpenSshKeys {
    data class Public(val keyType: String, val publicKey: String, val fingerprint: String)

    private const val BEGIN = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
    private const val END = "-----END OPENSSH " + "PRIVATE KEY-----"
    private val MAGIC = "openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII)

    fun publicOf(privateKey: CharSequence): Public? = runCatching {
        val start = privateKey.indexOf(BEGIN).takeIf { it >= 0 } ?: return null
        val end = privateKey.indexOf(END, start).takeIf { it >= 0 } ?: return null
        val body = java.io.ByteArrayOutputStream()
        for (i in start + BEGIN.length until end) {
            val ch = privateKey[i]
            if (!ch.isWhitespace()) body.write(ch.code)
        }
        if (body.size() == 0) return null
        val raw = body.toByteArray()
        val decoded = Base64.getDecoder().decode(raw)
        raw.fill(0)
        val buf = ByteBuffer.wrap(decoded)
        val magic = ByteArray(MAGIC.size).also(buf::get)
        if (!magic.contentEquals(MAGIC)) return null
        repeat(3) { string(buf) }
        if (buf.int < 1) return null
        val blob = string(buf)
        val keyType = String(string(ByteBuffer.wrap(blob)), Charsets.US_ASCII)
        val digest = MessageDigest.getInstance("SHA-256").digest(blob)
        decoded.fill(0)
        Public(
            keyType = keyType,
            publicKey = "$keyType ${Base64.getEncoder().encodeToString(blob)}",
            fingerprint = "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest),
        )
    }.getOrNull()

    private fun string(buf: ByteBuffer): ByteArray {
        val len = buf.int
        require(len in 0..buf.remaining())
        return ByteArray(len).also(buf::get)
    }
}
