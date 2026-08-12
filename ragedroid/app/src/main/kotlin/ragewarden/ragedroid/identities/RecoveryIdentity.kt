package ragewarden.ragedroid.identities

import ragewarden.ragedroid.jni.RageNative

class RecoveryIdentity(
    private val armoredSecret: String,
    override val displayLabel: String = "Paper recovery identity",
) : KotlinIdentity {
    override suspend fun tryUnwrap(
        stanzaTag: String,
        stanzaArgs: Array<String>,
        stanzaBody: ByteArray,
    ): ByteArray? {
        if (stanzaTag != "X25519" && stanzaTag != "scrypt") return null
        return null
    }

    fun decryptDirect(blob: ByteArray): ByteArray =
        RageNative.decryptWithSoftwareSecret(blob, armoredSecret)

    companion object {
        fun fromArmoredSecret(armoredSecret: String): RecoveryIdentity =
            RecoveryIdentity(armoredSecret = armoredSecret)
    }
}
