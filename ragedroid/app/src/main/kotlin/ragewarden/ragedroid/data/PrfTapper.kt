package ragewarden.ragedroid.data

data class PrfRequest(val rpId: String, val salt: ByteArray) {
    override fun equals(other: Any?): Boolean = other is PrfRequest &&
        rpId == other.rpId && salt.contentEquals(other.salt)
    override fun hashCode(): Int = 31 * rpId.hashCode() + salt.contentHashCode()
}

interface PrfTapper {
    suspend fun tap(requests: List<PrfRequest>): List<WirePrfInput>
}

class NoRecipientsConfiguredException :
    RuntimeException("Enrol at least one recipient before saving items.")

class PrfTapperNotConfiguredException(val pendingTapCount: Int) :
    RuntimeException(
        "$pendingTapCount FIDO2/Passkey recipient(s) are marked default-encrypt but " +
            "no PRF-tap handler is wired. Mark the recipient as decrypt-only, " +
            "or attach a PrfTapper before saving.",
    )
