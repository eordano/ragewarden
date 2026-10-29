package ragewarden.ragedroid.data

import ragewarden.ragedroid.R
import ragewarden.ragedroid.ui.uiQuantity
import ragewarden.ragedroid.ui.uiString

data class PrfRequest(val rpId: String, val credentialId: ByteArray, val salt: ByteArray) {
    override fun equals(other: Any?): Boolean = other is PrfRequest &&
        rpId == other.rpId && credentialId.contentEquals(other.credentialId) && salt.contentEquals(other.salt)
    override fun hashCode(): Int = 31 * (31 * rpId.hashCode() + credentialId.contentHashCode()) + salt.contentHashCode()

    companion object {
        private val rng = java.security.SecureRandom()

        fun fresh(rpId: String, credentialId: ByteArray): PrfRequest =
            PrfRequest(rpId, credentialId, ByteArray(32).also(rng::nextBytes))
    }
}

interface PrfTapper {
    suspend fun tap(requests: List<PrfRequest>): List<WirePrfInput>
}

class NoRecipientsConfiguredException : UserFacingException(text = { uiString(R.string.error_no_recipients) })

class PrfTapperNotConfiguredException(val pendingTapCount: Int) :
    UserFacingException(text = { uiQuantity(R.plurals.error_tap_prompt_unavailable, pendingTapCount, pendingTapCount) })
