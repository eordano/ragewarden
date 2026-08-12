package ragewarden.ragedroid.identities

import androidx.fragment.app.FragmentActivity
import ragewarden.ragedroid.data.PrfRequest
import ragewarden.ragedroid.data.PrfTapper
import ragewarden.ragedroid.data.RecipientStore
import ragewarden.ragedroid.data.WirePrfInput
import ragewarden.ragedroid.model.RecipientKind

/**
 * The **encryption** side of the hardware requirement.
 *
 * Wrapping a file key to a FIDO2/passkey recipient needs that authenticator's
 * PRF output, which only the authenticator can produce -- so saving an item costs
 * a tap too, not just revealing one. `BitwardenVaultRepository` has always had
 * the hook (`installPrfTapper`) and the failure
 * (`PrfTapperNotConfiguredException`), but nothing in the tree ever called
 * `installPrfTapper`: enrolling a passkey and then saving any item was a
 * guaranteed failure. This is that missing implementation.
 *
 * `PrfRequest` carries only (rp id, salt) because that is all core needs to
 * match a stanza; the credential id has to be looked up locally, which is why
 * this lives next to the [RecipientStore] rather than in `data/`.
 */
class CredentialManagerPrfTapper(
    private val activity: FragmentActivity,
    private val recipientStore: RecipientStore,
    private val accountId: String,
) : PrfTapper {

    override suspend fun tap(requests: List<PrfRequest>): List<WirePrfInput> {
        if (requests.isEmpty()) return emptyList()
        val stored = recipientStore.forAccount(accountId)
            .filter { it.kind == RecipientKind.Fido2 }

        return requests.map { request ->
            val match = stored.firstOrNull { r ->
                (r.fido2RpId == request.rpId && r.fido2Salt.contentEqualsOrNull(request.salt)) ||
                    (r.passkeyRpId == request.rpId && r.passkeySalt.contentEqualsOrNull(request.salt))
            } ?: throw HardwareTapUnavailableException(
                "This item is being wrapped to a FIDO2 recipient on \"${request.rpId}\" that is " +
                    "not enrolled on this device. Enrol it here, or clear its default-encrypt flag " +
                    "on the device that owns it.",
            )

            val credentialId = match.fido2CredentialId ?: match.passkeyCredentialId
                ?: throw HardwareTapUnavailableException(
                    "Recipient \"${match.displayName}\" has no stored credential id.",
                )

            // Reuse the identity's assertion path so enrol/encrypt/decrypt all
            // build the same WebAuthn request shape (userVerification=required,
            // prf.eval.first = salt).
            val prf = Fido2HmacIdentity(
                mockHmacKey = null,
                credentialId = credentialId,
                rpId = request.rpId,
                activity = activity,
                label = match.displayName,
            ).obtainPrfOutput(request.salt)

            WirePrfInput(
                rp_id = request.rpId,
                salt = request.salt.copyOf(),
                prf_output = prf,
            )
        }
    }

    private fun ByteArray?.contentEqualsOrNull(other: ByteArray): Boolean =
        this != null && this.contentEquals(other)
}
