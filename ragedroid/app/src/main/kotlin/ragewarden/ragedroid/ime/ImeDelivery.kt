package ragewarden.ragedroid.ime

import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toPersistentList
import ragewarden.ragedroid.data.LockState
import ragewarden.ragedroid.data.VaultBackend
import ragewarden.ragedroid.model.VaultItem

/**
 * Everything the keyboard is allowed to know and allowed to do, behind the vault
 * lock.
 *
 * `RagewardenInputMethodService` previously contained zero references to the
 * lock: it read [VaultBackend.snapshot] -- the in-process cache that stays
 * resident while locked -- listed the items, and on tap decrypted one and
 * `commitText`-ed it into whatever editor had focus. Locking the vault did not
 * touch that path, so the keyboard typed passwords out of a locked vault.
 *
 * The gate lives in this class rather than inline in the service so it is one
 * choke point with a test against it ([ragewarden.ragedroid.ime.ImeDeliveryTest])
 * instead of a condition sprinkled through an `InputMethodService` that no unit
 * test can instantiate.
 */
internal class ImeDelivery(
    private val lockState: LockState,
    private val backend: VaultBackend,
    private val auth: ImeAuthBroker = NoImeAuth,
) {
    data class Offer(
        val locked: Boolean,
        val deliverable: ImmutableList<VaultItem>,
        val protectedCount: Int,
    )

    sealed interface Outcome {
        data object Delivered : Outcome
        data class Refused(val reason: String) : Outcome
    }

    /**
     * What the keyboard may render. While locked this is empty -- item *names*
     * and sites are vault contents too, and a locked vault does not enumerate
     * itself onto a surface sitting inside a third-party app.
     */
    fun offer(): Offer {
        if (lockState.isLocked) {
            return Offer(locked = true, deliverable = persistentListOf(), protectedCount = 0)
        }
        val all = backend.snapshot()
        return Offer(
            locked = false,
            deliverable = all.toPersistentList(),
            protectedCount = all.count { it.rage },
        )
    }

    /**
     * The only path from the keyboard to an editor. [commit] is invoked at most
     * once and only on [Outcome.Delivered]; every other branch returns
     * [Outcome.Refused] without ever calling it.
     *
     * A protected item is decrypted by [auth], which runs the hardware tap in an
     * Activity (a keyboard cannot host one). The keyboard loses the field while
     * that sheet is up, so the plaintext is committed only after [auth] reports
     * the same [session] focused again, and only if the vault is still unlocked.
     */
    suspend fun deliver(itemId: String, session: ImeSession? = null, commit: (CharSequence) -> Unit): Outcome {
        if (lockState.isLocked) return Outcome.Refused(LOCKED)
        val item = backend.get(itemId) ?: return Outcome.Refused("unknown item")
        val plaintext = if (item.rage) {
            if (session == null) return Outcome.Refused(NO_FIELD)
            auth.authorize(item, session) ?: return Outcome.Refused(DECLINED)
        } else {
            runCatching { backend.decrypt(itemId, emptyList(), ragewarden.ragedroid.data.audit.AuditAction.Autofill) }.getOrNull()
                ?: return Outcome.Refused("decrypt failed")
        }
        try {
            // The decrypt (or the tap) suspends, and the vault can be locked
            // while it is in flight, so re-read immediately before anything
            // reaches the editor.
            if (lockState.isLocked) return Outcome.Refused(LOCKED_MID_FLIGHT)
            if (item.rage) {
                if (!auth.awaitReturn(session!!)) return Outcome.Refused(FIELD_CHANGED)
                if (lockState.isLocked) return Outcome.Refused(LOCKED_MID_FLIGHT)
            }
            // commitText parcels the text before it returns; the characters
            // are zeroed when withChars does.
            ragewarden.ragedroid.data.SecretText.withChars(plaintext) { commit(it) }
            return Outcome.Delivered
        } finally {
            plaintext.fill(0)
        }
    }

    internal companion object {
        const val LOCKED = "vault is locked"
        const val LOCKED_MID_FLIGHT = "vault locked while the item was decrypting"
        const val NO_FIELD = "no input field to type into"
        const val DECLINED = "the hardware tap was declined or failed"
        const val FIELD_CHANGED = "a different field was focused when the tap finished"
    }
}
