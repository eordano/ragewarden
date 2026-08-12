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
            deliverable = all.filterNot { it.rage }.toPersistentList(),
            protectedCount = all.count { it.rage },
        )
    }

    /**
     * The only path from the keyboard to an editor. [commit] is invoked at most
     * once and only on [Outcome.Delivered]; every other branch returns
     * [Outcome.Refused] without ever calling it.
     *
     * `identities = emptyList()` on the decrypt is load-bearing and is checked
     * twice over: `BitwardenVaultRepository.decrypt` hard-errors on a `rage`
     * item with no identities, and the `item.rage` branch below refuses before
     * it can get that far. An `InputMethodService` is not an Activity, so it
     * cannot host `BiometricPrompt`, Credential Manager or NFC reader mode --
     * it cannot run the hardware ceremony and must not pretend to.
     */
    suspend fun deliver(itemId: String, commit: (String) -> Unit): Outcome {
        if (lockState.isLocked) return Outcome.Refused(LOCKED)
        val item = backend.get(itemId) ?: return Outcome.Refused("unknown item")
        if (item.rage) return Outcome.Refused("Ragewarden-protected item")
        val plaintext = runCatching { backend.decrypt(itemId, emptyList()) }.getOrNull()
            ?: return Outcome.Refused("decrypt failed")
        try {
            // The decrypt above suspends and can wait on a network sync. The
            // vault can be locked (ON_STOP, or "Lock now" from another window)
            // while it is in flight, so the first check is not sufficient on its
            // own -- re-read immediately before anything reaches the editor.
            if (lockState.isLocked) return Outcome.Refused(LOCKED_MID_FLIGHT)
            commit(String(plaintext, Charsets.UTF_8))
            return Outcome.Delivered
        } finally {
            plaintext.fill(0)
        }
    }

    internal companion object {
        const val LOCKED = "vault is locked"
        const val LOCKED_MID_FLIGHT = "vault locked while the item was decrypting"
    }
}
