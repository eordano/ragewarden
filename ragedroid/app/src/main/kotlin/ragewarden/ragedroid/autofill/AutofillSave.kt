package ragewarden.ragedroid.autofill

import android.app.assist.AssistStructure
import java.nio.CharBuffer
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlinx.collections.immutable.persistentListOf
import ragewarden.ragedroid.data.ItemEdit
import ragewarden.ragedroid.data.VaultBackend
import ragewarden.ragedroid.model.NO_FOLDER
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.model.VaultItemKind

/** Credentials another app submitted, held in memory until the save sheet is done with them. */
internal class SaveCandidate(
    val webDomain: String?,
    val packageName: String?,
    /** The app's label, or the web domain; the new item's name. */
    val label: String,
    val username: String,
    val password: CharArray,
)

/** What saving [SaveCandidate] does to the vault. */
internal sealed interface SavePlan {
    /** A new protected login. */
    data class Create(val item: VaultItem) : SavePlan

    /** A login for the same site and username gets the new password. */
    data class Update(val item: VaultItem) : SavePlan

    /** That login already holds this password (an unprotected one, where it can be compared). */
    data class Unchanged(val item: VaultItem) : SavePlan
}

internal object AutofillSave {
    /** The submitted username and password, or null when no non-empty password field was filled. */
    fun candidate(structure: AssistStructure, labelOf: (String) -> String?): SaveCandidate? {
        val target = AutofillDatasets.target(structure) ?: return null
        val passwordId = target.password?.autofillId ?: return null
        val values = AssistStructureWalker.textValues(structure, setOfNotNull(passwordId, target.username?.autofillId))
        val password = values[passwordId]?.takeIf { it.isNotEmpty() } ?: return null
        val username = target.username?.autofillId?.let { values[it] }?.toString().orEmpty().trim()
        val label = target.webDomain ?: target.packageName?.let { labelOf(it) ?: it } ?: return null
        return SaveCandidate(target.webDomain, target.packageName, label, username, CharArray(password.length) { password[it] })
    }

    fun plan(candidate: SaveCandidate, items: List<VaultItem>): SavePlan {
        val same = HostMatcher.matchVaultItems(items, candidate.webDomain, candidate.packageName)
            .firstOrNull { it.kind == VaultItemKind.Login && it.username == candidate.username }
        return when {
            same == null -> SavePlan.Create(newLogin(candidate))
            !same.rage && same.password.toCharArray().contentEquals(candidate.password) -> SavePlan.Unchanged(same)
            else -> SavePlan.Update(same)
        }
    }

    /** Protected, like a login added in the app; the site is what [HostMatcher] matches next time. */
    fun newLogin(candidate: SaveCandidate): VaultItem = VaultItem(
        id = UUID.randomUUID().toString(),
        name = candidate.label,
        username = candidate.username,
        site = candidate.webDomain?.let { "https://$it" } ?: "androidapp://${candidate.packageName.orEmpty()}",
        folder = NO_FOLDER,
        rage = true,
        recipients = persistentListOf(),
        password = "",
        lastUsed = "",
        history = 0,
        kind = VaultItemKind.Login,
    )

    /**
     * Writes [plan]: a new login through [VaultBackend.create] (core's
     * buildCipher), a new password through [VaultBackend.edit] (core's
     * updateCipherPreserving, which keeps the item's other protected fields or
     * refuses without them). The UTF-8 copy of [password] is zeroed here.
     */
    suspend fun run(plan: SavePlan, password: CharArray, backend: VaultBackend): VaultItem {
        val buffer = Charsets.UTF_8.encode(CharBuffer.wrap(password))
        val bytes = ByteArray(buffer.remaining()).also { buffer.get(it) }
        buffer.clear()
        while (buffer.hasRemaining()) buffer.put(0)
        try {
            return when (plan) {
                is SavePlan.Create -> backend.create(plan.item, bytes)
                is SavePlan.Update -> backend.edit(plan.item, ItemEdit(newSecret = bytes))
                is SavePlan.Unchanged -> plan.item
            }
        } finally {
            bytes.fill(0)
        }
    }
}

/**
 * The hand-off from [RagewardenAutofillService.onSaveRequest] to
 * [AutofillSaveActivity]: the password stays in this process, and only a
 * random token travels in the intent. An entry not taken within two minutes
 * is zeroed and dropped.
 */
internal object PendingSaves {
    private class Entry(val candidate: SaveCandidate, val at: Long)

    private val entries = ConcurrentHashMap<String, Entry>()
    private const val TTL_MS = 120_000L

    fun put(candidate: SaveCandidate, now: Long = System.currentTimeMillis()): String {
        expire(now)
        val token = UUID.randomUUID().toString()
        entries[token] = Entry(candidate, now)
        return token
    }

    fun take(token: String, now: Long = System.currentTimeMillis()): SaveCandidate? {
        expire(now)
        return entries.remove(token)?.candidate
    }

    private fun expire(now: Long) {
        entries.entries.removeAll { (_, e) ->
            (now - e.at > TTL_MS).also { stale -> if (stale) e.candidate.password.fill('\u0000') }
        }
    }
}
