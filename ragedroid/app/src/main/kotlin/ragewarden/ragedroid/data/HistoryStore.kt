package ragewarden.ragedroid.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import java.time.Clock
import java.time.Instant
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toImmutableList
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import ragewarden.ragedroid.ui.screens.HistoryChange
import ragewarden.ragedroid.ui.screens.HistoryRevision

@Singleton
class HistoryStore @Inject constructor(
    @ApplicationContext context: Context,
    private val clock: Clock = Clock.systemDefaultZone(),
) {
    private val prefs = KeystorePrefs(
        context = context.applicationContext,
        prefsName = "ragewarden.history.v1",
        keyAlias = "ragewarden.history.aead.v1",
    )
    private val mutex = Mutex()

    fun forItem(accountId: String, itemId: String): ImmutableList<HistoryRevision> {
        if (accountId.isBlank() || itemId.isBlank()) return persistentListOf()
        val stored = loadStored(accountId, itemId)
        if (stored.isEmpty()) return persistentListOf()
        val now = LocalDateTime.now(clock)
        return stored.mapIndexed { index, rev ->
            val time = LocalDateTime.ofInstant(Instant.ofEpochMilli(rev.whenEpochMs), clock.zone)
            HistoryRevision(
                id = rev.id,
                when_ = formatTimestamp(time, now),
                by = rev.by,
                current = index == 0,
                changes = rev.changes.map { HistoryChange(it.field, it.diff) }.toImmutableList(),
            )
        }.toImmutableList()
    }

    suspend fun recordCreated(accountId: String, itemId: String, deviceLabel: String) {
        record(
            accountId = accountId,
            itemId = itemId,
            by = deviceLabel,
            changes = listOf(StoredChange("Created")),
        )
    }

    suspend fun recordRotated(accountId: String, itemId: String, deviceLabel: String) {
        record(
            accountId = accountId,
            itemId = itemId,
            by = deviceLabel,
            changes = listOf(StoredChange("Password", diff = "rotated")),
        )
    }

    suspend fun recordModified(
        accountId: String,
        itemId: String,
        deviceLabel: String,
        changes: List<HistoryChange>,
    ) {
        if (changes.isEmpty()) return
        record(
            accountId = accountId,
            itemId = itemId,
            by = deviceLabel,
            changes = changes.map { StoredChange(it.field, it.diff) },
        )
    }

    suspend fun clearItem(accountId: String, itemId: String) {
        if (accountId.isBlank() || itemId.isBlank()) return
        withContext(Dispatchers.IO) {
            mutex.withLock { prefs.remove(prefKey(accountId, itemId)) }
        }
    }

    private suspend fun record(
        accountId: String,
        itemId: String,
        by: String,
        changes: List<StoredChange>,
    ) {
        if (accountId.isBlank() || itemId.isBlank()) return
        withContext(Dispatchers.IO) {
            mutex.withLock {
                val current = loadStored(accountId, itemId).toMutableList()
                current.add(
                    0,
                    StoredRevision(
                        id = UUID.randomUUID().toString(),
                        whenEpochMs = clock.millis(),
                        by = by,
                        changes = changes,
                    ),
                )
                if (current.size > MAX_REVISIONS_PER_ITEM) {
                    current.subList(MAX_REVISIONS_PER_ITEM, current.size).clear()
                }
                save(accountId, itemId, current)
            }
        }
    }

    private fun loadStored(accountId: String, itemId: String): List<StoredRevision> {
        val raw = prefs.getString(prefKey(accountId, itemId), null) ?: return emptyList()
        return runCatching { JSON.decodeFromString<List<StoredRevision>>(raw) }.getOrDefault(emptyList())
    }

    private fun save(accountId: String, itemId: String, list: List<StoredRevision>) {
        prefs.putString(prefKey(accountId, itemId), JSON.encodeToString(list))
    }

    private fun prefKey(accountId: String, itemId: String): String = "history:$accountId:$itemId"

    @Serializable
    private data class StoredRevision(
        val id: String,
        val whenEpochMs: Long,
        val by: String,
        val changes: List<StoredChange>,
    )

    @Serializable
    private data class StoredChange(val field: String, val diff: String? = null)

    companion object {
        private const val MAX_REVISIONS_PER_ITEM = 50
        private val JSON = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    }
}

private fun formatTimestamp(time: LocalDateTime, now: LocalDateTime): String {
    val today = now.toLocalDate()
    val date = time.toLocalDate()
    return when {
        date == today -> "Today · ${time.format(TIME_FMT)}"
        date == today.minusDays(1) -> "Yesterday · ${time.format(TIME_FMT)}"
        else -> time.format(DATE_FMT)
    }
}

private val TIME_FMT: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm")
private val DATE_FMT: DateTimeFormatter = DateTimeFormatter.ofPattern("MMM d · HH:mm")
