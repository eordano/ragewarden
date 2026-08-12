package ragewarden.ragedroid.data.audit

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toImmutableList
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import ragewarden.ragedroid.data.KeystorePrefs

@Singleton
class AuditFeed @Inject constructor(
    @ApplicationContext context: Context,
    private val clock: Clock = Clock.systemDefaultZone(),
) {
    private val prefs = KeystorePrefs(
        context = context.applicationContext,
        prefsName = "ragewarden.audit.v1",
        keyAlias = "ragewarden.audit.aead.v1",
    )
    private val mutex = Mutex()

    private val _flow = MutableStateFlow(rebuild(loadStored()))
    val flow: StateFlow<ImmutableList<AuditEntry>> = _flow.asStateFlow()

    fun list(): ImmutableList<AuditEntry> = _flow.value

    suspend fun record(
        action: AuditAction,
        item: String,
        recipient: String? = null,
        site: String? = null,
        reason: String? = null,
        cleared: Boolean = false,
    ) {
        withContext(Dispatchers.IO) {
            mutex.withLock {
                val now = clock.millis()
                val current = loadStored().toMutableList()
                current.add(
                    0,
                    StoredEntry(
                        id = UUID.randomUUID().toString(),
                        whenEpochMs = now,
                        action = action,
                        item = item,
                        recipient = recipient,
                        site = site,
                        reason = reason,
                        cleared = cleared,
                    ),
                )
                if (current.size > MAX_ENTRIES) {
                    current.subList(MAX_ENTRIES, current.size).clear()
                }
                save(current)
                _flow.value = rebuild(current)
            }
        }
    }

    suspend fun clear() {
        withContext(Dispatchers.IO) {
            mutex.withLock {
                prefs.remove(KEY)
                _flow.value = persistentListOf()
            }
        }
    }

    private fun loadStored(): List<StoredEntry> {
        val raw = prefs.getString(KEY, null) ?: return emptyList()
        return runCatching { JSON.decodeFromString<List<StoredEntry>>(raw) }.getOrDefault(emptyList())
    }

    private fun save(list: List<StoredEntry>) {
        prefs.putString(KEY, JSON.encodeToString(list))
    }

    private fun rebuild(stored: List<StoredEntry>): ImmutableList<AuditEntry> {
        val now = LocalDateTime.now(clock)
        val today = now.toLocalDate()
        return stored.map { it.toAuditEntry(clock, now, today) }.toImmutableList()
    }

    @Serializable
    private data class StoredEntry(
        val id: String,
        val whenEpochMs: Long,
        val action: AuditAction,
        val item: String,
        val recipient: String? = null,
        val site: String? = null,
        val reason: String? = null,
        val cleared: Boolean = false,
    ) {
        fun toAuditEntry(clock: Clock, now: LocalDateTime, today: LocalDate): AuditEntry {
            val time = LocalDateTime.ofInstant(Instant.ofEpochMilli(whenEpochMs), clock.zone)
            return AuditEntry(
                id = id,
                timestamp = formatTimestamp(time, now),
                bucket = bucketFor(time.toLocalDate(), today),
                action = action,
                item = item,
                recipient = recipient,
                site = site,
                reason = reason,
                cleared = cleared,
            )
        }
    }

    companion object {
        private const val KEY = "entries"
        private const val MAX_ENTRIES = 500
        private val JSON = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    }
}

internal fun bucketFor(date: LocalDate, today: LocalDate): String {
    val days = ChronoUnit.DAYS.between(date, today)
    return when {
        days <= 0L -> "Today"
        days == 1L -> "Yesterday"
        days < 7L -> "Earlier this week"
        else -> "Earlier"
    }
}

internal fun formatTimestamp(time: LocalDateTime, now: LocalDateTime): String {
    val today = now.toLocalDate()
    val date = time.toLocalDate()
    val mins = ChronoUnit.MINUTES.between(time, now)
    return when {
        date == today && mins < 1L -> "Just now"
        date == today && mins < 60L -> "$mins minutes ago"
        date == today -> time.format(TIME_FMT)
        date == today.minusDays(1) -> "Yesterday · ${time.format(TIME_FMT)}"
        else -> time.format(DATE_FMT)
    }
}

private val TIME_FMT: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm")
private val DATE_FMT: DateTimeFormatter = DateTimeFormatter.ofPattern("MMM d · HH:mm")
