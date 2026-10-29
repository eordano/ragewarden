package ragewarden.ragedroid.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Singleton
class RotationTracker @Inject constructor(
    @ApplicationContext context: Context,
    private val recipientStore: RecipientStore,
) {
    private val prefs = KeystorePrefs(
        context = context.applicationContext,
        prefsName = "ragewarden.rotation.v1",
        keyAlias = "ragewarden.rotation.aead.v1",
    )

    private val _staleness = MutableStateFlow(0)
    val staleness: StateFlow<Int> = _staleness.asStateFlow()

    fun isStale(accountId: String): Boolean {
        if (accountId.isBlank()) return false
        val current = activeFingerprint(accountId) ?: return false
        return RotationProgress.isStale(loadStored(accountId), current)
    }

    fun markFresh(accountId: String) {
        if (accountId.isBlank()) return
        val current = activeFingerprint(accountId) ?: return
        save(accountId, RotationProgress.fresh(current))
        _staleness.value = _staleness.value + 1
    }

    fun markItemRotated(accountId: String, itemId: String): Set<String> {
        if (accountId.isBlank() || itemId.isBlank()) return emptySet()
        val current = activeFingerprint(accountId) ?: return emptySet()
        val stored = loadStored(accountId)
        if (!RotationProgress.isStale(stored, current)) return emptySet()
        val next = RotationProgress.itemRotated(stored, current, itemId)
        save(accountId, next)
        _staleness.value = _staleness.value + 1
        return next.rotatedIds
    }

    fun rotatedItemIds(accountId: String): Set<String> {
        if (accountId.isBlank()) return emptySet()
        val current = activeFingerprint(accountId) ?: return emptySet()
        return RotationProgress.rotatedIds(loadStored(accountId), current)
    }

    fun forget(accountId: String) {
        if (accountId.isBlank()) return
        prefs.remove(prefKey(accountId))
        _staleness.value = _staleness.value + 1
    }

    @Volatile
    var wrapSet: (() -> List<String>)? = null

    private fun activeFingerprint(accountId: String): String? {
        val ids = (runCatching { wrapSet?.invoke() }.getOrNull()
            ?: recipientStore.forAccount(accountId).filter { it.defaultEncrypt }.map { it.id })
            .sorted()
        if (ids.isEmpty()) return null
        val md = MessageDigest.getInstance("SHA-256")
        ids.forEach { md.update(it.toByteArray(Charsets.UTF_8)); md.update(0x1f) }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    private fun loadStored(accountId: String): RotationProgress.Stored? =
        RotationProgress.decode(runCatching { prefs.getString(prefKey(accountId), null) }.getOrNull())

    private fun save(accountId: String, stored: RotationProgress.Stored) {
        prefs.putString(prefKey(accountId), RotationProgress.encode(stored))
    }

    private fun prefKey(accountId: String): String = "rotation:$accountId"
}

internal object RotationProgress {
    @Serializable
    data class Stored(
        val fingerprint: String,
        val rotatedIds: Set<String> = emptySet(),
        val target: String? = null,
    )

    private val JSON = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    fun fresh(current: String): Stored = Stored(fingerprint = current)

    fun isStale(stored: Stored?, current: String): Boolean = stored == null || stored.fingerprint != current

    fun rotatedIds(stored: Stored?, current: String): Set<String> =
        if (stored != null && stored.target == current) stored.rotatedIds else emptySet()

    fun itemRotated(stored: Stored?, current: String, itemId: String): Stored {
        val carried = if (stored?.target == current) stored.rotatedIds else emptySet()
        return Stored(fingerprint = stored?.fingerprint.orEmpty(), rotatedIds = carried + itemId, target = current)
    }

    fun encode(stored: Stored): String = JSON.encodeToString(stored)

    fun decode(raw: String?): Stored? {
        if (raw == null) return null
        val parsed = runCatching { JSON.decodeFromString<Stored>(raw) }.getOrNull() ?: return Stored(fingerprint = raw)
        if (parsed.target == null && parsed.rotatedIds.isNotEmpty()) {
            return Stored(fingerprint = "", rotatedIds = parsed.rotatedIds, target = parsed.fingerprint)
        }
        return parsed
    }
}
