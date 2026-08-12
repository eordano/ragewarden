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
    @Serializable
    private data class Stored(val fingerprint: String, val rotatedIds: Set<String> = emptySet())

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
        val stored = loadStored(accountId) ?: return true
        return current != stored.fingerprint
    }

    fun markFresh(accountId: String) {
        if (accountId.isBlank()) return
        val current = activeFingerprint(accountId) ?: return
        save(accountId, Stored(fingerprint = current, rotatedIds = emptySet()))
        _staleness.value = _staleness.value + 1
    }

    fun markItemRotated(accountId: String, itemId: String): Set<String> {
        if (accountId.isBlank() || itemId.isBlank()) return emptySet()
        val current = activeFingerprint(accountId) ?: return emptySet()
        val stored = loadStored(accountId)
        if (stored != null && stored.fingerprint == current) return stored.rotatedIds
        val ids = (stored?.rotatedIds ?: emptySet()) + itemId
        save(accountId, Stored(fingerprint = current, rotatedIds = ids))
        _staleness.value = _staleness.value + 1
        return ids
    }

    fun rotatedItemIds(accountId: String): Set<String> {
        if (accountId.isBlank()) return emptySet()
        val current = activeFingerprint(accountId) ?: return emptySet()
        val stored = loadStored(accountId) ?: return emptySet()
        return if (stored.fingerprint == current) stored.rotatedIds else emptySet()
    }

    fun forget(accountId: String) {
        if (accountId.isBlank()) return
        prefs.remove(prefKey(accountId))
        _staleness.value = _staleness.value + 1
    }

    private fun activeFingerprint(accountId: String): String? {
        val ids = recipientStore.forAccount(accountId)
            .filter { it.defaultEncrypt }
            .map { it.id }
            .sorted()
        if (ids.isEmpty()) return null
        val md = MessageDigest.getInstance("SHA-256")
        ids.forEach { md.update(it.toByteArray(Charsets.UTF_8)); md.update(0x1f) }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    private fun loadStored(accountId: String): Stored? {
        val raw = prefs.getString(prefKey(accountId), null) ?: return null
        return runCatching { JSON.decodeFromString<Stored>(raw) }.getOrNull()
            ?: runCatching { Stored(fingerprint = raw) }.getOrNull()
    }

    private fun save(accountId: String, stored: Stored) {
        prefs.putString(prefKey(accountId), JSON.encodeToString(stored))
    }

    private fun prefKey(accountId: String): String = "rotation:$accountId"

    companion object {
        private val JSON = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    }
}
