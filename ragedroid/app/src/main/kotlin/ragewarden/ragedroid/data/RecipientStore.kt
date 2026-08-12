package ragewarden.ragedroid.data

import android.content.Context
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
import ragewarden.ragedroid.identities.MockHardware
import ragewarden.ragedroid.model.Recipient
import ragewarden.ragedroid.model.RecipientKind

@Serializable
data class StoredRecipient(
    val id: String,
    val kind: RecipientKind,
    val displayName: String,
    val createdAt: Long,
    val lastUsedAt: Long,
    val defaultEncrypt: Boolean = true,
    val pivPubkey: ByteArray? = null,
    val pivSerial: Int? = null,
    val pivSlot: Byte? = null,
    val fido2CredentialId: ByteArray? = null,
    val fido2RpId: String? = null,
    val fido2Salt: ByteArray? = null,
    val keystorePubkey: ByteArray? = null,
    val keystoreHandle: String? = null,
    val passkeyCredentialId: ByteArray? = null,
    val passkeyRpId: String? = null,
    val passkeySalt: ByteArray? = null,
    val recoveryArmoredPubkey: String? = null,
    /**
     * True when the Keystore key was generated with
     * `setUserAuthenticationRequired(true)`. Null means "enrolled before this
     * field existed" and is treated as *not* auth-bound, i.e. as a recipient
     * that cannot enforce a physical action.
     */
    val keystoreAuthBound: Boolean? = null,
    /**
     * True when this recipient's "hardware" is simulated. Mock recipients are
     * never published to the cross-device registry
     * (`BitwardenVaultRepository.pushRecipientRegistry`), are dropped entirely by
     * [RecipientStore.forAccount] outside a mock-enabled debug build, and render
     * with [MockHardware.LABEL_PREFIX] wherever they are shown.
     */
    val mock: Boolean = false,
) {
    override fun equals(other: Any?): Boolean = other is StoredRecipient && other.id == id
    override fun hashCode(): Int = id.hashCode()
}

class RecipientStore(context: Context) {
    private var activeAccountId: String? = null

    private val mutex = Mutex()

    private val prefs = KeystorePrefs(
        context = context.applicationContext,
        prefsName = "ragewarden.recipients.v2",
        keyAlias = "ragewarden.recipients.aead.v1",
    )

    private val _flow = MutableStateFlow<List<StoredRecipient>>(emptyList())
    val flow: StateFlow<List<StoredRecipient>> = _flow.asStateFlow()

    fun forAccount(accountId: String): List<StoredRecipient> =
        loadAll(accountId)
            .filterNot {
                it.kind == RecipientKind.StrongBox &&
                    (it.keystorePubkey?.size ?: 0) != EXPECTED_KEYSTORE_PUBKEY_LEN
            }
            // A mock recipient persisted by a debug build must not become live if
            // the same profile is ever read by a release build.
            .filterNot { it.mock && !MockHardware.enabled() }

    suspend fun setActiveAccount(accountId: String?) {
        withContext(Dispatchers.IO) {
            mutex.withLock {
                activeAccountId = accountId
                if (accountId != null && accountId.isNotBlank()) {
                    pruneLegacyKeystoreEntriesLocked(accountId)
                }
                _flow.value = loadAll(accountId)
            }
        }
    }

    private fun pruneLegacyKeystoreEntriesLocked(accountId: String) {
        val current = loadAll(accountId)
        val cleaned = current.filterNot {
            it.kind == RecipientKind.StrongBox &&
                (it.keystorePubkey?.size ?: 0) != EXPECTED_KEYSTORE_PUBKEY_LEN
        }
        if (cleaned.size != current.size) {
            save(accountId, cleaned)
        }
    }

    suspend fun add(accountId: String, recipient: StoredRecipient) {
        withContext(Dispatchers.IO) {
            mutex.withLock {
                val current = loadAll(accountId).toMutableList()
                current.removeAll { it.id == recipient.id }
                current.add(recipient)
                save(accountId, current)
                if (accountId == activeAccountId) _flow.value = current
            }
        }
    }

    suspend fun remove(accountId: String, recipientId: String) {
        withContext(Dispatchers.IO) {
            mutex.withLock {
                val current = loadAll(accountId).filterNot { it.id == recipientId }
                save(accountId, current)
                if (accountId == activeAccountId) _flow.value = current
            }
        }
    }

    suspend fun setDefaultEncrypt(accountId: String, recipientId: String, defaultEncrypt: Boolean) {
        withContext(Dispatchers.IO) {
            mutex.withLock {
                val current = loadAll(accountId).map {
                    if (it.id == recipientId) it.copy(defaultEncrypt = defaultEncrypt) else it
                }
                save(accountId, current)
                if (accountId == activeAccountId) _flow.value = current
            }
        }
    }

    suspend fun touch(
        accountId: String,
        recipientId: String,
        now: Long = System.currentTimeMillis(),
    ) {
        withContext(Dispatchers.IO) {
            mutex.withLock {
                val current = loadAll(accountId).map {
                    if (it.id == recipientId) it.copy(lastUsedAt = now) else it
                }
                save(accountId, current)
                if (accountId == activeAccountId) _flow.value = current
            }
        }
    }

    suspend fun clearAccount(accountId: String) {
        withContext(Dispatchers.IO) {
            mutex.withLock {
                prefs.remove(prefKey(accountId))
                if (accountId == activeAccountId) _flow.value = emptyList()
            }
        }
    }

    private fun loadAll(accountId: String?): List<StoredRecipient> {
        if (accountId.isNullOrBlank()) return emptyList()
        val raw = prefs.getString(prefKey(accountId), null) ?: return emptyList()
        return runCatching { JSON.decodeFromString<List<StoredRecipient>>(raw) }.getOrDefault(emptyList())
    }

    private fun save(accountId: String, list: List<StoredRecipient>) {
        prefs.putString(prefKey(accountId), JSON.encodeToString(list))
    }

    private fun prefKey(accountId: String): String = "recipients:$accountId"

    companion object {
        private val JSON = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        private const val EXPECTED_KEYSTORE_PUBKEY_LEN = 33
    }
}

fun StoredRecipient.toUiRecipient(): Recipient = Recipient(
    id = id,
    kind = kind,
    name = MockHardware.label(displayName, mock),
    serial = pivSerial?.toString() ?: "",
    fingerprint = fingerprintShort(),
    enrolled = "",
    lastUsed = "",
    slot = pivSlot?.let { "0x%02x".format(it.toInt() and 0xFF) },
    firmware = null,
    coverage = null,
    descriptors = RecipientDescriptors.forStored(this),
    isMock = mock,
)

private fun StoredRecipient.fingerprintShort(): String {
    val bytes = pivPubkey ?: keystorePubkey ?: fido2CredentialId ?: passkeyCredentialId
    if (bytes == null) {
        val s = recoveryArmoredPubkey
        return if (s != null && s.length >= 16) s.takeLast(12) else "--"
    }
    return bytes.take(6).joinToString(":") { "%02x".format(it) }
}
