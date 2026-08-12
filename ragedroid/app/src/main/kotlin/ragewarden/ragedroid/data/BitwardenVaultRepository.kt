package ragewarden.ragedroid.data

import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toPersistentList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import androidx.tracing.trace
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.serialization.encodeToString
import org.json.JSONObject
import ragewarden.ragedroid.data.audit.AuditAction
import ragewarden.ragedroid.data.audit.AuditFeed
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.identities.KotlinIdentity
import ragewarden.ragedroid.jni.RageNative

@Singleton
class BitwardenVaultRepository @Inject constructor(
    private val sessionStore: SessionStore,
    private val recipientStore: RecipientStore,
    private val auditFeed: AuditFeed,
    private val rotationTracker: RotationTracker,
    private val historyStore: HistoryStore,
    private val recipientRegistry: RecipientRegistry,
) {
    @Volatile
    private var sessionBlob: ByteArray? = sessionStore.load()

    private data class CachedState(
        val snapshot: VaultSnapshot?,
        val blobMap: CipherRageBlobMap,
        val syncBytes: ByteArray?,
    )

    @Volatile
    private var cached: CachedState = CachedState(null, CipherRageBlobMap(emptyMap()), null)

    private val syncScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val syncMutex = Mutex()

    private var inFlightSync: Deferred<Result<VaultSnapshot>>? = null

    fun hasSession(): Boolean = sessionBlob != null

    suspend fun register(
        server: String,
        email: String,
        password: String,
        name: String,
        kdfIterations: Int = DEFAULT_KDF_ITERATIONS,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            RageNative.register(server, email, password, name, kdfIterations)
            Unit
        }
    }

    suspend fun login(
        server: String,
        email: String,
        password: String,
        deviceName: String = DEFAULT_DEVICE_NAME,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val blob = RageNative.login(server, email, password, deviceName)
            sessionBlob = blob
            sessionStore.save(blob)
        }
    }

    fun logout() {
        sessionStore.clear()
        sessionBlob = null
        cached = CachedState(null, CipherRageBlobMap(emptyMap()), null)
    }

    suspend fun sync(): Result<VaultSnapshot> {
        val deferred = syncMutex.withLock {
            inFlightSync ?: syncScope.async { syncImpl() }.also { inFlightSync = it }
        }
        return try {
            deferred.await()
        } finally {
            syncMutex.withLock {
                if (inFlightSync === deferred) inFlightSync = null
            }
        }
    }

    private fun syncImpl(): Result<VaultSnapshot> {
        val blob = sessionBlob ?: return Result.failure(IllegalStateException("no session"))
        return runCatching {
            val raw = trace("ragewarden.fetchVault") { RageNative.fetchVault(blob) }
            val current = cached
            if (current.snapshot != null && current.syncBytes?.contentEquals(raw) == true) {
                return@runCatching current.snapshot
            }
            trace("ragewarden.parseSnapshot") {
                val obj = JSONObject(String(raw, Charsets.UTF_8))
                val snapshot = VaultSnapshot.fromJsonObject(obj)
                val blobMap = CipherRageBlobMap.fromJsonObject(obj)
                cached = CachedState(snapshot, blobMap, raw)
                snapshot
            }
        }
    }

    /** The user's items: everything ragewarden keeps in the vault as machinery is hidden. */
    fun snapshot(): ImmutableList<VaultItem> {
        val all = cached.snapshot?.items ?: return persistentListOf()
        return all.filterNot { VaultMetaNames.isMeta(it.name) }.toPersistentList()
    }

    internal fun snapshotIncludingMeta(): ImmutableList<VaultItem> =
        cached.snapshot?.items ?: persistentListOf()

    fun snapshotWithRegistryMarker(): ImmutableList<VaultItem> = snapshotIncludingMeta()

    fun get(id: String): VaultItem? = cached.snapshot?.items?.firstOrNull { it.id == id }

    suspend fun decrypt(itemId: String, identities: List<KotlinIdentity>): Result<ByteArray> =
        withContext(Dispatchers.IO) {
            runCatching {
                val state = cached
                val item = state.snapshot?.items?.firstOrNull { it.id == itemId }
                    ?: error("unknown item id: $itemId")
                val plaintext = if (!item.rage) {
                    item.password.toByteArray(Charsets.UTF_8)
                } else {
                    val armored = state.blobMap.byItemId[itemId]
                        ?: error("no rage blob cached for $itemId")
                    val blobBytes = armored.toByteArray(Charsets.UTF_8)
                    if (identities.isEmpty()) {
                        error("no identities supplied for rage-encrypted item")
                    } else {
                        RageNative.decryptWithIdentities(blobBytes, identities.toTypedArray())
                    }
                }
                auditFeed.record(AuditAction.Reveal, item.name, site = item.site.takeIf { it.isNotBlank() })
                if (item.rage) maybeRotateInBackground(item, plaintext)
                plaintext
            }
        }

    private fun maybeRotateInBackground(item: VaultItem, plaintext: ByteArray) {
        if (!rotationTracker.isStale(accountId)) return
        if (item.id in rotationTracker.rotatedItemIds(accountId)) return
        syncScope.launch {
            runCatching {
                update(item, plaintext).getOrThrow()
                val rotated = rotationTracker.markItemRotated(accountId, item.id)
                val rageTotal = cached.snapshot?.items?.count { it.rage } ?: 0
                if (rageTotal > 0 && rotated.size >= rageTotal) {
                    rotationTracker.markFresh(accountId)
                    auditFeed.record(
                        action = AuditAction.Rotate,
                        item = "Recipient set",
                        reason = "All items rotated to current recipients",
                    )
                }
            }
        }
    }

    suspend fun create(
        item: VaultItem,
        plaintext: ByteArray,
    ): Result<VaultItem> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(IllegalStateException("no session"))
        runCatching {
            val ageBlob = encryptForActiveRecipients(plaintext)
            val armored = String(ageBlob, Charsets.UTF_8)
            val cipherIn = RageNative.buildRageCipherInFolder(blob, item.name, armored, item.folderId)
            RageNative.createCipher(blob, cipherIn)
            sync().getOrThrow()
            val saved = get(item.id) ?: item
            auditFeed.record(AuditAction.Enroll, saved.name, site = saved.site.takeIf { it.isNotBlank() })
            historyStore.recordCreated(accountId, saved.id, deviceLabel())
            saved
        }
    }

    suspend fun update(
        item: VaultItem,
        plaintext: ByteArray?,
    ): Result<VaultItem> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(IllegalStateException("no session"))
        runCatching {
            val cipherIn = if (plaintext != null) {
                val ageBlob = encryptForActiveRecipients(plaintext)
                val armored = String(ageBlob, Charsets.UTF_8)
                RageNative.buildRageCipherInFolder(blob, item.name, armored, item.folderId)
            } else {
                val existing = cached.blobMap.byItemId[item.id]
                    ?: error("cannot update metadata for non-rage item without rage blob")
                RageNative.buildRageCipherInFolder(blob, item.name, existing, item.folderId)
            }
            RageNative.updateCipher(blob, item.id, cipherIn)
            sync().getOrThrow()
            val saved = get(item.id) ?: item
            if (plaintext != null) {
                auditFeed.record(AuditAction.Rotate, saved.name, site = saved.site.takeIf { it.isNotBlank() })
                historyStore.recordRotated(accountId, saved.id, deviceLabel())
            } else {
                historyStore.recordModified(
                    accountId = accountId,
                    itemId = saved.id,
                    deviceLabel = deviceLabel(),
                    changes = listOf(ragewarden.ragedroid.ui.screens.HistoryChange("Metadata", diff = "updated")),
                )
            }
            saved
        }
    }

    private fun deviceLabel(): String {
        val model = android.os.Build.MODEL ?: "this device"
        val backing = if (recipientStore.forAccount(accountId).any { it.kind == ragewarden.ragedroid.model.RecipientKind.StrongBox }) {
            "StrongBox"
        } else {
            "this device"
        }
        return "$model · $backing"
    }

    /**
     * Publish this device's recipients into the one shared registry cipher.
     *
     * Read-modify-WRITE, and the read is a fresh [sync], not the cache. This
     * used to build its payload from `cached.snapshot` and sync only *after*
     * the write, which broke in two ways that were both reproduced against a
     * live server:
     *
     *  - Cold cache. The ordinary first-run path -- FirstRunScreen's
     *    login() -> Enroll -> persistRecipient() -> here -- never syncs in
     *    between, so `remoteEntries` was empty AND `markerCipherId` was null.
     *    That took the `createCipher` branch and left a SECOND
     *    `__ragedroid_recipients_v1__` cipher on the server holding only this
     *    phone's key. `core::registry::find_marker_cipher` then takes whichever
     *    the server returns first, so the browser's own Software and passkey
     *    entries vanished from every client's view: it could no longer decrypt
     *    what it had written, and unpublishing its entry became a no-op against
     *    the marker nobody was reading.
     *  - Stale-but-nonempty cache. Same write, quieter: any entry another
     *    client published since the last sync is simply not in the payload and
     *    is dropped.
     *
     * Both are the same rule -- never write a registry you did not just read --
     * and [RecipientRegistry.readEntries] enforces the rest of it by refusing
     * to build on a registry that is duplicated or unparseable instead of
     * replacing it.
     */
    suspend fun pushRecipientRegistry(): Result<Unit> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(IllegalStateException("no session"))
        runCatching {
            sync().getOrThrow()
            val current = cached.snapshot?.items ?: persistentListOf()
            val remoteEntries = recipientRegistry.readEntries(current)
            // Mock recipients never leave the device. A previous audit found
            // simulated hardware published to the cross-device registry as a
            // genuine YubiKey entry, where every other device would then wrap
            // real secrets to a key that does not exist. This filter is
            // unconditional -- it does not consult MockHardware.enabled(), because
            // a debug build must not be able to poison a shared registry either.
            val localEntries = recipientStore.forAccount(accountId).filterNot { it.mock }
            val ownedIds = localEntries.map { it.id }.toSet()
            val mergedRemote = remoteEntries
                .filterNot { it.id in ownedIds }
                .filterNot { remote ->
                    remote.kind == RecipientKind.StrongBox.name &&
                        (remote.keystorePubkey?.length ?: 0) != EXPECTED_KEYSTORE_PUBKEY_HEX_LEN
                }
            // The same projection the wrap path uses (RecipientPolicy), not a
            // second hand-rolled copy: the copy that lived here read only
            // `fido2*`, so a locally enrolled passkey published with a null
            // credential id and came back to every other client as
            // `MalformedKeyMaterial`.
            val label = deviceLabel()
            val mergedLocalAsWire = with(RecipientPolicy) { localEntries.map { it.toPolicyWire(label) } }
            val payload = kotlinx.serialization.json.Json.encodeToString(
                RecipientRegistry.WireDocument.serializer(),
                RecipientRegistry.WireDocument(
                    schema = 1,
                    entries = mergedRemote + mergedLocalAsWire,
                ),
            )
            val cipherIn = RageNative.buildMetaCipher(blob, RecipientRegistry.MARKER_NAME, payload)
            // readEntries() has already refused if there is more than one, so
            // this is "the marker" and not "a marker".
            val existingId = recipientRegistry.markerCipherId(current)
            if (existingId != null) {
                RageNative.updateCipher(blob, existingId, cipherIn)
            } else {
                RageNative.createCipher(blob, cipherIn)
            }
            sync().getOrThrow()
            Unit
        }
    }

    suspend fun decryptWithRecoveryPhrase(
        itemId: String,
        phrase: String,
    ): Result<ByteArray> = withContext(Dispatchers.IO) {
        runCatching {
            val state = cached
            val item = state.snapshot?.items?.firstOrNull { it.id == itemId }
                ?: error("unknown item id: $itemId")
            if (!item.rage) error("item $itemId is not rage-protected")
            val armored = state.blobMap.byItemId[itemId]
                ?: error("no rage blob cached for $itemId")
            val secretBytes = RageNative.recoveryFromPhrase(phrase)
            val armoredSecret = String(secretBytes, Charsets.UTF_8)
            try {
                RageNative.decryptWithSoftwareSecret(
                    armored.toByteArray(Charsets.UTF_8),
                    armoredSecret,
                )
            } finally {
                secretBytes.fill(0)
            }
        }
    }

    /**
     * Same read-modify-write rule as [pushRecipientRegistry], and for the same
     * reason: run against a cold cache this found no marker and returned
     * success without removing anything -- the silent no-op the browser saw when
     * it tried to withdraw its own entry.
     */
    suspend fun unpublishRecipient(recipientId: String): Result<Unit> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(IllegalStateException("no session"))
        runCatching {
            sync().getOrThrow()
            val current = cached.snapshot?.items ?: persistentListOf()
            val remoteEntries = recipientRegistry.readEntries(current)
            val existingId = recipientRegistry.markerCipherId(current)
                ?: return@runCatching Unit
            val filtered = remoteEntries.filterNot { it.id == recipientId }
            if (filtered.size == remoteEntries.size) {
                return@runCatching Unit
            }
            val payload = kotlinx.serialization.json.Json.encodeToString(
                RecipientRegistry.WireDocument.serializer(),
                RecipientRegistry.WireDocument(schema = 1, entries = filtered),
            )
            val cipherIn = RageNative.buildMetaCipher(blob, RecipientRegistry.MARKER_NAME, payload)
            RageNative.updateCipher(blob, existingId, cipherIn)
            sync().getOrThrow()
            Unit
        }
    }

    @Volatile
    private var prfTapper: PrfTapper? = null

    fun installPrfTapper(tapper: PrfTapper?) {
        prfTapper = tapper
    }

    private suspend fun encryptForActiveRecipients(plaintext: ByteArray): ByteArray {
        val recipients = collectActiveRecipients()
        if (recipients.isEmpty()) {
            throw NoRecipientsConfiguredException()
        }
        val prfRequests = recipients.mapNotNull { r ->
            when (r) {
                is WireRecipient.Fido2HmacSecret -> PrfRequest(r.rp_id, r.salt)
                is WireRecipient.PasskeyPrf -> PrfRequest(r.rp_id, r.salt)
                else -> null
            }
        }
        val prfInputs = if (prfRequests.isEmpty()) {
            emptyList()
        } else {
            val tapper = prfTapper
                ?: throw PrfTapperNotConfiguredException(prfRequests.size)
            tapper.tap(prfRequests)
        }
        val recipientsBytes = WireJson
            .encodeToString(WireRecipientListSerializer, recipients)
            .toByteArray(Charsets.UTF_8)
        val prfBytes = WireJson
            .encodeToString(WirePrfInputListSerializer, prfInputs)
            .toByteArray(Charsets.UTF_8)
        return RageNative.encryptToRecipients(plaintext, recipientsBytes, prfBytes)
    }

    /**
     * Delegates to the ONE canonical policy in core (`ragewarden_core::policy`),
     * the same one rageterm and ragemanifest run.
     *
     * This used to be a Kotlin `when` that dropped `RecipientKind.Software`
     * outright, while ragemanifest dropped StrongBox and YubiKey and rageterm
     * dropped PRF kinds. Three filters in three languages meant an item saved
     * here could be cryptographically unopenable in the browser and vice versa,
     * silently, with both clients reporting success. Do not reintroduce the
     * `when`; change `core/src/policy.rs`.
     */
    private fun collectActiveRecipients(): List<WireRecipient> {
        if (accountId.isBlank()) return emptyList()

        val localStored = recipientStore.forAccount(accountId)
        val label = deviceLabel()
        val localEntries = with(RecipientPolicy) { localStored.map { it.toPolicyWire(label) } }
        // readEntries, not extractFromSnapshot: a registry we cannot read must
        // fail the save rather than silently wrap the secret to this device's
        // keys alone, which is what "corrupt reads as empty" produced -- an item
        // that looks saved and that no other client can open.
        val registryEntries = recipientRegistry.readEntries(snapshotIncludingMeta())

        val selection = RecipientPolicy.select(
            registry = registryEntries,
            local = localEntries,
            localPrfEntryIds = RecipientPolicy.localPrfEntryIds(localStored),
        )

        for (skip in selection.skipped) {
            android.util.Log.w(
                "BitwardenVaultRepository",
                "recipient ${skip.id} (${skip.kind}) not wrapped: ${skip.reason}",
            )
        }
        return selection.recipients
    }

    companion object {
        const val DEFAULT_KDF_ITERATIONS: Int = 600_000
        const val DEFAULT_DEVICE_NAME: String = "ragedroid-android"
        private const val EXPECTED_KEYSTORE_PUBKEY_HEX_LEN: Int = 33 * 2
    }

    private fun parsedSession(): JSONObject? {
        val blob = sessionBlob ?: return null
        return runCatching {
            JSONObject(String(blob, Charsets.UTF_8))
        }.getOrNull()
    }

    private fun sessionString(key: String): String =
        parsedSession()?.optString(key, "") ?: ""

    private fun sessionInt(key: String, default: Int): Int =
        parsedSession()?.optInt(key, default) ?: default

    val email: String get() = sessionString("email")

    val serverUrl: String
        get() {
            val obj = parsedSession() ?: return ""
            val api = obj.optString("apiUrl", "")
            if (api.isNotEmpty()) return api
            return obj.optString("identityUrl", "")
        }

    val accountId: String get() = sessionString("userId")

    val kdfIterations: Int get() = sessionInt("kdfIterations", DEFAULT_KDF_ITERATIONS)

    suspend fun verifyMasterPassword(pw: String): Result<Boolean> = withContext(Dispatchers.IO) {
        val obj = parsedSession()
            ?: return@withContext Result.failure(IllegalStateException("no session"))
        val server = obj.optString("apiUrl", "")
            .ifEmpty { obj.optString("identityUrl", "") }
        val mail = obj.optString("email", "")
        if (server.isEmpty() || mail.isEmpty()) {
            return@withContext Result.failure(IllegalStateException("session missing server or email"))
        }
        runCatching {
            val freshBlob = RageNative.login(server, mail, pw, DEFAULT_DEVICE_NAME)
            freshBlob.size > 0
        }
    }

    suspend fun deleteCipher(itemId: String): Result<Unit> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(IllegalStateException("no session"))
        val target = get(itemId)
        runCatching {
            RageNative.deleteCipher(blob, itemId)
            val current = cached
            val snapshot = current.snapshot
            if (snapshot != null) {
                val remaining = snapshot.items.filterNot { it.id == itemId }.toPersistentList()
                cached = current.copy(
                    snapshot = snapshot.copy(items = remaining),
                    blobMap = CipherRageBlobMap(current.blobMap.byItemId - itemId),
                    syncBytes = null,
                )
            } else {
                cached = CachedState(null, CipherRageBlobMap(emptyMap()), null)
            }
            if (accountId.isNotBlank()) {
                runCatching { historyStore.clearItem(accountId, itemId) }
            }
            auditFeed.record(
                action = AuditAction.Delete,
                item = target?.name ?: itemId,
                site = target?.site?.takeIf { it.isNotBlank() },
            )
            sync().getOrThrow()
            Unit
        }
    }

    suspend fun deleteItem(itemId: String): Result<Unit> = deleteCipher(itemId)

    suspend fun listFolders(): Result<ImmutableList<Folder>> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(IllegalStateException("no session"))
        runCatching {
            val raw = RageNative.listFolders(blob)
            val arr = org.json.JSONArray(String(raw, Charsets.UTF_8))
            val out = mutableListOf<Folder>()
            for (i in 0 until arr.length()) {
                val f = arr.optJSONObject(i) ?: continue
                val id = f.optString("id")
                if (id.isEmpty()) continue
                out.add(Folder(id = id, name = f.optString("name")))
            }
            kotlinx.collections.immutable.persistentListOf<Folder>().addAll(out)
        }
    }

    suspend fun createFolder(name: String): Result<Folder> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(IllegalStateException("no session"))
        runCatching {
            val bytes = RageNative.createFolder(blob, name)
            val parsed = JSONObject(String(bytes, Charsets.UTF_8))
            cached = CachedState(null, CipherRageBlobMap(emptyMap()), null)
            Folder(id = parsed.optString("id"), name = parsed.optString("name"))
        }
    }

    suspend fun updateFolder(folderId: String, name: String): Result<Folder> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(IllegalStateException("no session"))
        runCatching {
            val bytes = RageNative.updateFolder(blob, folderId, name)
            val parsed = JSONObject(String(bytes, Charsets.UTF_8))
            cached = CachedState(null, CipherRageBlobMap(emptyMap()), null)
            Folder(id = parsed.optString("id"), name = parsed.optString("name"))
        }
    }

    suspend fun deleteFolder(folderId: String): Result<Unit> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(IllegalStateException("no session"))
        runCatching {
            RageNative.deleteFolder(blob, folderId)
            cached = CachedState(null, CipherRageBlobMap(emptyMap()), null)
            Unit
        }
    }
}
