package ragewarden.ragedroid.data

import androidx.tracing.trace
import javax.inject.Inject
import javax.inject.Singleton
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
import kotlinx.serialization.encodeToString
import org.json.JSONObject
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.audit.AuditAction
import ragewarden.ragedroid.data.audit.AuditFeed
import ragewarden.ragedroid.identities.KotlinIdentity
import ragewarden.ragedroid.identities.NoUsableIdentityException
import ragewarden.ragedroid.jni.RageNative
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.uiString

@Singleton
class BitwardenVaultRepository @Inject constructor(
    private val sessionStore: SessionStore,
    private val recipientStore: RecipientStore,
    private val auditFeed: AuditFeed,
    private val rotationTracker: RotationTracker,
    private val historyStore: HistoryStore,
    private val recipientRegistry: RecipientRegistry,
    private val lockState: LockState,
    private val vaultCache: VaultCache,
    private val deviceIdentity: DeviceIdentity,
    private val kdfPins: KdfPinStore,
) {
    @Volatile
    private var sessionBlob: ByteArray? = sessionStore.load()

    init {
        rotationTracker.wrapSet = {
            collectActiveRecipients().map { WireJson.encodeToString(WireRecipientListSerializer, listOf(it)) }
        }
        lockState.addOnLockListener { lock() }
        if (lockState.isLocked) lock()
    }

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
        allowLegacyKdf: Boolean = false,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val first = try {
                RageNative.loginWithDevice(server, email, password, deviceName, deviceIdentity.id, kdfPins.get(server, email), allowLegacyKdf)
            } catch (e: RuntimeException) {
                throw LegacyKdfException.from(e) ?: e
            }
            val blob = if (allowLegacyKdf) {
                runCatching { RageNative.upgradeKdf(first, password, deviceName) }.getOrElse { first }
            } else {
                first
            }
            sessionBlob = blob
            sessionStore.save(SessionBlobs.strip(blob))
            SessionBlobs.kdfPin(blob)?.let { kdfPins.put(server, email, it) }
            auditFeed.record(AuditAction.Login, email, site = server)
        }
    }

    fun logout() {
        sessionStore.clear()
        vaultCache.clear()
        sessionBlob?.fill(0)
        sessionBlob = null
        cached = CachedState(null, CipherRageBlobMap(emptyMap()), null)
    }

    val isUnlocked: Boolean get() = SessionBlobs.hasKeys(sessionBlob)

    @Synchronized
    fun lock() {
        val blob = sessionBlob ?: return
        if (SessionBlobs.hasKeys(blob)) {
            sessionBlob = SessionBlobs.strip(blob)
            blob.fill(0)
        }
        cached = CachedState(null, CipherRageBlobMap(emptyMap()), null)
    }

    suspend fun unlockWithPassword(pw: String): Result<Boolean> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
        runCatching {
            val unlocked = if (SessionBlobs.hasProtectedKey(blob)) {
                RageNative.unlockSession(SessionBlobs.strip(blob), pw).takeIf { it.isNotEmpty() }
            } else {
                reauthenticateOnline(blob, pw)
            } ?: return@runCatching false
            installUnlocked(unlocked)
            true
        }
    }

    suspend fun unlockWithSessionBlob(unlocked: ByteArray): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            if (!SessionBlobs.hasKeys(unlocked)) throw UserFacingException { uiString(R.string.error_saved_unlock_without_keys) }
            installUnlocked(unlocked)
        }
    }

    fun unlockedSessionForWrapping(): ByteArray? = sessionBlob?.takeIf { SessionBlobs.hasKeys(it) }?.copyOf()

    private fun installUnlocked(unlocked: ByteArray) {
        sessionBlob = unlocked
        sessionStore.save(SessionBlobs.strip(unlocked))
        val raw = cached.syncBytes ?: vaultCache.load()
        if (raw != null) runCatching { decodeRaw(unlocked, raw) }
    }

    private fun reauthenticateOnline(blob: ByteArray, pw: String): ByteArray? {
        val server = SessionBlobs.field(blob, "apiUrl").ifEmpty { SessionBlobs.field(blob, "identityUrl") }
        val mail = SessionBlobs.field(blob, "email")
        if (server.isEmpty() || mail.isEmpty()) throw UserFacingException { uiString(R.string.error_sign_in_incomplete) }
        val device = SessionBlobs.field(blob, "deviceId").ifEmpty { deviceIdentity.id }
        return try {
            RageNative.loginWithDevice(server, mail, pw, DEFAULT_DEVICE_NAME, device, SessionBlobs.kdfPin(blob), false)
        } catch (e: RuntimeException) {
            if (isRejectedCredential(e)) null else throw e
        }
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
        val blob = sessionBlob ?: return Result.failure(NotSignedInException())
        return runCatching {
            val raw = trace("ragewarden.fetchVault") { withFreshToken { RageNative.fetchVaultRaw(it) } }
            val current = cached
            if (current.snapshot != null && current.syncBytes?.contentEquals(raw) == true) {
                return@runCatching current.snapshot
            }
            runCatching { vaultCache.save(raw) }
            if (!SessionBlobs.hasKeys(blob)) throw VaultLockedException()
            decodeRaw(blob, raw)
        }
    }

    private fun <T> withFreshToken(call: (ByteArray) -> T): T {
        val blob = sessionBlob ?: throw NotSignedInException()
        return try {
            call(blob)
        } catch (e: RuntimeException) {
            if (!isUnauthorized(e)) throw e
            val refreshed = try {
                RageNative.refreshSession(blob)
            } catch (r: RuntimeException) {
                throw SessionExpiredException(r)
            }
            sessionBlob = refreshed
            sessionStore.save(SessionBlobs.strip(refreshed))
            call(refreshed)
        }
    }

    fun restoreFromCache(): Boolean {
        val blob = sessionBlob?.takeIf { SessionBlobs.hasKeys(it) } ?: return false
        if (cached.snapshot != null) return true
        val raw = vaultCache.load() ?: return false
        return runCatching { decodeRaw(blob, raw) }.isSuccess
    }

    private fun decodeRaw(blob: ByteArray, raw: ByteArray): VaultSnapshot =
        trace("ragewarden.parseSnapshot") {
            val obj = JSONObject(String(RageNative.decryptVault(blob, raw), Charsets.UTF_8))
            val snapshot = VaultSnapshot.fromJsonObject(obj)
            val blobMap = CipherRageBlobMap.fromJsonObject(obj)
            cached = CachedState(snapshot, blobMap, raw)
            snapshot
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

    suspend fun decrypt(
        itemId: String,
        identities: List<KotlinIdentity>,
        use: AuditAction? = AuditAction.Reveal,
        field: String = "",
    ): Result<ByteArray> =
        withContext(Dispatchers.IO) {
            val name = get(itemId)?.name ?: itemId
            runCatching {
                val state = cached
                val item = state.snapshot?.items?.firstOrNull { it.id == itemId }
                    ?: throw UserFacingException { uiString(R.string.error_item_gone) }
                val wanted = ItemFields.canonical(item.kind, field)
                val plaintext = if (field != ItemFields.WHOLE_PAYLOAD && !ItemFields.needsTap(item, field)) {
                    val outer = ItemFields.outerValue(item, field)
                        ?: if (wanted == "password") "" else throw UserFacingException { uiString(R.string.error_item_has_no_field, item.name, ItemFields.label(wanted).lowercase()) }
                    outer.toByteArray(Charsets.UTF_8)
                } else {
                    val armored = state.blobMap.byItemId[itemId]
                        ?: throw UserFacingException { uiString(R.string.error_item_not_on_device) }
                    if (identities.isEmpty()) throw NoUsableIdentityException(emptyList(), uiString(R.string.no_key_on_this_device_can))
                    val payload = decryptTyped(armored, identities)
                    try {
                        maybeRotateInBackground(item, payload.copyOf())
                        if (field == ItemFields.WHOLE_PAYLOAD) {
                            payload.copyOf()
                        } else {
                            RageNative.protectedField(ItemFields.cipherType(item.kind), payload, field)
                        }
                    } finally {
                        payload.fill(0)
                    }
                }
                if (use != null) auditFeed.record(use, item.name, site = item.site.takeIf { it.isNotBlank() })
                plaintext
            }.onFailure { e ->
                auditFeed.record(
                    action = use ?: AuditAction.Reveal,
                    item = name,
                    reason = e.message,
                    result = if (e is ragewarden.ragedroid.identities.HardwareTapCancelledException) {
                        ragewarden.ragedroid.data.audit.AuditResult.Declined
                    } else {
                        ragewarden.ragedroid.data.audit.AuditResult.Failed
                    },
                )
            }
        }

    /**
     * Protected items still wrapped to a recipient set that has since changed
     * (a revoke, a key added here or by another device): what [rewrap] renews.
     */
    fun staleProtectedItems(): List<VaultItem> =
        if (!rotationTracker.isStale(accountId)) {
            emptyList()
        } else {
            val done = rotationTracker.rotatedItemIds(accountId)
            snapshot().filter { it.rage && it.id !in done }
        }

    /**
     * Opens [itemId]'s whole payload with [identities] and writes it back to
     * the current recipients, unchanged -- the bulk form of the rotation a
     * reveal does in the background. Once every stale item is done the vault
     * is marked fresh.
     */
    suspend fun rewrap(itemId: String, identities: List<KotlinIdentity>): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val item = get(itemId) ?: throw UserFacingException { uiString(R.string.error_item_gone) }
            val armored = cached.blobMap.byItemId[itemId] ?: throw UserFacingException { uiString(R.string.error_item_not_on_device) }
            if (identities.isEmpty()) throw NoUsableIdentityException(emptyList(), uiString(R.string.no_key_on_this_device_can))
            val payload = decryptTyped(armored, identities)
            try {
                update(item, payload).getOrThrow()
            } finally {
                payload.fill(0)
            }
            val rotated = rotationTracker.markItemRotated(accountId, item.id)
            val rageTotal = cached.snapshot?.items?.count { it.rage } ?: 0
            if (rageTotal > 0 && rotated.size >= rageTotal) rotationTracker.markFresh(accountId)
            Unit
        }
    }

    private fun maybeRotateInBackground(item: VaultItem, payload: ByteArray) {
        if (!rotationTracker.isStale(accountId) || item.id in rotationTracker.rotatedItemIds(accountId)) {
            payload.fill(0)
            return
        }
        syncScope.launch {
            runCatching {
                try {
                    update(item, payload).getOrThrow()
                } finally {
                    payload.fill(0)
                }
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
        plaintext: ByteArray?,
    ): Result<VaultItem> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
        runCatching {
            val armored = if (item.rage) {
                String(encryptForActiveRecipients(plaintext ?: throw UserFacingException { uiString(R.string.error_protected_needs_secret) }), Charsets.UTF_8)
            } else {
                null
            }
            val plain = plaintext?.takeIf { !item.rage }?.let { String(it, Charsets.UTF_8) }
            val draft = CipherWrites.draft(
                item,
                plainPassword = plain.takeIf { item.kind == ragewarden.ragedroid.model.VaultItemKind.Login },
                plainNotes = plain.takeIf { item.kind == ragewarden.ragedroid.model.VaultItemKind.Note },
            )
            val cipherIn = RageNative.buildCipher(blob, draft, armored)
            withFreshToken { RageNative.createCipher(it, cipherIn) }
            sync().getOrThrow()
            val saved = get(item.id) ?: item
            auditFeed.record(AuditAction.Set, saved.name, site = saved.site.takeIf { it.isNotBlank() })
            historyStore.recordCreated(accountId, saved.id, deviceLabel())
            saved
        }
    }

    /**
     * A card, identity, SSH key or login. [secrets] are sealed together into
     * the rage blob (core's v2 field map, or v1 for the primary field alone)
     * and kept out of the Type-2 layer; [block] holds the rest of a typed
     * item's fields, and a login's other fields come from [item].
     */
    suspend fun createTyped(
        item: VaultItem,
        block: Map<String, String>,
        secrets: Map<String, String>,
    ): Result<VaultItem> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
        runCatching {
            val sealed = secrets.filterValues { it.isNotEmpty() }
            val armored = if (sealed.isEmpty()) null else seal(item, sealed.mapValues { it.value.toByteArray(Charsets.UTF_8) })
            val draft = if (item.kind == ragewarden.ragedroid.model.VaultItemKind.Login) {
                CipherWrites.loginDraft(item, sealed.keys)
            } else {
                CipherWrites.typedDraft(item, block, sealed.keys)
            }
            val cipherIn = RageNative.buildCipher(blob, draft, armored)
            withFreshToken { RageNative.createCipher(it, cipherIn) }
            sync().getOrThrow()
            val saved = snapshot().firstOrNull { it.name == item.name && it.kind == item.kind } ?: item
            auditFeed.record(AuditAction.Set, saved.name)
            historyStore.recordCreated(accountId, saved.id, deviceLabel())
            saved
        }
    }

    suspend fun update(
        item: VaultItem,
        plaintext: ByteArray?,
    ): Result<VaultItem> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
        runCatching {
            val armored = plaintext?.let { String(encryptForActiveRecipients(it), Charsets.UTF_8) }
            val current = get(item.id)
            val meta = JSONObject()
            if (current != null && current.name != item.name) meta.put("name", item.name)
            if (current != null && current.folderId != item.folderId) {
                if (item.folderId == null) meta.put("clearFolder", true) else meta.put("folderId", item.folderId)
            }
            withFreshToken { RageNative.updateCipherPreserving(it, item.id, armored, meta.toString().toByteArray(Charsets.UTF_8)) }
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

    suspend fun edit(item: VaultItem, edit: ItemEdit): Result<VaultItem> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
        runCatching {
            val secret = edit.newSecret
            val currentBlob = cached.blobMap.byItemId[item.id]
            val plainPassword = secret?.takeIf { !item.rage && item.kind == ragewarden.ragedroid.model.VaultItemKind.Login }
                ?.let { String(it, Charsets.UTF_8) }
            val (armored, protectedNames) = when {
                edit.migrateToSsh != null -> {
                    if (!item.rage || item.kind != ragewarden.ragedroid.model.VaultItemKind.Note) throw UserFacingException { uiString(R.string.error_only_protected_note_to_ssh) }
                    (currentBlob ?: throw UserFacingException { uiString(R.string.error_item_not_on_device) }) to listOf("privateKey")
                }
                item.rage && (secret != null || !edit.secretChanges.isNullOrEmpty()) -> resealed(item, edit)
                else -> null to null
            }
            if (armored != null && armored != currentBlob && currentBlob != null) recordHistory(item, currentBlob, deleted = false)
            withFreshToken { RageNative.updateCipherPreserving(it, item.id, armored, CipherWrites.edit(item, edit, plainPassword, protectedNames)) }
            sync().getOrThrow()
            val saved = get(item.id) ?: item
            auditFeed.record(AuditAction.Update, saved.name, site = saved.site.takeIf { it.isNotBlank() })
            historyStore.recordModified(
                accountId = accountId,
                itemId = saved.id,
                deviceLabel = deviceLabel(),
                changes = listOf(ragewarden.ragedroid.ui.screens.HistoryChange(if (secret != null) "Secret" else "Details", diff = "updated")),
            )
            saved
        }
    }

    /**
     * The item's payload with [ItemEdit.newSecret] (its primary field) and
     * [ItemEdit.secretChanges] applied, sealed and wrapped again. Fields that
     * do not change are read out of [ItemEdit.currentPayload], so changing one
     * protected field never drops the others.
     */
    /** decryptWithIdentities, rethrowing the typed hardware failure an identity recorded. */
    private fun decryptTyped(armored: String, identities: List<KotlinIdentity>): ByteArray {
        ragewarden.ragedroid.identities.HardwareFailures.clear()
        return try {
            RageNative.decryptWithIdentities(armored.toByteArray(Charsets.UTF_8), identities.toTypedArray())
        } catch (e: RuntimeException) {
            throw ragewarden.ragedroid.identities.HardwareFailures.rethrowable(e)
        }
    }

    private suspend fun resealed(item: VaultItem, edit: ItemEdit): Pair<String, List<String>> {
        val type = ItemFields.cipherType(item.kind)
        val changes = LinkedHashMap<String, ByteArray>()
        edit.newSecret?.let { changes[ItemFields.primary(item.kind)] = it.copyOf() }
        edit.secretChanges?.forEach { (k, v) -> changes[ItemFields.canonical(item.kind, k)] = v.toByteArray(Charsets.UTF_8) }
        val merged = LinkedHashMap<String, ByteArray>()
        try {
            val kept = ItemFields.protectedFields(item).filter { it !in changes }
            if (kept.isNotEmpty()) {
                val whole = edit.currentPayload
                    ?: throw UserFacingException { uiString(R.string.error_open_item_first, item.name) }
                kept.forEach { f -> merged[f] = RageNative.protectedField(type, whole, f) }
            }
            changes.filterValues { it.isNotEmpty() }.forEach { (k, v) -> merged[k] = v }
            if (merged.isEmpty()) throw UserFacingException { uiString(R.string.error_nothing_left_to_protect, item.name) }
            return seal(item, merged) to merged.keys.toList()
        } finally {
            changes.values.forEach { it.fill(0) }
            merged.values.forEach { it.fill(0) }
        }
    }

    /** Seals [fields] for [item]'s type and wraps the payload; every buffer is zeroed here. */
    private suspend fun seal(item: VaultItem, fields: Map<String, ByteArray>): String {
        val json = SecretText.fieldsJson(fields)
        val payload = try {
            RageNative.sealProtectedFields(ItemFields.cipherType(item.kind), json)
        } finally {
            json.fill(0)
        }
        return try {
            String(encryptForActiveRecipients(payload), Charsets.UTF_8)
        } finally {
            payload.fill(0)
        }
    }

    /**
     * Appends the item's current payload to the account's shared history
     * document before it is replaced or deleted. A failure stops the write:
     * replacing a value whose prior version could not be kept would lose it.
     */
    private fun recordHistory(item: VaultItem, priorArmored: String, deleted: Boolean) {
        val summary = org.json.JSONArray(item.recipients).toString().toByteArray(Charsets.UTF_8)
        withFreshToken { RageNative.historyRecord(it, item.id, priorArmored, summary, deleted) }
    }

    suspend fun history(itemId: String): Result<List<SharedHistoryEntry>> = withContext(Dispatchers.IO) {
        runCatching {
            val raw = withFreshToken { RageNative.historyLoad(it, itemId) }
            SharedHistoryEntry.parse(raw)
        }
    }

    fun legacyPrfWraps(itemId: String): Int =
        cached.blobMap.byItemId[itemId]?.let { runCatching { RageNative.legacyPrfWraps(it) }.getOrDefault(0) } ?: 0

    suspend fun moveToFolder(itemId: String, folderId: String?): Result<Unit> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
        runCatching {
            withFreshToken { RageNative.setFolder(it, itemId, folderId) }
            sync().getOrThrow()
            Unit
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
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
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
                withFreshToken { RageNative.updateCipher(it, existingId, cipherIn) }
            } else {
                withFreshToken { RageNative.createCipher(it, cipherIn) }
            }
            sync().getOrThrow()
            Unit
        }
    }

    suspend fun decryptWithRecoveryPhrase(
        itemId: String,
        phrase: String,
        field: String = "",
    ): Result<ByteArray> = withContext(Dispatchers.IO) {
        runCatching {
            val state = cached
            val item = state.snapshot?.items?.firstOrNull { it.id == itemId }
                ?: throw UserFacingException { uiString(R.string.error_item_gone) }
            if (!item.rage) throw UserFacingException { uiString(R.string.error_item_not_protected, item.name) }
            val armored = state.blobMap.byItemId[itemId]
                ?: throw UserFacingException { uiString(R.string.error_item_not_on_device) }
            val secretBytes = RageNative.recoveryFromPhrase(phrase)
            val armoredSecret = String(secretBytes, Charsets.UTF_8)
            val payload = try {
                RageNative.decryptWithSoftwareSecret(
                    armored.toByteArray(Charsets.UTF_8),
                    armoredSecret,
                )
            } finally {
                secretBytes.fill(0)
            }
            try {
                RageNative.protectedField(ItemFields.cipherType(item.kind), payload, field)
            } finally {
                payload.fill(0)
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
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
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
            withFreshToken { RageNative.updateCipher(it, existingId, cipherIn) }
            sync().getOrThrow()
            Unit
        }
    }

    @Volatile
    private var prfTapper: PrfTapper? = null

    fun installPrfTapper(tapper: PrfTapper?) {
        prfTapper = tapper
    }

    val installedPrfTapper: PrfTapper? get() = prfTapper

    private suspend fun encryptForActiveRecipients(plaintext: ByteArray): ByteArray {
        val recipients = collectActiveRecipients()
        if (recipients.isEmpty()) {
            throw NoRecipientsConfiguredException()
        }
        val prfRequests = recipients.mapNotNull { r ->
            when (r) {
                is WireRecipient.Fido2HmacSecret -> PrfRequest.fresh(r.rp_id, r.credential_id)
                is WireRecipient.PasskeyPrf -> PrfRequest.fresh(r.rp_id, r.credential_id)
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

    class NotSignedInException : UserFacingException(text = { uiString(R.string.error_signed_out) })

    class VaultLockedException : UserFacingException(text = { uiString(R.string.error_vault_locked) })

    class LegacyKdfException(val iterations: Int) :
        UserFacingException(text = { uiString(R.string.error_legacy_kdf, iterations, DEFAULT_KDF_ITERATIONS) }) {
        companion object {
            private val GOT = Regex("only (\\d+) PBKDF2 iterations")
            fun from(e: Throwable): LegacyKdfException? =
                GOT.find(e.message.orEmpty())?.groupValues?.get(1)?.toIntOrNull()?.let(::LegacyKdfException)
        }
    }

    class SessionExpiredException(cause: Throwable) : UserFacingException(cause, text = { uiString(R.string.error_session_expired) })

    companion object {
        internal fun isUnauthorized(e: Throwable): Boolean = "server returned 401" in e.message.orEmpty()

        internal fun isRejectedCredential(e: Throwable): Boolean {
            val m = e.message.orEmpty().lowercase()
            return "invalid_grant" in m || "username or password is incorrect" in m || "server returned 400" in m
        }

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

    val kdf: KdfSummary
        get() = KdfSummary(
            type = sessionInt("kdfType", KdfSummary.PBKDF2),
            iterations = kdfIterations,
            memoryMib = sessionInt("kdfMemoryMib", 0),
            parallelism = sessionInt("kdfParallelism", 0),
        )

    suspend fun verifyMasterPassword(pw: String): Result<Boolean> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
        runCatching {
            if (SessionBlobs.hasProtectedKey(blob)) {
                val probe = RageNative.unlockSession(SessionBlobs.strip(blob), pw)
                val ok = probe.isNotEmpty()
                probe.fill(0)
                ok
            } else {
                val fresh = reauthenticateOnline(blob, pw) ?: return@runCatching false
                installUnlocked(fresh)
                true
            }
        }
    }

    suspend fun deleteCipher(itemId: String): Result<Unit> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
        val target = get(itemId)
        runCatching {
            val prior = cached.blobMap.byItemId[itemId]
            if (target != null && target.rage && prior != null) recordHistory(target, prior, deleted = true)
            withFreshToken { RageNative.deleteCipher(it, itemId) }
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
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
        runCatching {
            val raw = withFreshToken { RageNative.listFolders(it) }
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
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
        runCatching {
            val bytes = withFreshToken { RageNative.createFolder(it, name) }
            auditFeed.record(AuditAction.CreateFolder, name)
            val parsed = JSONObject(String(bytes, Charsets.UTF_8))
            cached = CachedState(null, CipherRageBlobMap(emptyMap()), null)
            Folder(id = parsed.optString("id"), name = parsed.optString("name"))
        }
    }

    suspend fun updateFolder(folderId: String, name: String): Result<Folder> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
        runCatching {
            val bytes = withFreshToken { RageNative.updateFolder(it, folderId, name) }
            auditFeed.record(AuditAction.RenameFolder, name)
            val parsed = JSONObject(String(bytes, Charsets.UTF_8))
            cached = CachedState(null, CipherRageBlobMap(emptyMap()), null)
            Folder(id = parsed.optString("id"), name = parsed.optString("name"))
        }
    }

    suspend fun deleteFolder(folderId: String): Result<Unit> = withContext(Dispatchers.IO) {
        val blob = sessionBlob ?: return@withContext Result.failure(NotSignedInException())
        runCatching {
            withFreshToken { RageNative.deleteFolder(it, folderId) }
            auditFeed.record(AuditAction.DeleteFolder, folderId)
            cached = CachedState(null, CipherRageBlobMap(emptyMap()), null)
            Unit
        }
    }
}
