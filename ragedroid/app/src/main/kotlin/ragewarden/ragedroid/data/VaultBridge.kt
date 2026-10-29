package ragewarden.ragedroid.data

import ragewarden.ragedroid.data.audit.AuditAction
import android.content.Context
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.EntryPointAccessors
import dagger.hilt.components.SingletonComponent
import kotlinx.collections.immutable.ImmutableList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import ragewarden.ragedroid.identities.KotlinIdentity
import ragewarden.ragedroid.model.VaultItem

@EntryPoint
@InstallIn(SingletonComponent::class)
interface VaultBridgeEntryPoint {
    fun bitwardenRepo(): BitwardenVaultRepository
    fun recipientStore(): RecipientStore
    fun sessionStore(): SessionStore
    fun auditFeed(): ragewarden.ragedroid.data.audit.AuditFeed
}

interface VaultBackend {
    fun snapshot(): ImmutableList<VaultItem>
    fun get(id: String): VaultItem?
    suspend fun decrypt(itemId: String, identities: List<KotlinIdentity>): ByteArray = decrypt(itemId, identities, AuditAction.Reveal)
    suspend fun decrypt(itemId: String, identities: List<KotlinIdentity>, use: AuditAction?): ByteArray

    /**
     * One field of the item (see [ItemFields]): a protected one is narrowed out
     * of the decrypted payload by core, never shown raw; [ItemFields.WHOLE_PAYLOAD]
     * returns the payload whole, for re-wrapping.
     */
    suspend fun decryptField(itemId: String, identities: List<KotlinIdentity>, use: AuditAction?, field: String): ByteArray =
        if (field.isEmpty()) decrypt(itemId, identities, use) else throw UnsupportedOperationException("field reveals are not wired in this backend")
    suspend fun update(item: VaultItem, plaintext: ByteArray?): VaultItem
    suspend fun create(item: VaultItem, plaintext: ByteArray?): VaultItem
    suspend fun createTyped(item: VaultItem, block: Map<String, String>, secrets: Map<String, String>): VaultItem =
        throw UnsupportedOperationException("typed items are not wired in this backend")
    suspend fun edit(item: VaultItem, edit: ItemEdit): VaultItem =
        throw UnsupportedOperationException("edit is not wired in this backend")

    suspend fun delete(itemId: String)
    suspend fun listFolders(): ImmutableList<Folder>
    suspend fun createFolder(name: String): Folder
    suspend fun updateFolder(folderId: String, name: String): Folder
    suspend fun deleteFolder(folderId: String)
}

private class RepoVaultBackend(private val repo: BitwardenVaultRepository) : VaultBackend {
    override fun snapshot(): ImmutableList<VaultItem> = repo.snapshot()
    override fun get(id: String): VaultItem? = repo.get(id)
    override suspend fun decrypt(itemId: String, identities: List<KotlinIdentity>, use: AuditAction?): ByteArray =
        repo.decrypt(itemId, identities, use).getOrThrow()

    override suspend fun decryptField(itemId: String, identities: List<KotlinIdentity>, use: AuditAction?, field: String): ByteArray =
        repo.decrypt(itemId, identities, use, field).getOrThrow()

    override suspend fun update(item: VaultItem, plaintext: ByteArray?): VaultItem =
        repo.update(item, plaintext).getOrThrow()

    override suspend fun create(item: VaultItem, plaintext: ByteArray?): VaultItem =
        repo.create(item, plaintext).getOrThrow()

    override suspend fun createTyped(item: VaultItem, block: Map<String, String>, secrets: Map<String, String>): VaultItem =
        repo.createTyped(item, block, secrets).getOrThrow()

    override suspend fun edit(item: VaultItem, edit: ItemEdit): VaultItem =
        repo.edit(item, edit).getOrThrow()

    override suspend fun delete(itemId: String) {
        repo.deleteItem(itemId).getOrThrow()
    }

    override suspend fun listFolders(): ImmutableList<Folder> =
        repo.listFolders().getOrThrow()

    override suspend fun createFolder(name: String): Folder =
        repo.createFolder(name).getOrThrow()

    override suspend fun updateFolder(folderId: String, name: String): Folder =
        repo.updateFolder(folderId, name).getOrThrow()

    override suspend fun deleteFolder(folderId: String) {
        repo.deleteFolder(folderId).getOrThrow()
    }
}

@Deprecated(
    "Use Hilt-injected RecipientStore / BitwardenVaultRepository directly. " +
        "VaultBridge will be removed in the next architectural pass.",
    level = DeprecationLevel.WARNING,
)
object VaultBridge {
    @Volatile
    private var repoCached: BitwardenVaultRepository? = null

    @Volatile
    private var backend: VaultBackend? = null

    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private fun entryPoint(context: Context): VaultBridgeEntryPoint =
        EntryPointAccessors.fromApplication(
            context.applicationContext,
            VaultBridgeEntryPoint::class.java,
        )

    fun recipientStore(context: Context): RecipientStore =
        entryPoint(context).recipientStore()

    fun auditFeed(context: Context): ragewarden.ragedroid.data.audit.AuditFeed =
        entryPoint(context).auditFeed()

    fun repository(): BitwardenVaultRepository? = repoCached

    fun hasBackend(): Boolean = backend != null

    fun installRepository(repo: BitwardenVaultRepository) {
        synchronized(this) {
            repoCached = repo
            backend = RepoVaultBackend(repo)
        }
    }

    fun ensureBackend(context: Context): VaultBackend {
        backend?.let { return it }
        synchronized(this) {
            backend?.let { return it }
            val ep = entryPoint(context)
            val repo = ep.bitwardenRepo()
            repoCached = repo
            val store = ep.recipientStore()
            ioScope.launch { store.setActiveAccount(repo.accountId.ifBlank { null }) }
            return RepoVaultBackend(repo).also { backend = it }
        }
    }
}
