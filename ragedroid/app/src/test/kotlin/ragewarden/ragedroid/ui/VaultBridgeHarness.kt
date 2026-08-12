package ragewarden.ragedroid.ui

import android.app.Application
import dagger.hilt.internal.GeneratedComponent
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.toImmutableList
import ragewarden.ragedroid.data.BitwardenVaultRepository
import ragewarden.ragedroid.data.Folder
import ragewarden.ragedroid.data.HistoryStore
import ragewarden.ragedroid.data.LockPolicy
import ragewarden.ragedroid.data.LockState
import ragewarden.ragedroid.data.RecipientStore
import ragewarden.ragedroid.data.RotationTracker
import ragewarden.ragedroid.data.VaultBackend
import ragewarden.ragedroid.data.audit.AuditFeed
import ragewarden.ragedroid.di.AppEntryPoint
import ragewarden.ragedroid.identities.KotlinIdentity
import ragewarden.ragedroid.model.VaultItem

/**
 * What it takes to render `RecipientDetailScreen` on the JVM.
 *
 * That screen reaches for two process-wide singletons during composition, which
 * is why nothing in this repo had ever instantiated it and why both of its
 * descriptor comparisons could be reverted with every suite staying green:
 *
 *  1. `context.appEntryPoint().recipientStore()` -- a Hilt entry point. This
 *     module's `robolectric.properties` pins `application=android.app.Application`,
 *     which is not a Hilt component holder, so the lookup throws outright.
 *  2. `VaultBridge.ensureBackend(context).snapshot()` -- the vault contents.
 *
 * [EntryPointApplication] answers (1) without a Dagger graph. `EntryPoints.get`
 * casts the component straight to the requested entry point when it implements
 * `dagger.hilt.internal.GeneratedComponent` (marker interface, no members), so
 * an Application that implements both the marker and `AppEntryPoint` *is* a
 * legal component holder as far as Hilt is concerned. No test-only Hilt
 * dependency, no generated graph, and nothing in `src/main` bent to suit a test.
 *
 * [installVaultBackend] answers (2). `VaultBridge.installRepository` takes a
 * real `BitwardenVaultRepository` (six stores, an eager `sessionStore.load()`),
 * which is more than "what items exist" needs, so the private `backend` field is
 * set directly. `ensureBackend` returns early when it is non-null and the Hilt
 * lookup behind it is never reached.
 *
 * Reflection is a real cost and worth naming: if `VaultBridge` renames that
 * field, [installVaultBackend] throws `NoSuchFieldException` and the tests go
 * red loudly rather than silently rendering an empty vault -- which would look
 * exactly like the bug they exist to catch. That failure mode is the reason it
 * throws rather than falling back to anything.
 */
class EntryPointApplication : Application(), GeneratedComponent, AppEntryPoint {

    /**
     * `RecipientDetailScreen` only holds this, using it in the revoke flow --
     * which is gated on a non-null repository and therefore unreachable here.
     * The constructor is cheap: `KeystorePrefs` opens SharedPreferences eagerly
     * (Robolectric backs those with a real file) and touches the Android
     * Keystore only lazily, on the first read.
     */
    override fun recipientStore(): RecipientStore = RecipientStore(this)

    override fun bitwardenRepo(): BitwardenVaultRepository = notWired("bitwardenRepo")
    override fun lockPolicy(): LockPolicy = notWired("lockPolicy")
    override fun lockState(): LockState = notWired("lockState")
    override fun auditFeed(): AuditFeed = notWired("auditFeed")
    override fun rotationTracker(): RotationTracker = notWired("rotationTracker")
    override fun historyStore(): HistoryStore = notWired("historyStore")

    private fun notWired(name: String): Nothing = throw UnsupportedOperationException(
        "$name is not wired in EntryPointApplication. A screen reaching for it during " +
            "composition is a new dependency, not something to stub away quietly.",
    )
}

/** A vault whose contents are exactly what the test says they are. */
class FakeVaultBackend(items: List<VaultItem>) : VaultBackend {

    private val items: ImmutableList<VaultItem> = items.toImmutableList()

    override fun snapshot(): ImmutableList<VaultItem> = items

    override fun get(id: String): VaultItem? = items.firstOrNull { it.id == id }

    override suspend fun decrypt(itemId: String, identities: List<KotlinIdentity>): ByteArray =
        unreachable("decrypt")

    override suspend fun update(item: VaultItem, plaintext: ByteArray?): VaultItem =
        unreachable("update")

    override suspend fun create(item: VaultItem, plaintext: ByteArray): VaultItem =
        unreachable("create")

    override suspend fun delete(itemId: String) = unreachable("delete")

    override suspend fun listFolders(): ImmutableList<Folder> = unreachable("listFolders")

    override suspend fun createFolder(name: String): Folder = unreachable("createFolder")

    override suspend fun updateFolder(folderId: String, name: String): Folder =
        unreachable("updateFolder")

    override suspend fun deleteFolder(folderId: String) = unreachable("deleteFolder")

    private fun unreachable(name: String): Nothing = throw UnsupportedOperationException(
        "$name is a write path; a read-only screen test reaching it is a bug in the test.",
    )
}

/** Point `VaultBridge` at [backend] for the current Robolectric sandbox. */
@Suppress("DEPRECATION")
fun installVaultBackend(backend: VaultBackend?) {
    val cls = Class.forName("ragewarden.ragedroid.data.VaultBridge")
    val instance = cls.getDeclaredField("INSTANCE").apply { isAccessible = true }.get(null)
    cls.getDeclaredField("backend").apply { isAccessible = true }.set(instance, backend)
}
