package ragewarden.ragedroid.ui

import android.content.pm.ApplicationInfo
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toPersistentList
import kotlinx.collections.immutable.toImmutableList
import kotlinx.coroutines.delay
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.Clipboard
import ragewarden.ragedroid.data.SessionStore
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.data.toUiRecipient
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.model.NO_FOLDER
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.model.VaultItemKind
import ragewarden.ragedroid.ui.components.Toast
import ragewarden.ragedroid.ui.components.ToastHost
import ragewarden.ragedroid.ui.components.ToastKind
import ragewarden.ragedroid.ui.screens.AccountScreen
import ragewarden.ragedroid.ui.screens.AddItemKind
import ragewarden.ragedroid.ui.screens.AddItemScreen
import ragewarden.ragedroid.ui.screens.AddItemTypePickerScreen
import ragewarden.ragedroid.ui.screens.AddRecipientScreen
import ragewarden.ragedroid.ui.screens.AuditLogScreen
import ragewarden.ragedroid.ui.screens.BackfillWizardScreen
import ragewarden.ragedroid.ui.screens.BulkProtectScreen
import ragewarden.ragedroid.ui.screens.CustomImeScreen
import ragewarden.ragedroid.ui.screens.EditItemScreen
import ragewarden.ragedroid.ui.screens.FirstRunScreen
import ragewarden.ragedroid.ui.screens.FolderEditScreen
import ragewarden.ragedroid.ui.screens.FoldersScreen
import ragewarden.ragedroid.ui.screens.ItemDetailScreen
import ragewarden.ragedroid.ui.screens.ItemHistoryScreen
import ragewarden.ragedroid.ui.screens.KindDetailScreen
import ragewarden.ragedroid.ui.screens.LockScreen
import ragewarden.ragedroid.ui.screens.PaperRecoveryWizardScreen
import ragewarden.ragedroid.ui.screens.RecipientDetailScreen
import ragewarden.ragedroid.ui.screens.RecipientsScreen
import ragewarden.ragedroid.ui.screens.RecoverFromPhraseScreen
import ragewarden.ragedroid.ui.screens.SearchScreen
import ragewarden.ragedroid.ui.screens.SettingsScreen
import ragewarden.ragedroid.ui.screens.SystemAutofillPickerScreen
import ragewarden.ragedroid.ui.screens.TapFailureKind
import ragewarden.ragedroid.ui.screens.TapFailureScreen
import ragewarden.ragedroid.ui.screens.TokenExpiredScreen
import ragewarden.ragedroid.ui.screens.VaultListScreen
import ragewarden.ragedroid.ui.theme.rageColors

internal sealed interface Stage {
    data object FirstRun : Stage
    data object Vault : Stage
    data object Search : Stage
    data object Settings : Stage
    data object Account : Stage
    data object AddRecipient : Stage
    data object Folders : Stage
    data object FolderEdit : Stage
    data object AddItemTypePicker : Stage
    data class AddItem(val kind: AddItemKind) : Stage
    data class RecipientDetail(val recipientId: String) : Stage
    data object AuditLog : Stage
    data object BackfillWizard : Stage
    data object BulkProtect : Stage
    data object PaperRecovery : Stage
    data object RecoverFromPhrase : Stage
    data object RecipientsList : Stage
    data class TapFailure(val itemId: String, val kind: TapFailureKind) : Stage
    data class ItemHistory(val itemId: String) : Stage
    data object TokenExpired : Stage
    data object AutofillPickerPreview : Stage
    data object ImePreview : Stage
}

internal object StageCodec {
    private val objects: List<Stage> = listOf(
        Stage.FirstRun, Stage.Vault, Stage.Search, Stage.Settings, Stage.Account, Stage.AddRecipient,
        Stage.Folders, Stage.FolderEdit, Stage.AddItemTypePicker, Stage.AuditLog, Stage.BackfillWizard,
        Stage.BulkProtect, Stage.PaperRecovery, Stage.RecoverFromPhrase, Stage.RecipientsList,
        Stage.TokenExpired, Stage.AutofillPickerPreview, Stage.ImePreview,
    )

    fun encode(stage: Stage): List<String> = when (stage) {
        is Stage.AddItem -> listOf("AddItem", stage.kind.name)
        is Stage.RecipientDetail -> listOf("RecipientDetail", stage.recipientId)
        is Stage.TapFailure -> listOf("TapFailure", stage.itemId, stage.kind.name)
        is Stage.ItemHistory -> listOf("ItemHistory", stage.itemId)
        else -> listOf(stage.toString())
    }

    fun decode(parts: List<String>): Stage? = runCatching {
        when (parts.firstOrNull()) {
            "AddItem" -> Stage.AddItem(AddItemKind.valueOf(parts[1]))
            "RecipientDetail" -> Stage.RecipientDetail(parts[1])
            "TapFailure" -> Stage.TapFailure(parts[1], TapFailureKind.valueOf(parts[2]))
            "ItemHistory" -> Stage.ItemHistory(parts[1])
            else -> objects.firstOrNull { it.toString() == parts.firstOrNull() }
        }
    }.getOrNull()

    val saver: Saver<Stage, Any> = listSaver(save = { encode(it) }, restore = { decode(it) })
}

@Composable
fun RageApp() {
    val localContext = LocalContext.current
    val context = localContext.applicationContext
    val sessionStore = remember(context) { SessionStore(context) }

    /**
     * The Activity, captured separately.
     *
     * `context` above is deliberately the *application* context (the stores and
     * entry points below outlive any Activity), and this used to be the only
     * context in the function -- so the three `(context as? Activity)?.moveTaskToBack(true)`
     * calls, one of them the locked-vault back handler, were unconditionally
     * null-safe no-ops. Back was silently swallowed instead of backgrounding the
     * app, and a revision of `docs/THREAT-MODEL.md` described it as working.
     */
    val hostActivity = LocalActivity.current ?: localContext.findActivity()

    val signedInAtLaunch = remember { sessionStore.has() || VaultBridge.hasBackend() }
    var stage by rememberSaveable(stateSaver = StageCodec.saver) {
        mutableStateOf<Stage>(if (signedInAtLaunch) Stage.Vault else Stage.FirstRun)
    }

    /**
     * The lock is a *state*, not a `Stage`, and it does not live in this
     * composition.
     *
     * It used to be `Stage.Lock`, a peer of every other stage -- which meant any
     * `onBack` that assigned `stage = Stage.Vault` walked straight out of it. It
     * did, twice: the lock screen's "Settings" affordance reached
     * `SettingsScreen`, whose `onBack` was `stage = Stage.Vault`, and the global
     * `BackHandler` mapped `Stage.Settings -> Stage.Vault` independently. Lock ->
     * Settings -> Back landed in the unlocked vault in two taps, with no
     * authentication anywhere in the path.
     *
     * It was then a `var locked by remember { ... }`, which fixed the navigation
     * bypass but introduced two more: `remember` dies with the composition, so
     * rotating the phone re-ran the initialiser and -- with `lockOnLaunch` off --
     * re-derived `false`, dropping a lock the user had asked for; and nothing
     * outside this one composable could observe it, so the IME and autofill
     * services happily served plaintext out of a locked vault.
     *
     * It is now [ragewarden.ragedroid.data.LockState]: a process singleton,
     * persisted, observed here. It cannot be navigated out of, it survives
     * Activity recreation and process death, and every other reader of secret
     * material consults the same instance. Nothing below sets it false except a
     * verified unlock and sign-out; while it is true the entire stage tree is
     * *not composed* (see the `if (locked)` at the render site), so no screen
     * behind the lock is live, holding decrypted state, or reachable by back.
     *
     * `stage` keeps its value across a lock, so unlocking returns the user where
     * they were -- but the screens are rebuilt from scratch, so a reveal that was
     * on screen when the app stopped is gone.
     *
     * Locking also drops the keys: `BitwardenVaultRepository` listens on
     * [ragewarden.ragedroid.data.LockState] and strips the user key out of the
     * session blob and clears the decrypted vault cache. Unlock re-derives the
     * key from the master password (or the biometric-sealed copy) and decrypts
     * the sealed offline copy of the vault, so it still works offline.
     */
    val lockState = remember(context) { context.appEntryPoint().lockState() }
    val locked by lockState.locked.collectAsState()
    var wasStopped by remember { mutableStateOf(false) }
    var paperRecoveryFromFirstRun by remember { mutableStateOf(false) }
    var openItemId by rememberSaveable { mutableStateOf<String?>(null) }
    var editItemId by rememberSaveable { mutableStateOf<String?>(null) }
    var openIdentityPickerForItem by remember { mutableStateOf<String?>(null) }
    var toast by remember { mutableStateOf<Toast?>(null) }
    var vaultRefreshTick by remember { mutableStateOf(0) }
    var folderEditTarget by remember { mutableStateOf<ragewarden.ragedroid.ui.screens.FolderEntry?>(null) }

    val scope = rememberCoroutineScope()
    val clipboard = remember(context) {
        val auditFeed = runCatching { context.appEntryPoint().auditFeed() }.getOrNull()
        // Not the composition's scope: the clear can land after this screen is gone.
        val auditScope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.Main.immediate)
        Clipboard(
            context = context,
            onSensitiveCopy = { copy ->
                auditFeed?.let { feed ->
                    val id = auditScope.async { feed.recordReturningId(action = copy.action, item = copy.item, reason = copy.field) }
                    val gone: () -> Unit = { auditScope.launch { feed.markCleared(id.await()) } }
                    gone
                }
            },
        )
    }

    LaunchedEffect(toast) {
        if (toast != null) {
            delay(3000)
            toast = null
        }
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_STOP -> {
                    wasStopped = true
                }
                Lifecycle.Event.ON_START -> {
                    if (wasStopped) {
                        wasStopped = false
                        val signedIn = sessionStore.has() || VaultBridge.hasBackend()
                        if (signedIn && stage !is Stage.FirstRun) {
                            lockState.lock()
                        }
                    }
                }
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // `locked` is a key, not just a guard: `stage` no longer changes across an
    // unlock (it stays whatever it was), so keying on `stage` alone would mean
    // the post-unlock sync never fired on a cold launch that starts locked.
    LaunchedEffect(stage, locked) {
        if (!locked && stage is Stage.Vault) {
            val repo = VaultBridge.repository()
            if (repo != null && repo.hasSession()) {
                if (repo.snapshot().isEmpty()) {
                    val outcome = runCatching { repo.sync() }.getOrNull()
                    val failure = outcome?.exceptionOrNull()
                    if (outcome?.isSuccess == true) {
                        vaultRefreshTick += 1
                    } else if (failure != null && isAuthFailure(failure)) {
                        android.util.Log.i("RageApp.autosync", "session expired, routing to TokenExpired")
                        stage = Stage.TokenExpired
                        return@LaunchedEffect
                    }
                }
                val pushResult = runCatching { repo.pushRecipientRegistry() }
                val pushFailure = pushResult.getOrNull()?.exceptionOrNull()
                    ?: pushResult.exceptionOrNull()
                if (pushFailure != null && isAuthFailure(pushFailure)) {
                    stage = Stage.TokenExpired
                }
            }
        }
    }

    val showToast: (String) -> Unit = { msg -> toast = inferToast(msg) }
    val finishPaperRecovery: (Stage, Stage) -> Unit = { afterFirstRun, otherwise ->
        showToast(context.getString(R.string.recovery_phrase_saved))
        if (paperRecoveryFromFirstRun) {
            paperRecoveryFromFirstRun = false
            scope.launch {
                VaultBridge.repository()?.pushRecipientRegistry()
                VaultBridge.repository()?.sync()
                stage = afterFirstRun
            }
        } else {
            stage = otherwise
        }
    }
    val isDebuggable = remember(context) {
        (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }

    var confirmSignOut by remember { mutableStateOf(false) }
    val requestSignOut: () -> Unit = { confirmSignOut = true }
    val performSignOut: () -> Unit = {
        confirmSignOut = false
        val signedOutAccountId = VaultBridge.repository()?.accountId.orEmpty()
        VaultBridge.repository()?.logout()
        runCatching { context.appEntryPoint().sessionKeyWrap().clear() }
        if (signedOutAccountId.isNotBlank()) {
            context.appEntryPoint().rotationTracker().forget(signedOutAccountId)
        }
        sessionStore.clear()
        // Signing out is the one legitimate way past the lock: there is nothing
        // left to protect once the session and the cached vault are gone.
        lockState.unlock()
        stage = Stage.FirstRun
    }
    val currentAccountId = VaultBridge.repository()?.accountId.orEmpty()
    val liveRecipients = remember(context, vaultRefreshTick, stage, locked, currentAccountId) {
        if (currentAccountId.isBlank()) {
            kotlinx.collections.immutable.persistentListOf<ragewarden.ragedroid.model.Recipient>()
        } else {
            context.appEntryPoint().recipientStore().forAccount(currentAccountId)
                .map { it.toUiRecipient() }
                .toPersistentList()
        }
    }

    androidx.activity.compose.BackHandler(enabled = true) {
        // While locked there is exactly one back behaviour: leave the app. Any
        // stage-dependent branch here would be a second escape route out of the
        // lock, which is how the original bypass worked.
        //
        // `hostActivity` replaces a cast of the application context that was
        // always null. If it is somehow still null (a preview or a Robolectric
        // host with no Activity) back is swallowed, which is where this branch
        // already was -- it never leaks past the lock either way.
        if (locked) {
            hostActivity?.moveTaskToBack(true)
            return@BackHandler
        }
        when (stage) {
            Stage.FirstRun, Stage.TokenExpired -> {
                hostActivity?.moveTaskToBack(true)
            }
            Stage.Vault -> {
                if (editItemId != null) editItemId = null
                else if (openItemId != null) openItemId = null
                else hostActivity?.moveTaskToBack(true)
            }
            is Stage.AddItem -> stage = Stage.AddItemTypePicker
            Stage.PaperRecovery -> {
                stage = if (paperRecoveryFromFirstRun) Stage.FirstRun else Stage.Settings
                paperRecoveryFromFirstRun = false
            }
            Stage.Search,
            Stage.Settings,
            Stage.AddItemTypePicker,
            Stage.AutofillPickerPreview,
            Stage.ImePreview,
            -> stage = Stage.Vault
            Stage.Account,
            Stage.AddRecipient,
            Stage.Folders,
            Stage.AuditLog,
            Stage.BackfillWizard,
            Stage.BulkProtect,
            Stage.RecoverFromPhrase,
            Stage.RecipientsList,
            -> stage = Stage.Settings
            Stage.FolderEdit -> stage = Stage.Folders
            is Stage.RecipientDetail -> stage = Stage.Settings
            is Stage.TapFailure -> {
                openItemId = (stage as Stage.TapFailure).itemId
                stage = Stage.Vault
            }
            is Stage.ItemHistory -> {
                openItemId = (stage as Stage.ItemHistory).itemId
                stage = Stage.Vault
            }
        }
    }

    val c = rageColors
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(c.background)
            .safeDrawingPadding(),
    ) {
        if (locked) {
            // Deliberately *instead of* the stage tree, not on top of it. An
            // overlay would leave the screen behind the lock composed and alive,
            // still holding whatever it had decrypted. This disposes it.
            LockScreen(
                onUnlock = { lockState.unlock() },
                onSignOut = requestSignOut,
                onToast = showToast,
                // Not `VaultBridge.repository()`: that is null until something
                // calls `ensureBackend`, and on a cold launch straight into the
                // lock nothing has. The lock screen needs a repository to verify
                // the master password against, so take the Hilt singleton -- the
                // same instance `ensureBackend` would install.
                repo = remember(context) { context.appEntryPoint().bitwardenRepo() },
            )
        } else {
        androidx.compose.runtime.CompositionLocalProvider(
            LocalLiveRecipients provides liveRecipients,
        ) {
        when (val current = stage) {
            Stage.FirstRun -> FirstRunScreen(
                onComplete = {
                    scope.launch {
                        VaultBridge.repository()?.sync()
                        stage = Stage.Vault
                    }
                },
                onPickPaperRecoveryBackup = {
                    paperRecoveryFromFirstRun = true
                    stage = Stage.PaperRecovery
                },
                showToast = showToast,
            )
            Stage.Vault -> VaultStage(
                openItemId = openItemId,
                editItemId = editItemId,
                refreshTick = vaultRefreshTick,
                onItemSaved = { vaultRefreshTick += 1 },
                onOpen = { openItemId = it },
                onEdit = { editItemId = it },
                onCloseDetail = { openItemId = null },
                onCloseEdit = { editItemId = null },
                clipboard = clipboard,
                showToast = showToast,
                onSettings = { stage = Stage.Settings },
                onSearch = { stage = Stage.Search },
                onAdd = { stage = Stage.AddItemTypePicker },
                onEnrollFirst = { stage = Stage.AddRecipient },
                onHistory = { id -> stage = Stage.ItemHistory(id) },
                onTapFailure = { id, kind -> stage = Stage.TapFailure(id, kind) },
                onRotate = { stage = Stage.BackfillWizard },
                autoOpenIdentityPickerForId = openIdentityPickerForItem,
                onIdentityPickerOpened = { openIdentityPickerForItem = null },
            )
            Stage.Search -> {
                val items = remember { vaultItems(context) }
                SearchScreen(
                    items = items,
                    onBack = { stage = Stage.Vault },
                    onOpen = { item ->
                        openItemId = item.id
                        stage = Stage.Vault
                    },
                )
            }
            Stage.Settings -> {
                val settingsItems = remember(context, vaultRefreshTick) {
                    VaultBridge.ensureBackend(context.applicationContext).snapshot()
                }
                SettingsScreen(
                items = settingsItems,
                onBack = { stage = Stage.Vault },
                onAccount = { stage = Stage.Account },
                onAddRecipient = { stage = Stage.AddRecipient },
                onOpenRecipient = { recipient ->
                    stage = Stage.RecipientDetail(recipient.id)
                },
                onRecovery = { stage = Stage.PaperRecovery },
                onRecoverFromPhrase = { stage = Stage.RecoverFromPhrase },
                onListRecipients = { stage = Stage.RecipientsList },
                onFolders = { stage = Stage.Folders },
                onOpenAuditLog = { stage = Stage.AuditLog },
                onLockNow = {
                    // Land on the vault list after the unlock, not back in
                    // Settings -- "lock now" ends the settings session too.
                    stage = Stage.Vault
                    lockState.lock()
                },
                onBackfill = { stage = Stage.BackfillWizard },
                onBulkProtect = { stage = Stage.BulkProtect },
                onAutofillPreview = { stage = Stage.AutofillPickerPreview },
                onImePreview = { stage = Stage.ImePreview },
                onDebugTokenExpired = if (isDebuggable) {
                    { stage = Stage.TokenExpired }
                } else {
                    null
                },
                onSignOut = requestSignOut,
                onToast = showToast,
                )
            }
            Stage.Account -> AccountScreen(
                onBack = { stage = Stage.Settings },
                onSignOut = requestSignOut,
                onToast = showToast,
            )
            Stage.AddRecipient -> AddRecipientScreen(
                recipientStore = context.appEntryPoint().recipientStore(),
                accountId = VaultBridge.repository()?.accountId,
                onBack = { stage = Stage.Settings },
                onPaperRecovery = { stage = Stage.PaperRecovery },
                onToast = showToast,
            )
            Stage.Folders -> FoldersScreen(
                repo = VaultBridge.ensureBackend(context),
                onBack = { stage = Stage.Settings },
                onEdit = { entry ->
                    folderEditTarget = entry
                    stage = Stage.FolderEdit
                },
                onNew = {
                    folderEditTarget = null
                    stage = Stage.FolderEdit
                },
            )
            Stage.FolderEdit -> FolderEditScreen(
                existing = folderEditTarget,
                repo = VaultBridge.ensureBackend(context),
                onBack = { stage = Stage.Folders },
                onSave = {
                    showToast(context.getString(R.string.folder_saved))
                    stage = Stage.Folders
                },
                onDelete = {
                    showToast(context.getString(R.string.folder_deleted))
                    stage = Stage.Folders
                },
            )
            Stage.AddItemTypePicker -> AddItemTypePickerScreen(
                onBack = { stage = Stage.Vault },
                onPick = { kind -> stage = Stage.AddItem(kind) },
            )
            is Stage.AddItem -> AddItemScreen(
                itemKind = (stage as Stage.AddItem).kind,
                repo = VaultBridge.ensureBackend(context),
                onBack = { stage = Stage.AddItemTypePicker },
                onSave = { _, _ ->
                    vaultRefreshTick += 1
                    showToast(context.getString(R.string.item_saved))
                    stage = Stage.Vault
                },
                onToast = showToast,
            )
            is Stage.RecipientDetail -> {
                val recipient = remember(current.recipientId, liveRecipients) {
                    liveRecipients.firstOrNull { it.id == current.recipientId }
                }
                if (recipient == null) {
                    val notFound = stringResource(R.string.recipient_not_found)
                    LeaveWhenGone(current.recipientId) {
                        showToast(notFound)
                        stage = Stage.Settings
                    }
                } else {
                    RecipientDetailScreen(
                        recipient = recipient,
                        onBack = { stage = Stage.Settings },
                        onToast = showToast,
                        onRewrapStale = { stage = Stage.BackfillWizard },
                    )
                }
            }
            Stage.AuditLog -> {
                val auditFeed = remember(context) {
                    context.appEntryPoint().auditFeed()
                }
                val auditEntries by auditFeed.flow.collectAsState()
                AuditLogScreen(
                    onBack = { stage = Stage.Settings },
                    entries = auditEntries,
                    onClear = {
                        scope.launch { auditFeed.clear() }
                        showToast(context.getString(R.string.activity_cleared))
                    },
                    onToast = showToast,
                )
            }
            Stage.BackfillWizard -> BackfillWizardScreen(
                onBack = { stage = Stage.Settings },
                onComplete = {
                    showToast(context.getString(R.string.backfill_complete))
                    stage = Stage.Settings
                },
                onToast = showToast,
            )
            Stage.BulkProtect -> BulkProtectScreen(
                onBack = { stage = Stage.Settings },
                onComplete = {
                    vaultRefreshTick += 1
                    stage = Stage.Settings
                },
                onToast = showToast,
            )
            Stage.RecoverFromPhrase -> RecoverFromPhraseScreen(
                onBack = { stage = Stage.Settings },
                onToast = showToast,
            )
            Stage.RecipientsList -> RecipientsScreen(
                onBack = {
                    vaultRefreshTick += 1
                    stage = Stage.Settings
                },
                onToast = showToast,
            )
            Stage.PaperRecovery -> PaperRecoveryWizardScreen(
                recipientStore = context.appEntryPoint().recipientStore(),
                accountId = VaultBridge.repository()?.accountId,
                onBack = {
                    if (paperRecoveryFromFirstRun) {
                        paperRecoveryFromFirstRun = false
                        stage = Stage.FirstRun
                    } else {
                        stage = Stage.Settings
                    }
                },
                onComplete = { finishPaperRecovery(Stage.Vault, Stage.Settings) },
                onTestNow = { finishPaperRecovery(Stage.RecoverFromPhrase, Stage.RecoverFromPhrase) },
                onToast = showToast,
            )
            is Stage.TapFailure -> {
                val items = remember { vaultItems(context) }
                val item = items.firstOrNull { it.id == current.itemId }
                TapFailureScreen(
                    kind = current.kind,
                    item = item,
                    onRetry = {
                        openItemId = current.itemId
                        stage = Stage.Vault
                    },
                    onPick = {
                        openIdentityPickerForItem = current.itemId
                        openItemId = current.itemId
                        stage = Stage.Vault
                    },
                    onBack = {
                        openItemId = null
                        stage = Stage.Vault
                    },
                    onSetUpDevice = { stage = Stage.AddRecipient },
                )
            }
            is Stage.ItemHistory -> {
                val items = remember { vaultItems(context) }
                val item = items.firstOrNull { it.id == current.itemId }
                val historyStore = remember(context) { context.appEntryPoint().historyStore() }
                val accountIdLive = VaultBridge.repository()?.accountId.orEmpty()
                val localEntries = remember(current.itemId, accountIdLive, vaultRefreshTick) {
                    historyStore.forItem(accountIdLive, current.itemId)
                }
                // The account's shared history document (every client writes it
                // before replacing or deleting a protected value), then what this
                // device recorded locally.
                var sharedEntries by remember(current.itemId, vaultRefreshTick) {
                    mutableStateOf<ImmutableList<ragewarden.ragedroid.ui.screens.HistoryRevision>>(persistentListOf())
                }
                LaunchedEffect(current.itemId, vaultRefreshTick) {
                    VaultBridge.repository()?.history(current.itemId)?.onSuccess { list ->
                        sharedEntries = list.map(::sharedRevision).toImmutableList()
                    }
                }
                ItemHistoryScreen(
                    item = item,
                    entries = (sharedEntries + localEntries).toImmutableList(),
                    onBack = {
                        openItemId = current.itemId
                        stage = Stage.Vault
                    },
                )
            }
            Stage.TokenExpired -> TokenExpiredScreen(
                onSignIn = requestSignOut,
                onLater = { stage = Stage.Vault },
            )
            Stage.AutofillPickerPreview -> SystemAutofillPickerScreen(
                domain = null,
                packageName = null,
                onAutofill = { item ->
                    showToast(context.getString(R.string.autofilled_preview, item.name))
                    stage = Stage.Settings
                },
                onCreate = { stage = Stage.AddItemTypePicker },
                onBack = { stage = Stage.Settings },
            )
            Stage.ImePreview -> CustomImeScreen(
                domain = null,
                packageName = null,
                onAutofill = { item ->
                    showToast(context.getString(R.string.filled_preview, item.name))
                    stage = Stage.Settings
                },
                onBack = { stage = Stage.Settings },
            )
        }
        }
        }

        if (confirmSignOut) {
            androidx.compose.material3.AlertDialog(
                onDismissRequest = { confirmSignOut = false },
                title = { androidx.compose.material3.Text(stringResource(R.string.sign_out)) },
                text = {
                    androidx.compose.material3.Text(
                        stringResource(R.string.this_removes_the_session_the_offline),
                    )
                },
                confirmButton = {
                    androidx.compose.material3.TextButton(onClick = performSignOut) {
                        androidx.compose.material3.Text(stringResource(R.string.sign_out_2))
                    }
                },
                dismissButton = {
                    androidx.compose.material3.TextButton(onClick = { confirmSignOut = false }) {
                        androidx.compose.material3.Text(stringResource(R.string.cancel))
                    }
                },
            )
        }
        ToastHost(toast = toast, modifier = Modifier.fillMaxSize())
    }
}


private fun vaultItems(context: android.content.Context): ImmutableList<VaultItem> {
    val backend = VaultBridge.ensureBackend(context.applicationContext)
    return backend.snapshot()
}

internal fun sharedRevision(e: ragewarden.ragedroid.data.SharedHistoryEntry): ragewarden.ragedroid.ui.screens.HistoryRevision {
    val time = java.time.Instant.ofEpochMilli(e.recordedAt).atZone(java.time.ZoneId.systemDefault())
    return ragewarden.ragedroid.ui.screens.HistoryRevision(
        id = "shared-${e.recordedAt}",
        when_ = time.format(java.time.format.DateTimeFormatter.ofPattern("MMMM d · HH:mm")),
        by = e.recipientsSummary.joinToString(", ").ifEmpty { uiString(R.string.another_client) },
        current = false,
        changes = persistentListOf(
            ragewarden.ragedroid.ui.screens.HistoryChange(
                if (e.deleted) uiString(R.string.audit_deleted) else uiString(R.string.previous_value),
                diff = e.stanzaTags.joinToString(" · ").ifEmpty { null },
            ),
        ),
    )
}

internal enum class DetailRoute { Login, Kind }

internal fun detailRouteFor(item: VaultItem): DetailRoute = when {
    item.kind == VaultItemKind.Login -> DetailRoute.Login
    item.kind == VaultItemKind.Note && item.rage && item.notes == null -> DetailRoute.Login
    else -> DetailRoute.Kind
}

@Composable
private fun VaultStage(
    openItemId: String?,
    editItemId: String?,
    refreshTick: Int,
    onItemSaved: () -> Unit,
    onOpen: (String) -> Unit,
    onEdit: (String) -> Unit,
    onCloseDetail: () -> Unit,
    onCloseEdit: () -> Unit,
    clipboard: Clipboard,
    showToast: (String) -> Unit,
    onSettings: () -> Unit,
    onSearch: () -> Unit,
    onAdd: () -> Unit,
    onEnrollFirst: () -> Unit,
    onHistory: (String) -> Unit,
    onTapFailure: (String, TapFailureKind) -> Unit,
    onRotate: () -> Unit,
    autoOpenIdentityPickerForId: String? = null,
    onIdentityPickerOpened: () -> Unit = {},
) {
    val context = LocalContext.current
    val appContext = context.applicationContext
    val backend = remember(appContext) { VaultBridge.ensureBackend(appContext) }
    val items: ImmutableList<VaultItem> = remember(backend, refreshTick) {
        backend.snapshot()
    }
    val current = openItemId?.let { id -> items.firstOrNull { it.id == id } }
    val editing = editItemId?.let { id -> items.firstOrNull { it.id == id } }
    val scope = rememberCoroutineScope()
    val accountId = remember(appContext) { VaultBridge.repository()?.accountId.orEmpty() }
    val rotationTracker = remember(appContext) { appContext.appEntryPoint().rotationTracker() }
    val staleness by rotationTracker.staleness.collectAsState()
    val hasAnyEnrolledRecipient = remember(appContext, accountId, refreshTick, staleness) {
        if (accountId.isBlank()) false
        else appContext.appEntryPoint().recipientStore().forAccount(accountId)
            .any { it.defaultEncrypt }
    }
    val rotationStale = remember(appContext, accountId, refreshTick, staleness) {
        if (accountId.isBlank()) false
        else rotationTracker.isStale(accountId)
    }
    var keyListResetTick by remember { mutableStateOf(0) }
    val keyListUnreadable = remember(appContext, accountId, refreshTick, staleness, keyListResetTick) {
        accountId.isNotBlank() && appContext.appEntryPoint().recipientStore().let { store ->
            store.forAccount(accountId)
            store.isUnreadable(accountId)
        }
    }

    // One coordinator per Activity + account. It owns identity resolution, the
    // biometric gate, the PIV PIN prompt, and the failure taxonomy; the screens
    // below stay hardware-agnostic.
    //
    // `context as? FragmentActivity` is null only in previews/Robolectric. When
    // it is null the coordinator resolves *no* Activity-bound identities and
    // reports each one as skipped-with-reason, rather than quietly returning a
    // shorter list that age might satisfy from a software recipient.
    val hostActivity = context.findActivity() as? androidx.fragment.app.FragmentActivity
    val tapCoordinator = remember(hostActivity, accountId) {
        ragewarden.ragedroid.identities.HardwareTapCoordinator(
            activity = hostActivity,
            recipientStore = appContext.appEntryPoint().recipientStore(),
            accountId = accountId,
        )
    }
    // The encryption-side tap. Without it, `encryptForActiveRecipients` throws
    // PrfTapperNotConfiguredException the moment any FIDO2/passkey recipient is
    // marked default-encrypt -- i.e. enrolling a passkey made every save fail.
    // Nothing in the tree called installPrfTapper before this.
    LaunchedEffect(hostActivity, accountId) {
        val repo = VaultBridge.repository()
        if (hostActivity != null && accountId.isNotBlank()) {
            repo?.installPrfTapper(
                ragewarden.ragedroid.identities.CredentialManagerPrfTapper(
                    activity = hostActivity,
                    recipientStore = appContext.appEntryPoint().recipientStore(),
                    accountId = accountId,
                ),
            )
        } else {
            repo?.installPrfTapper(null)
        }
    }

    val pendingPinRequest by tapCoordinator.pinRequest.collectAsState()
    val tapPresentation = remember(tapCoordinator, refreshTick, staleness, openItemId) {
        ragewarden.ragedroid.ui.components.TapPresentation.from(tapCoordinator.identitySet())
    }

    /**
     * The only gated decrypt path in the app UI. Non-`rage` items skip the
     * ceremony (there is nothing hardware-protected about them) but everything
     * `rage` goes through [HardwareTapCoordinator.authorize], which refuses up
     * front when no local key can satisfy the item and fails closed when a
     * biometric-bound key's prompt is unavailable.
     */
    val decryptWithGate: suspend (String, Set<String>?, String?, ragewarden.ragedroid.data.audit.AuditAction?, String) -> ByteArray = { itemId, onlyRecipientIds, purpose, use, field ->
        val item = backend.get(itemId)
        if (item == null || (field != ragewarden.ragedroid.data.ItemFields.WHOLE_PAYLOAD && !ragewarden.ragedroid.data.ItemFields.needsTap(item, field))) {
            backend.decryptField(itemId, emptyList(), use, field)
        } else {
            tapCoordinator.authorize(
                purpose = purpose ?: uiString(R.string.reveal_3, item.name),
                onlyRecipientIds = onlyRecipientIds,
            ) { identities ->
                backend.decryptField(itemId, identities, use, field)
            }
        }
    }

    when {
        editing != null -> EditItemScreen(
            item = editing,
            onCancel = onCloseEdit,
            onSave = { edit ->
                scope.launch {
                    runCatching {
                        // Re-sealing some protected fields needs the others: open the whole payload once.
                        val changing = buildSet {
                            if (edit.newSecret != null) add(ragewarden.ragedroid.data.ItemFields.primary(editing.kind))
                            edit.secretChanges?.keys?.let(::addAll)
                        }
                        val whole = if (editing.rage && edit.migrateToSsh == null && changing.isNotEmpty() &&
                            ragewarden.ragedroid.data.ItemFields.protectedFields(editing).any { it !in changing }
                        ) {
                            decryptWithGate(
                                editing.id,
                                null,
                                uiString(R.string.keep_the_rest_of_protected_while, editing.name),
                                null,
                                ragewarden.ragedroid.data.ItemFields.WHOLE_PAYLOAD,
                            )
                        } else {
                            null
                        }
                        try {
                            backend.edit(editing, edit.copy(currentPayload = whole))
                        } finally {
                            whole?.fill(0)
                        }
                    }.also { edit.newSecret?.fill(0) }.onSuccess {
                        onItemSaved()
                        showToast(context.getString(R.string.item_saved))
                        onCloseEdit()
                    }.onFailure { e ->
                        showToast(context.getString(R.string.save_failed, e.message ?: context.getString(R.string.unknown_error)))
                    }
                }
            },
            decryptCurrent = {
                // Editing a protected item still costs a tap: it decrypts the
                // current value to prefill the field.
                runCatching { decryptWithGate(editing.id, null, uiString(R.string.show_password_to_edit_it, editing.name), ragewarden.ragedroid.data.audit.AuditAction.Reveal, "") }.getOrNull()
            },
        )
        current != null -> {
            if (detailRouteFor(current) == DetailRoute.Login) {
                ItemDetailScreen(
                    item = current,
                    // use == null is the re-encrypt path, which re-wraps the whole payload.
                    decryptPassword = { id, only, purpose, use ->
                        decryptWithGate(id, only, purpose, use, if (use == null) ragewarden.ragedroid.data.ItemFields.WHOLE_PAYLOAD else "")
                    },
                    clipboard = clipboard,
                    showToast = showToast,
                    onBack = onCloseDetail,
                    onEdit = { onEdit(current.id) },
                    onHistory = { onHistory(current.id) },
                    onTapFailure = { kind -> onTapFailure(current.id, kind) },
                    onRotate = { plaintext ->
                        backend.update(current, plaintext)
                        onItemSaved()
                    },
                    onDelete = {
                        backend.delete(current.id)
                        onItemSaved()
                        onCloseDetail()
                    },
                    repository = VaultBridge.repository(),
                    autoOpenIdentityPicker = autoOpenIdentityPickerForId == current.id,
                    onIdentityPickerOpened = onIdentityPickerOpened,
                    onSetUpDevice = onEnrollFirst,
                    tapPresentation = tapPresentation,
                    pinRequest = pendingPinRequest,
                    decryptField = { field ->
                        decryptWithGate(
                            current.id,
                            null,
                            context.getString(R.string.show_field_purpose, current.name, ragewarden.ragedroid.data.ItemFields.label(field).lowercase()),
                            ragewarden.ragedroid.data.audit.AuditAction.Reveal,
                            field,
                        )
                    },
                )
            } else {
                KindDetailScreen(
                    item = current,
                    onBack = onCloseDetail,
                    onEdit = { onEdit(current.id) },
                    clipboard = clipboard,
                    showToast = showToast,
                    decryptProtected = { field ->
                        decryptWithGate(
                            current.id,
                            null,
                            uiString(R.string.show_on_screen_for_30_seconds, current.name, ragewarden.ragedroid.data.ItemFields.label(field).lowercase()),
                            ragewarden.ragedroid.data.audit.AuditAction.Reveal,
                            field,
                        )
                    },
                )
            }
        }
        else -> {
            val derivedFolders = remember(items) {
                (listOf(NO_FOLDER) + items.map { it.folder }.distinct().filter { it.isNotBlank() && it != NO_FOLDER })
                    .toPersistentList()
            }
            VaultListScreen(
                items = items,
                folders = derivedFolders,
                onOpen = { onOpen(it.id) },
                onSettings = onSettings,
                onAdd = onAdd,
                onSearch = onSearch,
                hasAnyEnrolledRecipient = hasAnyEnrolledRecipient,
                onEnrollFirst = onEnrollFirst,
                rotationStale = rotationStale,
                onRotate = onRotate,
                keyListUnreadable = keyListUnreadable,
                onResetKeyList = {
                    appContext.appEntryPoint().recipientStore().resetUnreadable(accountId)
                    keyListResetTick += 1
                    showToast(appContext.getString(R.string.key_list_reset_done))
                },
            )
        }
    }
}

private fun isAuthFailure(t: Throwable): Boolean =
    t is ragewarden.ragedroid.data.BitwardenVaultRepository.SessionExpiredException ||
        t.cause is ragewarden.ragedroid.data.BitwardenVaultRepository.SessionExpiredException

private fun inferToast(message: String): Toast {
    val lower = message.lowercase()
    val kind = when {
        lower.startsWith("autofilled") || lower.startsWith("copied") -> ToastKind.Success
        lower.contains("error") || lower.contains("failed") -> ToastKind.Error
        else -> ToastKind.Default
    }
    return Toast(message, kind)
}
