package ragewarden.ragedroid.ime

import androidx.compose.ui.res.stringResource
import ragewarden.ragedroid.R
import ragewarden.ragedroid.ui.components.rejectObscuredTouches
import ragewarden.ragedroid.ui.components.buttonTarget
import android.inputmethodservice.InputMethodService
import android.util.Log
import android.view.View
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Recomposer
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.AndroidUiDispatcher
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.setViewTreeLifecycleOwner
import androidx.savedstate.SavedStateRegistry
import androidx.savedstate.SavedStateRegistryController
import androidx.savedstate.SavedStateRegistryOwner
import androidx.savedstate.setViewTreeSavedStateRegistryOwner
import kotlinx.collections.immutable.ImmutableList
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import android.text.InputType
import android.view.inputmethod.EditorInfo
import ragewarden.ragedroid.data.LockState
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.components.VaultRow
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

/**
 * Keyboard delivery, only while the vault is unlocked. Unprotected items are
 * typed after a plain confirmation; a protected item opens [ImeAuthActivity]
 * for the hardware tap, and is typed once the same field has focus again.
 * Every listing and delivery goes through [ImeDelivery], which consults
 * [LockState] on every call; nothing in this class reaches the backend directly.
 */
class RagewardenInputMethodService :
    InputMethodService(),
    LifecycleOwner,
    SavedStateRegistryOwner {
    private val lifecycleRegistry = LifecycleRegistry(this)
    private val savedStateController = SavedStateRegistryController.create(this)

    private val lockState: LockState by lazy { applicationContext.appEntryPoint().lockState() }

    private val bound = MutableStateFlow<Pair<Long, ImeSession>?>(null)
    private var boundSeq = 0L

    private val broker = object : ImeAuthBroker {
        private var authStartedAt = 0L

        override suspend fun authorize(item: VaultItem, session: ImeSession): ByteArray? {
            val (nonce, result) = ImeAuthChannel.open()
            authStartedAt = boundSeq
            return try {
                startActivity(
                    ImeAuthActivity.intent(
                        this@RagewardenInputMethodService,
                        nonce,
                        item.id,
                        targetAppLabel.value ?: session.packageName,
                    ),
                )
                withTimeoutOrNull(AUTH_TIMEOUT_MS) { result.await() }
            } finally {
                ImeAuthChannel.close(nonce)
            }
        }

        override suspend fun awaitReturn(session: ImeSession): Boolean {
            val next = withTimeoutOrNull(RETURN_TIMEOUT_MS) {
                bound.filterNotNull().first { (seq, s) -> seq > authStartedAt && s.packageName != packageName }
            }
            return next?.second == session
        }
    }

    private val delivery: ImeDelivery by lazy {
        ImeDelivery(lockState, VaultBridge.ensureBackend(applicationContext), broker)
    }

    override val lifecycle: Lifecycle get() = lifecycleRegistry
    override val savedStateRegistry: SavedStateRegistry get() = savedStateController.savedStateRegistry

    override fun onCreate() {
        super.onCreate()
        savedStateController.performAttach()
        savedStateController.performRestore(null)
        lifecycleRegistry.currentState = Lifecycle.State.CREATED
    }

    /**
     * Shown with a hardware keyboard attached too. The stock answer hides an IME
     * whenever a physical keyboard is present (and the emulator always reports
     * one), but this keyboard is a credential picker, not a key layout: a phone
     * with a Bluetooth keyboard would otherwise never see it.
     */
    override fun onEvaluateInputViewShown(): Boolean = true

    /**
     * The keyboard's own recomposer. Without one, Compose builds a window
     * recomposer from the IME window's root view and looks for the lifecycle
     * owner there; the owner is set on the ComposeView, so the first show
     * crashed with "ViewTreeLifecycleOwner not found from ... parentPanel".
     */
    private val recomposer: Recomposer by lazy {
        Recomposer(AndroidUiDispatcher.CurrentThread).also { r ->
            lifecycleScope.launch(AndroidUiDispatcher.CurrentThread) { r.runRecomposeAndApplyChanges() }
        }
    }

    override fun onCreateInputView(): View {
        moveTo(Lifecycle.State.STARTED)
        val composeView = ComposeView(this).apply {
            filterTouchesWhenObscured = true
            setViewTreeLifecycleOwner(this@RagewardenInputMethodService)
            setViewTreeSavedStateRegistryOwner(this@RagewardenInputMethodService)
            setParentCompositionContext(recomposer)
            setContent {
                RageTheme {
                    // Collected, not read once: "Lock now" or an ON_STOP lock in
                    // the main Activity has to take the list off this surface
                    // while the keyboard is still on screen.
                    val locked by lockState.locked.collectAsState()
                    val offer = remember(locked) { delivery.offer() }
                    if (ownPinField.value) {
                        DigitPad(
                            onDigit = { d -> currentInputConnection?.commitText(d.toString(), 1) },
                            onBackspace = { currentInputConnection?.deleteSurroundingText(1, 0) },
                            onDone = { requestHideSelf(0) },
                        )
                    } else {
                        ImeSurface(
                            locked = offer.locked,
                            items = offer.deliverable,
                            protectedCount = offer.protectedCount,
                            onDeliver = { itemId -> deliverPlaintext(itemId) },
                            onCancel = { switchAwayQuietly() },
                            onUnlock = {
                                startActivity(
                                    android.content.Intent(this@RagewardenInputMethodService, ragewarden.ragedroid.MainActivity::class.java)
                                        .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK),
                                )
                            },
                        )
                    }
                }
            }
        }
        return composeView
    }

    override fun onStartInput(attribute: EditorInfo?, restarting: Boolean) {
        super.onStartInput(attribute, restarting)
        val pkg = attribute?.packageName
        bound.value = if (attribute == null || pkg == null) null else (++boundSeq to ImeSession(pkg, attribute.fieldId))
        ownPinField.value = attribute != null && pkg == packageName &&
            (attribute.inputType and InputType.TYPE_MASK_CLASS) == InputType.TYPE_CLASS_NUMBER
    }

    override fun onFinishInput() {
        super.onFinishInput()
        bound.value = null
    }

    override fun onStartInputView(info: EditorInfo?, restarting: Boolean) {
        super.onStartInputView(info, restarting)
        targetAppLabel.value = info?.packageName?.let { pkg ->
            runCatching {
                packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0)).toString()
            }.getOrDefault(pkg)
        }
        moveTo(Lifecycle.State.RESUMED)
    }

    override fun onFinishInputView(finishingInput: Boolean) {
        super.onFinishInputView(finishingInput)
        moveTo(Lifecycle.State.STARTED)
    }

    override fun onDestroy() {
        super.onDestroy()
        lifecycleRegistry.currentState = Lifecycle.State.DESTROYED
        recomposer.cancel()
    }

    /**
     * Lifecycle moves end at DESTROYED. InputMethodService.onDestroy finishes a
     * shown input view, so onFinishInputView can arrive during or after it;
     * moving a destroyed registry back to STARTED throws and takes the app's
     * process down with it.
     */
    private fun moveTo(state: Lifecycle.State) {
        if (lifecycleRegistry.currentState != Lifecycle.State.DESTROYED) lifecycleRegistry.currentState = state
    }

    /**
     * Delegates the whole decision to [ImeDelivery], which is the only thing in
     * the keyboard that touches the vault. `commitText` is reachable from
     * exactly one place -- the [ImeDelivery.deliver] callback below -- and
     * [ImeDelivery] invokes it only after two lock checks, one before the
     * decrypt and one after it.
     *
     * Runs on [lifecycleScope] instead of `runBlocking` -- the old code blocked
     * the IME's main thread on a decrypt that can wait on a network sync.
     */
    private fun deliverPlaintext(itemId: String) {
        val session = bound.value?.second
        lifecycleScope.launch {
            val outcome = delivery.deliver(itemId, session) { text ->
                currentInputConnection?.commitText(text, 1)
            }
            if (outcome is ImeDelivery.Outcome.Refused) {
                Log.w(TAG, "IME refused to deliver: ${outcome.reason}")
            }
            switchAwayQuietly()
        }
    }

    private fun switchAwayQuietly() {
        val switched = runCatching { switchToPreviousInputMethod() }.getOrDefault(false)
        if (!switched) {
            requestHideSelf(0)
        }
    }

    private companion object {
        const val TAG = "RagewardenIme"
        const val AUTH_TIMEOUT_MS = 120_000L
        const val RETURN_TIMEOUT_MS = 30_000L
    }
}

/**
 * The keyboard's root.
 *
 * `locked` is checked here as well as in [ImeDelivery] on purpose. The service
 * already passes an empty list while locked, so this branch is not what keeps
 * the items off screen in production -- it is what makes the rule hold for any
 * caller, including a future one that forgets to empty the list. The test
 * `ImeSurfaceLockedTest` passes a *populated* list with `locked = true` and
 * asserts nothing from it renders.
 */
@Composable
internal fun ImeSurface(
    locked: Boolean,
    items: ImmutableList<VaultItem>,
    protectedCount: Int,
    onDeliver: (String) -> Unit,
    onCancel: () -> Unit,
    onUnlock: () -> Unit = {},
) {
    if (locked) {
        LockedKeyboardNotice(onCancel = onCancel, onUnlock = onUnlock)
    } else {
        KeyboardSurface(
            items = items,
            protectedCount = protectedCount,
            onDeliver = onDeliver,
            onCancel = onCancel,
        )
    }
}

/**
 * What the keyboard shows while the vault is locked. It lists nothing and offers
 * no delivery affordance at all: unlocking needs `BiometricPrompt` or the master
 * password field, and an `InputMethodService` can host neither, so the only
 * honest instruction is to go and open the app.
 */
@Composable
private fun LockedKeyboardNotice(onCancel: () -> Unit, onUnlock: () -> Unit) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.background)
            .heightIn(min = 240.dp, max = 360.dp)
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        Text(
            text = stringResource(R.string.vault_locked),
            style = RageType.eyebrow,
            color = c.fgSecondary,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp),
        )
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = stringResource(R.string.ragewarden_is_locked_so_this_keyboard),
            style = RageType.caption,
            color = c.fgSecondary,
            modifier = Modifier.padding(horizontal = 4.dp),
        )
        Spacer(modifier = Modifier.height(8.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.End,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .buttonTarget(onClick = onCancel)
                    .padding(horizontal = 8.dp, vertical = 6.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(text = stringResource(R.string.switch_back), style = RageType.caption, color = c.fgSecondary)
            }
            Box(
                modifier = Modifier
                    .rejectObscuredTouches()
                    .buttonTarget(onClick = onUnlock)
                    .padding(horizontal = 8.dp, vertical = 6.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(text = stringResource(R.string.unlock_ragewarden), style = RageType.caption, color = c.accent)
            }
        }
    }
}

@Composable
private fun KeyboardSurface(
    items: ImmutableList<VaultItem>,
    protectedCount: Int,
    onDeliver: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val c = rageColors
    var pending by remember { mutableStateOf<VaultItem?>(null) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.background)
            .heightIn(min = 240.dp, max = 360.dp)
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        val current = pending
        if (current == null) {
            Text(
                text = stringResource(R.string.type_a_credential),
                style = RageType.eyebrow,
                color = c.fgSecondary,
                modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp),
            )
            Spacer(modifier = Modifier.height(6.dp))
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(c.surface, RoundedCornerShape(8.dp)),
            ) {
                LazyColumn(modifier = Modifier.fillMaxWidth()) {
                    items(items, key = { it.id }) { item ->
                        VaultRow(item = item, onClick = { pending = item })
                    }
                }
            }
            if (protectedCount > 0) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.protected_items_open_ragewarden_for_your),
                    style = RageType.meta,
                    color = c.fgSecondary,
                    modifier = Modifier.padding(horizontal = 4.dp),
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .buttonTarget(onClick = onCancel)
                        .padding(horizontal = 8.dp, vertical = 6.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(text = stringResource(R.string.switch_back), style = RageType.caption, color = c.fgSecondary)
                }
            }
        } else {
            DeliveryConfirm(
                item = current,
                onConfirm = {
                    onDeliver(current.id)
                    pending = null
                },
                onCancel = {
                    pending = null
                    onCancel()
                },
            )
        }
    }
}

/**
 * The hardware tap for a protected item runs in [ImeAuthActivity]; this only
 * says which of the two paths a tap takes.
 */
@Composable
private fun DeliveryConfirm(
    item: VaultItem,
    onConfirm: () -> Unit,
    onCancel: () -> Unit,
) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surfaceElevated, RoundedCornerShape(10.dp))
            .border(1.dp, c.border, RoundedCornerShape(10.dp))
            .padding(horizontal = 16.dp, vertical = 14.dp),
    ) {
        Text(
            text = stringResource(R.string.type_password_into, item.name, targetAppLabel.value ?: stringResource(R.string.this_field)),
            style = RageType.rowTitle,
            color = c.fgEmphasis,
        )
        Text(
            text = if (item.rage) {
                stringResource(R.string.ragewarden_opens_to_ask_for_your)
            } else {
                stringResource(R.string.this_item_is_not_ragewarden_protected)
            },
            style = RageType.caption,
            color = c.fgSecondary,
        )
        Spacer(modifier = Modifier.height(12.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
        ) {
            Box(
                modifier = Modifier
                    .buttonTarget(onClick = onCancel)
                    .padding(horizontal = 8.dp, vertical = 6.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(text = stringResource(R.string.cancel), style = RageType.caption, color = c.fgSecondary)
            }
            Box(
                modifier = Modifier
                    .background(c.accent, RoundedCornerShape(8.dp))
                    .rejectObscuredTouches()
                    .buttonTarget(onClick = onConfirm)
                    .padding(horizontal = 14.dp, vertical = 8.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = if (item.rage) stringResource(R.string.unlock_and_type) else stringResource(R.string.type_it),
                    style = RageType.button,
                    color = c.background,
                    maxLines = 1,
                )
            }
        }
    }
}

private val targetAppLabel = androidx.compose.runtime.mutableStateOf<String?>(null)

private val ownPinField = androidx.compose.runtime.mutableStateOf(false)

/**
 * Shown when the focused field is a numeric field of Ragewarden itself -- the
 * PIV PIN prompt of [ImeAuthActivity] -- so the PIN can be typed without switching
 * keyboards in the middle of a delivery.
 */
@Composable
internal fun DigitPad(onDigit: (Int) -> Unit, onBackspace: () -> Unit, onDone: () -> Unit) {
    val c = rageColors
    val rows = listOf(listOf(1, 2, 3), listOf(4, 5, 6), listOf(7, 8, 9))
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.background)
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        rows.forEach { row ->
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                row.forEach { d -> PadKey(label = d.toString(), modifier = Modifier.weight(1f)) { onDigit(d) } }
            }
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            PadKey(label = "⌫", modifier = Modifier.weight(1f), onClick = onBackspace)
            PadKey(label = "0", modifier = Modifier.weight(1f)) { onDigit(0) }
            PadKey(label = stringResource(R.string.done), modifier = Modifier.weight(1f), onClick = onDone)
        }
    }
}

@Composable
private fun PadKey(label: String, modifier: Modifier, onClick: () -> Unit) {
    val c = rageColors
    Box(
        modifier = modifier
            .height(48.dp)
            .background(c.surface, RoundedCornerShape(8.dp))
            .rejectObscuredTouches()
            .buttonTarget(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Text(text = label, style = RageType.rowTitle, color = c.fgEmphasis)
    }
}
