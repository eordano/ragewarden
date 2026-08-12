package ragewarden.ragedroid.ime

import android.inputmethodservice.InputMethodService
import android.util.Log
import android.view.View
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
import kotlinx.coroutines.launch
import ragewarden.ragedroid.data.LockState
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.di.appEntryPoint
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.ui.components.VaultRow
import ragewarden.ragedroid.ui.theme.RageTheme
import ragewarden.ragedroid.ui.theme.RageType
import ragewarden.ragedroid.ui.theme.rageColors

/**
 * Keyboard delivery for **unprotected** items only, and only while the vault is
 * unlocked.
 *
 * An `InputMethodService` is not an Activity: it cannot host `BiometricPrompt`,
 * cannot show Credential Manager's sheet, and cannot start NFC reader-mode
 * discovery. So it cannot run the hardware ceremony, and it must not pretend to.
 *
 * An earlier version filtered `rage` items out of the list -- correctly -- and
 * then ran the full `InlineTapReveal` "tap to authorize" ceremony over the
 * items that were left, i.e. a hardware-consent dialog for credentials that had
 * no hardware protection and required no authorization. That is worse than no
 * prompt: it teaches the user that the ceremony is decorative. It is replaced
 * here by a plain confirmation that says what it is, plus an honest count of the
 * protected items this surface deliberately will not touch.
 *
 * The version after that still contained no reference to the vault lock at all.
 * It read [VaultBridge]'s in-process cache, which stays populated while locked,
 * so locking the vault did not stop the keyboard listing its contents or typing
 * a password out of it. Both the listing and the delivery now go through
 * [ImeDelivery], which consults [LockState] on every call; nothing in this class
 * reaches the backend directly.
 */
class RagewardenInputMethodService :
    InputMethodService(),
    LifecycleOwner,
    SavedStateRegistryOwner {
    private val lifecycleRegistry = LifecycleRegistry(this)
    private val savedStateController = SavedStateRegistryController.create(this)

    private val lockState: LockState by lazy { applicationContext.appEntryPoint().lockState() }

    private val delivery: ImeDelivery by lazy {
        ImeDelivery(lockState, VaultBridge.ensureBackend(applicationContext))
    }

    override val lifecycle: Lifecycle get() = lifecycleRegistry
    override val savedStateRegistry: SavedStateRegistry get() = savedStateController.savedStateRegistry

    override fun onCreate() {
        super.onCreate()
        savedStateController.performAttach()
        savedStateController.performRestore(null)
        lifecycleRegistry.currentState = Lifecycle.State.CREATED
    }

    override fun onCreateInputView(): View {
        lifecycleRegistry.currentState = Lifecycle.State.STARTED
        val composeView = ComposeView(this).apply {
            filterTouchesWhenObscured = true
            setViewTreeLifecycleOwner(this@RagewardenInputMethodService)
            setViewTreeSavedStateRegistryOwner(this@RagewardenInputMethodService)
            setContent {
                RageTheme {
                    // Collected, not read once: "Lock now" or an ON_STOP lock in
                    // the main Activity has to take the list off this surface
                    // while the keyboard is still on screen.
                    val locked by lockState.locked.collectAsState()
                    val offer = remember(locked) { delivery.offer() }
                    ImeSurface(
                        locked = offer.locked,
                        items = offer.deliverable,
                        protectedCount = offer.protectedCount,
                        onDeliver = { itemId -> deliverPlaintext(itemId) },
                        onCancel = { switchAwayQuietly() },
                    )
                }
            }
        }
        return composeView
    }

    override fun onStartInputView(info: android.view.inputmethod.EditorInfo?, restarting: Boolean) {
        super.onStartInputView(info, restarting)
        lifecycleRegistry.currentState = Lifecycle.State.RESUMED
    }

    override fun onFinishInputView(finishingInput: Boolean) {
        super.onFinishInputView(finishingInput)
        lifecycleRegistry.currentState = Lifecycle.State.STARTED
    }

    override fun onDestroy() {
        lifecycleRegistry.currentState = Lifecycle.State.DESTROYED
        super.onDestroy()
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
        lifecycleScope.launch {
            val outcome = delivery.deliver(itemId) { text ->
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
) {
    if (locked) {
        LockedKeyboardNotice(onCancel = onCancel)
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
private fun LockedKeyboardNotice(onCancel: () -> Unit) {
    val c = rageColors
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.background)
            .heightIn(min = 240.dp, max = 360.dp)
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        Text(
            text = "VAULT LOCKED",
            style = RageType.eyebrow,
            color = c.fgSecondary,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp),
        )
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = "Ragewarden is locked, so this keyboard will not list or type any " +
                "credential. Open Ragewarden and unlock it first -- a keyboard cannot " +
                "host the unlock prompt.",
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
                    .clickable(onClick = onCancel)
                    .padding(horizontal = 8.dp, vertical = 6.dp),
            ) {
                Text(text = "Switch back", style = RageType.caption, color = c.fgSecondary)
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
                text = "UNPROTECTED CREDENTIALS ONLY",
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
                    text = "$protectedCount Ragewarden-protected item(s) are not shown. A keyboard " +
                        "cannot host the hardware prompt -- open Ragewarden to use them.",
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
                        .clickable(onClick = onCancel)
                        .padding(horizontal = 8.dp, vertical = 6.dp),
                ) {
                    Text(text = "Switch back", style = RageType.caption, color = c.fgSecondary)
                }
            }
        } else {
            UnprotectedDeliveryConfirm(
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
 * Deliberately not [ragewarden.ragedroid.ui.components.InlineTapReveal]: nothing
 * here is authorized by hardware, and the copy says so.
 */
@Composable
private fun UnprotectedDeliveryConfirm(
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
            text = "Type ${item.name} password into this field?",
            style = RageType.rowTitle,
            color = c.fgEmphasis,
        )
        Text(
            text = "This item is not Ragewarden-protected: no key authorizes this, " +
                "and the text is committed straight into the app you are in.",
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
                    .clickable(onClick = onCancel)
                    .padding(horizontal = 8.dp, vertical = 6.dp),
            ) {
                Text(text = "Cancel", style = RageType.caption, color = c.fgSecondary)
            }
            Box(
                modifier = Modifier
                    .background(c.accent, RoundedCornerShape(8.dp))
                    .clickable(onClick = onConfirm)
                    .padding(horizontal = 14.dp, vertical = 8.dp),
            ) {
                Text(text = "Type it", style = RageType.button, color = c.background, maxLines = 1)
            }
        }
    }
}
