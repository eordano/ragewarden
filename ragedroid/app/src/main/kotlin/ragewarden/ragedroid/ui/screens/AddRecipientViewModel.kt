package ragewarden.ragedroid.ui.screens

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import androidx.compose.ui.res.stringResource
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import java.lang.ref.WeakReference
import javax.inject.Inject
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import ragewarden.ragedroid.R
import ragewarden.ragedroid.data.RecipientStore
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.data.audit.AuditAction
import ragewarden.ragedroid.data.audit.AuditFeed
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.identities.YubiKeyX25519UnsupportedException
import ragewarden.ragedroid.identities.enrollKeystoreIdentity
import ragewarden.ragedroid.identities.enrollPasskeyWithPrf
import ragewarden.ragedroid.identities.enrollYubiKeyPiv
import ragewarden.ragedroid.identities.isStrongBoxAvailable
import ragewarden.ragedroid.ui.uiString

private const val TAG = "AddRecipientViewModel"

enum class EnrollKind(
    @androidx.annotation.StringRes val title: Int,
    @androidx.annotation.StringRes val desc: Int,
    val recipientKind: RecipientKind,
    val singleton: Boolean,
) {
    YubiKey(
        title = R.string.yubikey_piv_slot,
        desc = R.string.x25519_keypair_on_the_device_identical,
        recipientKind = RecipientKind.YubiKey,
        singleton = false,
    ),
    Fido2(
        title = R.string.passkey,
        desc = R.string.a_passkey_on_this_phone_in,
        recipientKind = RecipientKind.PasskeyPrf,
        singleton = false,
    ),
    StrongBox(
        title = R.string.this_phone_strongbox,
        desc = R.string.tee_backed_key_convenient_but_tied,
        recipientKind = RecipientKind.StrongBox,
        singleton = true,
    ),
    Recovery(
        title = R.string.paper_recovery_identity,
        desc = R.string.paper_recovery_desc,
        recipientKind = RecipientKind.Recovery,
        singleton = true,
    ),
}

sealed interface AddRecipientPhase {
    object Picker : AddRecipientPhase
    object Listening : AddRecipientPhase
    object Found : AddRecipientPhase
    object Done : AddRecipientPhase
    /** [title] and [detailRes] are string resources; [detail] is text from the failure itself. */
    data class Failed(
        @androidx.annotation.StringRes val title: Int,
        val titleArgs: List<String> = emptyList(),
        @androidx.annotation.StringRes val detailRes: Int? = null,
        val detail: String = "",
        val recoverable: Boolean,
    ) : AddRecipientPhase
}

data class AddRecipientUiState(
    val phase: AddRecipientPhase = AddRecipientPhase.Picker,
    val pickedKind: EnrollKind? = null,
    val pinPromptOpen: Boolean = false,
    val retryNonce: Int = 0,
    /**
     * The phone has no screen lock or biometric, so a Keystore key cannot be
     * bound to user authentication: nothing is generated until the user picks
     * "Set a screen lock" or "Enrol without confirmation".
     */
    val unboundKeyConsentOpen: Boolean = false,
)

sealed interface AddRecipientAction {
    data class PickKind(val kind: EnrollKind, val activity: FragmentActivity) : AddRecipientAction
    data class SubmitPin(val pin: CharArray, val activity: FragmentActivity) : AddRecipientAction
    object CancelEnrollment : AddRecipientAction
    /** Generate the Keystore key without user authentication, after [AddRecipientUiState.unboundKeyConsentOpen]. */
    object ConfirmUnboundKey : AddRecipientAction
    /** The user went to set a screen lock instead; back to the picker. */
    object DeclineUnboundKey : AddRecipientAction
    object Retry : AddRecipientAction
    object Back : AddRecipientAction
}

sealed interface AddRecipientEvent {
    data class Toast(val message: String) : AddRecipientEvent
    object NavigateToPaperRecovery : AddRecipientEvent
    object Done : AddRecipientEvent
}

@HiltViewModel
class AddRecipientViewModel @Inject constructor(
    private val recipientStore: RecipientStore,
    private val auditFeed: AuditFeed,
    @ApplicationContext private val appContext: Context,
) : ViewModel() {

    private val _state = MutableStateFlow(AddRecipientUiState())
    val state: StateFlow<AddRecipientUiState> = _state.asStateFlow()

    private val _events = Channel<AddRecipientEvent>(Channel.BUFFERED)
    val events: Flow<AddRecipientEvent> = _events.receiveAsFlow()

    private var enrollJob: Job? = null
    private var activityRef: WeakReference<FragmentActivity> = WeakReference(null)

    fun onAction(action: AddRecipientAction) {
        when (action) {
            is AddRecipientAction.PickKind -> handlePickKind(action.kind, action.activity)
            is AddRecipientAction.SubmitPin -> handleSubmitPin(action.pin, action.activity)
            AddRecipientAction.CancelEnrollment -> handleCancel()
            AddRecipientAction.Retry -> handleRetry()
            AddRecipientAction.Back -> handleBack()
            AddRecipientAction.ConfirmUnboundKey -> {
                _state.value = _state.value.copy(unboundKeyConsentOpen = false, phase = AddRecipientPhase.Listening)
                launchStrongBox(allowUnbound = true)
            }
            AddRecipientAction.DeclineUnboundKey ->
                _state.value = _state.value.copy(unboundKeyConsentOpen = false, phase = AddRecipientPhase.Picker, pickedKind = null)
        }
    }

    /** Whether a Keystore key can be bound to user authentication here; replaced in tests. */
    internal var authBindable: () -> Boolean = { ragewarden.ragedroid.identities.isBiometricEnrollable(appContext) }

    /** Generates the Keystore key; replaced in tests, which have no AndroidKeyStore. */
    internal var keystoreEnroll: suspend (displayName: String, useStrongBox: Boolean, requireBiometric: Boolean) -> StoredRecipient =
        { name, strongBox, biometric -> enrollKeystoreIdentity(displayName = name, useStrongBox = strongBox, requireBiometric = biometric).first }

    private fun handlePickKind(kind: EnrollKind, activity: FragmentActivity) {
        activityRef = WeakReference(activity)
        if (kind == EnrollKind.Recovery) {
            _events.trySend(AddRecipientEvent.NavigateToPaperRecovery)
            return
        }
        enrollJob?.cancel()
        _state.value = _state.value.copy(
            pickedKind = kind,
            phase = AddRecipientPhase.Listening,
            pinPromptOpen = false,
        )
        startEnrollment(kind, activity)
    }

    private fun handleRetry() {
        val current = _state.value
        val kind = current.pickedKind ?: return
        enrollJob?.cancel()
        _state.value = current.copy(
            phase = AddRecipientPhase.Listening,
            retryNonce = current.retryNonce + 1,
            pinPromptOpen = false,
        )
        startEnrollment(kind, activityHint = activityRef.get())
    }

    private fun startEnrollment(kind: EnrollKind, activityHint: FragmentActivity?) {
        when (kind) {
            EnrollKind.StrongBox -> if (authBindable()) {
                launchStrongBox(allowUnbound = false)
            } else {
                _state.value = _state.value.copy(unboundKeyConsentOpen = true, phase = AddRecipientPhase.Picker)
            }
            EnrollKind.YubiKey -> {
                if (activityHint == null) {
                    _state.value = _state.value.copy(
                        phase = AddRecipientPhase.Failed(
                            title = R.string.yubikey_enrolment_needs_an_activity_context,
                            detailRes = R.string.reopen_this_screen_and_try_again,
                            recoverable = false,
                        ),
                    )
                } else {
                    _state.value = _state.value.copy(
                        phase = AddRecipientPhase.Listening,
                        pinPromptOpen = true,
                    )
                }
            }
            EnrollKind.Fido2 -> {
                if (activityHint == null) {
                    _state.value = _state.value.copy(
                        phase = AddRecipientPhase.Failed(
                            title = R.string.passkey_enrolment_needs_an_activity_context,
                            detailRes = R.string.reopen_this_screen_and_try_again,
                            recoverable = false,
                        ),
                    )
                } else {
                    launchFido2(activityHint)
                }
            }
            EnrollKind.Recovery -> Unit
        }
    }

    private fun launchStrongBox(allowUnbound: Boolean) {
        enrollJob = viewModelScope.launch {
            val result = safeRun {
                val biometric = authBindable()
                check(biometric || allowUnbound) { "an unbound Keystore key needs the user's consent first" }
                val useStrongBox = runCatching { isStrongBoxAvailable(appContext) }.getOrDefault(false)
                // Named for what protects it: a key with no user authentication
                // is not "StrongBox" in any sense a user would rely on.
                val displayName = when {
                    !biometric -> uiString(R.string.this_phone_no_confirmation)
                    useStrongBox -> uiString(R.string.this_phone_strongbox)
                    else -> uiString(R.string.this_phone_tee)
                }
                keystoreEnroll(displayName, useStrongBox, biometric).copy(defaultEncrypt = biometric)
            }
            result.onSuccess { recipient ->
                try {
                    persist(recipient)
                    _state.value = _state.value.copy(phase = AddRecipientPhase.Done)
                } catch (ce: CancellationException) {
                    Log.w(
                        TAG,
                        "Cancelled before persisting Keystore recipient ${recipient.id} " +
                            "(handle=${recipient.keystoreHandle}); orphan key may remain in AndroidKeyStore.",
                    )
                    throw ce
                }
            }.onFailure { e ->
                applyFailure(EnrollKind.StrongBox, e)
            }
        }
    }

    private fun launchFido2(activity: FragmentActivity) {
        enrollJob = viewModelScope.launch {
            val result = safeRun {
                enrollPasskeyWithPrf(
                    activity = activity,
                    accountId = currentAccountId().ifBlank { "anonymous" },
                )
            }
            result.onSuccess { (recipient, _) ->
                try {
                    persist(recipient)
                    _state.value = _state.value.copy(phase = AddRecipientPhase.Done)
                } catch (ce: CancellationException) {
                    Log.w(
                        TAG,
                        "Cancelled before persisting Passkey recipient ${recipient.id}; " +
                            "orphan credential may remain on the authenticator.",
                    )
                    throw ce
                }
            }.onFailure { e ->
                applyFailure(EnrollKind.Fido2, e)
            }
        }
    }

    private fun handleSubmitPin(pin: CharArray, activity: FragmentActivity) {
        activityRef = WeakReference(activity)
        _state.value = _state.value.copy(
            pinPromptOpen = false,
            phase = AddRecipientPhase.Listening,
        )
        enrollJob = viewModelScope.launch {
            val result = try {
                Result.success(enrollYubiKeyPiv(activity = activity, pin = pin))
            } catch (ce: CancellationException) {
                pin.fill(' ')
                throw ce
            } catch (t: Throwable) {
                Result.failure<Pair<StoredRecipient, Any?>>(t)
            } finally {
                pin.fill(' ')
            }
            result.onSuccess { (recipient, _) ->
                try {
                    persist(recipient)
                    _state.value = _state.value.copy(phase = AddRecipientPhase.Done)
                } catch (ce: CancellationException) {
                    Log.w(
                        TAG,
                        "Cancelled before persisting YubiKey recipient ${recipient.id}; " +
                            "PIV slot key may exist on the YubiKey.",
                    )
                    throw ce
                }
            }.onFailure { e ->
                applyFailure(EnrollKind.YubiKey, e)
            }
        }
    }

    private fun handleCancel() {
        enrollJob?.cancel()
        enrollJob = null
        activityRef = WeakReference(null)
        _state.value = AddRecipientUiState()
    }

    private fun handleBack() {
        val current = _state.value
        if (current.pickedKind != null && current.phase !is AddRecipientPhase.Done) {
            enrollJob?.cancel()
            enrollJob = null
            activityRef = WeakReference(null)
            _state.value = AddRecipientUiState()
        } else {
            enrollJob?.cancel()
            enrollJob = null
            activityRef = WeakReference(null)
            _state.value = AddRecipientUiState()
            _events.trySend(AddRecipientEvent.Done)
        }
    }

    fun resetToPicker() {
        if (_state.value.phase is AddRecipientPhase.Done || _state.value.pickedKind != null) {
            enrollJob?.cancel()
            enrollJob = null
            activityRef = WeakReference(null)
            _state.value = AddRecipientUiState()
        }
    }

    private fun applyFailure(kind: EnrollKind, e: Throwable) {
        val mapped = mapEnrollFailure(kind, e)
        if (mapped == null) {
            _state.value = AddRecipientUiState()
        } else {
            _state.value = _state.value.copy(phase = mapped, pinPromptOpen = false)
        }
    }

    private suspend fun persist(recipient: StoredRecipient) {
        val accountId = currentAccountId()
        if (accountId.isBlank()) return
        withContext(NonCancellable) {
            recipientStore.add(accountId, recipient)
            auditFeed.record(
                action = AuditAction.EnrollIdentity,
                item = recipient.displayName,
                recipient = recipient.id,
                reason = uiString(R.string.recipient_added_2, recipient.kind),
            )
            VaultBridge.repository()?.pushRecipientRegistry()
        }
    }

    private fun currentAccountId(): String =
        VaultBridge.repository()?.accountId.orEmpty()

    private suspend fun <T> safeRun(block: suspend () -> T): Result<T> = try {
        Result.success(block())
    } catch (ce: CancellationException) {
        throw ce
    } catch (t: Throwable) {
        Result.failure(t)
    }

    private fun mapEnrollFailure(kind: EnrollKind, e: Throwable): AddRecipientPhase.Failed? = when (e) {
        is GetCredentialCancellationException,
        is CreateCredentialCancellationException,
        -> null
        is UserNotAuthenticatedException,
        is KeyPermanentlyInvalidatedException,
        -> AddRecipientPhase.Failed(
            title = R.string.biometric_expired_tap_to_retry,
            detail = e.message.orEmpty(),
            recoverable = true,
        )
        is ragewarden.ragedroid.data.StoreUnreadableException -> AddRecipientPhase.Failed(
            title = ragewarden.ragedroid.R.string.key_list_unreadable_enrol,
            detail = "",
            recoverable = false,
        )
        is YubiKeyX25519UnsupportedException -> AddRecipientPhase.Failed(
            title = R.string.yubikey_firmware_too_old_need_5,
            detail = e.message.orEmpty(),
            recoverable = false,
        )
        else -> AddRecipientPhase.Failed(
            title = R.string.enrolment_failed,
            titleArgs = listOf(e.message ?: e::class.simpleName.orEmpty()),
            detailRes = R.string.the_enrolment_did_not_complete,
            recoverable = true,
        )
    }
}
