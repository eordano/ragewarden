package ragewarden.ragedroid.ui.screens

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
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
import ragewarden.ragedroid.data.RecipientStore
import ragewarden.ragedroid.data.StoredRecipient
import ragewarden.ragedroid.data.VaultBridge
import ragewarden.ragedroid.data.audit.AuditAction
import ragewarden.ragedroid.data.audit.AuditFeed
import ragewarden.ragedroid.model.RecipientKind
import ragewarden.ragedroid.identities.YubiKeyX25519UnsupportedException
import ragewarden.ragedroid.identities.enrollKeystoreIdentity
import ragewarden.ragedroid.identities.enrollPasskeyWithPrf
import ragewarden.ragedroid.identities.enrollYubiKeyPivX25519
import ragewarden.ragedroid.identities.isStrongBoxAvailable

private const val TAG = "AddRecipientViewModel"

enum class EnrollKind(
    val title: String,
    val desc: String,
    val recipientKind: RecipientKind,
    val singleton: Boolean,
) {
    YubiKey(
        title = "YubiKey (PIV slot)",
        desc = "X25519 keypair on the device. Identical to age-plugin-yubikey.",
        recipientKind = RecipientKind.YubiKey,
        singleton = false,
    ),
    Fido2(
        title = "FIDO2 hmac-secret",
        desc = "Any FIDO2 authenticator. Tap is built into the protocol.",
        recipientKind = RecipientKind.Fido2,
        singleton = false,
    ),
    StrongBox(
        title = "This phone (StrongBox)",
        desc = "TEE-backed key. Convenient, but tied to this device.",
        recipientKind = RecipientKind.StrongBox,
        singleton = true,
    ),
    Recovery(
        title = "Paper recovery identity",
        desc = "Printable age identity. No-network backup.",
        recipientKind = RecipientKind.Recovery,
        singleton = true,
    ),
}

sealed interface AddRecipientPhase {
    object Picker : AddRecipientPhase
    object Listening : AddRecipientPhase
    object Found : AddRecipientPhase
    object Done : AddRecipientPhase
    data class Failed(
        val title: String,
        val detail: String,
        val recoverable: Boolean,
    ) : AddRecipientPhase
}

data class AddRecipientUiState(
    val phase: AddRecipientPhase = AddRecipientPhase.Picker,
    val pickedKind: EnrollKind? = null,
    val pinPromptOpen: Boolean = false,
    val retryNonce: Int = 0,
)

sealed interface AddRecipientAction {
    data class PickKind(val kind: EnrollKind, val activity: FragmentActivity) : AddRecipientAction
    data class SubmitPin(val pin: CharArray, val activity: FragmentActivity) : AddRecipientAction
    object CancelEnrollment : AddRecipientAction
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
        }
    }

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
            EnrollKind.StrongBox -> launchStrongBox()
            EnrollKind.YubiKey -> {
                if (activityHint == null) {
                    _state.value = _state.value.copy(
                        phase = AddRecipientPhase.Failed(
                            title = "YubiKey enrolment needs an Activity context.",
                            detail = "Reopen this screen and try again.",
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
                            title = "Passkey enrolment needs an Activity context.",
                            detail = "Reopen this screen and try again.",
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

    private fun launchStrongBox() {
        enrollJob = viewModelScope.launch {
            val result = safeRun {
                val useStrongBox = isStrongBoxAvailable(appContext)
                val biometric = ragewarden.ragedroid.identities.isBiometricEnrollable(appContext)
                val displayName = when {
                    useStrongBox -> "This phone (StrongBox)"
                    biometric -> "This phone (TEE)"
                    else -> "This phone (no biometric)"
                }
                enrollKeystoreIdentity(
                    displayName = displayName,
                    useStrongBox = useStrongBox,
                    requireBiometric = biometric,
                )
            }
            result.onSuccess { (recipient, _) ->
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
                Result.success(enrollYubiKeyPivX25519(activity = activity, pin = pin))
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
                action = AuditAction.Enroll,
                item = recipient.displayName,
                recipient = recipient.id,
                reason = "${recipient.kind} recipient added",
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
            title = "Biometric expired. Tap to retry.",
            detail = e.message.orEmpty(),
            recoverable = true,
        )
        is YubiKeyX25519UnsupportedException -> AddRecipientPhase.Failed(
            title = "YubiKey firmware too old (need 5.7+). Try a different identity.",
            detail = e.message.orEmpty(),
            recoverable = false,
        )
        else -> AddRecipientPhase.Failed(
            title = "Enrolment failed: ${e.message ?: e::class.simpleName}",
            detail = "${kind.title} enrolment did not complete.",
            recoverable = true,
        )
    }
}
