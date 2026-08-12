package ragewarden.ragedroid.identities

/**
 * Failure taxonomy for the hardware ceremony.
 *
 * These exist because `KotlinIdentity.tryUnwrap` returning `null` is *only*
 * allowed to mean "this stanza is not addressed to me". Every other outcome --
 * no device presented, user cancelled, PIN wrong, authenticator refused --
 * must be distinguishable, because "return null on any problem" is exactly how
 * a hardware requirement degrades into a software fall-through: age walks on to
 * the next identity in the list and, if a software/recovery recipient is also
 * present, decrypts with no physical action at all.
 *
 * `JniIdentity::try_unwrap_stanza` (`jni/src/jni_identity.rs:69-76`) turns a
 * pending Java exception into `IdentityError::Hardware`, which
 * `ragewarden_core::decrypt` surfaces as `age::DecryptError::Io` and aborts the
 * whole decrypt rather than trying the next identity. That is the behaviour we
 * want: fail closed.
 */
sealed class HardwareTapException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause) {
    /** Should the UI offer a retry button? */
    open val retryable: Boolean get() = true
}

/** No device was presented in time. */
class HardwareTapTimeoutException(message: String, cause: Throwable? = null) :
    HardwareTapException(message, cause)

/** The user dismissed the system/authenticator prompt. */
class HardwareTapCancelledException(message: String, cause: Throwable? = null) :
    HardwareTapException(message, cause)

/** The device was present and refused: wrong PIN, wrong slot, wrong credential. */
class HardwareTapFailedException(message: String, cause: Throwable? = null) :
    HardwareTapException(message, cause)

/**
 * The recipient exists but this surface structurally cannot drive it -- an
 * `InputMethodService` has no Activity to host `BiometricPrompt` or
 * `CredentialManager`, and no NFC reader can be started without one.
 * Not retryable here; the user has to move to the app.
 */
class HardwareTapUnavailableException(message: String, cause: Throwable? = null) :
    HardwareTapException(message, cause) {
    override val retryable: Boolean get() = false
}

/**
 * Thrown before any decrypt is attempted when the item's recipients cannot be
 * satisfied by anything on this device. Carries the per-recipient reasons so
 * the prompt can say *which* key is missing instead of "reveal failed".
 */
class NoUsableIdentityException(
    val skipped: List<SkippedRecipient>,
    message: String,
) : HardwareTapException(message) {
    override val retryable: Boolean get() = false
}

/** Why a stored recipient could not be turned into a usable identity. */
data class SkippedRecipient(
    val recipientId: String,
    val label: String,
    val reason: String,
)
