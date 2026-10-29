package ragewarden.ragedroid.data.audit

import androidx.compose.runtime.Immutable
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

enum class AuditAction {
    Reveal, Copy, Autofill, Set, Update, Rotate, Delete, EnrollIdentity, RemoveRecipient,
    Login, Logout, Sync, CreateFolder, RenameFolder, DeleteFolder, Recover, BulkProtect, Totp,
    Exec, AgentAdd;

    companion object {
        private val LEGACY = mapOf(
            "AutofillPassword" to Autofill, "CopyPassword" to Copy, "DeleteCipher" to Delete,
            "EditCipher" to Update, "Enroll" to EnrollIdentity, "EnrollPasskey" to EnrollIdentity,
            "EnrollRecovery" to EnrollIdentity, "RecoverFromPhrase" to Recover, "RevealPassword" to Reveal,
            "RotateCipher" to Rotate, "SetCipher" to Set,
        )

        fun parse(name: String): AuditAction? = entries.firstOrNull { it.name == name } ?: LEGACY[name]
    }
}

@Serializable
enum class AuditResult {
    @SerialName("ok") Ok,
    @SerialName("declined") Declined,
    @SerialName("failed") Failed,
}

@Immutable
data class AuditEntry(
    val id: String,
    val timestamp: String,
    val bucket: String,
    val action: AuditAction,
    val item: String,
    val recipient: String? = null,
    val site: String? = null,
    val reason: String? = null,
    val cleared: Boolean = false,
    val result: AuditResult = AuditResult.Ok,
)
