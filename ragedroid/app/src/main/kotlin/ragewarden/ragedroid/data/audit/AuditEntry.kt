package ragewarden.ragedroid.data.audit

import androidx.compose.runtime.Immutable

enum class AuditAction { Autofill, Copy, Reveal, Totp, Failed, Enroll, Rotate, Delete }

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
)
