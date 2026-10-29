package ragewarden.ragedroid.data

import androidx.annotation.StringRes
import ragewarden.ragedroid.R
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.model.VaultItemKind
import ragewarden.ragedroid.ui.UiStrings

/**
 * Field names are Bitwarden's (camelCase), the same ones core's protected
 * payload and `rage:fields` marker use. An empty name is the item's primary
 * field, as in core's `protected::canonical_field`.
 */
object ItemFields {
    const val WHOLE_PAYLOAD = "*"

    val CARD = listOf("cardholderName", "brand", "number", "expMonth", "expYear", "code")
    val IDENTITY = listOf(
        "title", "firstName", "middleName", "lastName", "address1", "address2", "address3", "city",
        "state", "postalCode", "country", "company", "email", "phone", "ssn", "username",
        "passportNumber", "licenseNumber",
    )
    val SSH_KEY = listOf("privateKey", "publicKey", "keyFingerprint")

    fun cipherType(kind: VaultItemKind): Int = when (kind) {
        VaultItemKind.Login -> 1
        VaultItemKind.Note -> 2
        VaultItemKind.Card -> 3
        VaultItemKind.Identity -> 4
        VaultItemKind.SshKey -> 5
    }

    fun blockKey(kind: VaultItemKind): String? = when (kind) {
        VaultItemKind.Card -> "card"
        VaultItemKind.Identity -> "identity"
        VaultItemKind.SshKey -> "sshKey"
        else -> null
    }

    fun blockFields(kind: VaultItemKind): List<String> = when (kind) {
        VaultItemKind.Card -> CARD
        VaultItemKind.Identity -> IDENTITY
        VaultItemKind.SshKey -> SSH_KEY
        else -> emptyList()
    }

    fun primary(kind: VaultItemKind): String = when (kind) {
        VaultItemKind.Login -> "password"
        VaultItemKind.Note -> "notes"
        VaultItemKind.Card -> "number"
        VaultItemKind.Identity -> "ssn"
        VaultItemKind.SshKey -> "privateKey"
    }

    /** What "protect this item" seals for a new item of [kind]. */
    fun defaultProtected(kind: VaultItemKind): List<String> = when (kind) {
        VaultItemKind.Login -> listOf("password")
        VaultItemKind.Note -> listOf("notes")
        VaultItemKind.Card -> listOf("number", "code")
        VaultItemKind.Identity -> listOf("ssn", "passportNumber", "licenseNumber")
        VaultItemKind.SshKey -> listOf("privateKey", "passphrase")
    }

    fun canonical(kind: VaultItemKind, field: String): String =
        if (field.isEmpty() || (kind == VaultItemKind.Note && field == "password")) primary(kind) else field

    fun protectedFields(item: VaultItem): List<String> = when {
        !item.rage -> emptyList()
        item.protectedFields.isEmpty() -> listOf(primary(item.kind))
        else -> item.protectedFields
    }

    fun needsTap(item: VaultItem, field: String): Boolean = canonical(item.kind, field) in protectedFields(item)

    /** The plaintext of an unprotected field, from the synced item. */
    fun outerValue(item: VaultItem, field: String): String? = when (val name = canonical(item.kind, field)) {
        "password" -> item.password.ifEmpty { null }
        "notes" -> item.notes
        "username" -> item.username.ifEmpty { null }
        "totp" -> item.totpSeed
        "passphrase" -> item.passphrase
        else -> item.block[name]
    }

    /** The field's name as shown to the user; an unknown field shows its key. */
    fun label(field: String): String = labelRes(field)?.let { UiStrings.get(it) } ?: field

    @StringRes
    fun labelRes(field: String): Int? = when (field) {
        "password" -> R.string.field_password
        "notes" -> R.string.field_note
        "totp" -> R.string.field_totp_seed
        "number" -> R.string.field_card_number
        "code" -> R.string.field_security_code
        "ssn" -> R.string.field_ssn
        "passportNumber" -> R.string.field_passport_number
        "licenseNumber" -> R.string.field_license_number
        "privateKey" -> R.string.field_private_key
        "passphrase" -> R.string.field_passphrase
        else -> null
    }
}
