package ragewarden.ragedroid.model

import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.persistentMapOf
import kotlinx.collections.immutable.ImmutableMap
import androidx.compose.runtime.Immutable
import kotlinx.collections.immutable.ImmutableList

enum class VaultItemKind { Login, Card, Note, Identity, SshKey }

/** The folder name of an item in no folder; the vault list's show-everything chip uses it too. */
const val NO_FOLDER: String = "All"

@Immutable
data class VaultItem(
    val id: String,
    val name: String,
    val username: String,
    val site: String,
    val folder: String,
    val folderId: String? = null,
    val rage: Boolean,
    val recipients: ImmutableList<String>,
    val password: String,
    val totpSeed: String? = null,
    val notes: String? = null,
    val lastUsed: String,
    val history: Int,
    val favorite: Boolean = false,
    val kind: VaultItemKind = VaultItemKind.Login,
    val cardNumber: String? = null,
    val cvv: String? = null,
    val expiry: String? = null,
    val cardholder: String? = null,
    val brand: String? = null,
    val fullName: String? = null,
    val dob: String? = null,
    val address: String? = null,
    val phone: String? = null,
    val email: String? = null,
    val nationalId: String? = null,
    val keyType: String? = null,
    val fingerprint: String? = null,
    val publicKey: String? = null,
    val privateKey: String? = null,
    val comment: String? = null,
    val passphrase: String? = null,
    /** Card, identity or SSH key block values by Bitwarden field name, protected ones absent. */
    val block: ImmutableMap<String, String> = persistentMapOf(),
    /** What the rage blob holds, by Bitwarden field name; each one needs a tap. */
    val protectedFields: ImmutableList<String> = persistentListOf(),
)
