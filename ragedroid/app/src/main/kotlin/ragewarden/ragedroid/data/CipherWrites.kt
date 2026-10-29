package ragewarden.ragedroid.data

import org.json.JSONArray
import org.json.JSONObject
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.model.VaultItemKind

data class ItemEdit(
    val name: String? = null,
    val username: String? = null,
    val site: String? = null,
    val totp: String? = null,
    val notes: String? = null,
    val newSecret: ByteArray? = null,
    val folderId: String? = null,
    val clearFolder: Boolean = false,
    /** Changed card, identity or SSH key fields; an empty value clears one. */
    val block: Map<String, String>? = null,
    /** New values for protected fields; an empty value stops protecting (and drops) one. */
    val secretChanges: Map<String, String>? = null,
    /** The item's whole decrypted payload, needed when only some protected fields change. */
    val currentPayload: ByteArray? = null,
    /** Turn a protected note holding an OpenSSH private key into an SSH key item. */
    val migrateToSsh: OpenSshKeys.Public? = null,
)

object CipherWrites {
    fun draft(item: VaultItem, plainPassword: String?, plainNotes: String?): ByteArray {
        val login = item.kind == VaultItemKind.Login
        val o = JSONObject()
            .put("login", login)
            .put("name", item.name)
            .put("favorite", item.favorite)
        item.folderId?.let { o.put("folderId", it) }
        val notes = plainNotes ?: item.notes.takeUnless { item.rage && item.kind == VaultItemKind.Note }
        notes?.takeIf { it.isNotEmpty() }?.let { o.put("notes", it) }
        if (login) {
            item.username.takeIf { it.isNotEmpty() }?.let { o.put("username", it) }
            o.put("uris", JSONArray(listOfNotNull(item.site.takeIf { it.isNotBlank() })))
            item.totpSeed?.takeIf { it.isNotBlank() }?.let { o.put("totp", it) }
            plainPassword?.let { o.put("password", it) }
        }
        return o.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * A login whose [protectedNames] (password, totp, notes) the rage blob
     * passed alongside holds: those are left out of the Type-2 layer.
     */
    fun loginDraft(item: VaultItem, protectedNames: Collection<String>): ByteArray {
        val outer = item.copy(
            totpSeed = item.totpSeed.takeUnless { "totp" in protectedNames },
            notes = item.notes.takeUnless { "notes" in protectedNames },
        )
        val o = JSONObject(String(draft(outer, item.password.takeIf { it.isNotEmpty() && "password" !in protectedNames }, null), Charsets.UTF_8))
        if (protectedNames.isNotEmpty()) o.put("protectedFields", JSONArray(protectedNames.toList()))
        return o.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * A card, identity or SSH key: [block] holds its Bitwarden fields, and the
     * ones named in [protectedNames] are left out because the rage blob passed
     * alongside holds them.
     */
    fun typedDraft(item: VaultItem, block: Map<String, String>, protectedNames: Collection<String>): ByteArray {
        val key = ItemFields.blockKey(item.kind) ?: error("${item.kind} is not a typed item")
        val allowed = ItemFields.blockFields(item.kind)
        val o = JSONObject()
            .put("login", false)
            .put("name", item.name)
            .put("favorite", item.favorite)
        item.folderId?.let { o.put("folderId", it) }
        item.notes?.takeIf { it.isNotEmpty() }?.let { o.put("notes", it) }
        val outer = JSONObject()
        block.filter { (k, v) -> k in allowed && k !in protectedNames && v.isNotEmpty() }.forEach { (k, v) -> outer.put(k, v) }
        o.put(key, outer)
        if (protectedNames.isNotEmpty()) o.put("protectedFields", JSONArray(protectedNames.toList()))
        return o.toString().toByteArray(Charsets.UTF_8)
    }

    fun edit(item: VaultItem, edit: ItemEdit, plainPassword: String?, protectedNames: List<String>? = null): ByteArray {
        val login = item.kind == VaultItemKind.Login
        val o = JSONObject()
        val migrate = edit.migrateToSsh
        if (migrate != null) {
            o.put("sshKey", JSONObject().put("publicKey", migrate.publicKey).put("keyFingerprint", migrate.fingerprint))
        }
        val blockKey = ItemFields.blockKey(item.kind)
        val allowed = ItemFields.blockFields(item.kind)
        edit.block?.filterKeys { it in allowed && it !in ItemFields.protectedFields(item) }
            ?.filter { (k, v) -> v != (item.block[k] ?: "") }
            ?.takeIf { blockKey != null && it.isNotEmpty() }
            ?.let { changed -> o.put(blockKey!!, JSONObject().also { b -> changed.forEach { (k, v) -> b.put(k, v) } }) }
        protectedNames?.let { o.put("protectedFields", JSONArray(it)) }
        edit.name?.takeIf { it != item.name }?.let { o.put("name", it) }
        if (login) {
            edit.username?.takeIf { it != item.username }?.let { o.put("username", it) }
            edit.site?.takeIf { it != item.site }?.let { o.put("uris", JSONArray(listOfNotNull(it.takeIf(String::isNotBlank)))) }
            edit.totp?.takeIf { it != (item.totpSeed ?: "") }?.let { o.put("totp", it) }
            plainPassword?.let { o.put("password", it) }
        }
        if (!(item.rage && item.kind == VaultItemKind.Note)) {
            edit.notes?.takeIf { it != (item.notes ?: "") }?.let { o.put("notes", it) }
        }
        edit.folderId?.let { o.put("folderId", it) }
        if (edit.clearFolder) o.put("clearFolder", true)
        return o.toString().toByteArray(Charsets.UTF_8)
    }
}
