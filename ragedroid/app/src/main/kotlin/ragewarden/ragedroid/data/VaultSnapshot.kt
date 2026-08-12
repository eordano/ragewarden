package ragewarden.ragedroid.data

import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.toImmutableList
import org.json.JSONArray
import org.json.JSONObject
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.model.VaultItemKind

/**
 * Cipher names the three clients use as storage for their own bookkeeping.
 * None of them is a user item, and a vault list that shows one is wrong twice:
 * it offers to edit machinery, and it inflates the item count in the header.
 *
 * The list is the union across all three clients, not just ours, because the
 * vault is shared. Only ragedroid's own marker was excluded before, which meant
 * a vault that rageterm or the browser had also touched rendered:
 *  - `Ragewarden Recipients (do not edit)` -- rageterm's *private* recipient
 *    list (`rageterm/src/recipients.rs:20`), one bogus row, observed inflating
 *    the header to "3 items · 2 protected"
 *  - one `__ragewarden_history_v1__:<cipherId>` row per item the browser has
 *    ever edited (`ragemanifest/src/wasm/sync.rs:1045`), so the junk grew with
 *    every browser edit
 *
 * Matching is by family, not by literal: the history name carries a cipher id,
 * so there is no fixed string to compare against. Adding a marker anywhere in
 * the ecosystem means adding it here.
 */
object VaultMetaNames {
    /** `rageterm/src/recipients.rs::RECIPIENT_LIST_NAME`. */
    const val RAGETERM_RECIPIENT_LIST: String = "Ragewarden Recipients (do not edit)"

    /**
     * `core/src/history.rs::MARKER_NAME`. rageterm keeps one document under
     * this exact name; ragemanifest keeps one per cipher, named
     * `"$HISTORY:<cipherId>"`. Both are matched.
     */
    const val HISTORY: String = "__ragewarden_history_v1__"

    fun isMeta(name: String): Boolean =
        name == RecipientRegistry.MARKER_NAME ||
            name == RAGETERM_RECIPIENT_LIST ||
            name == HISTORY ||
            name.startsWith("$HISTORY:")
}

data class VaultSnapshot(val items: ImmutableList<VaultItem>) {
    companion object {
        fun fromJsonObject(obj: JSONObject): VaultSnapshot {
            val arr = obj.optJSONArray("items") ?: JSONArray()
            val out = ArrayList<VaultItem>(arr.length())
            for (i in 0 until arr.length()) {
                out.add(parseItem(arr.getJSONObject(i)))
            }
            return VaultSnapshot(out.toImmutableList())
        }

        fun fromJson(bytes: ByteArray): VaultSnapshot =
            fromJsonObject(JSONObject(String(bytes, Charsets.UTF_8)))

        private fun parseItem(o: JSONObject): VaultItem {
            val recipientsArr = o.optJSONArray("recipients") ?: JSONArray()
            val recipients = (0 until recipientsArr.length())
                .map { recipientsArr.getString(it) }
                .toImmutableList()
            fun optStr(key: String): String? {
                if (!o.has(key) || o.isNull(key)) return null
                return o.optString(key).ifBlank { null }
            }
            val cipherType = if (o.has("cipherType") && !o.isNull("cipherType")) {
                o.optInt("cipherType", 1)
            } else {
                1
            }
            val kind = mapKind(cipherType, o)
            val card = o.optJSONObject("card")
            val identity = o.optJSONObject("identity")
            val ssh = o.optJSONObject("ssh")
            fun optFromObj(src: JSONObject?, key: String): String? {
                if (src == null) return null
                if (!src.has(key) || src.isNull(key)) return null
                return src.optString(key).ifBlank { null }
            }
            val identityFullName = identity?.let {
                val first = optFromObj(it, "firstName")
                val middle = optFromObj(it, "middleName")
                val last = optFromObj(it, "lastName")
                listOfNotNull(first, middle, last).joinToString(" ").ifBlank { null }
            }
            val identityAddress = identity?.let {
                val parts = listOfNotNull(
                    optFromObj(it, "address1"),
                    optFromObj(it, "address2"),
                    optFromObj(it, "address3"),
                    optFromObj(it, "city"),
                    optFromObj(it, "state"),
                    optFromObj(it, "postalCode"),
                    optFromObj(it, "country"),
                )
                if (parts.isEmpty()) null else parts.joinToString(", ")
            }
            return VaultItem(
                id = o.getString("id"),
                name = optStr("name") ?: "",
                username = optStr("username") ?: "",
                site = optStr("site") ?: "",
                folder = optStr("folder") ?: "All",
                folderId = optStr("folderId"),
                rage = o.optBoolean("rage"),
                recipients = recipients,
                password = if (o.optBoolean("rage")) "" else (optStr("plainPassword") ?: ""),
                totpSeed = optStr("totpSeed"),
                notes = optStr("notes"),
                lastUsed = optStr("lastUsed") ?: "",
                history = o.optInt("history", 0),
                favorite = o.optBoolean("favorite"),
                kind = kind,
                cardNumber = optFromObj(card, "number"),
                cvv = optFromObj(card, "code"),
                expiry = card?.let {
                    val month = optFromObj(it, "expMonth")
                    val year = optFromObj(it, "expYear")
                    when {
                        month != null && year != null -> "$month/$year"
                        else -> null
                    }
                },
                cardholder = optFromObj(card, "cardholderName"),
                brand = optFromObj(card, "brand"),
                fullName = identityFullName,
                dob = optFromObj(identity, "dob"),
                address = identityAddress,
                phone = optFromObj(identity, "phone"),
                email = optFromObj(identity, "email"),
                nationalId = optFromObj(identity, "ssn") ?: optFromObj(identity, "passportNumber"),
                keyType = optFromObj(ssh, "keyType"),
                fingerprint = optFromObj(ssh, "fingerprint"),
                publicKey = optFromObj(ssh, "publicKey"),
                privateKey = optFromObj(ssh, "privateKey"),
                comment = optFromObj(ssh, "comment"),
                passphrase = optFromObj(ssh, "passphrase"),
            )
        }

        private fun mapKind(cipherType: Int, o: JSONObject): VaultItemKind = when (cipherType) {
            1 -> VaultItemKind.Login
            2 -> VaultItemKind.Note
            3 -> VaultItemKind.Card
            4 -> VaultItemKind.Identity
            else -> if (o.optJSONObject("ssh") != null) VaultItemKind.SshKey else VaultItemKind.Login
        }
    }
}

data class CipherRageBlobMap(val byItemId: Map<String, String>) {
    companion object {
        fun fromJsonObject(obj: JSONObject): CipherRageBlobMap {
            val arr = obj.optJSONArray("items") ?: JSONArray()
            val out = HashMap<String, String>(arr.length())
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                if (!o.optBoolean("rage")) continue
                if (!o.has("rageBlob") || o.isNull("rageBlob")) continue
                val blob = o.optString("rageBlob")
                if (blob.isNotBlank()) out[o.getString("id")] = blob
            }
            return CipherRageBlobMap(out)
        }

        fun fromJson(bytes: ByteArray): CipherRageBlobMap =
            fromJsonObject(JSONObject(String(bytes, Charsets.UTF_8)))
    }
}
