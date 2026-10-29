package ragewarden.ragedroid.data

import kotlinx.collections.immutable.persistentListOf
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import ragewarden.ragedroid.model.VaultItem
import ragewarden.ragedroid.model.VaultItemKind

@RunWith(RobolectricTestRunner::class)
class CipherWritesTest {
    private fun item(kind: VaultItemKind, rage: Boolean, notes: String? = null) = VaultItem(
        id = "i1", name = "GitHub", username = "octo", site = "github.com", folder = "Work", folderId = "f1",
        rage = rage, recipients = persistentListOf(), password = "", totpSeed = "JBSWY3DP", notes = notes,
        lastUsed = "", history = 0, favorite = true, kind = kind,
    )

    private fun json(b: ByteArray) = JSONObject(String(b, Charsets.UTF_8))

    @Test
    fun a_protected_login_draft_keeps_every_login_field_and_no_password() {
        val d = json(CipherWrites.draft(item(VaultItemKind.Login, rage = true, notes = "recovery codes in the safe"), null, null))
        assertTrue(d.getBoolean("login"))
        assertEquals("octo", d.getString("username"))
        assertEquals("github.com", d.getJSONArray("uris").getString(0))
        assertEquals("JBSWY3DP", d.getString("totp"))
        assertEquals("f1", d.getString("folderId"))
        assertTrue(d.getBoolean("favorite"))
        assertEquals("recovery codes in the safe", d.getString("notes"))
        assertFalse(d.has("password"))
    }

    @Test
    fun a_protected_note_never_puts_its_body_in_the_type2_notes() {
        val d = json(CipherWrites.draft(item(VaultItemKind.Note, rage = true, notes = "the secret body"), null, null))
        assertFalse(d.getBoolean("login"))
        assertFalse(d.has("notes"))
        assertFalse(d.has("username"))
    }

    @Test
    fun an_edit_sends_only_what_changed() {
        val before = item(VaultItemKind.Login, rage = true)
        val e = json(CipherWrites.edit(before, ItemEdit(name = "GitHub", username = "octocat", totp = "JBSWY3DP", notes = ""), null))
        assertEquals("octocat", e.getString("username"))
        assertFalse(e.has("name"))
        assertFalse(e.has("totp"))
        assertFalse(e.has("password"))
        assertFalse(e.has("notes"))
    }
}
