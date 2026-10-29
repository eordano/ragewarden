package ragewarden.ragedroid.data

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.model.VaultItemKind
import ragewarden.ragedroid.ui.screens.AddItemKind
import ragewarden.ragedroid.ui.screens.typedFields

/**
 * The Kotlin half of typed items: what the add form seals, what the draft
 * leaves in the Type-2 layer, and how a synced item names its protected
 * fields. The sealing and decryption themselves are core's, exercised on a
 * device by DeliveryFlowsTest.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class TypedItemsTest {

    @Test
    fun a_protected_card_seals_number_and_cvv_and_keeps_them_out_of_the_draft() {
        val t = typedFields(AddItemKind.Card, cardholder = "Maya Voss", cardNumber = "4111 1111 1111 1111", cardExp = "12 / 29", cardCvv = "123", protect = true)!!
        assertNull(t.problem)
        assertEquals(VaultItemKind.Card, t.kind)
        assertEquals(mapOf("number" to "4111111111111111", "code" to "123"), t.secrets)
        assertEquals(mapOf("cardholderName" to "Maya Voss", "expMonth" to "12", "expYear" to "29"), t.block)

        val draft = JSONObject(String(CipherWrites.typedDraft(item(VaultItemKind.Card), t.block, t.secrets.keys)))
        val card = draft.getJSONObject("card")
        assertFalse(card.has("number"))
        assertFalse(card.has("code"))
        assertEquals("Maya Voss", card.getString("cardholderName"))
        assertEquals(listOf("number", "code"), draft.getJSONArray("protectedFields").let { a -> (0 until a.length()).map(a::getString) })
        val json = JSONObject(String(SecretText.fieldsJson(t.secrets.mapValues { it.value.toByteArray() })))
        assertEquals("4111111111111111", json.getString("number"))
        assertEquals("123", json.getString("code"))
    }

    @Test
    fun a_login_with_a_protected_totp_and_notes_keeps_them_out_of_the_draft() {
        val login = item(VaultItemKind.Login).copy(username = "me", site = "example.com", totpSeed = "JBSWY3DPEHPK3PXP", notes = "secret note")
        val draft = JSONObject(String(CipherWrites.loginDraft(login, listOf("password", "totp", "notes"))))
        assertEquals(true, draft.getBoolean("login"))
        assertEquals("me", draft.getString("username"))
        assertFalse(draft.has("totp"))
        assertFalse(draft.has("notes"))
        assertFalse(draft.has("password"))
        assertEquals(listOf("password", "totp", "notes"), draft.getJSONArray("protectedFields").let { a -> (0 until a.length()).map(a::getString) })

        val onlyPassword = JSONObject(String(CipherWrites.loginDraft(login, listOf("password"))))
        assertEquals("JBSWY3DPEHPK3PXP", onlyPassword.getString("totp"))
        assertEquals("secret note", onlyPassword.getString("notes"))
    }

    @Test
    fun a_totp_another_client_protected_needs_a_tap_and_has_no_outer_value() {
        val dto = JSONObject()
            .put("id", "l1").put("name", "Bank").put("rage", true).put("cipherType", 1)
            .put("protectedFields", org.json.JSONArray(listOf("password", "totp")))
        val login = VaultSnapshot.fromJsonObject(JSONObject().put("items", org.json.JSONArray().put(dto))).items.single()
        assertNull(login.totpSeed)
        assertTrue(ItemFields.needsTap(login, "totp"))
        assertFalse(ItemFields.needsTap(login, "username"))
    }

    @Test
    fun an_unprotected_card_keeps_everything_in_the_block() {
        val t = typedFields(AddItemKind.Card, cardNumber = "4111", cardCvv = "123", protect = false)!!
        assertTrue(t.secrets.isEmpty())
        assertEquals(mapOf("number" to "4111", "code" to "123"), t.block)
        assertFalse(JSONObject(String(CipherWrites.typedDraft(item(VaultItemKind.Card), t.block, emptySet()))).has("protectedFields"))
    }

    @Test
    fun a_synced_card_names_its_protected_fields_and_has_no_values_for_them() {
        val dto = JSONObject()
            .put("id", "c1").put("name", "Amex").put("rage", true).put("cipherType", 3)
            .put("card", JSONObject().put("cardholderName", "Maya Voss").put("expMonth", "12").put("expYear", "29"))
            .put("protectedFields", org.json.JSONArray(listOf("number", "code")))
        val item = VaultSnapshot.fromJsonObject(JSONObject().put("items", org.json.JSONArray().put(dto))).items.single()
        assertEquals(listOf("number", "code"), item.protectedFields)
        assertNull(item.cardNumber)
        assertTrue(ItemFields.needsTap(item, "number"))
        assertTrue(ItemFields.needsTap(item, ""))
        assertFalse(ItemFields.needsTap(item, "expMonth"))
        assertEquals("12", ItemFields.outerValue(item, "expMonth"))
    }

    @Test
    fun a_protected_item_without_a_field_list_still_taps_for_its_primary_field() {
        val legacy = item(VaultItemKind.Login).copy(rage = true)
        assertTrue(ItemFields.needsTap(legacy, ""))
        assertTrue(ItemFields.needsTap(legacy, "password"))
        assertFalse(ItemFields.needsTap(legacy, "username"))
    }

    @Test
    fun an_ssh_key_seals_private_key_and_passphrase_and_publishes_its_public_half() {
        val t = typedFields(AddItemKind.Ssh, sshPrivateKey = PLAIN_KEY, sshPassphrase = "hunter2", protect = true)!!
        assertNull(t.problem)
        assertEquals(setOf("privateKey", "passphrase"), t.secrets.keys)
        assertEquals("hunter2", t.secrets["passphrase"])
        assertEquals(PUBLIC_KEY, t.block["publicKey"])
        assertEquals(FINGERPRINT, t.block["keyFingerprint"])
        assertFalse(t.block.containsKey("privateKey"))
        val draft = JSONObject(String(CipherWrites.typedDraft(item(VaultItemKind.SshKey), t.block, t.secrets.keys)))
        assertEquals(PUBLIC_KEY, draft.getJSONObject("sshKey").getString("publicKey"))
        assertFalse(draft.getJSONObject("sshKey").has("privateKey"))
    }

    @Test
    fun the_public_half_is_read_from_an_encrypted_key_too() {
        val pub = OpenSshKeys.publicOf(ENCRYPTED_KEY)!!
        assertEquals("ssh-ed25519", pub.keyType)
        assertEquals(ENCRYPTED_FINGERPRINT, pub.fingerprint)
        assertNull(OpenSshKeys.publicOf("not a key"))
    }

    @Test
    fun an_unprotected_ssh_key_refuses_a_passphrase_and_a_non_openssh_key() {
        assertTrue(typedFields(AddItemKind.Ssh, sshPrivateKey = PLAIN_KEY, sshPassphrase = "x", protect = false)!!.problem != null)
        assertTrue(typedFields(AddItemKind.Ssh, sshPrivateKey = "-----BEGIN RSA " + "PRIVATE KEY-----", protect = true)!!.problem != null)
        val plain = typedFields(AddItemKind.Ssh, sshPrivateKey = PLAIN_KEY, protect = false)!!
        assertTrue(plain.secrets.isEmpty())
        assertTrue(plain.block.getValue("privateKey").startsWith(PEM_BEGIN))
    }

    private fun item(kind: VaultItemKind) = ragewarden.ragedroid.model.VaultItem(
        id = "new", name = "Item", username = "", site = "", folder = "All", rage = false,
        recipients = kotlinx.collections.immutable.persistentListOf(), password = "", lastUsed = "", history = 0, kind = kind,
    )

    private companion object {
        // Throwaway keys generated for this test; the header is split so a
        // secret scanner does not read the fixture as a leaked key.
        const val PEM_BEGIN = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
        const val PEM_END = "-----END " + "OPENSSH PRIVATE KEY-----"
        const val PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBrvGPv6PjfY2xW8Uk8lrVYZAqlpU0SkAJ9TcDba5nwM"
        const val FINGERPRINT = "SHA256:+JRhDJluAuHSIkl6cty172OtYQ8zxb/GAFBfXCgYmhw"
        const val ENCRYPTED_FINGERPRINT = "SHA256:vfreP2LASxtKdHZgdMIqzo3FLdwHj43/Vv5N0IE+Myc"

        val PLAIN_KEY = PEM_BEGIN + "\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
            "QyNTUxOQAAACAa7xj7+j432NsVvFJPJa1WGQKpaVNEpACfU3A22uZ8DAAAAJhlNHAoZTRw\n" +
            "KAAAAAtzc2gtZWQyNTUxOQAAACAa7xj7+j432NsVvFJPJa1WGQKpaVNEpACfU3A22uZ8DA\n" +
            "AAAEDnMbbs1qUCuBjEGiJkoHlIjyhxFaCFnjPsj5M7t2dTxhrvGPv6PjfY2xW8Uk8lrVYZ\n" +
            "AqlpU0SkAJ9TcDba5nwMAAAADnJhZ2Vkcm9pZC10ZXN0AQIDBAUGBw==\n" +
            PEM_END + "\n"

        val ENCRYPTED_KEY = PEM_BEGIN + "\n" +
            "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCEswxx/o\n" +
            "gOCCoNcqrzNvwMAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIPjMhebvKLYehl7M\n" +
            "iDCK52emVzvfyol6tFwsZcYNmI7dAAAAoJmdGa/GC0VWdqfHzXKqgIGozgjlJje9izjaO3\n" +
            "tr/LRNA91qmnGmUtSjDXnPiWwlJuis5Q/+KvqsvBs2cI2lRpj7hTizwNqC+CK3VjLA2WTo\n" +
            "XU7nOGyb3Xh9C8W5hGN/DYgAjvdZ7YoOrnS6E40AJ3dPotg3qDJVcopWXl4fe9clI5VhS5\n" +
            "hBheJGC6uYMtFWOZPZD1+TGRER5Dn47/CKl2E=\n" +
            PEM_END + "\n"
    }
}
