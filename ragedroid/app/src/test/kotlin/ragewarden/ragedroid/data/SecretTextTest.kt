package ragewarden.ragedroid.data

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class SecretTextTest {
    @Test
    fun the_characters_are_zeroed_once_the_delivery_returns() {
        var seen: CharSequence? = null
        val delivered = SecretText.withChars("pässwörd 🔑".toByteArray()) { cs ->
            seen = cs
            cs.toString()
        }
        assertEquals("pässwörd 🔑", delivered)
        assertTrue("the CharSequence handed out is zeroed after", seen!!.all { it == '\u0000' })
    }

    @Test
    fun fields_json_escapes_without_making_value_strings() {
        val tricky = "a\"b\\c\nd\u0001é"
        val json = SecretText.fieldsJson(linkedMapOf("number" to "4111".toByteArray(), "notes" to tricky.toByteArray()))
        val o = JSONObject(String(json))
        assertEquals("4111", o.getString("number"))
        assertEquals(tricky, o.getString("notes"))
    }
}
