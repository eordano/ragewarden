package ragewarden.ragedroid.jni

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RageNativeShapeTest {

    @Test
    fun encryptToRecipients_with_invalid_json_throws_MalformedStanza() {
        try {
            RageNative.encryptToRecipients(
                plaintext = byteArrayOf(0x68, 0x69),
                recipientsJson = "{ not json".toByteArray(Charsets.UTF_8),
                prfInputsJson = byteArrayOf(),
            )
            fail("expected MalformedStanza, got success")
        } catch (e: RageNativeException.MalformedStanza) {
            assertTrue(
                "exception message should mention recipients_json, was: ${e.message}",
                e.message?.contains("recipients_json") == true,
            )
        }
    }

    @Test
    fun encryptToRecipients_with_invalid_prf_json_throws_MalformedStanza() {
        try {
            RageNative.encryptToRecipients(
                plaintext = byteArrayOf(0x68, 0x69),
                recipientsJson = "[]".toByteArray(Charsets.UTF_8),
                prfInputsJson = "{ malformed".toByteArray(Charsets.UTF_8),
            )
            fail("expected MalformedStanza, got success")
        } catch (e: RageNativeException.MalformedStanza) {
            assertTrue(
                "exception message should mention prf_inputs_json, was: ${e.message}",
                e.message?.contains("prf_inputs_json") == true,
            )
        }
    }

    @Test
    fun encryptToRecipients_with_unknown_recipient_kind_throws_MalformedStanza() {
        val bogus = """[{"kind":"NotARecipientKind","public_key":""}]"""
        try {
            RageNative.encryptToRecipients(
                plaintext = byteArrayOf(0x68, 0x69),
                recipientsJson = bogus.toByteArray(Charsets.UTF_8),
                prfInputsJson = byteArrayOf(),
            )
            fail("expected MalformedStanza, got success")
        } catch (e: RageNativeException.MalformedStanza) {
        }
    }

    @Test
    fun pubkeyFromArmoredSecret_on_garbage_throws_MalformedStanza() {
        try {
            RageNative.pubkeyFromArmoredSecret("AGE-SECRET-KEY-1NOTAREALSECRET")
            fail("expected MalformedStanza, got success")
        } catch (e: RageNativeException.MalformedStanza) {
        }
    }

    @Test
    fun decryptWithSoftwareSecret_with_bad_secret_throws_MalformedStanza() {
        try {
            RageNative.decryptWithSoftwareSecret(
                blob = byteArrayOf(),
                armoredSecret = "not-an-age-secret",
            )
            fail("expected MalformedStanza, got success")
        } catch (e: RageNativeException.MalformedStanza) {
        }
    }
}
