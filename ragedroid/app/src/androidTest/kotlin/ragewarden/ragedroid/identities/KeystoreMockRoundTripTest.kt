package ragewarden.ragedroid.identities

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.junit.runner.RunWith
import ragewarden.ragedroid.jni.RageNative

@RunWith(AndroidJUnit4::class)
class KeystoreMockRoundTripTest {
    @Test
    fun mock_keystore_identity_opens_a_real_ragedroid_keystore_v1_stanza() {
        System.setProperty(MockHardware.ENV_VAR, "1")
        val identity = AndroidKeystoreIdentity.enrollMock("mock-ks")
        val pub = identity.expectedPublicKey.joinToString(",") { (it.toInt() and 0xFF).toString() }
        val recipients = """[{"type":"android_keystore","public_key":[$pub],"key_handle":"mock-ks"}]"""
        val plaintext = "correct horse battery staple".toByteArray()
        val blob = RageNative.encryptToRecipients(plaintext, recipients.toByteArray(), "[]".toByteArray())
        val opened = RageNative.decryptWithIdentities(blob, arrayOf<KotlinIdentity>(identity))
        assertArrayEquals(plaintext, opened)
    }

    @Test
    fun a_kotlin_identity_is_called_back_through_the_jni_and_opens_its_stanza() {
        val identity = SoftwareP256Identity("test-ks")
        val pub = identity.publicKey.joinToString(",") { (it.toInt() and 0xFF).toString() }
        val recipients = """[{"type":"android_keystore","public_key":[$pub],"key_handle":"test-ks"}]"""
        val plaintext = "minified callbacks still resolve".toByteArray()
        val blob = RageNative.encryptToRecipients(plaintext, recipients.toByteArray(), "[]".toByteArray())
        assertArrayEquals(plaintext, RageNative.decryptWithIdentities(blob, arrayOf<KotlinIdentity>(identity)))
    }
}
