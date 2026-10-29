package ragewarden.ragedroid.data

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class StoreUnreadableException(store: String, cause: Throwable) :
    IllegalStateException("$store cannot be decrypted on this device", cause)

interface AeadKeySource {
    fun aesKey(alias: String): SecretKey
    fun hmacKey(alias: String): SecretKey
}

object AndroidKeystoreKeys : AeadKeySource {
    private const val KEYSTORE = "AndroidKeyStore"

    override fun aesKey(alias: String): SecretKey = loadOrCreate(alias, KeyProperties.KEY_ALGORITHM_AES) { builder ->
        builder.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
    }

    override fun hmacKey(alias: String): SecretKey = loadOrCreate(alias, KeyProperties.KEY_ALGORITHM_HMAC_SHA256) { it }

    @Synchronized
    private fun loadOrCreate(
        alias: String,
        algorithm: String,
        configure: (KeyGenParameterSpec.Builder) -> KeyGenParameterSpec.Builder,
    ): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val purposes = if (algorithm == KeyProperties.KEY_ALGORITHM_AES) {
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        } else {
            KeyProperties.PURPOSE_SIGN
        }
        fun generate(strongBox: Boolean): SecretKey {
            val gen = KeyGenerator.getInstance(algorithm, KEYSTORE)
            gen.init(configure(KeyGenParameterSpec.Builder(alias, purposes)).setIsStrongBoxBacked(strongBox).build())
            return gen.generateKey()
        }
        return try {
            generate(strongBox = true)
        } catch (_: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }
    }
}

internal class KeystorePrefs(
    context: Context,
    private val prefsName: String,
    private val keyAlias: String,
    private val keys: AeadKeySource = keySourceOverride ?: AndroidKeystoreKeys,
) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(prefsName, Context.MODE_PRIVATE)

    private val key: SecretKey by lazy { keys.aesKey(keyAlias) }
    private val nameKey: SecretKey by lazy { keys.hmacKey("$keyAlias.names") }

    fun getString(prefKey: String, default: String?): String? {
        val hashed = storedName(prefKey)
        val raw = prefs.getString(hashed, null)
            ?: prefs.getString(prefKey, null)?.also { legacy ->
                prefs.edit().putString(hashed, legacy).remove(prefKey).commit()
            }
            ?: return default
        return try {
            decrypt(raw)
        } catch (e: Exception) {
            throw StoreUnreadableException(prefsName, e)
        }
    }

    fun putString(prefKey: String, value: String): Boolean =
        prefs.edit().putString(storedName(prefKey), encrypt(value)).remove(prefKey).commit()

    fun remove(prefKey: String): Boolean = prefs.edit().remove(storedName(prefKey)).remove(prefKey).commit()

    internal fun storedName(prefKey: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(nameKey)
        val digest = mac.doFinal(prefKey.toByteArray(Charsets.UTF_8))
        return "h:" + Base64.encodeToString(digest, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
    }

    private fun encrypt(plaintext: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(iv + ct, Base64.NO_WRAP)
    }

    private fun decrypt(encoded: String): String {
        val raw = Base64.decode(encoded, Base64.NO_WRAP)
        require(raw.size > IV_LEN) { "ciphertext too short" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, raw, 0, IV_LEN))
        return String(cipher.doFinal(raw, IV_LEN, raw.size - IV_LEN), Charsets.UTF_8)
    }

    companion object {
        @Volatile
        internal var keySourceOverride: AeadKeySource? = null
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LEN = 12
        private const val GCM_TAG_BITS = 128
    }
}
