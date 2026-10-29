package ragewarden.ragedroid.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import dagger.hilt.android.qualifiers.ApplicationContext
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SessionKeyWrap @Inject constructor(@ApplicationContext context: Context) {
    private val prefs = context.getSharedPreferences("ragewarden.session.bio.v1", Context.MODE_PRIVATE)

    fun isEnrolled(): Boolean = prefs.contains(KEY_BLOB)

    var declined: Boolean
        get() = prefs.getBoolean(KEY_DECLINED, false)
        set(value) {
            prefs.edit().putBoolean(KEY_DECLINED, value).commit()
        }

    fun encryptCipher(): Cipher? = runCatching {
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key(create = true)) }
    }.getOrNull()

    fun decryptCipher(): Cipher? {
        val stored = prefs.getString(KEY_BLOB, null) ?: return null
        val raw = Base64.decode(stored, Base64.NO_WRAP)
        return try {
            val k = key(create = false) ?: return null.also { clear() }
            Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(128, raw, 0, IV_LEN)) }
        } catch (_: KeyPermanentlyInvalidatedException) {
            clear()
            null
        }
    }

    fun store(authenticated: Cipher, unlockedSession: ByteArray) {
        val ct = authenticated.doFinal(unlockedSession)
        prefs.edit().putString(KEY_BLOB, Base64.encodeToString(authenticated.iv + ct, Base64.NO_WRAP)).commit()
    }

    fun unwrap(authenticated: Cipher): ByteArray {
        val raw = Base64.decode(prefs.getString(KEY_BLOB, null) ?: error("nothing wrapped"), Base64.NO_WRAP)
        return authenticated.doFinal(raw, IV_LEN, raw.size - IV_LEN)
    }

    fun clear() {
        prefs.edit().remove(KEY_BLOB).commit()
        runCatching { KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(ALIAS) }
    }

    private fun key(create: Boolean): SecretKey? {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        if (!create) return null
        fun generate(strongBox: Boolean): SecretKey {
            val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            gen.init(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    .setInvalidatedByBiometricEnrollment(true)
                    .setUnlockedDeviceRequired(true)
                    .setIsStrongBoxBacked(strongBox)
                    .build(),
            )
            return gen.generateKey()
        }
        return try {
            generate(strongBox = true)
        } catch (_: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "ragewarden.session.keys.auth.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LEN = 12
        const val KEY_BLOB = "wrapped_session_v1"
        const val KEY_DECLINED = "declined"
    }
}
