package ragewarden.ragedroid.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class VaultCache internal constructor(
    private val file: File,
    private val keys: AeadKeySource,
) {
    @Inject
    constructor(@ApplicationContext context: Context) : this(
        File(context.noBackupFilesDir, "vaultcache.v1.bin"),
        KeystorePrefs.keySourceOverride ?: AndroidKeystoreKeys,
    )

    @Synchronized
    fun save(rawEncryptedVault: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, keys.aesKey(ALIAS))
        val sealed = cipher.iv + cipher.doFinal(rawEncryptedVault)
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(sealed)
        if (!tmp.renameTo(file)) {
            tmp.delete()
            error("could not replace vault cache")
        }
    }

    @Synchronized
    fun load(): ByteArray? {
        if (!file.exists()) return null
        return runCatching {
            val sealed = file.readBytes()
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, keys.aesKey(ALIAS), GCMParameterSpec(128, sealed, 0, IV_LEN))
            cipher.doFinal(sealed, IV_LEN, sealed.size - IV_LEN)
        }.getOrNull()
    }

    @Synchronized
    fun clear() {
        file.delete()
    }

    private companion object {
        const val ALIAS = "ragewarden.vaultcache.aead.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LEN = 12
    }
}
