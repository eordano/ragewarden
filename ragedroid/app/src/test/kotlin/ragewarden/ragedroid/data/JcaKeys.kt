package ragewarden.ragedroid.data

import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object JcaKeys : AeadKeySource {
    private val keys = HashMap<String, SecretKey>()

    @Synchronized
    override fun aesKey(alias: String): SecretKey =
        keys.getOrPut(alias) { KeyGenerator.getInstance("AES").apply { init(256) }.generateKey() }

    @Synchronized
    override fun hmacKey(alias: String): SecretKey =
        keys.getOrPut(alias) { KeyGenerator.getInstance("HmacSHA256").generateKey() }

    @Synchronized
    fun forget(alias: String) {
        keys.remove(alias)
    }
}
