package ragewarden.ragedroid.data

import org.json.JSONObject
import ragewarden.ragedroid.jni.RageNative

data class GeneratedRecovery(
    val mnemonic: String,
    val armoredPubkey: String,
    val armoredSecret: String,
)

object Recovery {
    fun generate(): GeneratedRecovery {
        val bytes = RageNative.generateRecoveryMnemonic()
        val obj = JSONObject(String(bytes, Charsets.UTF_8))
        return GeneratedRecovery(
            mnemonic = obj.getString("mnemonic"),
            armoredPubkey = obj.getString("armoredPubkey"),
            armoredSecret = obj.getString("armoredSecret"),
        )
    }
}
