package ragewarden.ragedroid.data

import org.json.JSONObject

object SessionBlobs {
    private const val ENC = "userEncKeyB64"
    private const val MAC = "userMacKeyB64"
    private const val PROTECTED = "protectedUserKey"

    private fun parse(blob: ByteArray): JSONObject? = runCatching { JSONObject(String(blob, Charsets.UTF_8)) }.getOrNull()

    fun hasKeys(blob: ByteArray?): Boolean {
        val o = blob?.let(::parse) ?: return false
        return o.optString(ENC).isNotEmpty() && o.optString(MAC).isNotEmpty()
    }

    fun hasProtectedKey(blob: ByteArray?): Boolean = blob?.let(::parse)?.optString(PROTECTED)?.isNotEmpty() == true

    fun field(blob: ByteArray?, name: String): String = blob?.let(::parse)?.optString(name).orEmpty()

    fun kdfPin(blob: ByteArray?): String? {
        val o = blob?.let(::parse) ?: return null
        val iterations = o.optInt("kdfIterations", 0).takeIf { it > 0 } ?: return null
        val pin = JSONObject().put("kdf", o.optInt("kdfType", 0)).put("iterations", iterations)
        if (o.has("kdfMemoryMib")) pin.put("memoryMib", o.getInt("kdfMemoryMib"))
        if (o.has("kdfParallelism")) pin.put("parallelism", o.getInt("kdfParallelism"))
        return pin.toString()
    }

    fun strip(blob: ByteArray): ByteArray {
        val o = parse(blob) ?: return blob
        o.put(ENC, "")
        o.put(MAC, "")
        return o.toString().toByteArray(Charsets.UTF_8)
    }
}
