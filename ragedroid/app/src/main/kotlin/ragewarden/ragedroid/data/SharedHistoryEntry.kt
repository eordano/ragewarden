package ragewarden.ragedroid.data

import org.json.JSONArray

/** One entry of core's shared history document (`historyLoad`), newest first. */
data class SharedHistoryEntry(
    val recordedAt: Long,
    val recipientsSummary: List<String>,
    val stanzaTags: List<String>,
    val deleted: Boolean,
) {
    companion object {
        fun parse(json: ByteArray): List<SharedHistoryEntry> {
            val arr = JSONArray(String(json, Charsets.UTF_8))
            return (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                fun strings(key: String) = o.optJSONArray(key)?.let { a -> (0 until a.length()).map(a::getString) }.orEmpty()
                SharedHistoryEntry(
                    recordedAt = o.optLong("recordedAt"),
                    recipientsSummary = strings("recipientsSummary"),
                    stanzaTags = strings("stanzaTags"),
                    deleted = o.optBoolean("deleted"),
                )
            }
        }
    }
}
