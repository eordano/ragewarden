package ragewarden.ragedroid.data

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test
import ragewarden.ragedroid.data.audit.AuditAction
import ragewarden.ragedroid.data.audit.AuditResult

class AuditVocabularyConformanceTest {
    private fun vocabulary(): JsonObject {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val f = File(dir, "core/tests/vectors/audit_vocabulary_v1.json")
            if (f.isFile) return Json.parseToJsonElement(f.readText()).jsonObject
            dir = dir.parentFile
        }
        error("core/tests/vectors/audit_vocabulary_v1.json not found above ${System.getProperty("user.dir")}")
    }

    @Test
    fun kinds_and_results_are_the_shared_vocabulary() {
        val v = vocabulary()
        val kinds = v.getValue("kinds").jsonArray.map { it.jsonPrimitive.content }
        assertEquals(kinds, AuditAction.entries.map { it.name })
        val results = v.getValue("results").jsonArray.map { it.jsonPrimitive.content }
        assertEquals(results, AuditResult.entries.map { it.name.lowercase() })
    }

    @Test
    fun every_legacy_name_maps_where_core_says() {
        vocabulary().getValue("legacy_names").jsonObject.forEach { (old, now) ->
            assertEquals(old, now.jsonPrimitive.content, AuditAction.parse(old)?.name)
        }
    }
}
