package ragewarden.ragedroid.ui

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * User-facing text speaks of items, keys and protection, not of the file
 * format underneath. Scans every string resource and every sentence-shaped
 * string literal in ui/, ime/ and autofill/ for implementation vocabulary.
 */
class UiVocabularyTest {
    private fun appRoot(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            File(dir, "app/src/main").takeIf { it.isDirectory }?.let { return it }
            File(dir, "src/main/res").takeIf { it.isDirectory }?.let { return File(dir, "src/main") }
            dir = dir.parentFile
        }
        error("app sources not found above ${System.getProperty("user.dir")}")
    }

    @Test
    fun ui_text_has_no_format_jargon() {
        val main = appRoot()
        val hits = mutableListOf<String>()
        File(main, "res").walkTopDown().filter { it.name.startsWith("strings") && it.extension == "xml" }.forEach { f ->
            f.readLines().forEachIndexed { i, line ->
                val value = VALUE.find(line)?.groupValues?.get(1) ?: return@forEachIndexed
                if (DENY.containsMatchIn(value)) hits += "${f.parentFile.name}/${f.name}:${i + 1}: $value"
            }
        }
        listOf("ui", "ime", "autofill").map { File(main, "kotlin/ragewarden/ragedroid/$it") }
            .flatMap { it.walkTopDown().filter { f -> f.extension == "kt" }.toList() }
            .forEach { f ->
                f.readLines().forEachIndexed { i, line ->
                    val trimmed = line.trimStart()
                    if (trimmed.startsWith("//") || trimmed.startsWith("*")) return@forEachIndexed
                    LITERAL.findAll(line).map { it.groupValues[1] }
                        .filter { it.contains(' ') && DENY.containsMatchIn(it) }
                        .forEach { hits += "${f.name}:${i + 1}: $it" }
                }
            }
        assertTrue("implementation vocabulary in UI text:\n" + hits.joinToString("\n"), hits.isEmpty())
    }

    private companion object {
        val VALUE = Regex("""<string name="[^"]+">(.*)</string>""")
        val LITERAL = Regex(""""((?:[^"\\]|\\.)*)"""")
        val DENY = Regex(
            listOf(
                """\b""" + "r" + """age-protected""",
                """\bstanzas?\b""",
                """\bcipher(s|text)?\b""",
                """\bblobs?\b""",
                """\bage (header|headers|envelope|identity|identities|stanza)\b""",
                """cross-device registry""",
                """\b(wrapped|encrypted) with """ + "r" + """age\b""",
                """PBKDF2 KDF""",
                """No caching, no exceptions""",
            ).joinToString("|"),
            RegexOption.IGNORE_CASE,
        )
    }
}
