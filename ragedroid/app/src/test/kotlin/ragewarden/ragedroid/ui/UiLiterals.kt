package ragewarden.ragedroid.ui

/** Finds string literals holding human text in Kotlin source, for StringResourcesTest. */
internal object UiLiterals {
    private val SKIP_LINE = Regex(
        """^\s*(import |package |@Suppress|@file:)|\bLog\.[a-z]\(|\bTAG\b|testTag\(|Regex\(|\bconst val\b|getStringExtra|putExtra\(|EXTRA_|\.Builder\(|BuildConfig""" +
            """|\.(contains|startsWith|endsWith|substringAfter|substringBefore|removePrefix|removeSuffix|equals)\(|ofPattern\(|SimpleDateFormat\(|Refused\(""",
    )
    private val DEV_CALL = Regex("""\b(error|check|require|checkNotNull|requireNotNull)\s*\(|IllegalStateException\(|IllegalArgumentException\(""")
    private val DEV_BLOCK = Regex("""(check|require)\([^\n]*\)\s*\{\s*$""")
    private val TEXT_SLOT = Regex(
        """(?:\b(?:text|label|title|sub|kicker|placeholder|contentDescription|subtitle|hint|message|body)\s*=|\b(?:Text|showToast)\()\s*$""",
    )
    private val WORD = Regex("""[A-Za-z]{2}""")
    private val SINGLE = Regex("""[A-Z][a-z]+(-[a-z]+)?(\.\.\.|\u2026)?""")

    /** "line: text" for each offending literal. */
    fun offenders(src: String): List<String> {
        val previews = previewRanges(src)
        val out = mutableListOf<String>()
        var i = 0
        while (i < src.length) {
            val c = src[i]
            when {
                src.startsWith("//", i) -> i = src.indexOf('\n', i).let { if (it < 0) src.length else it }
                src.startsWith("/*", i) -> i = src.indexOf("*/", i).let { if (it < 0) src.length else it + 2 }
                src.startsWith("\"\"\"", i) -> i = src.indexOf("\"\"\"", i + 3).let { if (it < 0) src.length else it + 3 }
                c == '\'' -> i = skipChar(src, i)
                c == '"' -> {
                    val (end, text, first) = readLiteral(src, i)
                    val inSlot = TEXT_SLOT.containsMatchIn(src.substring(src.lastIndexOf('\n', i - 1) + 1, i))
                    val human = human(text) || (inSlot && WORD.containsMatchIn(text))
                    if (human && previews.none { i in it } && !allowed(src, i, first)) {
                        out += "${src.substring(0, i).count { it == '\n' } + 1}: ${text.take(60)}"
                    }
                    i = end
                }
                else -> i++
            }
        }
        return out
    }

    /**
     * Human text: one capitalised word ("Remove", "Verifying..."), or
     * whitespace in the literal's own text and either two words or a word and
     * a template ("Protected $n items", "New $label"). A word glued to a
     * template ("field-$name", "package:$pkg") is a key; lower-case and
     * all-caps single words ("password", "GET") are keys too.
     */
    private fun human(text: String): Boolean {
        if (SINGLE.matches(text)) return true
        if (!text.replace("\u0000", "").any { it.isWhitespace() }) return false
        val words = text.split(Regex("""[\s\u0000]+""")).count { WORD.containsMatchIn(it) }
        return words >= 2 || (words >= 1 && '\u0000' in text)
    }

    private fun allowed(src: String, pos: Int, first: String): Boolean {
        val ls = src.lastIndexOf('\n', pos - 1) + 1
        val le = src.indexOf('\n', pos).let { if (it < 0) src.length else it }
        val line = src.substring(ls, le)
        if (SKIP_LINE.containsMatchIn(line) || inLogCall(src, pos)) return true
        if (first.trimStart().firstOrNull()?.isLowerCase() == true) {
            val before = src.substring(ls, pos)
            val prevLine = src.substring(src.lastIndexOf('\n', (ls - 2).coerceAtLeast(0)).coerceAtLeast(0), ls)
            if (DEV_CALL.containsMatchIn(before) || DEV_BLOCK.containsMatchIn(prevLine.trimEnd('\n')) || DEV_BLOCK.containsMatchIn(before)) return true
        }
        return false
    }

    private fun inLogCall(src: String, pos: Int): Boolean {
        val start = (pos - 400).coerceAtLeast(0)
        val window = src.substring(start, pos)
        return Regex("""\bLog\.[a-z]\(""").findAll(window).any { m ->
            window.substring(m.range.last).fold(0) { d, ch -> if (ch == '(') d + 1 else if (ch == ')') d - 1 else d } > 0
        }
    }

    private fun skipChar(src: String, i: Int): Int {
        var j = i + 1
        if (j < src.length && src[j] == '\\') j += 2 else j++
        while (j < src.length && src[j] != '\'') j++
        return j + 1
    }

    /** End index, the literal's text with templates blanked, and its first literal part. */
    private fun readLiteral(src: String, start: Int): Triple<Int, String, String> {
        val text = StringBuilder()
        var first: String? = null
        val part = StringBuilder()
        var j = start + 1
        while (j < src.length) {
            val c = src[j]
            when {
                c == '\\' -> { part.append(src.getOrNull(j + 1) ?: ' '); j += 2 }
                c == '"' -> {
                    if (first == null) first = part.toString()
                    text.append(part)
                    return Triple(j + 1, text.toString(), first)
                }
                c == '$' && src.getOrNull(j + 1) == '{' -> {
                    if (first == null) first = part.toString()
                    text.append(part).append('\u0000'); part.clear()
                    var depth = 1
                    j += 2
                    while (j < src.length && depth > 0) {
                        when (src[j]) {
                            '"' -> { j = readLiteral(src, j).first; continue }
                            '{' -> depth++
                            '}' -> depth--
                        }
                        j++
                    }
                }
                c == '$' && (src.getOrNull(j + 1)?.let { it.isLetter() || it == '_' } == true) -> {
                    if (first == null) first = part.toString()
                    text.append(part).append('\u0000'); part.clear()
                    j++
                    while (j < src.length && (src[j].isLetterOrDigit() || src[j] == '_')) j++
                }
                c == '\n' -> return Triple(j, text.append(part).toString(), first ?: part.toString())
                else -> { part.append(c); j++ }
            }
        }
        return Triple(j, text.append(part).toString(), first ?: part.toString())
    }

    private fun previewRanges(src: String): List<IntRange> = Regex("@Preview").findAll(src).mapNotNull { m ->
        val open = src.indexOf('{', m.range.last).takeIf { it >= 0 } ?: return@mapNotNull null
        var depth = 0
        var k = open
        while (k < src.length) {
            if (src[k] == '{') depth++
            if (src[k] == '}') { depth--; if (depth == 0) break }
            k++
        }
        m.range.first..k
    }.toList()
}
