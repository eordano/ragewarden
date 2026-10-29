package ragewarden.ragedroid.data

import java.nio.ByteBuffer
import java.nio.CharBuffer

/**
 * Secret text as zeroable arrays up to the Android API that takes it. The
 * platform APIs that deliver text -- `ClipData`, `AutofillValue`,
 * `InputConnection.commitText` -- accept any `CharSequence` and turn it into a
 * `String` only while parcelling it for the binder call; handing them a
 * [CharBuffer] over a [CharArray] that is zeroed once that call returns keeps
 * this process from holding a `String` copy of its own.
 */
object SecretText {
    /** UTF-8 [bytes] decoded straight into a [CharArray]; no `String` is made. */
    fun chars(bytes: ByteArray): CharArray {
        val decoded = Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes))
        val out = CharArray(decoded.remaining())
        decoded.get(out)
        if (decoded.hasArray()) decoded.array().fill('\u0000')
        return out
    }

    /** Runs [use] with [bytes] as a `CharSequence`, then zeroes the characters. */
    inline fun <T> withChars(bytes: ByteArray, use: (CharSequence) -> T): T {
        val c = chars(bytes)
        try {
            return use(CharBuffer.wrap(c))
        } finally {
            c.fill('\u0000')
        }
    }

    /**
     * A JSON object of field name to secret value, built as bytes: the values
     * never become `String`s. Values must be UTF-8; quotes, backslashes and
     * control characters are escaped as JSON requires.
     */
    fun fieldsJson(fields: Map<String, ByteArray>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write('{'.code)
        fields.entries.forEachIndexed { i, (name, value) ->
            if (i > 0) out.write(','.code)
            out.write(org.json.JSONObject.quote(name).toByteArray(Charsets.UTF_8))
            out.write(':'.code)
            out.write('"'.code)
            for (b in value) {
                val u = b.toInt() and 0xff
                when {
                    u == '"'.code -> { out.write('\\'.code); out.write('"'.code) }
                    u == '\\'.code -> { out.write('\\'.code); out.write('\\'.code) }
                    u < 0x20 -> out.write("\\u%04x".format(u).toByteArray(Charsets.US_ASCII))
                    else -> out.write(u)
                }
            }
            out.write('"'.code)
        }
        out.write('}'.code)
        return out.toByteArray()
    }
}
