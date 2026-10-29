package ragewarden.ragedroid.ui

import android.content.Context
import android.util.LayoutDirection
import androidx.test.core.app.ApplicationProvider
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import ragewarden.ragedroid.R

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class StringResourcesTest {
    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    @Config(qualifiers = "ar-rXB")
    fun ui_text_comes_from_resources_so_a_pseudo_locale_reaches_it() {
        val text = context.getString(R.string.master_password)
        assertNotEquals("Master password", text)
        assertEquals(LayoutDirection.RTL, context.resources.configuration.layoutDirection)
    }

    /**
     * No string literal in ui/, ime/ or autofill/ holds human text: no
     * capitalised word, none of two or more words or of a word and a template
     * anywhere (see [UiLiterals]), and nothing at all in a text slot (`text =`,
     * `label =`, `Text(`, `showToast(` ...). The allowlist is what is not UI text:
     * logcat, test tags, intent extras, keys and constants, matching against
     * core's own error text, date patterns, lower-case developer invariants
     * handed to error/check/require, the IME's logged refusal reasons, and
     * @Preview sample data.
     */
    @Test
    fun no_multi_word_literal_in_ui_code() {
        val src = appMain()
        val hits = listOf("ui", "ime", "autofill")
            .flatMap { File(src, it).walkTopDown().filter { f -> f.extension == "kt" && f.name != "UiStrings.kt" }.toList() }
            .flatMap { f -> UiLiterals.offenders(f.readText()).map { "${f.name}:$it" } }
        assertTrue(
            "${hits.size} UI literals not in string resources. Put the text in res/values/strings.xml and read it " +
                "with stringResource, or uiString outside composition:\n" + hits.take(30).joinToString("\n"),
            hits.isEmpty(),
        )
    }

    @Test
    fun the_scan_flags_text_and_passes_keys() {
        val q = '"'
        fun flagged(code: String) = UiLiterals.offenders(code.replace('`', q)).isNotEmpty()
        assertTrue(flagged("Text(`Hello there`)"))
        assertTrue(flagged("onToast(`Protected ${'$'}n items`)"))
        assertTrue(flagged("val label = `Saved`\nText(text = `Saved`)"))
        assertTrue(flagged("error(`The vault locked. Try again.`)"))
        assertTrue(flagged("label = if (p) `New ${'$'}field` else other"))
        assertTrue(!flagged("val key = `field-${'$'}name`"))
        assertTrue(flagged("val s = if (busy) `Removing...` else `Remove`"))
        assertTrue(!flagged("val k = if (a) `password` else `GET`"))
        assertTrue(!flagged("Log.w(TAG, `decrypt failed for item`, e)"))
        assertTrue(!flagged("error(`no repository bound yet`)"))
        assertTrue(!flagged("if (msg.contains(`no matching key`)) x"))
        assertTrue(!flagged("Modifier.testTag(`unlock button`)"))
        assertTrue(!flagged("@Preview\n@Composable\nfun P() { Text(`Sample item name`) }"))
        assertTrue(!flagged("val key = `ragedroid.autofill.domain`"))
    }

    private fun appMain(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            File(dir, "app/src/main/kotlin/ragewarden/ragedroid").takeIf { it.isDirectory }?.let { return it }
            File(dir, "src/main/kotlin/ragewarden/ragedroid").takeIf { it.isDirectory }?.let { return it }
            dir = dir.parentFile
        }
        error("app sources not found above ${System.getProperty("user.dir")}")
    }
}
