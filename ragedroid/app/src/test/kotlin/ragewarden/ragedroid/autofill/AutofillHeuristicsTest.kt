package ragewarden.ragedroid.autofill

import android.text.InputType
import android.view.View
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class AutofillHeuristicsTest {
    @Test
    fun explicit_autofill_hint_password_classified_as_password() {
        val view = makeView(
            id = "field-pw",
            autofillHints = listOf(View.AUTOFILL_HINT_PASSWORD),
        )
        val candidate = AutofillHeuristics.classify(view)
        assertEquals(FieldRole.Password, candidate.role)
    }

    @Test
    fun explicit_autofill_hint_username_classified_as_username() {
        val view = makeView(
            id = "field-u",
            autofillHints = listOf(View.AUTOFILL_HINT_USERNAME),
        )
        val candidate = AutofillHeuristics.classify(view)
        assertEquals(FieldRole.Username, candidate.role)
    }

    @Test
    fun email_hint_classified_as_username() {
        val view = makeView(
            id = "field-em",
            autofillHints = listOf(View.AUTOFILL_HINT_EMAIL_ADDRESS),
        )
        val candidate = AutofillHeuristics.classify(view)
        assertEquals(FieldRole.Username, candidate.role)
    }

    @Test
    fun html_input_type_password_wins() {
        val view = makeView(
            id = "field-html-pw",
            htmlAttributes = mapOf("type" to "password", "name" to "userPwd"),
        )
        assertEquals(FieldRole.Password, AutofillHeuristics.classify(view).role)
    }

    @Test
    fun html_autocomplete_username_classifies_username() {
        val view = makeView(
            id = "field-html-user",
            htmlAttributes = mapOf("type" to "text", "autocomplete" to "username"),
        )
        assertEquals(FieldRole.Username, AutofillHeuristics.classify(view).role)
    }

    @Test
    fun html_name_token_password_classifies_password() {
        val view = makeView(
            id = "field-html-name",
            htmlAttributes = mapOf("type" to "text", "name" to "user_password"),
        )
        assertEquals(FieldRole.Password, AutofillHeuristics.classify(view).role)
    }

    @Test
    fun input_type_password_variation_classifies_password() {
        val view = makeView(
            id = "field-pw-var",
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD,
        )
        assertEquals(FieldRole.Password, AutofillHeuristics.classify(view).role)
    }

    @Test
    fun visible_password_input_type_classifies_password() {
        val view = makeView(
            id = "field-pw-visible",
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
        )
        assertEquals(FieldRole.Password, AutofillHeuristics.classify(view).role)
    }

    @Test
    fun email_input_type_classifies_username() {
        val view = makeView(
            id = "field-em-input",
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS,
        )
        assertEquals(FieldRole.Username, AutofillHeuristics.classify(view).role)
    }

    @Test
    fun view_id_token_user_classifies_username() {
        val view = makeView(
            id = "etUserName",
            viewIdEntry = "etUserName",
            inputType = InputType.TYPE_CLASS_TEXT,
        )
        assertEquals(FieldRole.Username, AutofillHeuristics.classify(view).role)
    }

    @Test
    fun unknown_field_returns_unknown() {
        val view = makeView(
            id = "unrelated",
            inputType = InputType.TYPE_CLASS_TEXT,
        )
        assertEquals(FieldRole.Unknown, AutofillHeuristics.classify(view).role)
    }

    @Test
    fun classify_all_filters_unknown_and_pickPair_returns_best() {
        val views = listOf(
            makeView(
                id = "userField",
                viewIdEntry = "loginEmail",
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS,
            ),
            makeView(
                id = "passField",
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD,
            ),
            makeView(id = "noise"),
        )
        val candidates = AutofillHeuristics.classifyAll(views)
        assertEquals(2, candidates.size)
        val (u, p) = AutofillHeuristics.pickPair(candidates)
        assertNotNull(u)
        assertNotNull(p)
        assertEquals("userField", u!!.autofillId)
        assertEquals("passField", p!!.autofillId)
    }

    @Test
    fun pickPair_returns_nulls_when_only_unknowns() {
        val candidates = AutofillHeuristics.classifyAll(listOf(makeView(id = "noise")))
        val (u, p) = AutofillHeuristics.pickPair(candidates)
        assertNull(u)
        assertNull(p)
    }

    private fun makeView(
        id: String,
        autofillHints: List<String> = emptyList(),
        htmlAttributes: Map<String, String> = emptyMap(),
        viewIdEntry: String? = null,
        hint: String? = null,
        inputType: Int = 0,
        webDomain: String? = null,
        className: String? = "android.widget.EditText",
    ): AutofillFieldView = AutofillFieldView(
        autofillIdToken = id,
        autofillHints = autofillHints,
        htmlAttributes = htmlAttributes,
        viewIdEntry = viewIdEntry,
        hint = hint,
        inputType = inputType,
        webDomain = webDomain,
        className = className,
    )
}
