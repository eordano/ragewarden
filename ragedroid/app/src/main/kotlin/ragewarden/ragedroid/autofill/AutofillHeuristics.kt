package ragewarden.ragedroid.autofill

import android.text.InputType
import android.view.View
import androidx.compose.runtime.Immutable

@Immutable
data class FieldCandidate(
    val autofillId: String,
    val role: FieldRole,
    val score: Int,
    val webDomain: String? = null,
)

enum class FieldRole { Username, Password, Unknown }

data class AutofillFieldView(
    val autofillIdToken: String,
    val autofillHints: List<String>,
    val htmlAttributes: Map<String, String>,
    val viewIdEntry: String?,
    val hint: String?,
    val inputType: Int,
    val webDomain: String?,
    val className: String?,
)

object AutofillHeuristics {
    private val USERNAME_HINTS = setOf(
        View.AUTOFILL_HINT_USERNAME,
        View.AUTOFILL_HINT_EMAIL_ADDRESS,
    )

    private val PASSWORD_HINTS = setOf(
        View.AUTOFILL_HINT_PASSWORD,
    )

    private val USERNAME_TOKENS = listOf("user", "email", "login", "account", "uname", "ident")
    private val PASSWORD_TOKENS = listOf("password", "passwd", "passcode", "pass", "pwd")

    fun classify(view: AutofillFieldView): FieldCandidate {
        val (role, score) = classifyRole(view)
        return FieldCandidate(
            autofillId = view.autofillIdToken,
            role = role,
            score = score,
            webDomain = view.webDomain,
        )
    }

    fun classifyAll(views: List<AutofillFieldView>): List<FieldCandidate> =
        views.map(::classify).filter { it.role != FieldRole.Unknown }

    fun pickPair(candidates: List<FieldCandidate>): Pair<FieldCandidate?, FieldCandidate?> {
        val username = candidates
            .filter { it.role == FieldRole.Username }
            .maxByOrNull { it.score }
        val password = candidates
            .filter { it.role == FieldRole.Password }
            .maxByOrNull { it.score }
        return username to password
    }

    private fun classifyRole(view: AutofillFieldView): Pair<FieldRole, Int> {
        for (hint in view.autofillHints) {
            if (hint in PASSWORD_HINTS) return FieldRole.Password to 100
            if (hint in USERNAME_HINTS) return FieldRole.Username to 100
        }

        val htmlType = view.htmlAttributes["type"]?.lowercase()
        val htmlAutocomplete = view.htmlAttributes["autocomplete"]?.lowercase()
        val htmlName = view.htmlAttributes["name"]?.lowercase()
        val htmlId = view.htmlAttributes["id"]?.lowercase()
        if (htmlType == "password") return FieldRole.Password to 90
        if (htmlAutocomplete != null) {
            if ("password" in htmlAutocomplete) return FieldRole.Password to 90
            if ("username" in htmlAutocomplete || "email" in htmlAutocomplete) {
                return FieldRole.Username to 90
            }
        }
        if (htmlName != null && containsAny(htmlName, PASSWORD_TOKENS)) return FieldRole.Password to 80
        if (htmlId != null && containsAny(htmlId, PASSWORD_TOKENS)) return FieldRole.Password to 80
        if (htmlName != null && containsAny(htmlName, USERNAME_TOKENS)) return FieldRole.Username to 80
        if (htmlId != null && containsAny(htmlId, USERNAME_TOKENS)) return FieldRole.Username to 80

        if (isPasswordInputType(view.inputType)) return FieldRole.Password to 70

        val haystacks = listOfNotNull(view.viewIdEntry?.lowercase(), view.hint?.lowercase())
        for (h in haystacks) {
            if (containsAny(h, PASSWORD_TOKENS)) return FieldRole.Password to 60
            if (containsAny(h, USERNAME_TOKENS)) return FieldRole.Username to 60
        }

        if (isTextEmailInputType(view.inputType)) return FieldRole.Username to 50

        return FieldRole.Unknown to 0
    }

    private fun containsAny(text: String, tokens: List<String>): Boolean =
        tokens.any { it in text }

    private fun isPasswordInputType(inputType: Int): Boolean {
        if (inputType == 0) return false
        val klass = inputType and InputType.TYPE_MASK_CLASS
        val variation = inputType and InputType.TYPE_MASK_VARIATION
        if (klass != InputType.TYPE_CLASS_TEXT && klass != InputType.TYPE_CLASS_NUMBER) return false
        return variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
            variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
            variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD
    }

    private fun isTextEmailInputType(inputType: Int): Boolean {
        if (inputType == 0) return false
        val klass = inputType and InputType.TYPE_MASK_CLASS
        if (klass != InputType.TYPE_CLASS_TEXT) return false
        val variation = inputType and InputType.TYPE_MASK_VARIATION
        return variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
    }
}
