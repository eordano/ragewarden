package ragewarden.ragedroid.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.view.autofill.AutofillId

data class AutofillCandidate(
    val autofillId: AutofillId,
    val role: FieldRole,
    val score: Int,
)

data class WalkResult(
    val candidates: List<AutofillCandidate>,
    val webDomain: String?,
    val packageName: String?,
)

object AssistStructureWalker {
    fun walk(structure: AssistStructure, packageName: String?): WalkResult {
        val views = mutableListOf<Pair<AutofillId, AutofillFieldView>>()
        var webDomain: String? = null

        for (i in 0 until structure.windowNodeCount) {
            val window = structure.getWindowNodeAt(i)
            val root = window.rootViewNode ?: continue
            walkNode(root, views) { domain ->
                if (webDomain == null) webDomain = domain
            }
        }

        val classified = views.mapNotNull { (autofillId, view) ->
            val candidate = AutofillHeuristics.classify(view)
            if (candidate.role == FieldRole.Unknown) {
                null
            } else {
                AutofillCandidate(autofillId, candidate.role, candidate.score)
            }
        }
        return WalkResult(
            candidates = classified,
            webDomain = webDomain,
            packageName = packageName,
        )
    }

    private fun walkNode(
        node: AssistStructure.ViewNode,
        out: MutableList<Pair<AutofillId, AutofillFieldView>>,
        domainSink: (String) -> Unit,
    ) {
        node.webDomain?.takeIf { it.isNotBlank() }?.let(domainSink)

        val autofillId = node.autofillId
        if (autofillId != null) {
            val htmlAttrs: Map<String, String> = node.htmlInfo?.attributes
                ?.associate { it.first.lowercase() to it.second }
                ?: emptyMap()
            val view = AutofillFieldView(
                autofillIdToken = autofillId.toString(),
                autofillHints = node.autofillHints?.toList().orEmpty(),
                htmlAttributes = htmlAttrs,
                viewIdEntry = node.idEntry,
                hint = readHintCompat(node),
                inputType = node.inputType,
                webDomain = node.webDomain,
                className = node.className,
            )
            out.add(autofillId to view)
        }

        for (i in 0 until node.childCount) {
            walkNode(node.getChildAt(i), out, domainSink)
        }
    }

    /** What was typed into [ids], for a save request; fields with no text are left out. */
    fun textValues(structure: AssistStructure, ids: Set<AutofillId>): Map<AutofillId, CharSequence> {
        val out = HashMap<AutofillId, CharSequence>()
        fun visit(node: AssistStructure.ViewNode) {
            val id = node.autofillId
            val value = node.autofillValue
            if (id != null && id in ids && value != null && value.isText) out[id] = value.textValue
            for (i in 0 until node.childCount) visit(node.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) structure.getWindowNodeAt(i).rootViewNode?.let(::visit)
        return out
    }

    private fun readHintCompat(node: AssistStructure.ViewNode): String? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) node.hint else null
}
